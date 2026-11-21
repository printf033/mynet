#pragma once

/**
 * @file inboundManager.hpp
 * @brief 入站节点抽象基类 (InboundBase) 与统一入站管理器 (InboundManager)。
 *
 * 与 OutboundManager 形成严格对称的架构设计：
 * 1. 统一入站抽象：抽象基类 InboundBase 统领各类协议入站端点；
 * 2. 描述符与生命周期：统一管理监听套接字 (listenFd) 的绑定、非阻塞 accept 与优雅停机；
 * 3. 状态机工厂化产出：为新接入的客户端套接字创建匹配的协议状态机 (HandlerInboundConnectionBase)；
 * 4. 嗅探配置协同：按入站维度灵活开启/关闭首包应用层协议与域名嗅探；
 * 5. 全局注册与一键启停：支持多端口/多协议并发监听、批量拉起 (startAll) 与停止 (stopAll)。
 */

#include "address.hpp"
#include "config/log.hpp"
#include "connection.hpp"
#include "error.hpp"
#include "socket.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <optional>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

namespace mynet
{

    /**
     * @brief 入站节点抽象基类 (Abstract Inbound Base)
     *
     * 业务入站端点元数据描述符与协议状态机工厂 (Endpoint & Protocol Factory)。
     * 底层套接字生命周期与非阻塞 accept 严格托管给基础传输设施 AcceptorBase。
     */
    class InboundBase
    {
    protected:
        std::string tag_{};
        std::string type_{};
        std::string host_{"0.0.0.0"};
        uint16_t port_{0};
        int listenFd_{-1};
        sockaddr_in addr_{};
        bool running_{false};
        bool enableSniffing_{true};

    public:
        InboundBase(std::string tag, std::string type, std::string host, uint16_t port, bool enableSniffing = true)
            : tag_(std::move(tag)),
              type_(std::move(type)),
              host_(std::move(host)),
              port_(port),
              enableSniffing_(enableSniffing)
        {
        }

        virtual ~InboundBase() noexcept { close(); }

        InboundBase(const InboundBase &) = delete;
        InboundBase &operator=(const InboundBase &) = delete;
        InboundBase(InboundBase &&) = delete;
        InboundBase &operator=(InboundBase &&) = delete;

        [[nodiscard]] inline const std::string &tag() const noexcept { return tag_; }
        [[nodiscard]] inline const std::string &type() const noexcept { return type_; }
        [[nodiscard]] inline const std::string &host() const noexcept { return host_; }
        [[nodiscard]] inline uint16_t port() const noexcept { return port_; }
        [[nodiscard]] inline int listenFd() const noexcept { return listenFd_; }
        [[nodiscard]] inline const sockaddr_in &addr() const noexcept { return addr_; }
        [[nodiscard]] inline bool isRunning() const noexcept { return running_; }
        [[nodiscard]] inline bool isSniffingEnabled() const noexcept { return enableSniffing_; }
        inline void setSniffingEnabled(bool enable) noexcept { enableSniffing_ = enable; }

        /**
         * @brief 启动非阻塞 TCP 监听
         */
        virtual Result<> listen(int backlog = 128, bool reuseAddr = true, bool reusePort = true) noexcept
        {
            if (running_ && listenFd_ >= 0)
            {
                return {};
            }
            close();

            auto res = net::listenTcp(host_.c_str(), port_, addr_, backlog, reuseAddr, reusePort);
            if (!res)
            {
                LOG_ERROR("Inbound '{}' ({}): listenTcp {}:{} failed", tag_, type_, host_, port_);
                return std::unexpected(res.error());
            }
            listenFd_ = *res;

            if (port_ == 0)
            {
                port_ = ntohs(addr_.sin_port);
            }

            running_ = true;
            return {};
        }

        /**
         * @brief 非阻塞接收一个接入的客户端连接
         */
        [[nodiscard]] virtual Result<std::pair<int, sockaddr_in>> acceptOne() noexcept
        {
            return net::accept(listenFd_);
        }

        /**
         * @brief 关闭监听套接字
         */
        virtual void close() noexcept
        {
            if (listenFd_ >= 0)
            {
                ::close(listenFd_);
                listenFd_ = -1;
            }
            addr_ = {};
            running_ = false;
        }

        /**
         * @brief 为新接入的连接创建对应的协议状态机处理器
         */
        [[nodiscard]] virtual std::unique_ptr<handler::HandlerInboundConnectionBase> createHandler() = 0;
    };

} // namespace mynet

// 拆分到各协议独立目录下的具体入站端点实现
#include "direct/inbound.hpp"
#include "http/inbound.hpp"
#include "hysteria2/inbound.hpp"
#include "shadowsocks/inbound.hpp"
#include "socks/inbound.hpp"
#include "transparent.hpp"
#include "trojan/inbound.hpp"
#include "vless/inbound.hpp"
#include "vmess/inbound.hpp"

namespace mynet::inbound
{
    /**
     * @brief 驱动新接入的客户端套接字完成入站协议握手与目标地址解析
     */
    inline bool driveHandshake(int clientFd, handler::HandlerInboundConnectionBase &handler, int timeoutMs = 2000)
    {
        while (!handler.isEstablished() && handler.inboundStage() != handler::InboundStage::ERROR)
        {
            pollfd pfd{clientFd, POLLIN, 0};
            int prc = ::poll(&pfd, 1, timeoutMs);
            if (prc <= 0)
            {
                return false;
            }
            char buf[4096];
            ssize_t n = ::read(clientFd, buf, sizeof(buf));
            if (n <= 0)
            {
                return false;
            }
            [[maybe_unused]] auto _ = handler.appendRequest(buf, n);
            handler.handle();
            while (handler.hasResponse())
            {
                std::string resp = handler.takeResponse();
                if (!resp.empty())
                {
                    ::send(clientFd, resp.data(), resp.size(), MSG_NOSIGNAL);
                }
            }
        }
        return handler.isEstablished();
    }
} // namespace mynet::inbound

namespace mynet
{

    /**
     * @brief 统一入站管理器 (Inbound Manager)
     *
     * 集中注册与管理所有业务入站端点 (InboundBase)，支持一键多端口并发监听与平滑停机。
     */
    class InboundManager
    {
    private:
        mutable std::mutex mutex_{};
        std::unordered_map<std::string, std::shared_ptr<InboundBase>> inbounds_{};
        std::atomic<bool> running_{false};

    public:
        InboundManager() = default;

        ~InboundManager() noexcept { stopAll(); }

        InboundManager(const InboundManager &) = delete;
        InboundManager &operator=(const InboundManager &) = delete;
        InboundManager(InboundManager &&) = delete;
        InboundManager &operator=(InboundManager &&) = delete;

        [[nodiscard]] inline bool isRunning() const noexcept { return running_.load(std::memory_order_acquire); }

        /**
         * @brief 注册一个入站节点
         */
        void registerInbound(std::shared_ptr<InboundBase> inbound)
        {
            if (inbound == nullptr)
                return;
            std::lock_guard<std::mutex> lock(mutex_);
            inbounds_[inbound->tag()] = std::move(inbound);
        }

        /**
         * @brief 根据标签获取入站节点
         */
        [[nodiscard]] std::shared_ptr<InboundBase> get(std::string_view tag) const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = inbounds_.find(std::string(tag));
            return (it != inbounds_.end()) ? it->second : nullptr;
        }

        [[nodiscard]] bool has(std::string_view tag) const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return inbounds_.contains(std::string(tag));
        }

        /**
         * @brief 根据监听套接字描述符快速查找匹配的入站节点
         */
        [[nodiscard]] std::shared_ptr<InboundBase> findByListenFd(int fd) const
        {
            if (fd < 0)
                return nullptr;
            std::lock_guard<std::mutex> lock(mutex_);
            for (const auto &pair : inbounds_)
            {
                if (pair.second && pair.second->listenFd() == fd)
                {
                    return pair.second;
                }
            }
            return nullptr;
        }

        inline void remove(std::string_view tag)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = inbounds_.find(std::string(tag));
            if (it != inbounds_.end())
            {
                it->second->close();
                inbounds_.erase(it);
            }
        }

        [[nodiscard]] size_t size() const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return inbounds_.size();
        }

        [[nodiscard]] std::vector<std::string> listTags() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            std::vector<std::string> tags;
            tags.reserve(inbounds_.size());
            for (const auto &pair : inbounds_)
            {
                tags.push_back(pair.first);
            }
            return tags;
        }

        [[nodiscard]] std::vector<std::shared_ptr<InboundBase>> inbounds() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            std::vector<std::shared_ptr<InboundBase>> list;
            list.reserve(inbounds_.size());
            for (const auto &pair : inbounds_)
            {
                list.push_back(pair.second);
            }
            return list;
        }

        /**
         * @brief 启动全部已注册的入站节点监听
         */
        Result<> startAll(int backlog = 128)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto &pair : inbounds_)
            {
                if (auto res = pair.second->listen(backlog); !res)
                {
                    LOG_ERROR("InboundManager: failed to start inbound '{}': {}", pair.first, toString(res.error()));
                    return res;
                }
            }
            running_.store(true, std::memory_order_release);
            return {};
        }

        /**
         * @brief 停止并关闭全部入站节点监听
         */
        void stopAll() noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto &pair : inbounds_)
            {
                if (pair.second != nullptr)
                {
                    pair.second->close();
                }
            }
            running_.store(false, std::memory_order_release);
        }
    };

} // namespace mynet
