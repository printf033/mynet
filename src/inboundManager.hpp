#pragma once

/**
 * @file inboundManager.hpp
 * @brief 入站节点抽象与入站管理器 (Inbound & InboundManager)。
 *
 * 与 OutboundManager 形成严格对称的架构设计：
 * 1. 统一入站抽象：统领 Mixed (SOCKS4/5/HTTP)、SOCKS5、HTTP Proxy、Trojan、
 *    TProxy (透明代理) 与 Direct (直通) 等各类入站监听协议；
 * 2. 描述符与生命周期：统一管理监听套接字 (listenFd) 的绑定、非阻塞 accept 与优雅停机；
 * 3. 状态机工厂化产出：为新接入的客户端套接字创建匹配的协议状态机 (HandlerInboundConnection)；
 * 4. 嗅探配置协同：按入站维度灵活开启/关闭首包应用层协议与域名嗅探；
 * 5. 全局注册与一键启停：支持多端口/多协议并发监听、批量拉起 (startAll) 与停止 (stopAll)。
 */

#include "acceptor.hpp"
#include "error.hpp"
#include "handler/address.hpp"
#include "handler/direct.hpp"
#include "handler/http/http.hpp"
#include "handler/inbound.hpp"
#include "handler/mixed.hpp"
#include "handler/proxy/trojan.hpp"
#include "handler/socks/socks5.hpp"
#include "handler/transparent.hpp"
#include "config/log.hpp"
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
     */
    class Inbound
    {
    protected:
        std::string tag_{};
        std::string type_{};
        std::string host_{"0.0.0.0"};
        uint16_t port_{0};
        int listenFd_{-1};
        bool running_{false};
        bool enableSniffing_{true};

    public:
        Inbound(std::string tag, std::string type, std::string host, uint16_t port, bool enableSniffing = true)
            : tag_(std::move(tag)),
              type_(std::move(type)),
              host_(std::move(host)),
              port_(port),
              enableSniffing_(enableSniffing)
        {
        }

        virtual ~Inbound() noexcept { close(); }

        Inbound(const Inbound &) = delete;
        Inbound &operator=(const Inbound &) = delete;
        Inbound(Inbound &&) = delete;
        Inbound &operator=(Inbound &&) = delete;

        [[nodiscard]] inline const std::string &tag() const noexcept { return tag_; }
        [[nodiscard]] inline const std::string &type() const noexcept { return type_; }
        [[nodiscard]] inline const std::string &host() const noexcept { return host_; }
        [[nodiscard]] inline uint16_t port() const noexcept { return port_; }
        [[nodiscard]] inline int listenFd() const noexcept { return listenFd_; }
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

            listenFd_ = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (listenFd_ < 0)
            {
                LOG_ERROR("Inbound '{}' ({}): socket() failed: {}", tag_, type_, errnoText(errno));
                return std::unexpected(ERR::SOCKET_FAILED);
            }

            constexpr int one = 1;
            if (reuseAddr)
            {
                if (::setsockopt(listenFd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
                {
                    LOG_WARN("Inbound '{}': setsockopt(SO_REUSEADDR) failed: {}", tag_, errnoText(errno));
                }
            }
            if (reusePort)
            {
                if (::setsockopt(listenFd_, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) < 0)
                {
                    LOG_WARN("Inbound '{}': setsockopt(SO_REUSEPORT) failed: {}", tag_, errnoText(errno));
                }
            }

            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            if (::inet_pton(AF_INET, host_.c_str(), &addr.sin_addr) <= 0)
            {
                LOG_ERROR("Inbound '{}': invalid host IP '{}'", tag_, host_);
                close();
                return std::unexpected(ERR::ADDR_INVALID);
            }
            addr.sin_port = htons(port_);

            if (::bind(listenFd_, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr)) < 0)
            {
                LOG_ERROR("Inbound '{}' ({}:{}): bind() failed: {}", tag_, host_, port_, errnoText(errno));
                close();
                return std::unexpected(ERR::BIND_FAILED);
            }

            if (::listen(listenFd_, backlog) < 0)
            {
                LOG_ERROR("Inbound '{}': listen() failed: {}", tag_, errnoText(errno));
                close();
                return std::unexpected(ERR::LISTEN_FAILED);
            }

            // 若初始 port 为 0，动态更新实际内核绑定的端口
            if (port_ == 0)
            {
                socklen_t len = sizeof(addr);
                if (::getsockname(listenFd_, reinterpret_cast<sockaddr *>(&addr), &len) == 0)
                {
                    port_ = ntohs(addr.sin_port);
                }
            }

            running_ = true;
            return {};
        }

        /**
         * @brief 非阻塞接收一个接入的客户端连接
         */
        [[nodiscard]] virtual Result<std::pair<int, sockaddr_in>> acceptOne() noexcept
        {
            if (listenFd_ < 0)
            {
                return std::unexpected(ERR::ACCEPT_FAILED);
            }

            sockaddr_in clientAddr{};
            socklen_t len = sizeof(clientAddr);
            int clientFd = ::accept4(listenFd_, reinterpret_cast<sockaddr *>(&clientAddr), &len,
                                     SOCK_NONBLOCK | SOCK_CLOEXEC);
            if (clientFd < 0)
            {
                return std::unexpected(ERR::ACCEPT_FAILED);
            }
            return std::make_pair(clientFd, clientAddr);
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
            running_ = false;
        }

        /**
         * @brief 为新接入的连接创建对应的协议状态机处理器
         */
        [[nodiscard]] virtual std::unique_ptr<handler::HandlerInboundConnection> createHandler() = 0;
    };

    /**
     * @brief SOCKS5 入站节点 (SOCKS5 Inbound)
     */
    class Socks5Inbound : public Inbound
    {
    private:
        std::string username_{};
        std::string password_{};

    public:
        Socks5Inbound(std::string tag, std::string host, uint16_t port,
                      std::string username = "", std::string password = "",
                      bool enableSniffing = true)
            : Inbound(std::move(tag), "socks5", std::move(host), port, enableSniffing),
              username_(std::move(username)),
              password_(std::move(password))
        {
        }

        [[nodiscard]] std::unique_ptr<handler::HandlerInboundConnection> createHandler() override
        {
            auto h = std::make_unique<handler::HandlerInboundSocks5>();
            if (!username_.empty())
            {
                h->setAuthenticator([u = username_, p = password_](std::string_view user, std::string_view pass) {
                    return user == u && (p.empty() || pass == p);
                });
            }
            return h;
        }
    };

    /**
     * @brief 多协议混合入站节点 (Mixed Inbound: SOCKS4 / SOCKS5 / HTTP 自动嗅探自适应)
     */
    class MixedInbound : public Inbound
    {
    private:
        std::string username_{};
        std::string password_{};

    public:
        MixedInbound(std::string tag, std::string host, uint16_t port,
                     std::string username = "", std::string password = "",
                     bool enableSniffing = true)
            : Inbound(std::move(tag), "mixed", std::move(host), port, enableSniffing),
              username_(std::move(username)),
              password_(std::move(password))
        {
        }

        [[nodiscard]] std::unique_ptr<handler::HandlerInboundConnection> createHandler() override
        {
            auto h = std::make_unique<handler::HandlerInboundMixed>();
            if (!username_.empty())
            {
                h->setAuthenticator([u = username_, p = password_](std::string_view user, std::string_view pass) {
                    return user == u && (p.empty() || pass == p);
                });
            }
            return h;
        }
    };

    /**
     * @brief HTTP 代理入站节点 (HTTP / HTTPS CONNECT Inbound Proxy)
     */
    class HttpInbound : public Inbound
    {
    private:
        std::string username_{};
        std::string password_{};

    public:
        HttpInbound(std::string tag, std::string host, uint16_t port,
                    std::string username = "", std::string password = "",
                    bool enableSniffing = true)
            : Inbound(std::move(tag), "http", std::move(host), port, enableSniffing),
              username_(std::move(username)),
              password_(std::move(password))
        {
        }

        [[nodiscard]] std::unique_ptr<handler::HandlerInboundConnection> createHandler() override
        {
            auto h = std::make_unique<handler::HandlerInboundHttpProxy>();
            if (!username_.empty())
            {
                h->setAuthenticator([u = username_, p = password_](std::string_view user, std::string_view pass) {
                    return user == u && (p.empty() || pass == p);
                });
            }
            return h;
        }
    };

    /**
     * @brief Trojan 协议入站节点 (Trojan Inbound Proxy)
     */
    class TrojanInbound : public Inbound
    {
    private:
        std::string password_{};

    public:
        TrojanInbound(std::string tag, std::string host, uint16_t port, std::string password,
                      bool enableSniffing = true)
            : Inbound(std::move(tag), "trojan", std::move(host), port, enableSniffing),
              password_(std::move(password))
        {
        }

        [[nodiscard]] std::unique_ptr<handler::HandlerInboundConnection> createHandler() override
        {
            return std::make_unique<handler::HandlerInboundTrojan>(password_);
        }
    };

    /**
     * @brief 透明代理入站节点 (TProxy / Redirect Transparent Inbound)
     */
    class TProxyInbound : public Inbound
    {
    public:
        TProxyInbound(std::string tag, std::string host, uint16_t port, bool enableSniffing = true)
            : Inbound(std::move(tag), "tproxy", std::move(host), port, enableSniffing)
        {
        }

        Result<> listen(int backlog = 128, bool reuseAddr = true, bool reusePort = true) noexcept override
        {
            auto res = Inbound::listen(backlog, reuseAddr, reusePort);
            if (!res)
            {
                return res;
            }

            // 尝试为透明代理设置 IP_TRANSPARENT 标志
            constexpr int one = 1;
            if (::setsockopt(listenFd_, SOL_IP, IP_TRANSPARENT, &one, sizeof(one)) < 0)
            {
                LOG_DEBUG("TProxyInbound '{}': setsockopt(IP_TRANSPARENT) not enabled (requires CAP_NET_ADMIN)", tag_);
            }
            return {};
        }

        [[nodiscard]] std::unique_ptr<handler::HandlerInboundConnection> createHandler() override
        {
            return std::make_unique<handler::HandlerInboundTProxy>();
        }
    };

    /**
     * @brief 直连直通入站节点 (Direct Inbound Pass-through)
     */
    class DirectInbound : public Inbound
    {
    public:
        DirectInbound(std::string tag, std::string host, uint16_t port, bool enableSniffing = true)
            : Inbound(std::move(tag), "direct", std::move(host), port, enableSniffing)
        {
        }

        [[nodiscard]] std::unique_ptr<handler::HandlerInboundConnection> createHandler() override
        {
            return std::make_unique<handler::HandlerInboundDirect>();
        }
    };

    /**
     * @brief 统一入站管理器 (Inbound Manager)
     *
     * 与 OutboundManager 严格对称，维护全部入站节点的注册表并协调并发监听。
     */
    class InboundManager
    {
    private:
        mutable std::mutex mutex_{};
        std::unordered_map<std::string, std::shared_ptr<Inbound>> inbounds_{};

    public:
        InboundManager() = default;
        ~InboundManager() noexcept { stopAll(); }

        InboundManager(const InboundManager &) = delete;
        InboundManager &operator=(const InboundManager &) = delete;
        InboundManager(InboundManager &&) = delete;
        InboundManager &operator=(InboundManager &&) = delete;

        /**
         * @brief 注册一个入站节点
         */
        void registerInbound(std::shared_ptr<Inbound> inbound)
        {
            if (inbound == nullptr)
                return;
            std::lock_guard<std::mutex> lock(mutex_);
            inbounds_[inbound->tag()] = std::move(inbound);
        }

        /**
         * @brief 根据标签查找入站节点
         */
        [[nodiscard]] std::shared_ptr<Inbound> get(std::string_view tag) const
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
        }
    };

} // namespace mynet
