#pragma once

/**
 * @file acceptorManager.hpp
 * @brief 接收器管理器 (AcceptorManager)。
 *
 * 职责彻底解耦：
 * 1. 统一接收器抽象：Acceptor 统领各类协议入站端点；
 * 2. 描述符与生命周期：统一管理监听套接字 (listenFd) 的绑定、非阻塞 accept 与优雅停机；
 * 3. 状态机就绪装配：驱动新接入的客户端套接字完成协议握手并交付就绪的 Connection 实例；
 * 4. 嗅探配置协同：按端点维度灵活开启/关闭首包应用层协议与域名嗅探；
 * 5. 全局注册与一键启停：支持多端口/多协议并发监听、批量拉起 (startAll) 与停止 (stopAll)。
 */

#include "acceptor.hpp"
#include "address.hpp"
#include "config/log.hpp"
#include "connection.hpp"
#include "error.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <optional>
#include <poll.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

// 拆分到各协议独立目录下的具体接收器端点实现
#include "direct/inbound.hpp"
#include "http/inbound.hpp"
#include "hysteria2/inbound.hpp"
#include "shadowsocks/inbound.hpp"
#include "socks/inbound.hpp"
#include "transparent.hpp"
#include "trojan/inbound.hpp"
#include "tun/inbound.hpp"
#include "vless/inbound.hpp"
#include "vmess/inbound.hpp"

namespace mynet
{

    /**
     * @brief 统一接收器管理器 (AcceptorManager)
     *
     * 集中注册与管理所有业务接收器端点 (Acceptor)，支持一键多端口并发监听与平滑停机。
     */
    class AcceptorManager
    {
    private:
        mutable std::mutex mutex_{};
        std::unordered_map<std::string, std::shared_ptr<Acceptor>> acceptors_{};
        std::atomic<bool> running_{false};

    public:
        AcceptorManager() = default;

        ~AcceptorManager() noexcept { stopAll(); }

        AcceptorManager(const AcceptorManager &) = delete;
        AcceptorManager &operator=(const AcceptorManager &) = delete;
        AcceptorManager(AcceptorManager &&) = delete;
        AcceptorManager &operator=(AcceptorManager &&) = delete;

        [[nodiscard]] inline bool isRunning() const noexcept { return running_.load(std::memory_order_acquire); }

        /**
         * @brief 注册一个接收器节点
         */
        void registerAcceptor(std::shared_ptr<Acceptor> acceptor)
        {
            if (acceptor == nullptr)
                return;
            std::lock_guard<std::mutex> lock(mutex_);
            acceptors_[acceptor->tag()] = std::move(acceptor);
        }

        /**
         * @brief 根据标签获取接收器节点
         */
        [[nodiscard]] std::shared_ptr<Acceptor> get(std::string_view tag) const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = acceptors_.find(std::string(tag));
            return (it != acceptors_.end()) ? it->second : nullptr;
        }

        [[nodiscard]] inline std::shared_ptr<Acceptor> getAcceptor(std::string_view tag) const
        {
            return get(tag);
        }

        [[nodiscard]] bool has(std::string_view tag) const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return acceptors_.contains(std::string(tag));
        }

        /**
         * @brief 根据监听套接字描述符快速查找匹配的接收器节点
         */
        [[nodiscard]] std::shared_ptr<Acceptor> findByListenFd(int fd) const
        {
            if (fd < 0)
                return nullptr;
            std::lock_guard<std::mutex> lock(mutex_);
            for (const auto &pair : acceptors_)
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
            auto it = acceptors_.find(std::string(tag));
            if (it != acceptors_.end())
            {
                it->second->close();
                acceptors_.erase(it);
            }
        }

        [[nodiscard]] size_t size() const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return acceptors_.size();
        }

        [[nodiscard]] std::vector<std::string> listTags() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            std::vector<std::string> tags;
            tags.reserve(acceptors_.size());
            for (const auto &pair : acceptors_)
            {
                tags.push_back(pair.first);
            }
            return tags;
        }

        [[nodiscard]] std::vector<std::shared_ptr<Acceptor>> acceptors() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            std::vector<std::shared_ptr<Acceptor>> list;
            list.reserve(acceptors_.size());
            for (const auto &pair : acceptors_)
            {
                list.push_back(pair.second);
            }
            return list;
        }

        /**
         * @brief 启动全部已注册的接收器节点监听
         */
        Result<> startAll(int backlog = 128)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto &pair : acceptors_)
            {
                if (auto res = pair.second->listen(backlog); !res)
                {
                    LOG_ERROR("AcceptorManager: failed to start acceptor '{}': {}", pair.first, toString(res.error()));
                    return res;
                }
            }
            running_.store(true, std::memory_order_release);
            return {};
        }

        /**
         * @brief 停止并关闭全部接收器节点监听
         */
        void stopAll() noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto &pair : acceptors_)
            {
                if (pair.second)
                {
                    pair.second->close();
                }
            }
            running_.store(false, std::memory_order_release);
        }

        void clear() noexcept
        {
            stopAll();
            std::lock_guard<std::mutex> lock(mutex_);
            acceptors_.clear();
        }
    };

} // namespace mynet
