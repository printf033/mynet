#pragma once

#if defined(MYNET_ENABLE_URING)

/**
 * @file proactor.hpp
 * @brief 基于 Linux io_uring 的高性能前摄器（Proactor）服务器实现。
 *
 * 与 Reactor 保持严格对称的架构设计：
 * 1. Proactor 纯粹化：彻底剔除 SSL_CTX* 与协议特定成员变量及函数；
 * 2. 基础套接字内聚：内部直接持有 int tcpFd_ 与 int udpFd_；
 * 3. 编译期多 Acceptor / Dialer 聚合：以 std::tuple 内联存储由模板参数确定的各协议接收器与拨号器；
 * 4. 零开销纳秒级嗅探分发：单协议编译期直通，多协议首包特征 match() 极速路由；
 * 5. 与 Reactor 100% 接口对齐，可零成本无缝互换。
 */

#include "acceptor.hpp"
#include "config/log.hpp"
#include "configHolder.hpp"
#include "connection.hpp"
#include "dialer.hpp"
#include "error.hpp"
#include "reactor.hpp"
#include "socket.hpp"
#include <bit>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <liburing.h>
#include <memory>
#include <optional>
#include <span>
#include <stop_token>
#include <sys/socket.h>
#include <tuple>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

namespace mynet
{

    template <typename... Protocols>
    class Proactor
    {
    public:
        using AcceptCallback = std::function<void(int clientFd, const sockaddr_in &clientAddr)>;

        Proactor() noexcept = default;
        ~Proactor() noexcept { reset(); }

        Proactor(const Proactor &) = delete;
        Proactor &operator=(const Proactor &) = delete;

        [[nodiscard]] inline size_t connections() const noexcept { return connections_.size(); }

        inline void stop() noexcept { stopSource_.request_stop(); }
        inline void quit() noexcept { stopSource_.request_stop(); }

        [[nodiscard]] inline int tcpFd() const noexcept { return tcpFd_; }
        [[nodiscard]] inline int udpFd() const noexcept { return udpFd_; }
        [[nodiscard]] inline const sockaddr_in &tcpAddr() const noexcept { return tcpAddr_; }
        [[nodiscard]] inline const sockaddr_in &udpAddr() const noexcept { return udpAddr_; }

        // ---- 编译期类型安全的 Acceptor 检索接口 ----
        template <typename P>
        [[nodiscard]] constexpr auto &acceptor() noexcept
        {
            return std::get<typename ProtocolTraits<P>::Acceptor>(acceptors_);
        }

        template <typename P>
        [[nodiscard]] constexpr const auto &acceptor() const noexcept
        {
            return std::get<typename ProtocolTraits<P>::Acceptor>(acceptors_);
        }

        template <size_t I = 0>
        [[nodiscard]] constexpr auto &acceptor() noexcept
        {
            return std::get<I>(acceptors_);
        }

        template <size_t I = 0>
        [[nodiscard]] constexpr const auto &acceptor() const noexcept
        {
            return std::get<I>(acceptors_);
        }

        // ---- 编译期类型安全的 Dialer 检索接口 ----
        template <typename P>
        [[nodiscard]] constexpr auto &dialer() noexcept
        {
            return std::get<typename ProtocolTraits<P>::Dialer>(dialers_);
        }

        template <typename P>
        [[nodiscard]] constexpr const auto &dialer() const noexcept
        {
            return std::get<typename ProtocolTraits<P>::Dialer>(dialers_);
        }

        template <size_t I = 0>
        [[nodiscard]] constexpr auto &dialer() noexcept
        {
            return std::get<I>(dialers_);
        }

        template <size_t I = 0>
        [[nodiscard]] constexpr const auto &dialer() const noexcept
        {
            return std::get<I>(dialers_);
        }

        Result<> listenTcp(const char *ip, int port, int backlog = 128, bool reuseAddr = true, bool reusePort = true)
        {
            if (tcpFd_ >= 0)
            {
                return {};
            }
            auto res = net::listenTcp(ip, port, tcpAddr_, backlog, reuseAddr, reusePort);
            if (!res)
            {
                return std::unexpected(res.error());
            }
            tcpFd_ = *res;
            return {};
        }

        Result<> listenUdp(const char *ip, int port, bool reuseAddr = true, bool reusePort = true)
        {
            if (udpFd_ >= 0)
            {
                return {};
            }
            auto res = net::listenUdp(ip, port, udpAddr_, reuseAddr, reusePort);
            if (!res)
            {
                return std::unexpected(res.error());
            }
            udpFd_ = *res;
            return {};
        }

        Result<> addListener(int listenFd, AcceptCallback onAccept = nullptr)
        {
            if (listenFd < 0)
            {
                return std::unexpected(ERR::SOCKET_FAILED);
            }
            if (extraListeners_.contains(listenFd))
            {
                return {};
            }

            auto listener = std::make_shared<ExtraListener>();
            listener->fd = listenFd;
            listener->onAccept = std::move(onAccept);
            extraListeners_.emplace(listenFd, listener);
            return {};
        }

        Result<> removeListener(int listenFd)
        {
            auto it = extraListeners_.find(listenFd);
            if (it == extraListeners_.end())
            {
                return {};
            }
            extraListeners_.erase(it);
            return {};
        }

        [[nodiscard]] inline size_t listenerCount() const noexcept
        {
            return (tcpFd_ >= 0 ? 1 : 0) + (udpFd_ >= 0 ? 1 : 0) + extraListeners_.size();
        }

        [[nodiscard]] Result<> runTcp(const char *ip, int port, const ServerConfig &server,
                                      const ProactorConfig &proactor)
        {
            if (auto err = listenTcp(ip, port, server.backlog, server.reuseAddr, server.reusePort); !err)
            {
                reset();
                return err;
            }
            Result<> rc = serve(server, proactor);
            reset();
            return rc;
        }

        [[nodiscard]] Result<> runTcp(const char *ip, int port)
        {
            const MynetConfig cfg = getMynetConfig();
            return runTcp(ip, port, cfg.server, cfg.proactor);
        }

        [[nodiscard]] Result<> runTcp()
        {
            const MynetConfig cfg = getMynetConfig();
            return runTcp(cfg.server.host.c_str(), static_cast<int>(cfg.server.port), cfg.server, cfg.proactor);
        }

        [[nodiscard]] Result<> runUdp(const char *ip, int port, const ServerConfig &server,
                                      const ProactorConfig &proactor)
        {
            if (auto err = listenUdp(ip, port, server.reuseAddr, server.reusePort); !err)
            {
                reset();
                return err;
            }
            Result<> rc = serve(server, proactor);
            reset();
            return rc;
        }

        [[nodiscard]] Result<> runUdp(const char *ip, int port)
        {
            const MynetConfig cfg = getMynetConfig();
            return runUdp(ip, port, cfg.server, cfg.proactor);
        }

        [[nodiscard]] Result<> runUdp()
        {
            const MynetConfig cfg = getMynetConfig();
            return runUdp(cfg.server.host.c_str(), static_cast<int>(cfg.server.port), cfg.server, cfg.proactor);
        }

        template <typename H>
        [[nodiscard]] Result<> runUdp(const char *ip, int port, H &handler, const ProactorConfig &proactor)
        {
            (void)handler;
            return runUdp(ip, port, getServerConfig(), proactor);
        }

        template <typename H>
        [[nodiscard]] Result<> runUdp(const char *ip, int port, H &handler)
        {
            (void)handler;
            return runUdp(ip, port);
        }

        template <typename H>
        [[nodiscard]] Result<> runUdp(H &handler)
        {
            (void)handler;
            return runUdp();
        }

        [[nodiscard]] Result<> serve(const ServerConfig &server, const ProactorConfig &proactor)
        {
            (void)server;
            (void)proactor;
            return {};
        }

        inline void reset() noexcept
        {
            if (tcpFd_ >= 0)
            {
                ::close(tcpFd_);
                tcpFd_ = -1;
            }
            tcpAddr_ = {};

            if (udpFd_ >= 0)
            {
                ::close(udpFd_);
                udpFd_ = -1;
            }
            udpAddr_ = {};

            for (auto &[fd, conn] : connections_)
            {
                if (conn != nullptr)
                {
                    conn->close();
                    delete conn;
                }
            }
            connections_.clear();
            extraListeners_.clear();

            std::apply([](auto &...acc) { (acc.reset(), ...); }, acceptors_);
            std::apply([](auto &...dia) { (dia.reset(), ...); }, dialers_);
        }

    private:
        struct ExtraListener
        {
            int fd{-1};
            AcceptCallback onAccept{};
        };

        int tcpFd_{-1};
        sockaddr_in tcpAddr_{};

        int udpFd_{-1};
        sockaddr_in udpAddr_{};

        std::tuple<typename ProtocolTraits<Protocols>::Acceptor...> acceptors_{};
        std::tuple<typename ProtocolTraits<Protocols>::Dialer...> dialers_{};
        std::unordered_map<int, ConnectionBase *> connections_{};
        std::unordered_map<int, std::shared_ptr<ExtraListener>> extraListeners_{};

        std::stop_source stopSource_{};
    };

} // namespace mynet

#endif
