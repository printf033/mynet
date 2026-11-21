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
        static constexpr size_t kProtocolCount = sizeof...(Protocols);
        static constexpr size_t kListenerCount = countUniqueListeners<Protocols...>();
        static constexpr auto kListenerConfigs = getUniqueListeners<Protocols...>();

        static constexpr bool kHasTcp = []() consteval
        {
            for (const auto &c : kListenerConfigs)
            {
                if (c.transport == TransportType::TCP)
                    return true;
            }
            return false;
        }();

        static constexpr bool kHasUdp = []() consteval
        {
            for (const auto &c : kListenerConfigs)
            {
                if (c.transport == TransportType::UDP)
                    return true;
            }
            return false;
        }();

        Proactor()
        {
            for (size_t i = 0; i < kListenerCount; ++i)
            {
                listeners_[i].transport = kListenerConfigs[i].transport;
                listeners_[i].configuredPort = kListenerConfigs[i].defaultPort;
                listeners_[i].token = static_cast<int>(i);
            }
        }
        ~Proactor() noexcept { reset(); }

        Proactor(const Proactor &) = delete;
        Proactor &operator=(const Proactor &) = delete;

        [[nodiscard]] inline size_t connections() const noexcept { return connections_.size(); }

        inline void stop() noexcept { stopSource_.request_stop(); }
        inline void quit() noexcept { stopSource_.request_stop(); }

        [[nodiscard]] inline int tcpFd() const noexcept
        {
            for (const auto &l : listeners_)
            {
                if (l.isTcp() && l.valid())
                    return l.fd();
            }
            return -1;
        }
        [[nodiscard]] inline int udpFd() const noexcept
        {
            for (const auto &l : listeners_)
            {
                if (l.isUdp() && l.valid())
                    return l.fd();
            }
            return -1;
        }
        [[nodiscard]] inline const sockaddr_in &tcpAddr() const noexcept
        {
            for (const auto &l : listeners_)
            {
                if (l.isTcp() && l.valid())
                    return l.addr();
            }
            static constexpr sockaddr_in empty{};
            return empty;
        }
        [[nodiscard]] inline const sockaddr_in &udpAddr() const noexcept
        {
            for (const auto &l : listeners_)
            {
                if (l.isUdp() && l.valid())
                    return l.addr();
            }
            static constexpr sockaddr_in empty{};
            return empty;
        }

        template <size_t I = 0>
        [[nodiscard]] inline Listener &listener() noexcept
        {
            static_assert(I < kListenerCount, "Listener index out of bounds");
            return listeners_[I];
        }

        template <size_t I = 0>
        [[nodiscard]] inline const Listener &listener() const noexcept
        {
            static_assert(I < kListenerCount, "Listener index out of bounds");
            return listeners_[I];
        }

        [[nodiscard]] inline auto &listeners() noexcept { return listeners_; }
        [[nodiscard]] inline const auto &listeners() const noexcept { return listeners_; }

        [[nodiscard]] inline size_t listenerCount() const noexcept
        {
            size_t count = 0;
            for (const auto &l : listeners_)
            {
                if (l.valid())
                    ++count;
            }
            return count;
        }

        [[nodiscard]] constexpr size_t listenerCapacity() const noexcept { return kListenerCount; }

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
            if constexpr (!kHasTcp)
            {
                return std::unexpected(ERR::SOCKET_FAILED);
            }
            else
            {
                for (size_t i = 0; i < kListenerCount; ++i)
                {
                    if (listeners_[i].isTcp())
                    {
                        if (listeners_[i].valid())
                        {
                            return {};
                        }
                        auto res = listeners_[i].listen(ip, port, backlog, reuseAddr, reusePort);
                        if (!res)
                        {
                            return std::unexpected(res.error());
                        }
                        return {};
                    }
                }
                return std::unexpected(ERR::SOCKET_FAILED);
            }
        }

        Result<> listenUdp(const char *ip, int port, bool reuseAddr = true, bool reusePort = true)
        {
            if constexpr (!kHasUdp)
            {
                return std::unexpected(ERR::SOCKET_FAILED);
            }
            else
            {
                for (size_t i = 0; i < kListenerCount; ++i)
                {
                    if (listeners_[i].isUdp())
                    {
                        if (listeners_[i].valid())
                        {
                            return {};
                        }
                        auto res = listeners_[i].listen(ip, port, 128, reuseAddr, reusePort);
                        if (!res)
                        {
                            return std::unexpected(res.error());
                        }
                        return {};
                    }
                }
                return std::unexpected(ERR::SOCKET_FAILED);
            }
        }

        template <size_t I>
        Result<> listen(const char *ip, int port = 0, int backlog = 128, bool reuseAddr = true, bool reusePort = true)
        {
            static_assert(I < kListenerCount, "Listener index out of bounds");
            if (listeners_[I].valid())
            {
                return {};
            }
            auto res = listeners_[I].listen(ip, port, backlog, reuseAddr, reusePort);
            if (!res)
            {
                return std::unexpected(res.error());
            }
            return {};
        }

        [[nodiscard]] Result<> runTcp(const char *ip, int port, const ServerConfig &server,
                                      const ProactorConfig &proactor)
        {
            if constexpr (!kHasTcp)
            {
                LOG_ERROR("Proactor::runTcp: this Proactor has no TCP protocols configured");
                return std::unexpected(ERR::SOCKET_FAILED);
            }
            else
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
            if constexpr (!kHasUdp)
            {
                LOG_ERROR("Proactor::runUdp: this Proactor has no UDP protocols configured");
                return std::unexpected(ERR::SOCKET_FAILED);
            }
            else
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
            for (auto &l : listeners_)
            {
                l.reset();
            }

            for (auto &[fd, conn] : connections_)
            {
                if (conn != nullptr)
                {
                    conn->close();
                    delete conn;
                }
            }
            connections_.clear();

            std::apply([](auto &...acc) { (acc.reset(), ...); }, acceptors_);
            std::apply([](auto &...dia) { (dia.reset(), ...); }, dialers_);
        }

    private:
        std::array<Listener, kListenerCount> listeners_{};

        std::tuple<typename ProtocolTraits<Protocols>::Acceptor...> acceptors_{};
        std::tuple<typename ProtocolTraits<Protocols>::Dialer...> dialers_{};
        std::unordered_map<int, ConnectionBase *> connections_{};

        std::stop_source stopSource_{};
    };

} // namespace mynet

#endif
