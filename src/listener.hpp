#pragma once

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "config/log.hpp"
#include "datagramCore.hpp"
#include "error.hpp"
#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <expected>
#include <fcntl.h>
#include <mutex>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>

namespace mynet
{

    enum class TransportType : uint8_t
    {
        TCP,
        UDP
    };

    inline void ignoreSigpipeOnce() noexcept
    {
        static std::once_flag once;
        std::call_once(once, []() noexcept { ::signal(SIGPIPE, SIG_IGN); });
    }

    /**
     * @brief 真实传输套接字端点（封装基础套接字系统调用与地址状态）
     */
    struct SocketEndpoint
    {
        int fd{-1};
        sockaddr_in addr{};

        [[nodiscard]] constexpr bool valid() const noexcept { return fd >= 0; }
        [[nodiscard]] constexpr int getFd() const noexcept { return fd; }
        [[nodiscard]] constexpr const sockaddr_in &getAddr() const noexcept { return addr; }

        inline void reset() noexcept
        {
            if (fd >= 0)
            {
                ::close(fd);
                fd = -1;
            }
            addr = {};
        }

        [[nodiscard]] inline Result<int> listenTcp(const char *ip, int port, int backlog = 128, bool reuseAddr = true,
                                                   bool reusePort = true) noexcept
        {
            reset();
            if (ip == nullptr || port < 0 || port > 65535) [[unlikely]]
            {
                return std::unexpected(ERR::ADDR_INVALID);
            }

            ignoreSigpipeOnce();

            addr.sin_family = AF_INET;
            if (::inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) [[unlikely]]
            {
                LOG_ERROR("SocketEndpoint::listenTcp {}:{}: not an IPv4 address literal", ip, port);
                return std::unexpected(ERR::ADDR_INVALID);
            }
            addr.sin_port = ::htons(static_cast<uint16_t>(port));

            fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (fd < 0) [[unlikely]]
            {
                LOG_ERROR("SocketEndpoint::listenTcp {}:{}: socket() failed: {}", ip, port, errnoText(errno));
                return std::unexpected(ERR::SOCKET_FAILED);
            }

            constexpr int opt = 1;
            if (reuseAddr)
            {
                if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) [[unlikely]]
                {
                    LOG_ERROR("SocketEndpoint::listenTcp {}:{}: setsockopt(SO_REUSEADDR) failed: {}", ip, port,
                              errnoText(errno));
                    reset();
                    return std::unexpected(ERR::SETSOCKOPT_FAILED);
                }
            }
            if (reusePort)
            {
                if (::setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) [[unlikely]]
                {
                    LOG_ERROR("SocketEndpoint::listenTcp {}:{}: setsockopt(SO_REUSEPORT) failed: {}", ip, port,
                              errnoText(errno));
                    reset();
                    return std::unexpected(ERR::SETSOCKOPT_FAILED);
                }
            }

            if (::bind(fd, reinterpret_cast<const sockaddr *>(&addr), sizeof(sockaddr_in)) < 0) [[unlikely]]
            {
                LOG_ERROR("SocketEndpoint::listenTcp {}:{}: bind() failed: {}", ip, port, errnoText(errno));
                reset();
                return std::unexpected(ERR::BIND_FAILED);
            }

            if (::listen(fd, backlog) < 0) [[unlikely]]
            {
                LOG_ERROR("SocketEndpoint::listenTcp {}:{}: listen() failed: {}", ip, port, errnoText(errno));
                reset();
                return std::unexpected(ERR::LISTEN_FAILED);
            }

            if (port == 0)
            {
                socklen_t len = sizeof(addr);
                ::getsockname(fd, reinterpret_cast<sockaddr *>(&addr), &len);
            }

            return fd;
        }

        [[nodiscard]] inline Result<int> listenUdp(const char *ip, int port, bool reuseAddr = true,
                                                   bool reusePort = true) noexcept
        {
            reset();
            if (ip == nullptr || port < 0 || port > 65535) [[unlikely]]
            {
                return std::unexpected(ERR::ADDR_INVALID);
            }

            sockaddr_in sa{};
            sa.sin_family = AF_INET;
            if (::inet_pton(AF_INET, ip, &sa.sin_addr) <= 0) [[unlikely]]
            {
                LOG_ERROR("SocketEndpoint::listenUdp {}:{}: not an IPv4 address literal", ip, port);
                return std::unexpected(ERR::ADDR_INVALID);
            }
            sa.sin_port = ::htons(static_cast<uint16_t>(port));

            auto dgramRes = Datagram::bind(sa, reuseAddr, reusePort);
            if (!dgramRes) [[unlikely]]
            {
                LOG_ERROR("SocketEndpoint::listenUdp {}:{}: failed: {}", ip, port, toString(dgramRes.error()));
                return std::unexpected(dgramRes.error());
            }

            addr = dgramRes->localAddr();
            fd = dgramRes->release();
            return fd;
        }

        [[nodiscard]] inline Result<std::pair<int, sockaddr_in>> accept() noexcept
        {
            if (fd < 0) [[unlikely]]
            {
                return std::unexpected(ERR::ACCEPT_FAILED);
            }
            sockaddr_in clientAddr{};
            socklen_t len = sizeof(clientAddr);
            int clientFd =
                ::accept4(fd, reinterpret_cast<sockaddr *>(&clientAddr), &len, SOCK_NONBLOCK | SOCK_CLOEXEC);
            if (clientFd < 0) [[unlikely]]
            {
                return std::unexpected(ERR::ACCEPT_FAILED);
            }
            return std::make_pair(clientFd, clientAddr);
        }

        [[nodiscard]] inline Result<int> connectTcp(const char *ip, int port) noexcept
        {
            reset();
            if (ip == nullptr || port < 0 || port > 65535) [[unlikely]]
            {
                return std::unexpected(ERR::ADDR_INVALID);
            }

            addr.sin_family = AF_INET;
            if (::inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) [[unlikely]]
            {
                return std::unexpected(ERR::ADDR_INVALID);
            }
            addr.sin_port = ::htons(static_cast<uint16_t>(port));

            fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (fd < 0) [[unlikely]]
            {
                return std::unexpected(ERR::SOCKET_FAILED);
            }

            int rc = ::connect(fd, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr));
            if (rc < 0 && errno != EINPROGRESS) [[unlikely]]
            {
                reset();
                return std::unexpected(ERR::CONNECT_FAILED);
            }

            return fd;
        }
    };

    /**
     * @brief 协议监听端点封装（抽象单一端口监听器，支持 TCP 或 UDP 传输）
     */
    struct Listener
    {
        SocketEndpoint socket{};
        TransportType transport{TransportType::TCP};
        uint16_t configuredPort{0};
        int token{0};

        [[nodiscard]] constexpr bool isTcp() const noexcept { return transport == TransportType::TCP; }
        [[nodiscard]] constexpr bool isUdp() const noexcept { return transport == TransportType::UDP; }

        [[nodiscard]] constexpr bool valid() const noexcept { return socket.valid(); }
        [[nodiscard]] constexpr int fd() const noexcept { return socket.fd; }
        [[nodiscard]] constexpr const sockaddr_in &addr() const noexcept { return socket.addr; }

        inline void reset() noexcept { socket.reset(); }

        [[nodiscard]] inline Result<int> listen(const char *ip, int port = 0, int backlog = 128, bool reuseAddr = true,
                                                bool reusePort = true) noexcept
        {
            if (port == 0 && configuredPort != 0)
            {
                port = configuredPort;
            }
            if (isTcp())
            {
                return socket.listenTcp(ip, port, backlog, reuseAddr, reusePort);
            }
            else
            {
                return socket.listenUdp(ip, port, reuseAddr, reusePort);
            }
        }
    };

    /**
     * @brief 编译期监听器规格配置（用于去重与端口推导）
     */
    struct ListenerConfig
    {
        TransportType transport{TransportType::TCP};
        uint16_t defaultPort{0};
        size_t tag{0};

        constexpr bool operator==(const ListenerConfig &other) const noexcept
        {
            return transport == other.transport && defaultPort == other.defaultPort && tag == other.tag;
        }
    };

    /**
     * @brief 编译期空传输套接字端点（0 字节占位）
     */
    struct EmptySocket
    {
        static constexpr int fd = -1;
        static constexpr sockaddr_in addr{};

        [[nodiscard]] static constexpr bool valid() noexcept { return false; }
        [[nodiscard]] static constexpr int getFd() noexcept { return -1; }
        [[nodiscard]] static constexpr const sockaddr_in &getAddr() noexcept { return addr; }
        static constexpr void reset() noexcept {}

        [[nodiscard]] static constexpr Result<int> listenTcp(const char *, int, int = 128, bool = true,
                                                             bool = true) noexcept
        {
            return std::unexpected(ERR::SOCKET_FAILED);
        }
        [[nodiscard]] static constexpr Result<int> listenUdp(const char *, int, bool = true, bool = true) noexcept
        {
            return std::unexpected(ERR::SOCKET_FAILED);
        }
        [[nodiscard]] static constexpr Result<std::pair<int, sockaddr_in>> accept() noexcept
        {
            return std::unexpected(ERR::SOCKET_FAILED);
        }
        [[nodiscard]] static constexpr Result<int> connectTcp(const char *, int) noexcept
        {
            return std::unexpected(ERR::SOCKET_FAILED);
        }
    };

    /**
     * @brief 编译期协议套接字组合（按需零开销分配）
     */
    template <bool EnableTcp, bool EnableUdp>
    struct TransportSockets
    {
        using TcpEndpoint = std::conditional_t<EnableTcp, SocketEndpoint, EmptySocket>;
        using UdpEndpoint = std::conditional_t<EnableUdp, SocketEndpoint, EmptySocket>;

        [[no_unique_address]] TcpEndpoint tcp{};
        [[no_unique_address]] UdpEndpoint udp{};

        inline void reset() noexcept
        {
            if constexpr (EnableTcp)
            {
                tcp.reset();
            }
            if constexpr (EnableUdp)
            {
                udp.reset();
            }
        }
    };

    namespace net
    {
        [[nodiscard]] inline Result<int> listenTcp(const char *ip, int port, sockaddr_in &outAddr, int backlog = 128,
                                                   bool reuseAddr = true, bool reusePort = true) noexcept
        {
            SocketEndpoint ep;
            auto res = ep.listenTcp(ip, port, backlog, reuseAddr, reusePort);
            if (!res)
                return res;
            outAddr = ep.addr;
            return res;
        }

        [[nodiscard]] inline Result<int> listenUdp(const char *ip, int port, sockaddr_in &outAddr,
                                                   bool reuseAddr = true, bool reusePort = true) noexcept
        {
            SocketEndpoint ep;
            auto res = ep.listenUdp(ip, port, reuseAddr, reusePort);
            if (!res)
                return res;
            outAddr = ep.addr;
            return res;
        }

        [[nodiscard]] inline Result<std::pair<int, sockaddr_in>> accept(int listenFd) noexcept
        {
            SocketEndpoint ep;
            ep.fd = listenFd;
            return ep.accept();
        }

        [[nodiscard]] inline Result<int> connectTcp(const char *ip, int port, sockaddr_in &targetAddr) noexcept
        {
            SocketEndpoint ep;
            auto res = ep.connectTcp(ip, port);
            if (!res)
                return res;
            targetAddr = ep.addr;
            return res;
        }

        [[nodiscard]] inline Result<> checkConnectError(int socketFd) noexcept
        {
            if (socketFd < 0)
                return std::unexpected(ERR::SOCKET_FAILED);
            int err = 0;
            socklen_t len = sizeof(err);
            if (::getsockopt(socketFd, SOL_SOCKET, SO_ERROR, &err, &len) < 0)
                return std::unexpected(ERR::SOCKET_FAILED);
            if (err != 0)
                return std::unexpected(ERR::CONNECT_FAILED);
            return {};
        }
    } // namespace net

} // namespace mynet
