#pragma once

/**
 * @file socket.hpp
 * @brief 基础非阻塞 TCP 与 UDP 套接字创建、绑定、监听与连接工具库。
 *
 * 将基础套接字系统调用与协议级 Acceptor / Dialer 彻底解耦。
 */

#include "config/log.hpp"
#include "error.hpp"
#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>

namespace mynet::net
{

    /**
     * @brief 创建、配置并绑定非阻塞 TCP 监听套接字
     */
    [[nodiscard]] inline Result<int> listenTcp(const char *ip, int port, sockaddr_in &outAddr, int backlog = 128,
                                               bool reuseAddr = true, bool reusePort = true) noexcept
    {
        if (ip == nullptr || port < 0 || port > 65535) [[unlikely]]
        {
            return std::unexpected(ERR::ADDR_INVALID);
        }

        ::signal(SIGPIPE, SIG_IGN);

        outAddr = {};
        outAddr.sin_family = AF_INET;
        if (::inet_pton(AF_INET, ip, &outAddr.sin_addr) <= 0) [[unlikely]]
        {
            LOG_ERROR("listenTcp {}:{}: not an IPv4 address literal", ip, port);
            return std::unexpected(ERR::ADDR_INVALID);
        }
        outAddr.sin_port = ::htons(static_cast<uint16_t>(port));

        int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd < 0) [[unlikely]]
        {
            LOG_ERROR("listenTcp {}:{}: socket() failed: {}", ip, port, errnoText(errno));
            return std::unexpected(ERR::SOCKET_FAILED);
        }

        constexpr int opt = 1;
        if (reuseAddr)
        {
            if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) [[unlikely]]
            {
                LOG_ERROR("listenTcp {}:{}: setsockopt(SO_REUSEADDR) failed: {}", ip, port, errnoText(errno));
                ::close(fd);
                return std::unexpected(ERR::SETSOCKOPT_FAILED);
            }
        }
        if (reusePort)
        {
            if (::setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) [[unlikely]]
            {
                LOG_ERROR("listenTcp {}:{}: setsockopt(SO_REUSEPORT) failed: {}", ip, port, errnoText(errno));
                ::close(fd);
                return std::unexpected(ERR::SETSOCKOPT_FAILED);
            }
        }

        if (::bind(fd, reinterpret_cast<const sockaddr *>(&outAddr), sizeof(sockaddr_in)) < 0) [[unlikely]]
        {
            LOG_ERROR("listenTcp {}:{}: bind() failed: {}", ip, port, errnoText(errno));
            ::close(fd);
            return std::unexpected(ERR::BIND_FAILED);
        }

        if (::listen(fd, backlog) < 0) [[unlikely]]
        {
            LOG_ERROR("listenTcp {}:{}: listen() failed: {}", ip, port, errnoText(errno));
            ::close(fd);
            return std::unexpected(ERR::LISTEN_FAILED);
        }

        if (port == 0)
        {
            socklen_t len = sizeof(outAddr);
            ::getsockname(fd, reinterpret_cast<sockaddr *>(&outAddr), &len);
        }

        return fd;
    }

    /**
     * @brief 创建、配置并绑定非阻塞 UDP 套接字
     */
    [[nodiscard]] inline Result<int> listenUdp(const char *ip, int port, sockaddr_in &outAddr, bool reuseAddr = true,
                                               bool reusePort = true) noexcept
    {
        if (ip == nullptr || port < 0 || port > 65535) [[unlikely]]
        {
            return std::unexpected(ERR::ADDR_INVALID);
        }

        outAddr = {};
        outAddr.sin_family = AF_INET;
        if (::inet_pton(AF_INET, ip, &outAddr.sin_addr) <= 0) [[unlikely]]
        {
            LOG_ERROR("listenUdp {}:{}: not an IPv4 address literal", ip, port);
            return std::unexpected(ERR::ADDR_INVALID);
        }
        outAddr.sin_port = ::htons(static_cast<uint16_t>(port));

        int fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd < 0) [[unlikely]]
        {
            LOG_ERROR("listenUdp {}:{}: socket() failed: {}", ip, port, errnoText(errno));
            return std::unexpected(ERR::SOCKET_FAILED);
        }

        constexpr int opt = 1;
        if (reuseAddr)
        {
            if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) [[unlikely]]
            {
                LOG_ERROR("listenUdp {}:{}: setsockopt(SO_REUSEADDR) failed: {}", ip, port, errnoText(errno));
                ::close(fd);
                return std::unexpected(ERR::SETSOCKOPT_FAILED);
            }
        }
        if (reusePort)
        {
            if (::setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) [[unlikely]]
            {
                LOG_ERROR("listenUdp {}:{}: setsockopt(SO_REUSEPORT) failed: {}", ip, port, errnoText(errno));
                ::close(fd);
                return std::unexpected(ERR::SETSOCKOPT_FAILED);
            }
        }

        if (::bind(fd, reinterpret_cast<const sockaddr *>(&outAddr), sizeof(sockaddr_in)) < 0) [[unlikely]]
        {
            LOG_ERROR("listenUdp {}:{}: bind() failed: {}", ip, port, errnoText(errno));
            ::close(fd);
            return std::unexpected(ERR::BIND_FAILED);
        }

        if (port == 0)
        {
            socklen_t len = sizeof(outAddr);
            ::getsockname(fd, reinterpret_cast<sockaddr *>(&outAddr), &len);
        }

        return fd;
    }

    /**
     * @brief 非阻塞 accept 接收一个新接入的 TCP 客户端连接
     */
    [[nodiscard]] inline Result<std::pair<int, sockaddr_in>> accept(int listenFd) noexcept
    {
        if (listenFd < 0) [[unlikely]]
        {
            return std::unexpected(ERR::ACCEPT_FAILED);
        }

        sockaddr_in clientAddr{};
        socklen_t len = sizeof(clientAddr);
        int clientFd =
            ::accept4(listenFd, reinterpret_cast<sockaddr *>(&clientAddr), &len, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (clientFd < 0) [[unlikely]]
        {
            return std::unexpected(ERR::ACCEPT_FAILED);
        }
        return std::make_pair(clientFd, clientAddr);
    }

    /**
     * @brief 发起非阻塞 TCP 拨号连接
     */
    [[nodiscard]] inline Result<int> connectTcp(const char *ip, int port, sockaddr_in &targetAddr) noexcept
    {
        if (ip == nullptr || port < 0 || port > 65535) [[unlikely]]
        {
            return std::unexpected(ERR::ADDR_INVALID);
        }

        targetAddr = {};
        targetAddr.sin_family = AF_INET;
        if (::inet_pton(AF_INET, ip, &targetAddr.sin_addr) <= 0) [[unlikely]]
        {
            return std::unexpected(ERR::ADDR_INVALID);
        }
        targetAddr.sin_port = ::htons(static_cast<uint16_t>(port));

        int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd < 0) [[unlikely]]
        {
            return std::unexpected(ERR::SOCKET_FAILED);
        }

        int rc = ::connect(fd, reinterpret_cast<const sockaddr *>(&targetAddr), sizeof(targetAddr));
        if (rc < 0 && errno != EINPROGRESS) [[unlikely]]
        {
            ::close(fd);
            return std::unexpected(ERR::CONNECT_FAILED);
        }

        return fd;
    }

    /**
     * @brief 检查非阻塞 connect 是否成功完成
     */
    [[nodiscard]] inline Result<> checkConnectError(int socketFd) noexcept
    {
        if (socketFd < 0)
        {
            return std::unexpected(ERR::SOCKET_FAILED);
        }
        int err = 0;
        socklen_t len = sizeof(err);
        if (::getsockopt(socketFd, SOL_SOCKET, SO_ERROR, &err, &len) < 0)
        {
            return std::unexpected(ERR::SOCKET_FAILED);
        }
        if (err != 0)
        {
            return std::unexpected(ERR::CONNECT_FAILED);
        }
        return {};
    }

} // namespace mynet::net
