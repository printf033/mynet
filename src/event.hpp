#pragma once

#include "concepts.hpp"
#include "error.hpp"
#include "handler.hpp"
#include "log.hpp"
#include <arpa/inet.h>
#include <csignal>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace mynet
{

    /**
     * @brief 监听通道抽象基类
     *
     * 绑定基础文件描述符与协议处理器类型。
     */
    template <typename HandlerType>
        requires DerivedFromHandlerBase<HandlerType> && Resettable<HandlerType>
    struct EventBase
    {
    public:
        int fd = -1;
        using Handler = HandlerType;
        Handler *handler = nullptr;

        virtual ~EventBase() noexcept { reset(); }

        inline void reset() noexcept
        {
            if (fd != -1)
            {
                ::close(fd);
                fd = -1;
            }
            handler = nullptr;
        }
    };

    /**
     * @brief 约束从 EventBase 派生的所有监听通道类型
     */
    template <typename E>
    concept DerivedFromEventBase =
        requires { typename E::Handler; } && std::derived_from<E, EventBase<typename E::Handler>>;

    /**
     * @brief TCP / UDP 套接字监听通道
     */
    template <typename HandlerType>
        requires DerivedFromHandlerBase<HandlerType> && Resettable<HandlerType>
    struct EventSocket : public EventBase<HandlerType>
    {
    public:
        sockaddr_in addr{};

        inline void reset() noexcept
        {
            addr = {};
            EventBase<HandlerType>::reset();
        }

        /**
         * @brief 创建、配置并绑定非阻塞 TCP 监听套接字
         *
         * 采用 Linux 原生原子 SOCK_NONBLOCK | SOCK_CLOEXEC 创建标志，省去两次额外 fcntl() 系统调用开销。
         *
         * @param ip 目标 IPv4 字符串字面量（契约保证非空）
         * @param port 目标端口号（契约保证在 [0, 65535] 范围内）
         * @param backlog 挂起连接队列上限深度
         * @return Result<> 成功返回 {}，失败返回具体系统调用失败错误枚举
         */
        [[nodiscard]] Result<> listenTcp(const char *ip, int port, int backlog = 511) noexcept
        {
            contract_assert(ip != nullptr);
            contract_assert(port >= 0 && port <= ((1 << 16) - 1));
            reset();
            ::signal(SIGPIPE, SIG_IGN);

            addr.sin_family = AF_INET;
            if (::inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) [[unlikely]]
            {
                LOG_ERROR("listenTcp {}:{}: not an IPv4 address literal", ip, port);
                reset();
                return std::unexpected(ERR::ADDR_INVALID);
            }
            addr.sin_port = ::htons(static_cast<uint16_t>(port));

            EventBase<HandlerType>::fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (EventBase<HandlerType>::fd < 0) [[unlikely]]
            {
                LOG_ERROR("listenTcp {}:{}: socket() failed: {}", ip, port, log::errnoText(errno));
                reset();
                return std::unexpected(ERR::SOCKET_FAILED);
            }

            constexpr int opt = 1;
            if (::setsockopt(EventBase<HandlerType>::fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) [[unlikely]]
            {
                LOG_ERROR("listenTcp {}:{}: setsockopt(SO_REUSEADDR) failed: {}", ip, port, log::errnoText(errno));
                reset();
                return std::unexpected(ERR::SETSOCKOPT_FAILED);
            }
            if (::setsockopt(EventBase<HandlerType>::fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) [[unlikely]]
            {
                LOG_ERROR("listenTcp {}:{}: setsockopt(SO_REUSEPORT) failed: {}", ip, port, log::errnoText(errno));
                reset();
                return std::unexpected(ERR::SETSOCKOPT_FAILED);
            }
            if (::bind(EventBase<HandlerType>::fd, reinterpret_cast<const sockaddr *>(&addr), sizeof(sockaddr_in)) < 0)
                [[unlikely]]
            {
                LOG_ERROR("listenTcp {}:{}: bind() failed: {}", ip, port, log::errnoText(errno));
                reset();
                return std::unexpected(ERR::BIND_FAILED);
            }
            if (::listen(EventBase<HandlerType>::fd, backlog) < 0) [[unlikely]]
            {
                LOG_ERROR("listenTcp {}:{}: listen(backlog={}) failed: {}", ip, port, backlog, log::errnoText(errno));
                reset();
                return std::unexpected(ERR::LISTEN_FAILED);
            }
            return {};
        }

        /**
         * @brief 创建、配置并绑定非阻塞 UDP 数据报套接字
         */
        [[nodiscard]] Result<> listenUdp(const char *ip, int port) noexcept
        {
            contract_assert(ip != nullptr);
            contract_assert(port >= 0 && port <= ((1 << 16) - 1));
            reset();
            ::signal(SIGPIPE, SIG_IGN);

            addr.sin_family = AF_INET;
            if (::inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) [[unlikely]]
            {
                LOG_ERROR("listenUdp {}:{}: not an IPv4 address literal", ip, port);
                reset();
                return std::unexpected(ERR::ADDR_INVALID);
            }
            addr.sin_port = ::htons(static_cast<uint16_t>(port));

            EventBase<HandlerType>::fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (EventBase<HandlerType>::fd < 0) [[unlikely]]
            {
                LOG_ERROR("listenUdp {}:{}: socket() failed: {}", ip, port, log::errnoText(errno));
                reset();
                return std::unexpected(ERR::SOCKET_FAILED);
            }

            constexpr int opt = 1;
            if (::setsockopt(EventBase<HandlerType>::fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) [[unlikely]]
            {
                LOG_ERROR("listenUdp {}:{}: setsockopt(SO_REUSEADDR) failed: {}", ip, port, log::errnoText(errno));
                reset();
                return std::unexpected(ERR::SETSOCKOPT_FAILED);
            }
            if (::setsockopt(EventBase<HandlerType>::fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) [[unlikely]]
            {
                LOG_ERROR("listenUdp {}:{}: setsockopt(SO_REUSEPORT) failed: {}", ip, port, log::errnoText(errno));
                reset();
                return std::unexpected(ERR::SETSOCKOPT_FAILED);
            }
            if (::setsockopt(EventBase<HandlerType>::fd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt)) < 0) [[unlikely]]
            {
                LOG_ERROR("listenUdp {}:{}: setsockopt(SO_BROADCAST) failed: {}", ip, port, log::errnoText(errno));
                reset();
                return std::unexpected(ERR::SETSOCKOPT_FAILED);
            }
            if (::bind(EventBase<HandlerType>::fd, reinterpret_cast<const sockaddr *>(&addr), sizeof(sockaddr_in)) < 0)
                [[unlikely]]
            {
                LOG_ERROR("listenUdp {}:{}: bind() failed: {}", ip, port, log::errnoText(errno));
                reset();
                return std::unexpected(ERR::BIND_FAILED);
            }
            return {};
        }
    };

    /**
     * @brief 套接字事件通道约束
     */
    template <typename E>
    concept SocketEvent = requires { typename E::Handler; } && std::same_as<E, EventSocket<typename E::Handler>>;

    /**
     * @brief SSL / TLS 传输层监听标签特化类型
     */
    template <typename HandlerType>
        requires DerivedFromHandlerBase<HandlerType> && Resettable<HandlerType>
    struct EventSsl : public EventSocket<HandlerType>
    {
    };

    /**
     * @brief SSL 事件通道约束
     */
    template <typename E>
    concept SslEvent = requires { typename E::Handler; } && std::same_as<E, EventSsl<typename E::Handler>>;

    /**
     * @brief 监听通道协议运行时上下文状态特化特征模板
     */
    template <typename>
    struct Protocol
    {
    };

    template <typename H>
    struct Protocol<EventSsl<H>>
    {
        SSL_CTX *ctx = nullptr;
    };

} // namespace mynet
