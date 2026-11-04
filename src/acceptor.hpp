#pragma once

#include "constraints.hpp"
#include "error.hpp"
#include "log_config.hpp"
#include <arpa/inet.h>
#include <concepts>
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
     * @brief 监听接收器抽象基类
     *
     * 绑定基础文件描述符与处理器类型。处理器只需满足 HandlerConstraint：
     * 删除公共根类 HandlerBase 之后，流式处理器（HandlerConnection）与报文处理器
     * （HandlerDatagram）是两个并列的独立层次，接收层不应反向依赖其中任何一方。
     */
    template <typename HandlerType>
        requires HandlerConstraint<HandlerType>
    struct AcceptorBase
    {
    public:
        int fd = -1;
        using Handler = HandlerType;
        Handler *handler = nullptr;

        virtual ~AcceptorBase() noexcept { reset(); }

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
     * @brief 约束从 AcceptorBase 派生的所有接收器通道类型
     */
    template <typename A>
    concept DerivedFromAcceptorBase =
        requires { typename A::Handler; } && std::derived_from<A, AcceptorBase<typename A::Handler>>;

    /**
     * @brief TCP / UDP 套接字监听接收器
     */
    template <typename HandlerType>
        requires HandlerConstraint<HandlerType>
    struct AcceptorSocket : public AcceptorBase<HandlerType>
    {
    public:
        sockaddr_in addr{};

        inline void reset() noexcept
        {
            addr = {};
            AcceptorBase<HandlerType>::reset();
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
        [[nodiscard]] Result<> listenTcp(const char *ip, int port, int backlog, bool reuseAddr = true,
                                         bool reusePort = true) noexcept
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

            AcceptorBase<HandlerType>::fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (AcceptorBase<HandlerType>::fd < 0) [[unlikely]]
            {
                LOG_ERROR("listenTcp {}:{}: socket() failed: {}", ip, port, errnoText(errno));
                reset();
                return std::unexpected(ERR::SOCKET_FAILED);
            }

            constexpr int opt = 1;
            if (reuseAddr)
            {
                if (::setsockopt(AcceptorBase<HandlerType>::fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
                    [[unlikely]]
                {
                    LOG_ERROR("listenTcp {}:{}: setsockopt(SO_REUSEADDR) failed: {}", ip, port, errnoText(errno));
                    reset();
                    return std::unexpected(ERR::SETSOCKOPT_FAILED);
                }
            }
            if (reusePort)
            {
                if (::setsockopt(AcceptorBase<HandlerType>::fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0)
                    [[unlikely]]
                {
                    LOG_ERROR("listenTcp {}:{}: setsockopt(SO_REUSEPORT) failed: {}", ip, port, errnoText(errno));
                    reset();
                    return std::unexpected(ERR::SETSOCKOPT_FAILED);
                }
            }
            if (::bind(AcceptorBase<HandlerType>::fd, reinterpret_cast<const sockaddr *>(&addr), sizeof(sockaddr_in)) <
                0) [[unlikely]]
            {
                LOG_ERROR("listenTcp {}:{}: bind() failed: {}", ip, port, errnoText(errno));
                reset();
                return std::unexpected(ERR::BIND_FAILED);
            }
            if (::listen(AcceptorBase<HandlerType>::fd, backlog) < 0) [[unlikely]]
            {
                LOG_ERROR("listenTcp {}:{}: listen(backlog={}) failed: {}", ip, port, backlog, errnoText(errno));
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

            AcceptorBase<HandlerType>::fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (AcceptorBase<HandlerType>::fd < 0) [[unlikely]]
            {
                LOG_ERROR("listenUdp {}:{}: socket() failed: {}", ip, port, errnoText(errno));
                reset();
                return std::unexpected(ERR::SOCKET_FAILED);
            }

            constexpr int opt = 1;
            if (::setsockopt(AcceptorBase<HandlerType>::fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
                [[unlikely]]
            {
                LOG_ERROR("listenUdp {}:{}: setsockopt(SO_REUSEADDR) failed: {}", ip, port, errnoText(errno));
                reset();
                return std::unexpected(ERR::SETSOCKOPT_FAILED);
            }
            if (::setsockopt(AcceptorBase<HandlerType>::fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0)
                [[unlikely]]
            {
                LOG_ERROR("listenUdp {}:{}: setsockopt(SO_REUSEPORT) failed: {}", ip, port, errnoText(errno));
                reset();
                return std::unexpected(ERR::SETSOCKOPT_FAILED);
            }
            if (::setsockopt(AcceptorBase<HandlerType>::fd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt)) < 0)
                [[unlikely]]
            {
                LOG_ERROR("listenUdp {}:{}: setsockopt(SO_BROADCAST) failed: {}", ip, port, errnoText(errno));
                reset();
                return std::unexpected(ERR::SETSOCKOPT_FAILED);
            }
            if (::bind(AcceptorBase<HandlerType>::fd, reinterpret_cast<const sockaddr *>(&addr), sizeof(sockaddr_in)) <
                0) [[unlikely]]
            {
                LOG_ERROR("listenUdp {}:{}: bind() failed: {}", ip, port, errnoText(errno));
                reset();
                return std::unexpected(ERR::BIND_FAILED);
            }
            return {};
        }
    };

    /**
     * @brief 套接字接收器通道约束
     */
    template <typename A>
    concept SocketAcceptor = requires { typename A::Handler; } && std::same_as<A, AcceptorSocket<typename A::Handler>>;

    /**
     * @brief SSL / TLS 传输层监听接收器标签特化类型
     */
    template <typename HandlerType>
        requires HandlerConstraint<HandlerType>
    struct AcceptorSsl : public AcceptorSocket<HandlerType>
    {
    };

    /**
     * @brief SSL 接收器通道约束
     */
    template <typename A>
    concept SslAcceptor = requires { typename A::Handler; } && std::same_as<A, AcceptorSsl<typename A::Handler>>;

    /**
     * @brief 监听接收器协议运行时上下文状态特化特征模板
     */
    template <typename>
    struct Protocol
    {
    };

    template <typename H>
    struct Protocol<AcceptorSsl<H>>
    {
        SSL_CTX *ctx = nullptr;
    };

} // namespace mynet
