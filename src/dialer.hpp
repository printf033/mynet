#pragma once

#include "constraints.hpp"
#include "error.hpp"
#include "config/log.hpp"
#include <arpa/inet.h>
#include <cerrno>
#include <concepts>
#include <csignal>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace mynet
{

    /**
     * @brief 客户端出站拨号建连基类（与 AcceptorBase 严格对称）
     *
     * 负责发起并建立客户端到对端服务器的 TCP / UDP 连接（确立四元组）。
     * 处理器只需满足 HandlerConstraint。
     * 后续传输层出站建连器（如 DialerSsl、DialerQuic 等）均直接派生自本类。
     */
    template <typename HandlerType>
        requires HandlerConstraint<HandlerType>
    struct DialerBase
    {
    public:
        int fd = -1;
        using Handler = HandlerType;
        sockaddr_in targetAddr{};

        virtual ~DialerBase() noexcept { reset(); }

        inline void reset() noexcept
        {
            if (fd != -1)
            {
                ::close(fd);
                fd = -1;
            }
            targetAddr = {};
        }

        /**
         * @brief 检查非阻塞 connect 是否成功完成
         *
         * 在收到 Reactor 的可写事件 (EPOLLOUT) 时调用。
         *
         * @param socketFd 待检验的套接字描述符
         * @return 成功返回 {}，对端拒绝或超时返回错误码
         */
        [[nodiscard]] static Result<> checkConnectError(int socketFd) noexcept
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

        /**
         * @brief 创建非阻塞 TCP 套接字并向远端发起异步建连
         *
         * @param ip 目标服务端 IPv4 地址字面量
         * @param port 目标服务端端口号
         * @param bindInterface 可选的出口网卡绑定（SO_BINDTODEVICE）
         * @return Result<bool> 成功返回布尔值：
         *         - true: 连接立即可用（已连上，如本机回环）；
         *         - false: 连接处于非阻塞握手中（EINPROGRESS），需向 Reactor 挂载 EPOLLOUT 或等待 Proactor CQE；
         *         - unexpected: 发生系统调用错误。
         */
        [[nodiscard]] Result<bool> dialTcp(const char *ip, int port, const char *bindInterface = nullptr) noexcept
        {
            contract_assert(ip != nullptr);
            contract_assert(port >= 0 && port <= ((1 << 16) - 1));
            reset();
            ::signal(SIGPIPE, SIG_IGN);

            targetAddr.sin_family = AF_INET;
            if (::inet_pton(AF_INET, ip, &targetAddr.sin_addr) <= 0) [[unlikely]]
            {
                LOG_ERROR("dialTcp {}:{}: not an IPv4 address literal", ip, port);
                reset();
                return std::unexpected(ERR::ADDR_INVALID);
            }
            targetAddr.sin_port = ::htons(static_cast<uint16_t>(port));

            return dialTcp(targetAddr, bindInterface);
        }

        /**
         * @brief 从目标地址结构体发起非阻塞 TCP 建连
         */
        [[nodiscard]] Result<bool> dialTcp(const sockaddr_in &target, const char *bindInterface = nullptr) noexcept
        {
            reset();
            ::signal(SIGPIPE, SIG_IGN);
            targetAddr = target;

            fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (fd < 0) [[unlikely]]
            {
                LOG_ERROR("dialTcp: socket() failed: {}", errnoText(errno));
                reset();
                return std::unexpected(ERR::SOCKET_FAILED);
            }

            // TCP Keepalive & NODELAY
            constexpr int opt = 1;
            [[maybe_unused]] auto _ = ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

            if (bindInterface != nullptr && bindInterface[0] != '\0')
            {
                if (::setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, bindInterface, ::strlen(bindInterface)) < 0)
                    [[unlikely]]
                {
                    LOG_WARN("dialTcp: setsockopt(SO_BINDTODEVICE={}) failed: {}", bindInterface, errnoText(errno));
                }
            }

            int rc = ::connect(fd, reinterpret_cast<const sockaddr *>(&targetAddr), sizeof(sockaddr_in));
            if (rc == 0)
            {
                return true; // 立即完成
            }
            if (errno == EINPROGRESS)
            {
                return false; // 非阻塞握手中
            }

            LOG_ERROR("dialTcp: connect() failed: {}", errnoText(errno));
            reset();
            return std::unexpected(ERR::CONNECT_FAILED);
        }

        /**
         * @brief 创建非阻塞已连接 UDP 套接字（已关联目标四元组，可用 send/recv 直读）
         */
        [[nodiscard]] Result<> dialUdp(const char *ip, int port) noexcept
        {
            contract_assert(ip != nullptr);
            contract_assert(port >= 0 && port <= ((1 << 16) - 1));
            reset();
            ::signal(SIGPIPE, SIG_IGN);

            targetAddr.sin_family = AF_INET;
            if (::inet_pton(AF_INET, ip, &targetAddr.sin_addr) <= 0) [[unlikely]]
            {
                LOG_ERROR("dialUdp {}:{}: not an IPv4 address literal", ip, port);
                reset();
                return std::unexpected(ERR::ADDR_INVALID);
            }
            targetAddr.sin_port = ::htons(static_cast<uint16_t>(port));

            return dialUdp(targetAddr);
        }

        /**
         * @brief 从目标地址结构体创建非阻塞已连接 UDP 套接字
         */
        [[nodiscard]] Result<> dialUdp(const sockaddr_in &target) noexcept
        {
            reset();
            ::signal(SIGPIPE, SIG_IGN);
            targetAddr = target;

            fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (fd < 0) [[unlikely]]
            {
                LOG_ERROR("dialUdp: socket() failed: {}", errnoText(errno));
                reset();
                return std::unexpected(ERR::SOCKET_FAILED);
            }

            if (::connect(fd, reinterpret_cast<const sockaddr *>(&targetAddr), sizeof(sockaddr_in)) < 0) [[unlikely]]
            {
                LOG_ERROR("dialUdp: connect() failed: {}", errnoText(errno));
                reset();
                return std::unexpected(ERR::CONNECT_FAILED);
            }
            return {};
        }
    };

    /**
     * @brief 约束从 DialerBase 派生的所有出站通道类型
     */
    template <typename D>
    concept DerivedFromDialerBase =
        requires { typename D::Handler; } && std::derived_from<D, DialerBase<typename D::Handler>>;

    /**
     * @brief 基础出站建连器通道约束
     */
    template <typename D>
    concept BaseDialer = requires { typename D::Handler; } && std::same_as<D, DialerBase<typename D::Handler>>;

    /**
     * @brief SSL / TLS 传输层出站建连器特化类型（支持携带 SNI 与 ALPN）
     */
    template <typename HandlerType>
        requires HandlerConstraint<HandlerType>
    struct DialerSsl : public DialerBase<HandlerType>
    {
    public:
        std::string sni{};
        std::string alpn{"h2,http/1.1"};
    };

    /**
     * @brief SSL 出站建连器通道约束
     */
    template <typename D>
    concept SslDialer = requires { typename D::Handler; } && std::same_as<D, DialerSsl<typename D::Handler>>;

    /**
     * @brief 出站建连器协议运行时上下文状态特化特征模板
     */
    template <typename H>
    struct Protocol<DialerSsl<H>>
    {
        SSL_CTX *ctx = nullptr;
    };

    /**
     * @brief QUIC 出站建连器特化类型
     */
    template <typename HandlerType>
        requires HandlerConstraint<HandlerType>
    struct DialerQuic : public DialerBase<HandlerType>
    {
    public:
        std::string sni{};
    };

    /**
     * @brief QUIC 出站建连器通道约束
     */
    template <typename D>
    concept QuicDialer = requires { typename D::Handler; } && std::same_as<D, DialerQuic<typename D::Handler>>;

    /**
     * @brief QUIC 出站建连器协议运行时上下文状态特化特征模板
     */
    template <typename H>
    struct Protocol<DialerQuic<H>>
    {
        SSL_CTX *ctx = nullptr;
    };

} // namespace mynet
