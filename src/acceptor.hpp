#pragma once

/**
 * @file acceptor.hpp
 * @brief 协议接收器（Acceptor）基类与握手抽象。
 *
 * 职责彻底解耦：
 * 1. 纯虚/基类，无模板参数，零连接级可变成员；
 * 2. 专职负责特定协议的入站握手 (Inbound Handshake) 与首包特征嗅探 match()；
 * 3. 各协议自身继承并实现定制握手协议；
 * 4. 握手成功后交付装配好对应 Handler 的 ConnectionBase 实例。
 */

#include "config/log.hpp"
#include "error.hpp"
#include <concepts>
#include <cstdint>
#include <memory>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <span>
#include <string_view>
#include <utility>

namespace mynet
{

    class ConnectionBase;

    /**
     * @brief 空入站上下文结构（不占任何空间）
     */
    struct EmptyInbound
    {
    };

    /**
     * @brief 握手状态
     */
    enum class HandshakeStatus : uint8_t
    {
        SUCCESS,     ///< 握手成功并产出 Connection 实例
        IN_PROGRESS, ///< 握手进行中（如异步非阻塞握手）
        FAILED       ///< 握手失败
    };

    /**
     * @brief 协议接收器抽象基类（零连接级可变成员）
     */
    class IAcceptor
    {
    public:
        virtual ~IAcceptor() = default;

        /**
         * @brief 快速首包特征嗅探（用于单端口多协议混合调度）
         */
        [[nodiscard]] virtual bool match(std::span<const uint8_t> initialBytes) const noexcept
        {
            (void)initialBytes;
            return false;
        }

        /**
         * @brief 针对新接入的 clientFd 执行协议握手
         */
        virtual HandshakeStatus handshake(int clientFd, ConnectionBase *&outConn)
        {
            (void)clientFd;
            outConn = nullptr;
            return HandshakeStatus::SUCCESS;
        }

        /**
         * @brief 重置握手器状态
         */
        virtual void reset() noexcept {}

        /**
         * @brief 启动入站 TLS 握手绑定（握手由 Acceptor 专职负责）
         */
        static inline Result<SSL *> startTls(int clientFd, SSL_CTX *ctx) noexcept
        {
            if (ctx == nullptr) [[unlikely]]
            {
                LOG_ERROR("Acceptor::startTls: no SSL_CTX (fd {})", clientFd);
                return std::unexpected(ERR::SSL_CTX_FAILED);
            }
            SSL *ssl = SSL_new(ctx);
            if (ssl == nullptr) [[unlikely]]
            {
                LOG_ERROR("Acceptor::startTls: SSL_new() failed on fd {}", clientFd);
                return std::unexpected(ERR::SSL_NEW_FAILED);
            }
#ifdef MYNET_HAVE_KTLS
            SSL_set_options(ssl, SSL_OP_ENABLE_KTLS);
#endif
            if (SSL_set_fd(ssl, clientFd) != 1) [[unlikely]]
            {
                LOG_ERROR("Acceptor::startTls: SSL_set_fd failed on fd {}", clientFd);
                SSL_free(ssl);
                return std::unexpected(ERR::SSL_SET_FD_FAILED);
            }
            SSL_set_accept_state(ssl);
            return ssl;
        }

        static inline Result<SSL *> startTLS(int clientFd, SSL_CTX *ctx) noexcept { return startTls(clientFd, ctx); }

        /**
         * @brief 驱动非阻塞 TLS 握手演进
         */
        static inline HandshakeStatus doTlsHandshake(SSL *ssl) noexcept
        {
            if (ssl == nullptr) [[likely]]
            {
                return HandshakeStatus::SUCCESS;
            }
            const int r = SSL_accept(ssl);
            if (r == 1)
            {
                return HandshakeStatus::SUCCESS;
            }
            const int err = SSL_get_error(ssl, r);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            {
                return HandshakeStatus::IN_PROGRESS;
            }
            return HandshakeStatus::FAILED;
        }
    };

    /**
     * @brief 兼容泛型接收器模板包装（零数据成员，支持直接作为默认接收器或兼容原有泛型写法）
     *
     * @tparam InboundContext 协议特有的 inbound 上下文类型。默认为 EmptyInbound。
     */
    template <typename InboundContext = EmptyInbound>
    class Acceptor : public IAcceptor
    {
    public:
        using Inbound = InboundContext;
        using Handler = InboundContext;

        Acceptor() = default;
        explicit Acceptor([[maybe_unused]] InboundContext inbound) {}
        ~Acceptor() override = default;

        Acceptor(const Acceptor &) = default;
        Acceptor &operator=(const Acceptor &) = default;
        Acceptor(Acceptor &&) noexcept = default;
        Acceptor &operator=(Acceptor &&) noexcept = default;

        inline Result<SSL *> startTls(int clientFd, SSL_CTX *ctx) noexcept
        {
            return IAcceptor::startTls(clientFd, ctx);
        }

        inline Result<SSL *> startTLS(int clientFd, SSL_CTX *ctx) noexcept
        {
            return IAcceptor::startTls(clientFd, ctx);
        }

        inline HandshakeStatus doTlsHandshake(SSL *ssl) noexcept { return IAcceptor::doTlsHandshake(ssl); }
    };

    template <typename InboundContext = EmptyInbound>
    using AcceptorBase = Acceptor<InboundContext>;

    template <typename InboundContext = EmptyInbound>
    using AcceptorBaseCompat = Acceptor<InboundContext>;

    template <typename A>
    concept DerivedFromAcceptor = std::derived_from<A, IAcceptor>;

    template <typename A>
    concept BaseAcceptor = DerivedFromAcceptor<A>;

    template <typename A>
    concept DerivedFromAcceptorBase = DerivedFromAcceptor<A>;

} // namespace mynet
