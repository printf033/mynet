#pragma once

/**
 * @file acceptor.hpp
 * @brief 协议接收器（Acceptor）基类与统一入站抽象。
 *
 * 职责彻底解耦：
 * 1. 作为所有入站协议的统一抽象基类（IAcceptor / InboundBase）；
 * 2. 托管监听套接字生命周期 (listenFd) 的绑定、非阻塞 accept 与优雅停机；
 * 3. 专职负责特定协议的入站握手 (Inbound Handshake) 与首包特征嗅探 match()；
 * 4. 握手成功后交付装配好对应 Handler 的 Connection 实例。
 */

#include "config/log.hpp"
#include "connection.hpp"
#include "error.hpp"
#include "listener.hpp"
#include "transportStack.hpp"
#include <concepts>
#include <cstdint>
#include <memory>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace mynet
{

    class Connection;
    class Handler;

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
     * @brief 协议接收器统一抽象基类 (Acceptor / Inbound)
     *
     * 业务入站端点元数据描述符与协议接收器。
     * 直接管理监听套接字生命周期与非阻塞 accept，并抽象各协议的 match() 与握手逻辑。
     */
    class Acceptor
    {
    protected:
        struct SslCtxDeleter
        {
            void operator()(SSL_CTX *ctx) const noexcept
            {
                if (ctx != nullptr)
                {
                    SSL_CTX_free(ctx);
                }
            }
        };

        std::string tag_{};
        std::string type_{};
        std::string host_{"0.0.0.0"};
        uint16_t port_{0};
        Listener socket_{};
        bool running_{false};
        bool enableSniffing_{true};
        transport::TransportConfig transportConfig_{};
        std::shared_ptr<SSL_CTX> ownedSslCtx_{};
        SSL_CTX *externalSslCtx_{nullptr};

        [[nodiscard]] inline bool attachTransportToHandler(Handler &handler) const
        {
            if (!transportConfig_.enableTls && transportConfig_.type == transport::TransportType::TCP)
            {
                return true;
            }
            auto res = transport::attachConfiguredTransport(handler, transportConfig_, true, sslContext());
            return static_cast<bool>(res);
        }

    public:
        Acceptor(std::string tag = "", std::string type = "", std::string host = "0.0.0.0", uint16_t port = 0,
                 bool enableSniffing = true)
            : tag_(std::move(tag)),
              type_(std::move(type)),
              host_(std::move(host)),
              port_(port),
              enableSniffing_(enableSniffing)
        {
        }

        virtual ~Acceptor() noexcept { close(); }

        Acceptor(const Acceptor &) = delete;
        Acceptor &operator=(const Acceptor &) = delete;
        Acceptor(Acceptor &&) = delete;
        Acceptor &operator=(Acceptor &&) = delete;

        [[nodiscard]] inline const std::string &tag() const noexcept { return tag_; }
        [[nodiscard]] inline const std::string &type() const noexcept { return type_; }
        [[nodiscard]] inline const std::string &host() const noexcept { return host_; }
        [[nodiscard]] inline uint16_t port() const noexcept { return port_; }
        [[nodiscard]] inline int listenFd() const noexcept { return socket_.fd(); }
        [[nodiscard]] inline const sockaddr_in &addr() const noexcept { return socket_.addr(); }
        [[nodiscard]] inline bool isRunning() const noexcept { return running_; }
        [[nodiscard]] inline bool running() const noexcept { return running_; }
        [[nodiscard]] inline bool isSniffingEnabled() const noexcept { return enableSniffing_; }
        inline void setSniffingEnabled(bool enable) noexcept { enableSniffing_ = enable; }

        /**
         * @brief 启动非阻塞 TCP 监听
         */
        virtual Result<> listen(int backlog = 128, bool reuseAddr = true, bool reusePort = true) noexcept
        {
            if (running_ && socket_.valid())
            {
                return {};
            }
            close();

            auto res = socket_.listenTcp(host_.c_str(), port_, backlog, reuseAddr, reusePort);
            if (!res)
            {
                LOG_ERROR("Acceptor '{}' ({}): listenTcp {}:{} failed", tag_, type_, host_, port_);
                return std::unexpected(res.error());
            }

            if (port_ == 0)
            {
                port_ = ntohs(socket_.addr().sin_port);
            }

            running_ = true;
            return {};
        }

        /**
         * @brief 非阻塞接收一个接入的客户端连接
         */
        [[nodiscard]] virtual Result<std::pair<int, sockaddr_in>> acceptOne() noexcept { return socket_.accept(); }

        /**
         * @brief 关闭监听套接字
         */
        virtual void close() noexcept
        {
            socket_.reset();
            running_ = false;
        }

        /**
         * @brief 快速首包特征嗅探（用于单端口多协议混合调度）
         */
        [[nodiscard]] virtual bool match(std::span<const uint8_t> initialBytes) const noexcept
        {
            (void)initialBytes;
            return false;
        }

        /**
         * @brief 为新接入的连接创建对应的协议状态机处理器
         */
        [[nodiscard]] virtual std::unique_ptr<Handler> createHandler()
        {
            return nullptr;
        }

        /**
         * @brief 配置入站传输层（支持 TLS / WebSocket / gRPC 及共享服务端 SSL_CTX 预构建）
         */
        inline Result<> setTransportConfig(transport::TransportConfig cfg)
        {
            transportConfig_ = std::move(cfg);
            ownedSslCtx_.reset();
            if ((transportConfig_.enableTls || transportConfig_.type == transport::TransportType::TLS) &&
                externalSslCtx_ == nullptr && !transportConfig_.certFile.empty() && !transportConfig_.keyFile.empty())
            {
                auto ctxRes = transport::createSharedServerSslContext(transportConfig_);
                if (!ctxRes)
                {
                    return std::unexpected(ctxRes.error());
                }
                ownedSslCtx_ = std::shared_ptr<SSL_CTX>(*ctxRes, SslCtxDeleter{});
            }
            return {};
        }

        [[nodiscard]] inline const transport::TransportConfig &transportConfig() const noexcept
        {
            return transportConfig_;
        }

        inline Result<> configureTls(std::string certFile, std::string keyFile, std::string alpnProtocols = "")
        {
            transport::TransportConfig cfg = transportConfig_;
            cfg.enableTls = true;
            cfg.certFile = std::move(certFile);
            cfg.keyFile = std::move(keyFile);
            if (!alpnProtocols.empty())
            {
                cfg.alpnProtocols = std::move(alpnProtocols);
            }
            return setTransportConfig(std::move(cfg));
        }

        inline void setSslContext(SSL_CTX *ctx) noexcept { externalSslCtx_ = ctx; }

        [[nodiscard]] inline SSL_CTX *sslContext() const noexcept
        {
            return externalSslCtx_ != nullptr ? externalSslCtx_ : ownedSslCtx_.get();
        }

        /**
         * @brief 创建并装配好传输管线的协议 Handler（所有子类共用单一入口）
         */
        [[nodiscard]] virtual std::unique_ptr<Handler> buildConfiguredHandler()
        {
            auto h = createHandler();
            if (!h)
            {
                return nullptr;
            }
            if (!attachTransportToHandler(*h))
            {
                return nullptr;
            }
            return h;
        }

        /**
         * @brief 非阻塞建连装配：分配 owned Handler 并初始化传输握手（供独立 Connection 生命周期管理使用）
         */
        [[nodiscard]] virtual HandshakeStatus acceptConnection(int clientFd, Connection *&outConn)
        {
            auto h = createHandler();
            if (!h)
            {
                outConn = nullptr;
                return HandshakeStatus::SUCCESS;
            }
            if (!attachTransportToHandler(*h))
            {
                outConn = nullptr;
                return HandshakeStatus::FAILED;
            }
            h->onConnect(clientFd);
            [[maybe_unused]] auto _ = h->startTransportHandshake();
            auto *conn = new Connection();
            conn->setFd(clientFd);
            conn->setHandler(std::move(h));
            outConn = conn;
            return HandshakeStatus::SUCCESS;
        }

        /**
         * @brief 转发建连装配：直接创建并初始化挂载好传输管线的 Handler（不包装 Connection，供 Forwarder 零拷贝桥接使用）
         */
        [[nodiscard]] virtual std::unique_ptr<Handler> acceptForwarder(int clientFd)
        {
            auto h = buildConfiguredHandler();
            if (!h)
            {
                return nullptr;
            }
            h->onConnect(clientFd);
            [[maybe_unused]] auto _ = h->startTransportHandshake();
            return h;
        }

        /**
         * @brief 数据报入站接收装配：由 UDP/Datagram 接收器覆写，返回已绑定的 datagram socket fd
         */
        [[nodiscard]] virtual Result<int> acceptDatagram(const Address &peer)
        {
            (void)peer;
            return std::unexpected(ERR::ACCEPT_FAILED);
        }

        /**
         * @brief 重置握手器状态
         */
        virtual void reset() noexcept {}
    };

    /**
     * @brief 泛型接收器模板包装（继承自 Acceptor）
     */
    template <typename InboundContext = EmptyInbound>
    class TypedAcceptor : public Acceptor
    {
    public:
        using Inbound = InboundContext;
        using Handler = InboundContext;

        TypedAcceptor() = default;
        explicit TypedAcceptor([[maybe_unused]] InboundContext inbound) {}
        TypedAcceptor(std::string tag, std::string type, std::string host = "0.0.0.0", uint16_t port = 0,
                      bool enableSniffing = true)
            : Acceptor(std::move(tag), std::move(type), std::move(host), port, enableSniffing)
        {
        }
        ~TypedAcceptor() override = default;

        TypedAcceptor(const TypedAcceptor &) = default;
        TypedAcceptor &operator=(const TypedAcceptor &) = default;
        TypedAcceptor(TypedAcceptor &&) noexcept = default;
        TypedAcceptor &operator=(TypedAcceptor &&) noexcept = default;

        [[nodiscard]] std::unique_ptr<mynet::Handler> createHandler() override
        {
            if constexpr (std::derived_from<InboundContext, mynet::Handler>)
            {
                return std::make_unique<InboundContext>();
            }
            return nullptr;
        }

    };

    template <typename InboundContext = EmptyInbound>
    using AcceptorBase = TypedAcceptor<InboundContext>;

    template <typename A>
    concept DerivedFromAcceptor = std::derived_from<A, Acceptor>;

} // namespace mynet
