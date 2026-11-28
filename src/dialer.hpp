#pragma once

/**
 * @file dialer.hpp
 * @brief 客户端出站拨号握手器（Dialer）基类与出站抽象。
 *
 * 与 Acceptor 严格对称：
 * 1. 纯虚/基类，无模板参数，零连接级可变成员（移除 fd、targetAddr 等会话级可变状态）；
 * 2. 专职负责出站建连、多网卡赛马、路由标记 (SO_MARK) 与出站协议握手；
 * 3. 各协议自身继承并实现定制出站握手协议；
 * 4. 握手成功后交付装配好对应 Handler 的 ConnectionBase 实例或出站结果结构体。
 */

#include "acceptor.hpp"
#include "config/log.hpp"
#include "connection.hpp"
#include "connector.hpp"
#include "error.hpp"
#include "tls/fragmenter.hpp"
#include "transportStack.hpp"
#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <concepts>
#include <csignal>
#include <fcntl.h>
#include <mutex>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <span>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

#ifndef IPPROTO_MPTCP
#define IPPROTO_MPTCP 262
#endif

namespace mynet
{

    /**
     * @brief 空出站上下文结构（不占任何空间）
     */
    struct EmptyOutbound
    {
    };

    /**
     * @brief 出站拨号结果
     */
    struct OutboundDialResult
    {
        int fd{-1};                                    ///< 拨号成功的套接字描述符
        std::unique_ptr<Handler> handler{nullptr};     ///< 对应的出站协议状态机处理器
        std::string outboundTag{};                     ///< 命中的出站标签
        std::string targetEndpoint{};                  ///< 目标端点字符串表示
        bool immediateConnected{false};                ///< 连接是否立即可用（已非阻塞连上）
        sockaddr_in peerAddr{};                        ///< 目标 IPv4 地址（供异步建连引擎复用）
        bool connectDeferred{false};                   ///< 是否由底层 Proactor 异步发起 io_uring connect

        [[nodiscard]] inline bool ok() const noexcept { return handler != nullptr; }
    };

    /**
     * @brief 拨号器统一抽象基类 (Dialer / Outbound)
     *
     * 业务出站端点元数据描述符与协议拨号器（与 Acceptor 对称）。
     * 组合底层 Connector 完成 TCP/UDP 传输建连，并负责出站协议握手与 Handler / Connection 装配。
     */
    class DialerManager;

    class Dialer
    {
    protected:
        Connector connector_{};
        std::string tag_{};
        std::string type_{};
        std::atomic<bool> running_{false};
        transport::TransportConfig transportConfig_{};

        /**
         * @brief 解析主机名/字面值为 IPv4 地址（统一复用，消除 dialTcp / dialUdp 重复 DNS 解析逻辑）
         */
        [[nodiscard]] static Result<in_addr> resolveIpv4(std::string_view host, int sockType = SOCK_STREAM,
                                                         bool useCache = true) noexcept
        {
            return Connector::resolveIpv4(host, sockType, useCache);
        }

        /**
         * @brief 通用出站转发拨号建连与状态机处理器装配辅助函数 (DRY 统一代码复用)
         */
        template <typename HandlerType, typename... Args>
        Result<OutboundDialResult> dialForwarderHelper(std::string_view serverHost, uint16_t serverPort,
                                                       const Address &target, DialContext ctx, Args &&...args)
        {
            auto dialRes = dialTcp(serverHost, serverPort, nullptr, ctx);
            if (!dialRes)
            {
                return std::unexpected(dialRes.error());
            }

            auto h = std::make_unique<HandlerType>(std::forward<Args>(args)..., target);
            h->onConnect(dialRes->fd);
            if (transportConfig_.enableTls || transportConfig_.type != transport::TransportType::TCP)
            {
                transport::TransportConfig cfg = transportConfig_;
                if (cfg.sni.empty() && cfg.host.empty() && !serverHost.empty())
                {
                    cfg.sni = std::string(serverHost);
                }
                if (auto tr = transport::attachConfiguredTransport(*h, cfg, false); !tr)
                {
                    if (dialRes->fd >= 0)
                    {
                        ::close(dialRes->fd);
                    }
                    return std::unexpected(tr.error());
                }
                if (auto hs = h->startTransportHandshake(); !hs)
                {
                    if (dialRes->fd >= 0)
                    {
                        ::close(dialRes->fd);
                    }
                    return std::unexpected(hs.error());
                }
            }
            h->handle();

            OutboundDialResult res;
            res.fd = dialRes->fd;
            res.handler = std::move(h);
            res.outboundTag = tag_;
            res.targetEndpoint = target.toString();
            res.immediateConnected = dialRes->immediateConnected;
            res.peerAddr = dialRes->peerAddr;
            res.connectDeferred = dialRes->connectDeferred;
            return res;
        }

    public:
        Dialer() = default;
        explicit Dialer(DialerOptions options)
            : connector_(std::move(options))
        {
        }
        Dialer(std::string tag, std::string type, DialerOptions options = {})
            : connector_(std::move(options)),
              tag_(std::move(tag)),
              type_(std::move(type))
        {
        }
        virtual ~Dialer() = default;

        Dialer(const Dialer &) = delete;
        Dialer &operator=(const Dialer &) = delete;
        Dialer(Dialer &&) = delete;
        Dialer &operator=(Dialer &&) = delete;

        [[nodiscard]] static Result<in_addr> resolveIpv4Public(std::string_view host, int sockType = SOCK_STREAM,
                                                               bool useCache = true) noexcept
        {
            return resolveIpv4(host, sockType, useCache);
        }

        [[nodiscard]] inline const std::string &tag() const noexcept { return tag_; }
        [[nodiscard]] inline const std::string &type() const noexcept { return type_; }
        [[nodiscard]] inline bool isRunning() const noexcept { return running_.load(std::memory_order_relaxed); }

        inline void setTransportConfig(transport::TransportConfig cfg)
        {
            transportConfig_ = std::move(cfg);
        }
        [[nodiscard]] inline const transport::TransportConfig &transportConfig() const noexcept
        {
            return transportConfig_;
        }
        virtual void setManager(DialerManager *mgr) noexcept { (void)mgr; }

        [[nodiscard]] virtual std::string_view serverHost() const noexcept { return ""; }
        [[nodiscard]] virtual uint16_t serverPort() const noexcept { return 0; }

        virtual Result<> start() noexcept
        {
            running_.store(true, std::memory_order_release);
            return {};
        }

        virtual void stop() noexcept { running_.store(false, std::memory_order_release); }

        /**
         * @brief 转发拨号建连：返回 OutboundDialResult（原始 fd + Handler + 握手状态），专供 Forwarder 桥接转发
         */
        virtual Result<OutboundDialResult> dialForwarder(const Address &target, DialContext ctx = {})
        {
            (void)target;
            (void)ctx;
            return std::unexpected(ERR::CONNECT_FAILED);
        }

        /**
         * @brief 独立连接拨号建连：复用 dialForwarder() 完成建连与协议握手，并装配为 Connection 实例供非转发客户端处理
         */
        [[nodiscard]] virtual Result<std::unique_ptr<Connection>> dialConnection(const Address &target,
                                                                                 DialContext ctx = {})
        {
            auto res = dialForwarder(target, ctx);
            if (!res)
                return std::unexpected(res.error());
            if (!res->handler)
            {
                if (res->fd >= 0)
                    ::close(res->fd);
                return std::unexpected(ERR::CONNECT_FAILED);
            }
            auto conn = std::make_unique<Connection>();
            conn->setFd(res->fd);
            conn->setPeerAddr(res->peerAddr);
            conn->setHandler(std::move(res->handler));
            return conn;
        }

        virtual Result<int> dialDatagram(const Address &target)
        {
            (void)target;
            return std::unexpected(ERR::CONNECT_FAILED);
        }

        [[nodiscard]] inline Connector &connector() noexcept { return connector_; }
        [[nodiscard]] inline const Connector &connector() const noexcept { return connector_; }

        [[nodiscard]] inline const DialerOptions &options() const noexcept { return connector_.options(); }
        inline void setOptions(DialerOptions options) noexcept { connector_.setOptions(std::move(options)); }

        inline void setTcpPrefix(std::span<const uint8_t> prefix) noexcept { connector_.setTcpPrefix(prefix); }
        [[nodiscard]] inline std::span<const uint8_t> getTcpPrefix() const noexcept
        {
            return connector_.getTcpPrefix();
        }

        static inline bool flushTcpPrefix(int socketFd, std::span<const uint8_t> prefix) noexcept
        {
            return Connector::flushTcpPrefix(socketFd, prefix);
        }

        inline bool flushTcpPrefix(int socketFd = -1) const noexcept { return connector_.flushTcpPrefix(socketFd); }

        inline void setMark(uint32_t mark) noexcept { connector_.setMark(mark); }
        [[nodiscard]] inline uint32_t mark() const noexcept { return connector_.mark(); }

        inline void setTransparent(bool enable) noexcept { connector_.setTransparent(enable); }
        [[nodiscard]] inline bool isTransparent() const noexcept { return connector_.isTransparent(); }

        inline void setDscp(uint8_t val) noexcept { connector_.setDscp(val); }
        [[nodiscard]] inline uint8_t getDscp() const noexcept { return connector_.getDscp(); }

        inline void setMptcp(bool enable) noexcept { connector_.setMptcp(enable); }
        [[nodiscard]] inline bool isMptcp() const noexcept { return connector_.isMptcp(); }

        inline void setInterface(std::string_view ifname) noexcept { connector_.setInterface(ifname); }
        [[nodiscard]] inline std::string_view getInterface() const noexcept { return connector_.getInterface(); }

        virtual void reset() noexcept {}

        [[nodiscard]] Result<int> prepareTcpSocket(const char *bindIface = nullptr) const noexcept
        {
            return connector_.prepareTcpSocket(bindIface);
        }

        [[nodiscard]] Result<ConnectResult> dialTcp(const sockaddr_in &target,
                                                    const char *bindIface = nullptr,
                                                    DialContext ctx = {}) const noexcept
        {
            return connector_.connectTcp(target, bindIface, ctx);
        }

        [[nodiscard]] Result<ConnectResult> dialTcp(std::string_view host, uint16_t port,
                                                    const char *bindIface = nullptr,
                                                    DialContext ctx = {}) const noexcept
        {
            return connector_.connectTcp(host, port, bindIface, ctx);
        }

        [[nodiscard]] Result<ConnectResult> dialTcp(const char *ip, int port,
                                                    const char *bindIface = nullptr,
                                                    DialContext ctx = {}) const noexcept
        {
            return connector_.connectTcp(ip, port, bindIface, ctx);
        }

        [[nodiscard]] Result<Datagram> createConfiguredDatagram(const char *bindIface = nullptr) const noexcept
        {
            return connector_.createConfiguredDatagram(bindIface);
        }

        [[nodiscard]] Result<int> dialUdp(const sockaddr_in &target, const char *bindIface = nullptr) const noexcept
        {
            return connector_.connectUdp(target, bindIface);
        }

        [[nodiscard]] Result<int> dialUdp(std::string_view host, uint16_t port,
                                          const char *bindIface = nullptr) const noexcept
        {
            return connector_.connectUdp(host, port, bindIface);
        }

        [[nodiscard]] Result<int> dialUdp(const char *ip, int port, const char *bindIface = nullptr) const noexcept
        {
            return connector_.connectUdp(ip, port, bindIface);
        }
    };

    /**
     * @brief 兼容泛型出站拨号器模板包装（继承自 Dialer）
     *
     * @tparam OutboundContext 协议特有的 outbound 上下文类型。默认为 EmptyOutbound。
     */
    template <typename OutboundContext = EmptyOutbound>
    class TypedDialer : public Dialer
    {
    public:
        using Outbound = OutboundContext;
        using Handler = OutboundContext;

        TypedDialer() = default;
        explicit TypedDialer([[maybe_unused]] OutboundContext outbound) {}
        TypedDialer(std::string tag, std::string type, DialerOptions options = {})
            : Dialer(std::move(tag), std::move(type), std::move(options))
        {
        }
        explicit TypedDialer(DialerOptions options)
            : Dialer(std::move(options))
        {
        }
        ~TypedDialer() override = default;

        TypedDialer(const TypedDialer &) = default;
        TypedDialer &operator=(const TypedDialer &) = default;
        TypedDialer(TypedDialer &&) noexcept = default;
        TypedDialer &operator=(TypedDialer &&) noexcept = default;
    };

    template <typename OutboundContext = EmptyOutbound>
    using DialerBase = TypedDialer<OutboundContext>;

    template <typename OutboundContext = EmptyOutbound>
    using DialerBaseCompat = TypedDialer<OutboundContext>;

    template <typename D>
    concept DerivedFromDialer = std::derived_from<D, Dialer>;

    template <typename D>
    concept BaseDialer = DerivedFromDialer<D>;

    template <typename D>
    concept DerivedFromDialerBase = DerivedFromDialer<D>;

} // namespace mynet
