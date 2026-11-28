#pragma once

/**
 * @file transparent.hpp
 * @brief Linux Netfilter 透明代理入站状态机处理器、UDP TProxy 报文流水线与 TProxy 接收器 (AcceptorTransparent)
 *
 * 借鉴 dae 与 sing-box 设计：
 * 1. HandlerInboundRedirect: iptables -j REDIRECT (SO_ORIGINAL_DST 提取 + L7 零拷贝域名嗅探 + DNS 反向还原)
 * 2. HandlerInboundTProxy: iptables -j TPROXY (getsockname 原始目的提取 + 域名嗅探)
 * 3. HandlerInboundDatagramTProxy: UDP TProxy 数据报透明代理 (IP_RECVORIGDSTADDR + QUIC/DNS 嗅探)
 * 4. AcceptorTransparent: Linux TProxy 透明代理入站端点 (setsockopt IP_TRANSPARENT)
 */

#include "acceptor.hpp"
#include "address.hpp"
#include "connection.hpp"
#include "dns/cache.hpp"
#include "sniffer.hpp"
#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <linux/netfilter_ipv4.h>
#include <memory>
#include <netinet/in.h>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#ifndef SO_ORIGINAL_DST
#define SO_ORIGINAL_DST 80
#endif
#ifndef IP6T_SO_ORIGINAL_DST
#define IP6T_SO_ORIGINAL_DST 80
#endif
#include <sys/socket.h>
#include <utility>

#ifndef SO_ORIGINAL_DST
#define SO_ORIGINAL_DST 80
#endif
#ifndef IP6T_SO_ORIGINAL_DST
#define IP6T_SO_ORIGINAL_DST 80
#endif
#ifndef IP_ORIGDSTADDR
#define IP_ORIGDSTADDR 20
#endif
#ifndef IP_RECVORIGDSTADDR
#define IP_RECVORIGDSTADDR 20
#endif

namespace mynet::handler
{

    /**
     * @brief 从已连接套接字提取透明代理原始目的地址 (Linux Netfilter SO_ORIGINAL_DST)
     */
    [[nodiscard]] inline std::optional<Address> extractOriginalDst(int fd) noexcept
    {
        if (fd < 0)
        {
            return std::nullopt;
        }

        sockaddr_in sin{};
        socklen_t slen = sizeof(sin);
        if (::getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, &sin, &slen) == 0 && sin.sin_family == AF_INET)
        {
            return Address::fromIPv4(sin.sin_addr.s_addr, ntohs(sin.sin_port));
        }

        sockaddr_in6 sin6{};
        socklen_t slen6 = sizeof(sin6);
        if (::getsockopt(fd, SOL_IPV6, IP6T_SO_ORIGINAL_DST, &sin6, &slen6) == 0 && sin6.sin6_family == AF_INET6)
        {
            return Address::fromIPv6(reinterpret_cast<const uint8_t *>(&sin6.sin6_addr), ntohs(sin6.sin6_port));
        }

        return std::nullopt;
    }

    /**
     * @brief 从已连接套接字提取 Linux TProxy 原始目的地址 (getsockname 或 SO_ORIGINAL_DST 回落)
     */
    [[nodiscard]] inline std::optional<Address> extractTProxyDst(int fd) noexcept
    {
        if (fd < 0)
        {
            return std::nullopt;
        }

        sockaddr_storage ss{};
        socklen_t slen = sizeof(ss);
        if (::getsockname(fd, reinterpret_cast<sockaddr *>(&ss), &slen) == 0)
        {
            if (ss.ss_family == AF_INET)
            {
                const auto *sin = reinterpret_cast<const sockaddr_in *>(&ss);
                if (sin->sin_addr.s_addr != INADDR_ANY)
                {
                    return Address::fromIPv4(sin->sin_addr.s_addr, ntohs(sin->sin_port));
                }
            }
            else if (ss.ss_family == AF_INET6)
            {
                const auto *sin6 = reinterpret_cast<const sockaddr_in6 *>(&ss);
                if (!IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr))
                {
                    return Address::fromIPv6(reinterpret_cast<const uint8_t *>(&sin6->sin6_addr), ntohs(sin6->sin6_port));
                }
            }
        }

        return extractOriginalDst(fd);
    }

    enum class TransparentStage : uint8_t
    {
        RESOLVING, ///< 正在从套接字提取原始目的地址
        SNIFFING,  ///< 正在零拷贝嗅探首包应用层域名 (TLS SNI / HTTP Host)
        STREAMING, ///< 目标已确定，处于直接透明转发中
        ERROR      ///< 无法提取原始目的地址或严重协议错误
    };

    /**
     * @brief Linux Redirect 透明代理入站处理器 (iptables -j REDIRECT)
     */
    class HandlerInboundRedirect : public HandlerInbound
    {
    protected:
        TransparentStage transparentStage_{TransparentStage::RESOLVING};
        int clientFd_{-1};
        bool sniffingEnabled_{true};
        size_t maxSniffBytes_{4096};

    public:
        HandlerInboundRedirect() noexcept = default;
        explicit HandlerInboundRedirect(int clientFd) noexcept
            : clientFd_(clientFd)
        {
        }
        ~HandlerInboundRedirect() noexcept override = default;

        HandlerInboundRedirect(const HandlerInboundRedirect &) = delete;
        HandlerInboundRedirect &operator=(const HandlerInboundRedirect &) = delete;
        HandlerInboundRedirect(HandlerInboundRedirect &&) = delete;
        HandlerInboundRedirect &operator=(HandlerInboundRedirect &&) = delete;

        void setClientFd(int fd) noexcept { clientFd_ = fd; }
        void setSniffing(bool enable) noexcept { sniffingEnabled_ = enable; }
        [[nodiscard]] bool isSniffingEnabled() const noexcept { return sniffingEnabled_; }
        void setMaxSniffBytes(size_t maxBytes) noexcept { maxSniffBytes_ = maxBytes; }

        [[nodiscard]] TransparentStage stage() const noexcept { return transparentStage_; }

        void onConnect(int fd) noexcept override
        {
            HandlerInbound::onConnect(fd);
            clientFd_ = fd;
        }

        void reset() noexcept override
        {
            HandlerInbound::reset();
            transparentStage_ = TransparentStage::RESOLVING;
            clientFd_ = -1;
        }

        void onMessageComplete() noexcept override {}

        void onParseError(const char *reason) noexcept override
        {
            (void)reason;
            transparentStage_ = TransparentStage::ERROR;
            setStage(InboundStage::ERROR);
        }

        void handle() override
        {
            if (transparentStage_ == TransparentStage::RESOLVING)
            {
                resolveOriginalDst();
                if (transparentStage_ != TransparentStage::SNIFFING && transparentStage_ != TransparentStage::STREAMING)
                {
                    return;
                }
            }

            if (transparentStage_ == TransparentStage::SNIFFING)
            {
                sniffPayload();
            }
        }

    protected:
        virtual std::optional<Address> fetchOriginalDst()
        {
            const int targetFd = (clientFd_ >= 0) ? clientFd_ : fd();
            if (targetFd >= 0)
            {
                return extractOriginalDst(targetFd);
            }
            return std::nullopt;
        }

        void resolveOriginalDst()
        {
            targetAddress_ = fetchOriginalDst();
            if (!targetAddress_.has_value())
            {
                onParseError("Redirect: SO_ORIGINAL_DST not found on socket");
                transparentStage_ = TransparentStage::ERROR;
                setStage(InboundStage::ERROR);
                setCloseAfterResponse(true);
                return;
            }

            if (!sniffingEnabled_)
            {
                // 若禁用嗅探，尝试反查 DNS 逆向缓存后直接就绪
                tryFallbackReverseDns();
                transparentStage_ = TransparentStage::STREAMING;
                setStage(InboundStage::STREAMING);
                command_ = 0x01;
                onMessageComplete();
                if (requestCallback_)
                {
                    requestCallback_(0x01, *targetAddress_);
                }
                return;
            }

            // 进入嗅探状态，等待首包负载到达
            transparentStage_ = TransparentStage::SNIFFING;
            setStage(InboundStage::HANDSHAKE);
        }

        void sniffPayload()
        {
            const size_t avail = requestBytes();
            if (avail == 0)
            {
                setStage(InboundStage::HANDSHAKE);
                return;
            }

            std::span<const uint8_t> data(reinterpret_cast<const uint8_t *>(requestBegin()), avail);
            auto sniffResult = DomainSniffer::sniff(data, SniffTransport::TCP, targetAddress_->port);

            if (sniffResult.has_value())
            {
                if (!sniffResult->host.empty())
                {
                    const uint16_t port = sniffResult->port != 0 ? sniffResult->port : targetAddress_->port;
                    targetAddress_ = Address::fromDomain(sniffResult->host, port);
                }
                transitionToStreaming();
                return;
            }

            // 报文长度已超过嗅探窗口，或首字节不可能属于已知 TCP 嗅探协议，执行 DNS 反向还原兜底
            if (avail >= maxSniffBytes_ || !DomainSniffer::couldBeSniffable(data[0], SniffTransport::TCP) ||
                avail >= 512)
            {
                tryFallbackReverseDns();
                transitionToStreaming();
            }
            else
            {
                setStage(InboundStage::HANDSHAKE);
            }
        }

        void tryFallbackReverseDns()
        {
            if (!targetAddress_.has_value())
            {
                return;
            }
            if (auto rev = dns::DnsReverseCache::instance().lookup(*targetAddress_); rev.has_value())
            {
                targetAddress_ = *rev;
            }
        }

        void transitionToStreaming()
        {
            transparentStage_ = TransparentStage::STREAMING;
            setStage(InboundStage::STREAMING);
            command_ = 0x01;
            onMessageComplete();

            if (requestCallback_)
            {
                requestCallback_(0x01, *targetAddress_);
            }
        }
    };

    /**
     * @brief Linux TProxy 透明代理处理器 (iptables -j TPROXY)
     *
     * 与 Redirect 相比，TProxy 连接通过 getsockname 直接读取真实目的地址，
     * 具备原生全锥型保留特性。
     */
    class HandlerInboundTProxy : public HandlerInboundRedirect
    {
    public:
        using HandlerInboundRedirect::HandlerInboundRedirect;

    protected:
        std::optional<Address> fetchOriginalDst() override
        {
            const int targetFd = (clientFd_ >= 0) ? clientFd_ : fd();
            if (targetFd >= 0)
            {
                return extractTProxyDst(targetFd);
            }
            return std::nullopt;
        }
    };

    /**
     * @brief UDP TProxy 数据报透明代理入站处理器
     *
     * 负责解析带有 IP_RECVORIGDSTADDR 原始目的地址控制消息的 UDP 报文，
     * 联动 QUIC Initial 与 DNS 嗅探器还原目标域名。
     */
    class HandlerInboundDatagramTProxy : public HandlerInbound
    {
    public:
        using TProxyPacketCallback =
            std::function<void(const sockaddr_in &clientPeer, const Address &target, const char *data, size_t n)>;

    private:
        TProxyPacketCallback packetCallback_{nullptr};
        bool sniffingEnabled_{true};

    public:
        HandlerInboundDatagramTProxy() noexcept = default;
        explicit HandlerInboundDatagramTProxy(TProxyPacketCallback cb) noexcept
            : packetCallback_(std::move(cb))
        {
        }
        ~HandlerInboundDatagramTProxy() noexcept override = default;

        void setPacketCallback(TProxyPacketCallback cb) noexcept { packetCallback_ = std::move(cb); }
        void setSniffing(bool enable) noexcept { sniffingEnabled_ = enable; }
        [[nodiscard]] bool isSniffingEnabled() const noexcept { return sniffingEnabled_; }

        void reset() noexcept override { HandlerInbound::reset(); }

        /**
         * @brief 处理带有原始目的地址的入站 UDP 报文
         *
         * @param peer 客户端真实源地址
         * @param origDst 报文原本要发往的目标地址
         * @param data 报文载荷
         * @param n 报文有效长度
         */
        void onDatagramWithDst(const sockaddr_in &peer, const sockaddr_in &origDst, const char *data, size_t n) noexcept
        {
            if (data == nullptr || n == 0)
            {
                return;
            }

            Address target = Address::fromIPv4(origDst.sin_addr.s_addr, ntohs(origDst.sin_port));

            // 尝试应用层深度嗅探（UDP 链：QUIC Initial SNI / DNS 等 + 负缓存防抖）
            const uint32_t ipBe = origDst.sin_addr.s_addr;
            const uint8_t udpProtoKey = static_cast<uint8_t>(SniffTransport::UDP);
            bool sniffMatched = false;
            if (sniffingEnabled_ && !SniffNegativeCache::instance().isNegative(ipBe, target.port, udpProtoKey))
            {
                std::span<const uint8_t> payload(reinterpret_cast<const uint8_t *>(data), n);
                if (auto res = DomainSniffer::sniff(payload, SniffTransport::UDP, target.port); res.has_value())
                {
                    SniffNegativeCache::instance().recordSuccess(ipBe, target.port, udpProtoKey);
                    sniffMatched = true;
                    if (!res->host.empty())
                    {
                        const uint16_t p = res->port != 0 ? res->port : target.port;
                        target = Address::fromDomain(res->host, p);
                    }
                }
                else
                {
                    SniffNegativeCache::instance().recordFailure(ipBe, target.port, udpProtoKey);
                }
            }
            if (!sniffMatched)
            {
                if (auto rev = dns::DnsReverseCache::instance().lookup(target); rev.has_value())
                {
                    target = *rev;
                }
            }

            if (packetCallback_)
            {
                packetCallback_(peer, target, data, n);
            }
        }

        /**
         * @brief 从 msghdr 辅助控制信息中提取原始目的 IPv4 地址 (Linux IP_ORIGDSTADDR / IP_RECVORIGDSTADDR)
         */
        [[nodiscard]] static std::optional<sockaddr_in> extractOrigDst(const msghdr &msg) noexcept
        {
            for (auto *cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr;
                 cmsg = CMSG_NXTHDR(const_cast<msghdr *>(&msg), cmsg))
            {
                if (cmsg->cmsg_level == SOL_IP &&
                    (cmsg->cmsg_type == IP_ORIGDSTADDR || cmsg->cmsg_type == IP_RECVORIGDSTADDR))
                {
                    const auto *sin = reinterpret_cast<const sockaddr_in *>(CMSG_DATA(cmsg));
                    return *sin;
                }
            }
            return std::nullopt;
        }
    };

} // namespace mynet::handler

namespace mynet
{

    /**
     * @brief Linux TProxy 透明代理接收器 (AcceptorTransparent / InboundTransparent)
     */
    class AcceptorTransparent : public Acceptor
    {
    public:
        AcceptorTransparent(std::string tag, std::string host, uint16_t port, bool enableSniffing = true)
            : Acceptor(std::move(tag), "tproxy", std::move(host), port, enableSniffing)
        {
        }

        Result<> listen(int backlog = 128, bool reuseAddr = true, bool reusePort = true) noexcept override
        {
            if (auto r = Acceptor::listen(backlog, reuseAddr, reusePort); !r)
            {
                return r;
            }

            int transparentOpt = 1;
            if (::setsockopt(socket_.fd(), SOL_IP, IP_TRANSPARENT, &transparentOpt, sizeof(transparentOpt)) < 0)
            {
                LOG_WARN("AcceptorTransparent: setsockopt IP_TRANSPARENT on fd {} failed: {}", socket_.fd(),
                         errnoText(errno));
            }
            return {};
        }

        [[nodiscard]] std::unique_ptr<Handler> createHandler() override
        {
            auto h = std::make_unique<handler::HandlerInboundTProxy>();
            h->setSniffing(enableSniffing_);
            return h;
        }
    };

} // namespace mynet
