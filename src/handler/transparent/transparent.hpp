#pragma once

/**
 * @file handler/transparent/transparent.hpp
 * @brief Linux Netfilter 透明代理入站状态机处理器与 UDP TProxy 报文流水线
 *
 * 借鉴 dae 与 sing-box 设计：
 * 1. HandlerInboundRedirect: iptables -j REDIRECT (SO_ORIGINAL_DST 提取 + L7 零拷贝域名嗅探 + DNS 反向还原)
 * 2. HandlerInboundTProxy: iptables -j TPROXY (getsockname 原始目的提取 + 域名嗅探)
 * 3. HandlerInboundDatagramTProxy: UDP TProxy 数据报透明代理 (IP_RECVORIGDSTADDR + QUIC/DNS 嗅探)
 */

#include "../address.hpp"
#include "../inbound.hpp"
#include "../sniffing.hpp"
#include "../dns/cache.hpp"
#include "../../datagram.hpp"
#include <cstdint>
#include <functional>
#include <netinet/in.h>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <sys/socket.h>

#ifndef IP_ORIGDSTADDR
#define IP_ORIGDSTADDR 20
#endif
#ifndef IP_RECVORIGDSTADDR
#define IP_RECVORIGDSTADDR 20
#endif

namespace mynet::handler
{

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
    class HandlerInboundRedirect : public HandlerInboundConnection
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

        void reset() noexcept override
        {
            HandlerInboundConnection::reset();
            transparentStage_ = TransparentStage::RESOLVING;
            clientFd_ = -1;
        }

        void onMessageComplete() noexcept override {}

        void onParseError(const char *reason) noexcept override
        {
            (void)reason;
            transparentStage_ = TransparentStage::ERROR;
            stage_ = InboundStage::ERROR;
        }

        void process() override
        {
            if (transparentStage_ == TransparentStage::RESOLVING)
            {
                resolveOriginalDst();
                if (transparentStage_ != TransparentStage::SNIFFING &&
                    transparentStage_ != TransparentStage::STREAMING)
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
        virtual std::optional<ProxyAddress> fetchOriginalDst()
        {
            if (clientFd_ >= 0)
            {
                return ProxyAddress::fromOriginalDst(clientFd_);
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
                stage_ = InboundStage::ERROR;
                setCloseAfterResponse(true);
                return;
            }

            if (!sniffingEnabled_)
            {
                // 若禁用嗅探，尝试反查 DNS 逆向缓存后直接就绪
                tryFallbackReverseDns();
                transparentStage_ = TransparentStage::STREAMING;
                stage_ = InboundStage::STREAMING;
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
            stage_ = InboundStage::HANDSHAKE;
        }

        void sniffPayload()
        {
            const size_t avail = requestBytes();
            if (avail == 0)
            {
                stage_ = InboundStage::HANDSHAKE;
                return;
            }

            std::span<const uint8_t> data(reinterpret_cast<const uint8_t *>(requestBegin()), avail);
            auto sniffResult = sniffing::DomainSniffer::sniff(data);

            if (sniffResult.has_value())
            {
                if (!sniffResult->host.empty())
                {
                    const uint16_t port = sniffResult->port != 0 ? sniffResult->port : targetAddress_->port;
                    targetAddress_ = ProxyAddress::fromDomain(sniffResult->host, port);
                }
                transitionToStreaming();
                return;
            }

            // 检查首字节是否可能属于已知可嗅探协议 (TCP 仅嗅探 TLS / HTTP / BitTorrent / SSH)
            const uint8_t b0 = data[0];
            const bool couldBeTls = (b0 == 0x16);
            const bool couldBeHttp = (b0 == 'G' || b0 == 'P' || b0 == 'H' || b0 == 'D' ||
                                      b0 == 'C' || b0 == 'O' || b0 == 'T');
            const bool couldBeBt = (b0 == 19);
            const bool couldBeSsh = (b0 == 'S');
            const bool couldBeSniffable = couldBeTls || couldBeHttp || couldBeBt || couldBeSsh;

            // 报文长度已超过嗅探窗口，或已知不可能属于嗅探协议，执行 DNS 反向还原兜底
            if (avail >= maxSniffBytes_ || !couldBeSniffable || avail >= 512)
            {
                tryFallbackReverseDns();
                transitionToStreaming();
            }
            else
            {
                stage_ = InboundStage::HANDSHAKE;
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
            stage_ = InboundStage::STREAMING;
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
        std::optional<ProxyAddress> fetchOriginalDst() override
        {
            if (clientFd_ >= 0)
            {
                return ProxyAddress::fromTProxyDst(clientFd_);
            }
            return std::nullopt;
        }
    };

    /**
     * @brief UDP TProxy 数据报透明代理入站处理器
     *
     * 负责解析带有 IP_RECVORIGDSTADDR / IPV6_RECVORIGDSTADDR 原始目的地址控制消息的 UDP 报文，
     * 联动 QUIC Initial 与 DNS 嗅探器还原目标域名。
     */
    class HandlerInboundDatagramTProxy : public HandlerInboundDatagram
    {
    public:
        using TProxyPacketCallback =
            std::function<void(const sockaddr_in &clientPeer, const ProxyAddress &target, const char *data, size_t n)>;

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

        void reset() noexcept override
        {
            HandlerInboundDatagram::reset();
        }

        /**
         * @brief 处理带有原始目的地址的入站 UDP 报文
         *
         * @param peer 客户端真实源地址
         * @param origDst 报文原本要发往的目标地址
         * @param data 报文载荷
         * @param n 报文有效长度
         */
        void onDatagramWithDst(const sockaddr_in &peer, const sockaddr_in &origDst,
                               const char *data, size_t n) noexcept
        {
            if (data == nullptr || n == 0)
            {
                return;
            }

            ProxyAddress target = ProxyAddress::fromIPv4(origDst.sin_addr.s_addr, ntohs(origDst.sin_port));

            // 尝试应用层深度嗅探（QUIC Initial SNI / DNS）
            if (sniffingEnabled_)
            {
                std::span<const uint8_t> payload(reinterpret_cast<const uint8_t *>(data), n);
                if (auto res = sniffing::DomainSniffer::sniff(payload); res.has_value())
                {
                    if (!res->host.empty())
                    {
                        const uint16_t p = res->port != 0 ? res->port : target.port;
                        target = ProxyAddress::fromDomain(res->host, p);
                    }
                }
                else
                {
                    // 嗅探未命中，查询 DNS 逆向缓存
                    if (auto rev = dns::DnsReverseCache::instance().lookup(target); rev.has_value())
                    {
                        target = *rev;
                    }
                }
            }
            else
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
         * @brief 从 msghdr 辅助控制信息中提取原始目的 IPv4 地址 (Linux IP_ORIGDSTADDR)
         */
        [[nodiscard]] static std::optional<sockaddr_in> extractOrigDst(const msghdr &msg) noexcept
        {
            for (auto *cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr; cmsg = CMSG_NXTHDR(const_cast<msghdr *>(&msg), cmsg))
            {
                if (cmsg->cmsg_level == SOL_IP && (cmsg->cmsg_type == IP_ORIGDSTADDR || cmsg->cmsg_type == IP_RECVORIGDSTADDR))
                {
                    const auto *sin = reinterpret_cast<const sockaddr_in *>(CMSG_DATA(cmsg));
                    return *sin;
                }
            }
            return std::nullopt;
        }
    };

} // namespace mynet::handler
