#pragma once

/**
 * @file handler/proxy/mixed.hpp
 * @brief Mixed 混合代理协议入站状态机处理器 (HandlerInboundMixed)（同时支持 SOCKS4/SOCKS5 与 HTTP Proxy）。
 */

#include "../http/http.hpp"
#include "../inbound.hpp"
#include "../socks/socks4.hpp"
#include "../socks/socks5.hpp"

namespace mynet::handler
{

    enum class MixedProtocolType : uint8_t
    {
        UNKNOWN,
        SOCKS4,
        SOCKS5,
        HTTP
    };

    /**
     * @brief 混合协议入站服务端处理器 (Mixed Inbound)
     *
     * 对标 sing-box mixed 入站：在同一监听端口上自动根据客户端首字节分流：
     * - 0x04 -> SOCKS4 / SOCKS4a
     * - 0x05 -> SOCKS5
     * - 'C', 'G', 'P', 'H', 'D', 'O', 'T' 等 ASCII 字符 -> HTTP CONNECT / 明文代理
     */
    class HandlerInboundMixed : public HandlerInboundConnection
    {
    public:
        using AuthCallback = std::function<bool(std::string_view user, std::string_view pass)>;

    private:
        MixedProtocolType protocol_{MixedProtocolType::UNKNOWN};
        HandlerInboundSocks4 s4_{};
        HandlerInboundSocks5 s5_{};
        HandlerInboundHttpProxy http_{};
        AuthCallback authCallback_{nullptr};

    public:
        HandlerInboundMixed() noexcept = default;
        explicit HandlerInboundMixed(const ProxyConfig &cfg) noexcept
            : s4_(cfg),
              s5_(cfg)
        {
        }
        ~HandlerInboundMixed() noexcept override = default;

        HandlerInboundMixed(const HandlerInboundMixed &) = delete;
        HandlerInboundMixed &operator=(const HandlerInboundMixed &) = delete;
        HandlerInboundMixed(HandlerInboundMixed &&) = delete;
        HandlerInboundMixed &operator=(HandlerInboundMixed &&) = delete;

        void setAuthenticator(AuthCallback cb) noexcept
        {
            authCallback_ = cb;
            s5_.setAuthenticator(cb);
            s4_.setAuthenticator([cb](std::string_view uid) { return cb(uid, ""); });
            http_.setAuthenticator(cb);
        }

        [[nodiscard]] MixedProtocolType protocol() const noexcept { return protocol_; }

        [[nodiscard]] bool isEstablished() const noexcept
        {
            switch (protocol_)
            {
            case MixedProtocolType::SOCKS4:
                return s4_.isEstablished();
            case MixedProtocolType::SOCKS5:
                return s5_.isEstablished();
            case MixedProtocolType::HTTP:
                return http_.isEstablished();
            default:
                return false;
            }
        }

        [[nodiscard]] const std::optional<ProxyAddress> &targetAddress() const noexcept
        {
            switch (protocol_)
            {
            case MixedProtocolType::SOCKS4:
                return s4_.targetAddress();
            case MixedProtocolType::SOCKS5:
                return s5_.targetAddress();
            case MixedProtocolType::HTTP:
                return http_.targetAddress();
            default:
                return targetAddress_;
            }
        }

        void configure(const ProxyConfig &cfg) noexcept
        {
            s4_.configure(cfg);
            s5_.configure(cfg);
        }

        void reset() noexcept override
        {
            HandlerInboundConnection::reset();
            protocol_ = MixedProtocolType::UNKNOWN;
            s4_.reset();
            s5_.reset();
            http_.reset();
        }

        void onMessageComplete() noexcept {}
        void onParseError(const char *reason) noexcept { (void)reason; }

        void process() override
        {
            if (protocol_ == MixedProtocolType::UNKNOWN)
            {
                if (requestBytes() == 0)
                {
                    return;
                }
                const uint8_t b = static_cast<uint8_t>(*requestBegin());
                if (b == socks4::kVersion)
                {
                    protocol_ = MixedProtocolType::SOCKS4;
                }
                else if (b == socks5::kVersion)
                {
                    protocol_ = MixedProtocolType::SOCKS5;
                }
                else if (isHttpChar(b))
                {
                    protocol_ = MixedProtocolType::HTTP;
                }
                else
                {
                    onParseError("Mixed: Unrecognized protocol byte");
                    setCloseAfterResponse(true);
                    return;
                }
            }

            switch (protocol_)
            {
            case MixedProtocolType::SOCKS4:
                syncToChild(s4_);
                s4_.process();
                syncFromChild(s4_);
                if (s4_.isEstablished())
                {
                    stage_ = InboundStage::STREAMING;
                    targetAddress_ = s4_.targetAddress();
                    command_ = s4_.command();
                }
                break;
            case MixedProtocolType::SOCKS5:
                syncToChild(s5_);
                s5_.process();
                syncFromChild(s5_);
                if (s5_.isEstablished())
                {
                    stage_ = InboundStage::STREAMING;
                    targetAddress_ = s5_.targetAddress();
                    command_ = s5_.command();
                }
                break;
            case MixedProtocolType::HTTP:
                syncToChild(http_);
                http_.process();
                syncFromChild(http_);
                if (http_.isEstablished())
                {
                    stage_ = InboundStage::STREAMING;
                    targetAddress_ = http_.targetAddress();
                    command_ = http_.command();
                }
                break;
            default:
                break;
            }
        }

    private:
        static bool isHttpChar(uint8_t b) noexcept
        {
            return (b == 'C' || b == 'G' || b == 'P' || b == 'H' || b == 'D' || b == 'O' || b == 'T' ||
                    (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z'));
        }

        void syncToChild(HandlerConnection &child)
        {
            const size_t avail = requestBytes();
            if (avail > child.requestBytes())
            {
                const size_t diff = avail - child.requestBytes();
                const char *p = requestBegin() + child.requestBytes();
                [[maybe_unused]] auto _ = child.appendRequest(p, static_cast<ssize_t>(diff));
            }
        }

        void syncFromChild(HandlerConnection &child)
        {
            const size_t childAvail = child.requestBytes();
            if (requestBytes() > childAvail)
            {
                requestConsume(requestBytes() - childAvail);
            }

            while (child.hasResponse())
            {
                std::string resp = child.takeResponse();
                [[maybe_unused]] auto _ = pushResponse(resp);
            }

            if (child.closeAfterResponse())
            {
                setCloseAfterResponse(true);
            }

            if (child.isSpliceActive())
            {
                setSpliceTarget(child.spliceTarget());
            }
        }
    };

} // namespace mynet::handler
