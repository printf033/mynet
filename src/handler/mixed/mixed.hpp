#pragma once

/**
 * @file proxy/mixed/mixed.hpp
 * @brief Mixed 混合代理协议服务端状态机处理器（同时支持 SOCKS4/SOCKS5 与 HTTP Proxy）。
 */

#include "../http/http.hpp"
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
     * @brief 混合协议服务端处理器 (Mixed Inbound)
     *
     * 对标 sing-box mixed 入站：在同一监听端口上自动根据客户端首字节分流：
     * - 0x04 -> SOCKS4 / SOCKS4a
     * - 0x05 -> SOCKS5
     * - 'C', 'G', 'P', 'H', 'D', 'O', 'T' 等 ASCII 字符 -> HTTP CONNECT / 明文代理
     */
    class HandlerMixed : public HandlerConnection
    {
    public:
        using AuthCallback = std::function<bool(std::string_view user, std::string_view pass)>;
        using RequestCallback = std::function<void(uint8_t cmd, const ProxyAddress &target)>;

        static constexpr bool kEnableSplice = true;

        inline void enableSpliceForward(int targetFd) noexcept { setSpliceTarget(targetFd); }
        inline void enableSpliceForward(SPLICE_CONTROL ctrl) noexcept { setSpliceTarget(ctrl); }
        inline void disableSpliceForward() noexcept { disableSplice(); }
        [[nodiscard]] inline bool isSpliceForwardActive() const noexcept { return isSpliceActive(); }

    private:
        MixedProtocolType protocol_{MixedProtocolType::UNKNOWN};
        HandlerSocks4 s4_{};
        HandlerSocks5 s5_{};
        HandlerHttpProxy http_{};
        AuthCallback authCallback_{nullptr};
        RequestCallback requestCallback_{nullptr};

    public:
        HandlerMixed() noexcept = default;
        explicit HandlerMixed(const ProxyConfig &cfg) noexcept
            : s4_(cfg),
              s5_(cfg)
        {
        }
        ~HandlerMixed() noexcept override = default;

        HandlerMixed(const HandlerMixed &) = delete;
        HandlerMixed &operator=(const HandlerMixed &) = delete;
        HandlerMixed(HandlerMixed &&) = delete;
        HandlerMixed &operator=(HandlerMixed &&) = delete;

        void setAuthenticator(AuthCallback cb) noexcept
        {
            authCallback_ = cb;
            s5_.setAuthenticator(cb);
            s4_.setAuthenticator([cb](std::string_view uid) { return cb(uid, ""); });
            http_.setAuthenticator(cb);
        }

        void setOnRequest(RequestCallback cb) noexcept
        {
            requestCallback_ = cb;
            s4_.setOnRequest(cb);
            s5_.setOnRequest(cb);
            http_.setOnRequest(cb);
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

        [[nodiscard]] std::optional<ProxyAddress> targetAddress() const noexcept
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
                return std::nullopt;
            }
        }

        void configure(const ProxyConfig &cfg) noexcept
        {
            s4_.configure(cfg);
            s5_.configure(cfg);
        }

        void reset() noexcept override
        {
            HandlerConnection::reset();
            protocol_ = MixedProtocolType::UNKNOWN;
            s4_.reset();
            s5_.reset();
            http_.reset();
            disableSpliceForward();
        }

        void onMessageComplete() noexcept {}
        void onParseError(const char *reason) noexcept { (void)reason; }

        void process()
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
                break;
            case MixedProtocolType::SOCKS5:
                syncToChild(s5_);
                s5_.process();
                syncFromChild(s5_);
                break;
            case MixedProtocolType::HTTP:
                syncToChild(http_);
                http_.process();
                syncFromChild(http_);
                break;
            default:
                break;
            }
        }

    private:
        static bool isHttpChar(uint8_t b) noexcept
        {
            // ASCII 大写字符 (CONNECT, GET, POST, HEAD, PUT, DELETE, OPTIONS, TRACE)
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
