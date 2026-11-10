#pragma once

/**
 * @file handler/socks/socks.hpp
 * @brief 统一 SOCKS 代理协议入站状态机处理器 (HandlerInboundSocks)（同时支持 SOCKS4/SOCKS4a 与 SOCKS5 自适应嗅探）。
 */

#include "socks4.hpp"
#include "socks5.hpp"

namespace mynet::handler
{

    enum class SocksProtocolVersion : uint8_t
    {
        UNKNOWN,
        SOCKS4,
        SOCKS5
    };

    /**
     * @brief 统一 SOCKS 入站服务端处理器
     *
     * 自动嗅探客户端发起的首字节协议版本号：
     * - 0x04: 路由至 SOCKS4 / SOCKS4a 处理逻辑
     * - 0x05: 路由至 SOCKS5 (RFC 1928 / RFC 1929) 处理逻辑
     */
    class HandlerInboundSocks : public HandlerInboundConnection
    {
    public:
        using AuthCallback = std::function<bool(std::string_view user, std::string_view pass)>;

    private:
        SocksProtocolVersion version_{SocksProtocolVersion::UNKNOWN};
        HandlerInboundSocks4 s4_{};
        HandlerInboundSocks5 s5_{};
        AuthCallback authCallback_{nullptr};

    public:
        HandlerInboundSocks() noexcept = default;
        explicit HandlerInboundSocks(const ProxyConfig &cfg) noexcept
            : s4_(cfg),
              s5_(cfg)
        {
        }
        ~HandlerInboundSocks() noexcept override = default;

        HandlerInboundSocks(const HandlerInboundSocks &) = delete;
        HandlerInboundSocks &operator=(const HandlerInboundSocks &) = delete;
        HandlerInboundSocks(HandlerInboundSocks &&) = delete;
        HandlerInboundSocks &operator=(HandlerInboundSocks &&) = delete;

        void setAuthenticator(AuthCallback cb) noexcept
        {
            authCallback_ = cb;
            s5_.setAuthenticator(cb);
            s4_.setAuthenticator([cb](std::string_view uid) { return cb(uid, ""); });
        }

        [[nodiscard]] SocksProtocolVersion version() const noexcept { return version_; }
        [[nodiscard]] bool isEstablished() const noexcept
        {
            return (version_ == SocksProtocolVersion::SOCKS4 && s4_.isEstablished()) ||
                   (version_ == SocksProtocolVersion::SOCKS5 && s5_.isEstablished());
        }

        [[nodiscard]] const std::optional<ProxyAddress> &targetAddress() const noexcept
        {
            if (version_ == SocksProtocolVersion::SOCKS4)
            {
                return s4_.targetAddress();
            }
            if (version_ == SocksProtocolVersion::SOCKS5)
            {
                return s5_.targetAddress();
            }
            return targetAddress_;
        }

        void configure(const ProxyConfig &cfg) noexcept
        {
            s4_.configure(cfg);
            s5_.configure(cfg);
        }

        void reset() noexcept override
        {
            HandlerInboundConnection::reset();
            version_ = SocksProtocolVersion::UNKNOWN;
            s4_.reset();
            s5_.reset();
        }

        void onMessageComplete() noexcept {}
        void onParseError(const char *reason) noexcept { (void)reason; }

        void process() override
        {
            if (version_ == SocksProtocolVersion::UNKNOWN)
            {
                if (requestBytes() == 0)
                {
                    return;
                }
                const uint8_t firstByte = static_cast<uint8_t>(*requestBegin());
                if (firstByte == socks4::kVersion)
                {
                    version_ = SocksProtocolVersion::SOCKS4;
                }
                else if (firstByte == socks5::kVersion)
                {
                    version_ = SocksProtocolVersion::SOCKS5;
                }
                else
                {
                    onParseError("SOCKS: Unknown protocol version");
                    setCloseAfterResponse(true);
                    return;
                }
            }

            if (version_ == SocksProtocolVersion::SOCKS4)
            {
                syncToChild(s4_);
                s4_.process();
                syncFromChild(s4_);
                if (s4_.isEstablished())
                {
                    stage_ = InboundStage::STREAMING;
                    targetAddress_ = s4_.targetAddress();
                    command_ = s4_.command();
                }
            }
            else if (version_ == SocksProtocolVersion::SOCKS5)
            {
                syncToChild(s5_);
                s5_.process();
                syncFromChild(s5_);
                if (s5_.isEstablished())
                {
                    stage_ = InboundStage::STREAMING;
                    targetAddress_ = s5_.targetAddress();
                    command_ = s5_.command();
                }
            }
        }

    private:
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
