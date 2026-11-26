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
    class HandlerInboundSocks : public MuxInboundHandler<HandlerInboundSocks4, HandlerInboundSocks5>
    {
    public:
        using AuthCallback = std::function<bool(std::string_view user, std::string_view pass)>;

    private:
        SocksProtocolVersion version_{SocksProtocolVersion::UNKNOWN};
        ProxyConfig proxyCfg_{};
        bool hasCustomProxyCfg_{false};
        AuthCallback authCallback_{nullptr};
        HandlerInboundSocks4 *s4Ptr_{nullptr};
        HandlerInboundSocks5 *s5Ptr_{nullptr};

    public:
        HandlerInboundSocks() noexcept = default;
        explicit HandlerInboundSocks(const ProxyConfig &cfg) noexcept
            : proxyCfg_(cfg),
              hasCustomProxyCfg_(true)
        {
        }
        ~HandlerInboundSocks() noexcept override = default;

        HandlerInboundSocks(const HandlerInboundSocks &) = delete;
        HandlerInboundSocks &operator=(const HandlerInboundSocks &) = delete;
        HandlerInboundSocks(HandlerInboundSocks &&) = delete;
        HandlerInboundSocks &operator=(HandlerInboundSocks &&) = delete;

        void setAuthenticator(AuthCallback cb) noexcept
        {
            authCallback_ = std::move(cb);
            if (s5Ptr_ != nullptr)
            {
                s5Ptr_->setAuthenticator(authCallback_);
            }
            if (s4Ptr_ != nullptr && authCallback_)
            {
                auto fn = authCallback_;
                s4Ptr_->setAuthenticator([fn](std::string_view uid) { return fn(uid, ""); });
            }
        }

        [[nodiscard]] SocksProtocolVersion version() const noexcept { return version_; }

        [[nodiscard]] const std::optional<ProxyAddress> &targetAddress() const noexcept
        {
            if (s4Ptr_ != nullptr)
            {
                return s4Ptr_->targetAddress();
            }
            if (s5Ptr_ != nullptr)
            {
                return s5Ptr_->targetAddress();
            }
            return targetAddress_;
        }

        void configure(const ProxyConfig &cfg) noexcept
        {
            proxyCfg_ = cfg;
            hasCustomProxyCfg_ = true;
            if (s4Ptr_ != nullptr)
                s4Ptr_->configure(cfg);
            if (s5Ptr_ != nullptr)
                s5Ptr_->configure(cfg);
        }

        void reset() noexcept override
        {
            MuxInboundHandler::reset();
            version_ = SocksProtocolVersion::UNKNOWN;
            s4Ptr_ = nullptr;
            s5Ptr_ = nullptr;
        }

        void handle() override
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
                    s4Ptr_ = hasCustomProxyCfg_ ? &emplaceChild<HandlerInboundSocks4>(proxyCfg_)
                                                : &emplaceChild<HandlerInboundSocks4>();
                    if (authCallback_)
                    {
                        auto fn = authCallback_;
                        s4Ptr_->setAuthenticator([fn](std::string_view uid) { return fn(uid, ""); });
                    }
                }
                else if (firstByte == socks5::kVersion)
                {
                    version_ = SocksProtocolVersion::SOCKS5;
                    s5Ptr_ = hasCustomProxyCfg_ ? &emplaceChild<HandlerInboundSocks5>(proxyCfg_)
                                                : &emplaceChild<HandlerInboundSocks5>();
                    if (authCallback_)
                    {
                        s5Ptr_->setAuthenticator(authCallback_);
                    }
                }
                else
                {
                    onParseError("SOCKS: Unknown protocol version");
                    setCloseAfterResponse(true);
                    return;
                }
            }

            if (Handler *child = activeChild(); child != nullptr)
            {
                driveChild(*child);
            }
        }
    };

} // namespace mynet::handler
