#pragma once

/**
 * @file handler/direct.hpp
 * @brief 直连直通代理处理器（入站直通 HandlerInboundDirect 与出站直通 HandlerOutboundDirect）。
 */

#include "inbound.hpp"
#include "outbound.hpp"

namespace mynet::handler
{

    /**
     * @brief 直连入站直通处理器 (Direct Inbound Pass-through)
     */
    class HandlerInboundDirect : public HandlerInboundConnection
    {
    public:
        using DirectRequestCallback = std::function<void(const ProxyAddress &target)>;

    private:
        DirectRequestCallback directCallback_{nullptr};
        bool triggered_{false};

    public:
        HandlerInboundDirect() noexcept
        {
            stage_ = InboundStage::STREAMING;
        }

        explicit HandlerInboundDirect(const ProxyAddress &target) noexcept
        {
            targetAddress_ = target;
            stage_ = InboundStage::STREAMING;
        }

        ~HandlerInboundDirect() noexcept override = default;

        HandlerInboundDirect(const HandlerInboundDirect &) = delete;
        HandlerInboundDirect &operator=(const HandlerInboundDirect &) = delete;
        HandlerInboundDirect(HandlerInboundDirect &&) = delete;
        HandlerInboundDirect &operator=(HandlerInboundDirect &&) = delete;

        void setTarget(const ProxyAddress &target) { targetAddress_ = target; }
        void setOnDirectRequest(DirectRequestCallback cb) noexcept { directCallback_ = std::move(cb); }
        void setOnRequest(DirectRequestCallback cb) noexcept { directCallback_ = std::move(cb); }
        using HandlerInboundConnection::setOnRequest;

        void reset() noexcept override
        {
            HandlerInboundConnection::reset();
            stage_ = InboundStage::STREAMING;
            triggered_ = false;
        }

        void process() override
        {
            if (!triggered_)
            {
                triggered_ = true;
                onMessageComplete();
                if (directCallback_ && targetAddress_.has_value())
                {
                    directCallback_(*targetAddress_);
                }
                else if (requestCallback_ && targetAddress_.has_value())
                {
                    requestCallback_(command_, *targetAddress_);
                }
            }
        }
    };

    /**
     * @brief 直连出站处理器 (Direct Outbound)
     *
     * 初始即处于 STREAMING 状态，建连后可直接通过 splice 桥接入站。
     */
    class HandlerOutboundDirect : public HandlerOutboundConnection
    {
    public:
        HandlerOutboundDirect() noexcept
        {
            stage_ = OutboundStage::STREAMING;
        }

        explicit HandlerOutboundDirect(const ProxyAddress &target) noexcept
            : HandlerOutboundConnection(target)
        {
            stage_ = OutboundStage::STREAMING;
        }

        void reset() noexcept override
        {
            HandlerOutboundConnection::reset();
            stage_ = OutboundStage::STREAMING;
        }

        void process() override {}
    };

} // namespace mynet::handler
