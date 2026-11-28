#pragma once

/**
 * @file handler/proxy/direct.hpp
 * @brief 广义代理协议：直连直通代理协议 (Direct Pass-through Proxy Protocol)。
 *
 * 在广义代理协议体系中，direct 是一种透明穿透型协议：
 * 无需任何封装包装，直接与目标服务器建立原始 TCP/UDP 会话，并通过 Linux splice 零拷贝高速桥接。
 */

#include "../connection.hpp"
#include <functional>
#include <utility>

namespace mynet::handler
{

    /**
     * @brief 广义代理协议：直连入站直通处理器 (Direct Inbound Proxy Handler)
     */
    class HandlerInboundDirect : public HandlerInbound
    {
    public:
        using DirectRequestCallback = std::function<void(const Address &target)>;

    private:
        DirectRequestCallback directCallback_{nullptr};
        bool triggered_{false};

    public:
        HandlerInboundDirect() noexcept { setStage(InboundStage::STREAMING); }

        explicit HandlerInboundDirect(const Address &target) noexcept
        {
            targetAddress_ = target;
            setStage(InboundStage::STREAMING);
        }

        ~HandlerInboundDirect() noexcept override = default;

        HandlerInboundDirect(const HandlerInboundDirect &) = delete;
        HandlerInboundDirect &operator=(const HandlerInboundDirect &) = delete;
        HandlerInboundDirect(HandlerInboundDirect &&) = delete;
        HandlerInboundDirect &operator=(HandlerInboundDirect &&) = delete;

        void setTarget(const Address &target) { targetAddress_ = target; }
        void setOnDirectRequest(DirectRequestCallback cb) noexcept { directCallback_ = std::move(cb); }
        void setOnRequest(DirectRequestCallback cb) noexcept { directCallback_ = std::move(cb); }
        using HandlerInbound::setOnRequest;

        void reset() noexcept override
        {
            HandlerInbound::reset();
            setStage(InboundStage::STREAMING);
            triggered_ = false;
        }

        void handle() override
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
     * @brief 广义代理协议：直连出站处理器 (Direct Outbound Proxy Handler)
     *
     * 初始即处于 STREAMING 状态，建连后可直接通过 Linux splice 桥接入站。
     */
    class HandlerOutboundDirect : public HandlerOutbound
    {
    public:
        HandlerOutboundDirect() noexcept { setStage(OutboundStage::STREAMING); }

        explicit HandlerOutboundDirect(const Address &target) noexcept
            : HandlerOutbound(target)
        {
            setStage(OutboundStage::STREAMING);
        }

        void reset() noexcept override
        {
            HandlerOutbound::reset();
            setStage(OutboundStage::STREAMING);
        }

        void handle() override {}
    };

} // namespace mynet::handler
