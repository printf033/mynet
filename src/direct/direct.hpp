#pragma once

/**
 * @file handler/proxy/direct.hpp
 * @brief 广义代理协议：直连直通代理协议 (Direct Pass-through Proxy Protocol)。
 *
 * 在广义代理协议体系中，direct 是一种透明穿透型协议：
 * 无需任何封装包装，直接与目标服务器建立原始 TCP/UDP 会话，并通过 Linux splice 零拷贝高速桥接。
 */

#include "../inboundHandler.hpp"
#include "../outboundHandler.hpp"
#include <functional>
#include <utility>

namespace mynet::handler
{

    /**
     * @brief 广义代理协议：直连入站直通处理器 (Direct Inbound Proxy Handler)
     */
    class HandlerInboundDirect : public HandlerInboundConnectionBase
    {
    public:
        using DirectRequestCallback = std::function<void(const ProxyAddress &target)>;

    private:
        DirectRequestCallback directCallback_{nullptr};
        bool triggered_{false};

    public:
        HandlerInboundDirect() noexcept { stage_ = InboundStage::STREAMING; }

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
        using HandlerInboundConnectionBase::setOnRequest;

        void reset() noexcept override
        {
            HandlerInboundConnectionBase::reset();
            stage_ = InboundStage::STREAMING;
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
    class HandlerOutboundDirect : public HandlerOutboundConnectionBase
    {
    public:
        HandlerOutboundDirect() noexcept { stage_ = OutboundStage::STREAMING; }

        explicit HandlerOutboundDirect(const ProxyAddress &target) noexcept
            : HandlerOutboundConnectionBase(target)
        {
            stage_ = OutboundStage::STREAMING;
        }

        void reset() noexcept override
        {
            HandlerOutboundConnectionBase::reset();
            stage_ = OutboundStage::STREAMING;
        }

        void handle() override {}
    };

} // namespace mynet::handler
