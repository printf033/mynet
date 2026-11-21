#pragma once

/**
 * @file handler/proxy/block.hpp
 * @brief 广义代理协议：拦截阻断黑洞协议 (Block / Blackhole Proxy Protocol)。
 *
 * 在广义代理协议体系中，block 是一种特殊的终止型伪协议：
 * 立即断开或丢弃数据，实现针对恶意流量、广告过滤与安全策略的高性能黑洞处置。
 */

#include "../connection.hpp"

namespace mynet::handler
{

    /**
     * @brief 广义代理协议：拦截阻断入站处理器 (Block Inbound Proxy Handler)
     */
    class HandlerInboundBlock : public HandlerInboundConnectionBase
    {
    public:
        static constexpr bool kEnableSplice = false;

        HandlerInboundBlock() noexcept
        {
            setCloseAfterResponse(true);
            stage_ = InboundStage::ERROR;
        }

        ~HandlerInboundBlock() noexcept override = default;

        HandlerInboundBlock(const HandlerInboundBlock &) = delete;
        HandlerInboundBlock &operator=(const HandlerInboundBlock &) = delete;
        HandlerInboundBlock(HandlerInboundBlock &&) = delete;
        HandlerInboundBlock &operator=(HandlerInboundBlock &&) = delete;

        void reset() noexcept override
        {
            HandlerInboundConnectionBase::reset();
            setCloseAfterResponse(true);
            stage_ = InboundStage::ERROR;
        }

        void handle() override
        {
            if (requestBytes() > 0)
            {
                requestConsume(requestBytes());
            }
            setCloseAfterResponse(true);
        }
    };

    /**
     * @brief 广义代理协议：拦截阻断出站处理器 (Block Outbound Proxy Handler)
     */
    class HandlerOutboundBlock : public HandlerOutboundConnectionBase
    {
    public:
        static constexpr bool kEnableSplice = false;

        HandlerOutboundBlock() noexcept
        {
            setCloseAfterResponse(true);
            stage_ = OutboundStage::ERROR;
        }

        void reset() noexcept override
        {
            HandlerOutboundConnectionBase::reset();
            setCloseAfterResponse(true);
            stage_ = OutboundStage::ERROR;
        }

        void handle() override
        {
            if (requestBytes() > 0)
            {
                requestConsume(requestBytes());
            }
            setCloseAfterResponse(true);
        }
    };

} // namespace mynet::handler
