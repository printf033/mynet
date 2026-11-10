#pragma once

/**
 * @file handler/block.hpp
 * @brief 拦截阻断代理处理器（入站黑洞 HandlerInboundBlock 与出站黑洞 HandlerOutboundBlock）。
 */

#include "inbound.hpp"
#include "outbound.hpp"

namespace mynet::handler
{

    /**
     * @brief 拦截阻断入站处理器 (Block Inbound / Blackhole)
     */
    class HandlerInboundBlock : public HandlerInboundConnection
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
            HandlerInboundConnection::reset();
            setCloseAfterResponse(true);
            stage_ = InboundStage::ERROR;
        }

        void process() override
        {
            if (requestBytes() > 0)
            {
                requestConsume(requestBytes());
            }
            setCloseAfterResponse(true);
        }
    };

    /**
     * @brief 拦截阻断出站处理器 (Block Outbound / Blackhole)
     */
    class HandlerOutboundBlock : public HandlerOutboundConnection
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
            HandlerOutboundConnection::reset();
            setCloseAfterResponse(true);
            stage_ = OutboundStage::ERROR;
        }

        void process() override
        {
            if (requestBytes() > 0)
            {
                requestConsume(requestBytes());
            }
            setCloseAfterResponse(true);
        }
    };

} // namespace mynet::handler
