#pragma once

/**
 * @file proxy/block.hpp
 * @brief 拦截阻断代理处理器 (Block Outbound / Blackhole)。
 */

#include "../connection.hpp"

namespace mynet::handler
{

    /**
     * @brief 拦截阻断处理器
     */
    class HandlerBlock : public HandlerConnection
    {
    public:
        static constexpr bool kEnableSplice = false;

        HandlerBlock() noexcept { setCloseAfterResponse(true); }
        ~HandlerBlock() noexcept override = default;

        HandlerBlock(const HandlerBlock &) = delete;
        HandlerBlock &operator=(const HandlerBlock &) = delete;
        HandlerBlock(HandlerBlock &&) = delete;
        HandlerBlock &operator=(HandlerBlock &&) = delete;

        [[nodiscard]] bool isEstablished() const noexcept { return false; }

        void reset() noexcept override
        {
            HandlerConnection::reset();
            setCloseAfterResponse(true);
        }

        void onMessageComplete() noexcept {}
        void onParseError(const char *reason) noexcept { (void)reason; }

        void process()
        {
            // 收到任何数据立即阻断并关闭
            if (requestBytes() > 0)
            {
                requestConsume(requestBytes());
            }
            setCloseAfterResponse(true);
        }
    };

} // namespace mynet::handler
