#pragma once

/**
 * @file proxy/direct.hpp
 * @brief 直连直通代理处理器 (Direct Outbound / Inbound Pass-through)。
 */

#include "../connection.hpp"
#include "address.hpp"
#include <cstdint>
#include <functional>
#include <optional>

namespace mynet::handler
{

    /**
     * @brief 直连直通处理器
     */
    class HandlerDirect : public HandlerConnection
    {
    public:
        using RequestCallback = std::function<void(const ProxyAddress &target)>;

        static constexpr bool kEnableSplice = true;

        inline void enableSpliceForward(int targetFd) noexcept { setSpliceTarget(targetFd); }
        inline void enableSpliceForward(SPLICE_CONTROL ctrl) noexcept { setSpliceTarget(ctrl); }
        inline void disableSpliceForward() noexcept { disableSplice(); }
        [[nodiscard]] inline bool isSpliceForwardActive() const noexcept { return isSpliceActive(); }

    private:
        ProxyAddress target_{};
        RequestCallback requestCallback_{nullptr};
        bool triggered_{false};

    public:
        HandlerDirect() noexcept = default;
        explicit HandlerDirect(const ProxyAddress &target) noexcept
            : target_(target)
        {
        }
        ~HandlerDirect() noexcept override = default;

        HandlerDirect(const HandlerDirect &) = delete;
        HandlerDirect &operator=(const HandlerDirect &) = delete;
        HandlerDirect(HandlerDirect &&) = delete;
        HandlerDirect &operator=(HandlerDirect &&) = delete;

        void setTarget(const ProxyAddress &target) { target_ = target; }
        void setOnRequest(RequestCallback cb) noexcept { requestCallback_ = std::move(cb); }

        [[nodiscard]] bool isEstablished() const noexcept { return true; }
        [[nodiscard]] const ProxyAddress &targetAddress() const noexcept { return target_; }

        void reset() noexcept override
        {
            HandlerConnection::reset();
            triggered_ = false;
            disableSpliceForward();
        }

        void onMessageComplete() noexcept {}
        void onParseError(const char *reason) noexcept { (void)reason; }

        void process()
        {
            if (!triggered_)
            {
                triggered_ = true;
                onMessageComplete();
                if (requestCallback_)
                {
                    requestCallback_(target_);
                }
            }
        }
    };

} // namespace mynet::handler
