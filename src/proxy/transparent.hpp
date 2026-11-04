#pragma once

/**
 * @file proxy/transparent.hpp
 * @brief Linux Netfilter 透明代理状态机处理器（Redirect / TProxy）。
 */

#include "../connection.hpp"
#include "address.hpp"
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace mynet::proxy
{

    enum class TransparentStage : uint8_t
    {
        RESOLVING, ///< 正在从套接字提取 SO_ORIGINAL_DST
        STREAMING, ///< 目标已提取，处于直接零拷贝透明转发中
        ERROR      ///< 无法提取原始目的地址
    };

    /**
     * @brief Linux Redirect 透明代理处理器 (iptables -j REDIRECT)
     */
    class HandlerRedirect : public HandlerConnection
    {
    public:
        using RequestCallback = std::function<void(uint8_t cmd, const ProxyAddress &target)>;

        static constexpr bool kEnableSplice = true;

        inline void enableSpliceForward(int targetFd) noexcept { setSpliceTarget(targetFd); }
        inline void enableSpliceForward(SPLICE_CONTROL ctrl) noexcept { setSpliceTarget(ctrl); }
        inline void disableSpliceForward() noexcept { disableSplice(); }
        [[nodiscard]] inline bool isSpliceForwardActive() const noexcept { return isSpliceActive(); }

    private:
        TransparentStage stage_{TransparentStage::RESOLVING};
        RequestCallback requestCallback_{nullptr};
        std::optional<ProxyAddress> targetAddress_{std::nullopt};
        int clientFd_{-1};

    public:
        HandlerRedirect() noexcept = default;
        explicit HandlerRedirect(int clientFd) noexcept
            : clientFd_(clientFd)
        {
        }
        ~HandlerRedirect() noexcept override = default;

        HandlerRedirect(const HandlerRedirect &) = delete;
        HandlerRedirect &operator=(const HandlerRedirect &) = delete;
        HandlerRedirect(HandlerRedirect &&) = delete;
        HandlerRedirect &operator=(HandlerRedirect &&) = delete;

        void setClientFd(int fd) noexcept { clientFd_ = fd; }
        void setOnRequest(RequestCallback cb) noexcept { requestCallback_ = std::move(cb); }

        [[nodiscard]] TransparentStage stage() const noexcept { return stage_; }
        [[nodiscard]] bool isEstablished() const noexcept { return stage_ == TransparentStage::STREAMING; }
        [[nodiscard]] const std::optional<ProxyAddress> &targetAddress() const noexcept { return targetAddress_; }

        void reset() noexcept override
        {
            HandlerConnection::reset();
            stage_ = TransparentStage::RESOLVING;
            targetAddress_.reset();
            clientFd_ = -1;
            disableSpliceForward();
        }

        void onMessageComplete() noexcept {}
        void onParseError(const char *reason) noexcept
        {
            (void)reason;
            stage_ = TransparentStage::ERROR;
        }

        void process()
        {
            if (stage_ == TransparentStage::RESOLVING)
            {
                resolveOriginalDst();
            }
        }

    private:
        void resolveOriginalDst()
        {
            if (clientFd_ >= 0)
            {
                targetAddress_ = ProxyAddress::fromOriginalDst(clientFd_);
            }

            if (!targetAddress_.has_value())
            {
                // 若未绑定 fd 或非重定向连接，报错关闭
                onParseError("Redirect: SO_ORIGINAL_DST not found on socket");
                stage_ = TransparentStage::ERROR;
                setCloseAfterResponse(true);
                return;
            }

            stage_ = TransparentStage::STREAMING;
            onMessageComplete();

            if (requestCallback_)
            {
                requestCallback_(0x01, *targetAddress_);
            }
        }
    };

    /**
     * @brief Linux TProxy 透明代理处理器 (iptables -j TPROXY)
     */
    using HandlerTProxy = HandlerRedirect;

} // namespace mynet::proxy
