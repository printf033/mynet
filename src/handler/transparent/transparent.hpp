#pragma once

/**
 * @file handler/transparent/transparent.hpp
 * @brief Linux Netfilter 透明代理入站状态机处理器 (HandlerInboundRedirect / HandlerInboundTProxy)。
 */

#include "../address.hpp"
#include "../inbound.hpp"
#include <cstdint>
#include <functional>
#include <optional>

namespace mynet::handler
{

    enum class TransparentStage : uint8_t
    {
        RESOLVING, ///< 正在从套接字提取 SO_ORIGINAL_DST
        STREAMING, ///< 目标已提取，处于直接零拷贝透明转发中
        ERROR      ///< 无法提取原始目的地址
    };

    /**
     * @brief Linux Redirect 透明代理入站处理器 (iptables -j REDIRECT)
     */
    class HandlerInboundRedirect : public HandlerInboundConnection
    {
    private:
        TransparentStage transparentStage_{TransparentStage::RESOLVING};
        int clientFd_{-1};

    public:
        HandlerInboundRedirect() noexcept = default;
        explicit HandlerInboundRedirect(int clientFd) noexcept
            : clientFd_(clientFd)
        {
        }
        ~HandlerInboundRedirect() noexcept override = default;

        HandlerInboundRedirect(const HandlerInboundRedirect &) = delete;
        HandlerInboundRedirect &operator=(const HandlerInboundRedirect &) = delete;
        HandlerInboundRedirect(HandlerInboundRedirect &&) = delete;
        HandlerInboundRedirect &operator=(HandlerInboundRedirect &&) = delete;

        void setClientFd(int fd) noexcept { clientFd_ = fd; }

        [[nodiscard]] TransparentStage stage() const noexcept { return transparentStage_; }

        void reset() noexcept override
        {
            HandlerInboundConnection::reset();
            transparentStage_ = TransparentStage::RESOLVING;
            clientFd_ = -1;
        }

        void onMessageComplete() noexcept {}
        void onParseError(const char *reason) noexcept
        {
            (void)reason;
            transparentStage_ = TransparentStage::ERROR;
            stage_ = InboundStage::ERROR;
        }

        void process() override
        {
            if (transparentStage_ == TransparentStage::RESOLVING)
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
                onParseError("Redirect: SO_ORIGINAL_DST not found on socket");
                transparentStage_ = TransparentStage::ERROR;
                stage_ = InboundStage::ERROR;
                setCloseAfterResponse(true);
                return;
            }

            transparentStage_ = TransparentStage::STREAMING;
            stage_ = InboundStage::STREAMING;
            command_ = 0x01;
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
    using HandlerInboundTProxy = HandlerInboundRedirect;

} // namespace mynet::handler
