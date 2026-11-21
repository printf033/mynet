#pragma once

/**
 * @file handler/outboundHandler.hpp
 * @brief 出站协议状态机处理器基类（面向流式连接 HandlerOutboundConnectionBase 与面向数据报
 * HandlerOutboundDatagramBase）。
 */

#include "address.hpp"
#include "connection.hpp"
#include "datagram.hpp"
#include <cstdint>
#include <functional>
#include <string_view>

namespace mynet::handler
{

    enum class OutboundStage : uint8_t
    {
        INITIAL,    ///< 初始未握手状态
        CONNECTING, ///< 正在发送出站协议头部或等待对端认证回执
        STREAMING,  ///< 握手完成，进入流式数据透传/内核零拷贝转发
        ERROR       ///< 出站协议握手失败或对端报错
    };

    /**
     * @brief 客户端流式连接出站协议处理器基类 (Stream Outbound Connection Base)
     *
     * 派生自 HandlerConnection，满足 HandlerConstraint 与 MandatoryMethodConnection。
     * 适用于直连、SOCKS5、Trojan、VLESS、Hysteria2 等客户端出站协议。
     */
    class HandlerOutboundConnectionBase : public HandlerConnection
    {
    public:
        static constexpr bool kEnableSplice = true;

        inline void enableSpliceForward(int targetFd) noexcept { setSpliceTarget(targetFd); }
        inline void enableSpliceForward(SPLICE_CONTROL ctrl) noexcept { setSpliceTarget(ctrl); }
        inline void disableSpliceForward() noexcept { disableSplice(); }
        [[nodiscard]] inline bool isSpliceForwardActive() const noexcept { return isSpliceActive(); }

    protected:
        OutboundStage stage_{OutboundStage::INITIAL};
        ProxyAddress target_{};

    public:
        HandlerOutboundConnectionBase() noexcept = default;
        explicit HandlerOutboundConnectionBase(const ProxyAddress &target) noexcept
            : target_(target)
        {
        }
        ~HandlerOutboundConnectionBase() noexcept override = default;

        HandlerOutboundConnectionBase(const HandlerOutboundConnectionBase &) = delete;
        HandlerOutboundConnectionBase &operator=(const HandlerOutboundConnectionBase &) = delete;
        HandlerOutboundConnectionBase(HandlerOutboundConnectionBase &&) = delete;
        HandlerOutboundConnectionBase &operator=(HandlerOutboundConnectionBase &&) = delete;

        void setTarget(const ProxyAddress &target) noexcept { target_ = target; }
        void setStage(OutboundStage st) noexcept { stage_ = st; }

        [[nodiscard]] inline OutboundStage outboundStage() const noexcept { return stage_; }
        [[nodiscard]] inline OutboundStage stage() const noexcept { return stage_; }
        [[nodiscard]] inline bool isEstablished() const noexcept { return stage_ == OutboundStage::STREAMING; }
        [[nodiscard]] inline const ProxyAddress &target() const noexcept { return target_; }

        void reset() noexcept override
        {
            HandlerConnection::reset();
            stage_ = OutboundStage::INITIAL;
            target_ = ProxyAddress{};
            disableSplice();
        }

        void onMessageComplete() noexcept override {}
        void onParseError(const char *reason) noexcept override
        {
            (void)reason;
            stage_ = OutboundStage::ERROR;
        }

        virtual void handle() {}
    };

    /**
     * @brief 客户端数据报出站协议处理器基类 (Datagram Outbound Base)
     *
     * 派生自 HandlerDatagram，满足 DatagramConstraint。
     * 适用于纯 UDP、DNS 数据报出站等无连接/报文级出站协议。
     */
    class HandlerOutboundDatagramBase : public HandlerDatagram
    {
    protected:
        OutboundStage stage_{OutboundStage::STREAMING};
        sockaddr_in remotePeer_{};

    public:
        HandlerOutboundDatagramBase() noexcept = default;
        explicit HandlerOutboundDatagramBase(const DatagramConfig &config) noexcept
            : HandlerDatagram(config)
        {
        }
        explicit HandlerOutboundDatagramBase(const sockaddr_in &peer) noexcept
            : remotePeer_(peer)
        {
        }
        ~HandlerOutboundDatagramBase() noexcept override = default;

        HandlerOutboundDatagramBase(const HandlerOutboundDatagramBase &) = delete;
        HandlerOutboundDatagramBase &operator=(const HandlerOutboundDatagramBase &) = delete;
        HandlerOutboundDatagramBase(HandlerOutboundDatagramBase &&) = delete;
        HandlerOutboundDatagramBase &operator=(HandlerOutboundDatagramBase &&) = delete;

        void setRemotePeer(const sockaddr_in &peer) noexcept { remotePeer_ = peer; }
        void setStage(OutboundStage st) noexcept { stage_ = st; }

        [[nodiscard]] inline const sockaddr_in &remotePeer() const noexcept { return remotePeer_; }
        [[nodiscard]] inline OutboundStage outboundStage() const noexcept { return stage_; }
        [[nodiscard]] inline OutboundStage stage() const noexcept { return stage_; }
        [[nodiscard]] inline bool isEstablished() const noexcept { return stage_ == OutboundStage::STREAMING; }

        void reset() noexcept override
        {
            HandlerDatagram::reset();
            stage_ = OutboundStage::STREAMING;
            remotePeer_ = {};
        }
    };

} // namespace mynet::handler
