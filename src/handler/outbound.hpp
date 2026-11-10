#pragma once

/**
 * @file handler/outbound.hpp
 * @brief 出站协议状态机处理器基类（面向流式连接 HandlerOutboundConnection 与面向数据报 HandlerOutboundDatagram）。
 */

#include "../connection.hpp"
#include "../datagram.hpp"
#include "address.hpp"
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
     * @brief 客户端流式连接出站协议处理器基类 (Stream Outbound Connection)
     *
     * 派生自 HandlerConnection，满足 HandlerConstraint 与 MandatoryMethodConnection。
     * 适用于直连、SOCKS5、Trojan、VLESS、Hysteria2 等客户端出站协议。
     */
    class HandlerOutboundConnection : public HandlerConnection
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
        HandlerOutboundConnection() noexcept = default;
        explicit HandlerOutboundConnection(const ProxyAddress &target) noexcept
            : target_(target)
        {
        }
        ~HandlerOutboundConnection() noexcept override = default;

        HandlerOutboundConnection(const HandlerOutboundConnection &) = delete;
        HandlerOutboundConnection &operator=(const HandlerOutboundConnection &) = delete;
        HandlerOutboundConnection(HandlerOutboundConnection &&) = delete;
        HandlerOutboundConnection &operator=(HandlerOutboundConnection &&) = delete;

        void setTarget(const ProxyAddress &target) noexcept { target_ = target; }
        [[nodiscard]] const ProxyAddress &target() const noexcept { return target_; }
        [[nodiscard]] OutboundStage stage() const noexcept { return stage_; }
        [[nodiscard]] bool isEstablished() const noexcept { return stage_ == OutboundStage::STREAMING; }

        void reset() noexcept override
        {
            HandlerConnection::reset();
            stage_ = OutboundStage::INITIAL;
            target_ = {};
            disableSpliceForward();
        }

        void onMessageComplete() noexcept override {}
        void onParseError(const char *reason) noexcept override
        {
            (void)reason;
            stage_ = OutboundStage::ERROR;
        }

        virtual void process() {}
    };

    /**
     * @brief 客户端数据报出站协议处理器基类 (Datagram Outbound)
     *
     * 派生自 HandlerDatagram，满足 DatagramConstraint。
     * 适用于纯 UDP、DNS 查询、QUIC 原始数据报等无连接/报文级出站协议。
     */
    class HandlerOutboundDatagram : public HandlerDatagram
    {
    protected:
        OutboundStage stage_{OutboundStage::STREAMING};
        sockaddr_in remotePeer_{};

    public:
        HandlerOutboundDatagram() noexcept = default;
        explicit HandlerOutboundDatagram(const DatagramConfig &config) noexcept
            : HandlerDatagram(config)
        {
        }
        explicit HandlerOutboundDatagram(const sockaddr_in &peer) noexcept
            : remotePeer_(peer)
        {
        }
        ~HandlerOutboundDatagram() noexcept override = default;

        HandlerOutboundDatagram(const HandlerOutboundDatagram &) = delete;
        HandlerOutboundDatagram &operator=(const HandlerOutboundDatagram &) = delete;
        HandlerOutboundDatagram(HandlerOutboundDatagram &&) = delete;
        HandlerOutboundDatagram &operator=(HandlerOutboundDatagram &&) = delete;

        void setRemotePeer(const sockaddr_in &peer) noexcept { remotePeer_ = peer; }
        [[nodiscard]] const sockaddr_in &remotePeer() const noexcept { return remotePeer_; }
        [[nodiscard]] OutboundStage stage() const noexcept { return stage_; }
        [[nodiscard]] bool isEstablished() const noexcept { return stage_ == OutboundStage::STREAMING; }

        void reset() noexcept override
        {
            HandlerDatagram::reset();
            stage_ = OutboundStage::STREAMING;
            remotePeer_ = {};
        }
    };

} // namespace mynet::handler
