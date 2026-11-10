#pragma once

/**
 * @file handler/inbound.hpp
 * @brief 入站协议状态机处理器基类（面向流式连接 HandlerInboundConnection 与面向数据报 HandlerInboundDatagram）。
 */

#include "../connection.hpp"
#include "../datagram.hpp"
#include "address.hpp"
#include <cstdint>
#include <functional>
#include <optional>
#include <string_view>

namespace mynet::handler
{

    enum class InboundStage : uint8_t
    {
        HANDSHAKE,  ///< 正在接收并解析入站握手报文/鉴权/提取目标地址
        STREAMING,  ///< 握手完成，进入数据流式透传/内核零拷贝转发阶段
        ERROR       ///< 鉴权失败或协议格式畸变
    };

    /**
     * @brief 服务端流式连接入站协议处理器基类 (Stream Inbound Connection)
     *
     * 派生自 HandlerConnection，满足 HandlerConstraint 与 MandatoryMethodConnection。
     * 适用于 TCP、TLS 以及基于 QUIC 逻辑流的代理入站协议（如 SOCKS5、Trojan、VLESS、Hysteria2、TUIC、HTTP Proxy 等）。
     */
    class HandlerInboundConnection : public HandlerConnection
    {
    public:
        using RequestCallback = std::function<void(uint8_t cmd, const ProxyAddress &target)>;

        static constexpr bool kEnableSplice = true;

        inline void enableSpliceForward(int targetFd) noexcept { setSpliceTarget(targetFd); }
        inline void enableSpliceForward(SPLICE_CONTROL ctrl) noexcept { setSpliceTarget(ctrl); }
        inline void disableSpliceForward() noexcept { disableSplice(); }
        [[nodiscard]] inline bool isSpliceForwardActive() const noexcept { return isSpliceActive(); }

    protected:
        InboundStage stage_{InboundStage::HANDSHAKE};
        std::optional<ProxyAddress> targetAddress_{std::nullopt};
        uint8_t command_{0};
        RequestCallback requestCallback_{nullptr};

    public:
        HandlerInboundConnection() noexcept = default;
        ~HandlerInboundConnection() noexcept override = default;

        HandlerInboundConnection(const HandlerInboundConnection &) = delete;
        HandlerInboundConnection &operator=(const HandlerInboundConnection &) = delete;
        HandlerInboundConnection(HandlerInboundConnection &&) = delete;
        HandlerInboundConnection &operator=(HandlerInboundConnection &&) = delete;

        void setOnRequest(RequestCallback cb) noexcept { requestCallback_ = std::move(cb); }

        [[nodiscard]] InboundStage inboundStage() const noexcept { return stage_; }
        [[nodiscard]] InboundStage stage() const noexcept { return stage_; }
        [[nodiscard]] bool isEstablished() const noexcept { return stage_ == InboundStage::STREAMING; }
        [[nodiscard]] uint8_t command() const noexcept { return command_; }
        [[nodiscard]] const std::optional<ProxyAddress> &targetAddress() const noexcept { return targetAddress_; }
        [[nodiscard]] const ProxyAddress &target() const noexcept
        {
            static const ProxyAddress kEmpty{};
            return targetAddress_.has_value() ? *targetAddress_ : kEmpty;
        }

        void reset() noexcept override
        {
            HandlerConnection::reset();
            stage_ = InboundStage::HANDSHAKE;
            targetAddress_.reset();
            command_ = 0;
            disableSpliceForward();
        }

        void onMessageComplete() noexcept override {}
        void onParseError(const char *reason) noexcept override
        {
            (void)reason;
            stage_ = InboundStage::ERROR;
        }

        virtual void process() {}
    };

    /**
     * @brief 服务端数据报入站协议处理器基类 (Datagram Inbound)
     *
     * 派生自 HandlerDatagram，满足 DatagramConstraint。
     * 适用于纯 UDP、DNS、QUIC 原始数据报等无连接/报文级入站协议。
     */
    class HandlerInboundDatagram : public HandlerDatagram
    {
    public:
        using DatagramCallback = std::function<void(const sockaddr_in &peer, std::string_view payload)>;

    protected:
        InboundStage stage_{InboundStage::STREAMING};
        DatagramCallback datagramCallback_{nullptr};

    public:
        HandlerInboundDatagram() noexcept = default;
        explicit HandlerInboundDatagram(const DatagramConfig &config) noexcept
            : HandlerDatagram(config)
        {
        }
        ~HandlerInboundDatagram() noexcept override = default;

        HandlerInboundDatagram(const HandlerInboundDatagram &) = delete;
        HandlerInboundDatagram &operator=(const HandlerInboundDatagram &) = delete;
        HandlerInboundDatagram(HandlerInboundDatagram &&) = delete;
        HandlerInboundDatagram &operator=(HandlerInboundDatagram &&) = delete;

        void setOnDatagram(DatagramCallback cb) noexcept { datagramCallback_ = std::move(cb); }

        [[nodiscard]] InboundStage inboundStage() const noexcept { return stage_; }
        [[nodiscard]] InboundStage stage() const noexcept { return stage_; }
        [[nodiscard]] bool isEstablished() const noexcept { return stage_ == InboundStage::STREAMING; }

        void reset() noexcept override
        {
            HandlerDatagram::reset();
            stage_ = InboundStage::STREAMING;
        }
    };

} // namespace mynet::handler
