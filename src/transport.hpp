#pragma once

/**
 * @file transport.hpp
 * @brief 通用传输层抽象 (Universal Transport Abstraction)
 *
 * 支持 TCP、TLS、WebSocket (RFC 6455) 与 gRPC / Gun-lite (HTTP/2 流式封包) 协议传输抽象。
 */

#include "error.hpp"
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mynet::transport
{

    /**
     * @brief 传输协议类型
     */
    enum class TransportType : uint8_t
    {
        TCP = 0,
        TLS = 1,
        WEBSOCKET = 2,
        GRPC = 3
    };

    [[nodiscard]] constexpr std::string_view toString(TransportType type) noexcept
    {
        switch (type)
        {
        case TransportType::TCP:
            return "tcp";
        case TransportType::TLS:
            return "tls";
        case TransportType::WEBSOCKET:
            return "websocket";
        case TransportType::GRPC:
            return "grpc";
        default:
            return "unknown";
        }
    }

    /**
     * @brief 传输通道状态机阶段
     */
    enum class TransportState : uint8_t
    {
        INITIAL = 0,
        HANDSHAKING = 1,
        STREAMING = 2,
        CLOSED = 3,
        FAILED = 4
    };

    /**
     * @brief 传输层统一配置参数
     */
    struct TransportConfig
    {
        TransportType type{TransportType::TCP};
        std::string path{"/"};               ///< WebSocket 路径或 gRPC service 名
        std::string host{""};                ///< HTTP Host / SNI 报头覆盖
        std::string serviceName{""};         ///< gRPC 专属 service 命名 (如 "TunService")
        uint32_t maxEarlyData{0};            ///< 0-RTT Early-Data 限制 (WebSocket / TLS 1.3)
        std::string earlyDataHeaderName{""}; ///< Early Data 携带 HTTP 请求头名 (如 "Sec-WebSocket-Protocol")

        TransportConfig() = default;
    };

    /**
     * @brief 传输层协议状态与封包抽象接口
     */
    class ITransport
    {
    public:
        virtual ~ITransport() noexcept = default;

        [[nodiscard]] virtual TransportType type() const noexcept = 0;
        [[nodiscard]] virtual TransportState state() const noexcept = 0;
        [[nodiscard]] virtual bool isReady() const noexcept = 0;
        virtual void reset() noexcept = 0;
    };

} // namespace mynet::transport
