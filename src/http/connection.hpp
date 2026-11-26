#pragma once

#include "connection.hpp"
#include <cstdint>
#include <string_view>

namespace mynet::http
{
    /**
     * @brief HTTP/1.x 专属流式连接会话实现
     *
     * 继承自统一的 ConnectionBase，在连接层管理 HTTP/1.x 会话流式传输与状态。
     */
    class ConnectionHttp : public Connection
    {
    public:
        using Connection::Connection;
        [[nodiscard]] constexpr std::string_view version() const noexcept { return "HTTP/1.1"; }
    };

    using HttpConnection = ConnectionHttp;

    /**
     * @brief HTTP/2 多路复用逻辑流连接会话实现
     *
     * 继承自统一的 ConnectionBase，管理单一逻辑流在物理 TCP 连接上的多路复用映射。
     */
    class ConnectionHttp2 : public Connection
    {
    private:
        uint32_t streamId_{0};
        uint32_t windowSize_{65535};

    public:
        ConnectionHttp2() noexcept : Connection(-1) {}

        explicit ConnectionHttp2(uint32_t streamId, int parentFd = -1)
            : Connection(parentFd), streamId_(streamId)
        {
        }

        [[nodiscard]] constexpr std::string_view version() const noexcept { return "HTTP/2"; }
        [[nodiscard]] inline uint32_t streamId() const noexcept { return streamId_; }
        inline void setStreamId(uint32_t id) noexcept { streamId_ = id; }
        [[nodiscard]] inline uint32_t windowSize() const noexcept { return windowSize_; }
        inline void updateWindow(int32_t delta) noexcept { windowSize_ += delta; }
    };

    using Http2Connection = ConnectionHttp2;

    /**
     * @brief HTTP/3 基于 QUIC/UDP 的逻辑流连接会话实现
     *
     * 继承自统一的 ConnectionBase，将底层的 UDP 数据报连接与 QUIC 逻辑流无缝投影为统一的 Connection 会话。
     */
    class ConnectionHttp3 : public Connection
    {
    private:
        uint64_t streamId_{0};
        bool isDatagram_{true};

    public:
        ConnectionHttp3() noexcept : Connection(-1) {}

        explicit ConnectionHttp3(uint64_t streamId, int parentFd = -1)
            : Connection(parentFd), streamId_(streamId)
        {
        }

        [[nodiscard]] constexpr std::string_view version() const noexcept { return "HTTP/3"; }
        [[nodiscard]] inline uint64_t streamId() const noexcept { return streamId_; }
        inline void setStreamId(uint64_t id) noexcept { streamId_ = id; }
        [[nodiscard]] inline bool isDatagram() const noexcept { return isDatagram_; }
    };

    using Http3Connection = ConnectionHttp3;

} // namespace mynet::http
