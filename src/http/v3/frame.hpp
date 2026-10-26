#pragma once

/**
 * @file http/v3/frame.hpp
 * @brief RFC 9114 HTTP/3 标准协议帧结构、序列化与解码器。
 */

#include "varint.hpp"
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace mynet
{
    namespace http::v3
    {
        /**
         * @brief RFC 9114 Section 7.2 HTTP/3 协议帧类型枚举
         */
        enum class FRAME_TYPE : uint64_t
        {
            DATA = 0x00,
            HEADERS = 0x01,
            CANCEL_PUSH = 0x03,
            SETTINGS = 0x04,
            PUSH_PROMISE = 0x05,
            GOAWAY = 0x07,
            MAX_PUSH_ID = 0x0d
        };

        /**
         * @brief RFC 9114 Section 8.1 HTTP/3 协议错误码枚举
         */
        enum class H3_ERROR : uint64_t
        {
            H3_NO_ERROR = 0x0100,
            H3_GENERAL_PROTOCOL_ERROR = 0x0101,
            H3_INTERNAL_ERROR = 0x0102,
            H3_STREAM_CREATION_ERROR = 0x0103,
            H3_CLOSED_CRITICAL_STREAM = 0x0104,
            H3_FRAME_UNEXPECTED = 0x0105,
            H3_FRAME_ERROR = 0x0106,
            H3_EXCESSIVE_LOAD = 0x0107,
            H3_ID_ERROR = 0x0108,
            H3_SETTINGS_ERROR = 0x0109,
            H3_MISSING_SETTINGS = 0x010a,
            H3_REQUEST_REJECTED = 0x010b,
            H3_REQUEST_CANCELLED = 0x010c,
            H3_REQUEST_INCOMPLETE = 0x010d,
            H3_MESSAGE_ERROR = 0x010e,
            H3_CONNECT_ERROR = 0x010f,
            H3_VERSION_FALLBACK = 0x0110
        };

        [[nodiscard]] constexpr std::string_view toString(H3_ERROR err) noexcept
        {
            switch (err)
            {
            case H3_ERROR::H3_NO_ERROR:
                return "no error";
            case H3_ERROR::H3_GENERAL_PROTOCOL_ERROR:
                return "general protocol error";
            case H3_ERROR::H3_INTERNAL_ERROR:
                return "internal error";
            case H3_ERROR::H3_STREAM_CREATION_ERROR:
                return "stream creation error";
            case H3_ERROR::H3_CLOSED_CRITICAL_STREAM:
                return "critical stream closed";
            case H3_ERROR::H3_FRAME_UNEXPECTED:
                return "unexpected frame received";
            case H3_ERROR::H3_FRAME_ERROR:
                return "frame syntax or semantic error";
            case H3_ERROR::H3_EXCESSIVE_LOAD:
                return "peer generating excessive load";
            case H3_ERROR::H3_ID_ERROR:
                return "stream or push id error";
            case H3_ERROR::H3_SETTINGS_ERROR:
                return "settings error";
            case H3_ERROR::H3_MISSING_SETTINGS:
                return "mandatory settings frame missing";
            case H3_ERROR::H3_REQUEST_REJECTED:
                return "request rejected before processing";
            case H3_ERROR::H3_REQUEST_CANCELLED:
                return "request cancelled";
            case H3_ERROR::H3_REQUEST_INCOMPLETE:
                return "request stream terminated prematurely";
            case H3_ERROR::H3_MESSAGE_ERROR:
                return "malformed request or response message";
            case H3_ERROR::H3_CONNECT_ERROR:
                return "connect stream error";
            case H3_ERROR::H3_VERSION_FALLBACK:
                return "downgrade to earlier http version requested";
            }
            return "unknown http/3 error";
        }

        /**
         * @brief RFC 9114 Section 7.2.8: 保留 Grease 帧类型判别 (0x1f * N + 0x21)
         */
        [[nodiscard]] constexpr bool isReservedGreaseFrame(uint64_t type) noexcept
        {
            return (type >= 0x21) && ((type - 0x21) % 0x1f == 0);
        }

        /**
         * @brief HTTP/3 协议帧解码错误枚举
         */
        enum class FRAME_DECODE_ERROR : uint8_t
        {
            FRAME_TOO_LARGE = 0,
            INVALID_VARINT = 1
        };

        [[nodiscard]] constexpr std::string_view toString(FRAME_DECODE_ERROR err) noexcept
        {
            switch (err)
            {
            case FRAME_DECODE_ERROR::FRAME_TOO_LARGE:
                return "frame payload exceeds the configured maximum frame size";
            case FRAME_DECODE_ERROR::INVALID_VARINT:
                return "invalid or truncated variable-length integer in frame header";
            }
            return "unknown frame decode error";
        }

        /**
         * @brief HTTP/3 协议帧实体
         */
        struct Frame
        {
            uint64_t type = 0;
            std::string payload{};
        };

        /**
         * @brief 按照 RFC 9114 格式将帧类型与载荷序列化追加至输出缓冲区
         *
         * @param out 待追加的目标字符串缓冲区
         * @param type 帧类型（varint）
         * @param payload 帧载荷二进制数据
         */
        inline void appendFrame(std::string &out, uint64_t type, std::string_view payload)
        {
            const size_t needed = varintLength(type) + varintLength(payload.size()) + payload.size();
            out.reserve(out.size() + needed);
            appendVarint(out, type);
            appendVarint(out, payload.size());
            out.append(payload);
        }

        inline void appendFrame(std::string &out, const Frame &f)
        {
            appendFrame(out, f.type, f.payload);
        }

        /**
         * @brief 无状态 HTTP/3 协议分帧解码器
         */
        class FrameDecoder
        {
        public:
            FrameDecoder() noexcept = default;

            inline void setMaxFrameSize(uint64_t n) noexcept { maxFrameSize_ = (n == 0) ? (16ULL << 20) : n; }
            [[nodiscard]] inline uint64_t maxFrameSize() const noexcept { return maxFrameSize_; }

            /**
             * @brief 从输入缓冲区解析提取下一个完整 HTTP/3 协议帧
             *
             * @param in 输入数据缓冲区
             * @return 成功且有完整帧返回 Frame；数据不足返回 nullopt；解析超限或破损返回错误码
             */
            [[nodiscard]] inline std::expected<std::optional<Frame>, FRAME_DECODE_ERROR> next(Buffer &in) const
            {
                const size_t available = in.readableBytes();
                if (available == 0) [[unlikely]]
                {
                    return std::optional<Frame>{};
                }

                const auto *base = reinterpret_cast<const uint8_t *>(in.readableBegin());
                const uint8_t *ptr = base;
                size_t rem = available;

                // 1. 解码帧类型
                auto typeRes = readVarint(ptr, rem);
                if (!typeRes)
                {
                    if (typeRes.error() == VARINT_ERROR::INSUFFICIENT_BYTES)
                    {
                        return std::optional<Frame>{};
                    }
                    return std::unexpected(FRAME_DECODE_ERROR::INVALID_VARINT);
                }

                // 2. 解码帧长度
                auto lenRes = readVarint(ptr, rem);
                if (!lenRes)
                {
                    if (lenRes.error() == VARINT_ERROR::INSUFFICIENT_BYTES)
                    {
                        return std::optional<Frame>{};
                    }
                    return std::unexpected(FRAME_DECODE_ERROR::INVALID_VARINT);
                }

                const uint64_t length = *lenRes;
                if (length > maxFrameSize_) [[unlikely]]
                {
                    return std::unexpected(FRAME_DECODE_ERROR::FRAME_TOO_LARGE);
                }

                if (rem < length)
                {
                    // 载荷尚未完整到达，保持只读游标不推进
                    return std::optional<Frame>{};
                }

                Frame frame;
                frame.type = *typeRes;
                frame.payload.assign(reinterpret_cast<const char *>(ptr), static_cast<size_t>(length));

                const size_t consumed = static_cast<size_t>((ptr - base)) + static_cast<size_t>(length);
                in.retrieve(consumed);

                return std::optional<Frame>{std::move(frame)};
            }

        private:
            uint64_t maxFrameSize_ = 16ULL << 20; // 默认最大 16 MiB
        };

        /**
         * @brief RFC 9114 Section 7.2.4.1 HTTP/3 设置标识符常量
         */
        namespace settings
        {
            inline constexpr uint64_t kQpackMaxTableCapacity = 0x01;
            inline constexpr uint64_t kMaxFieldSectionSize = 0x06;
            inline constexpr uint64_t kQpackBlockedStreams = 0x07;
        } // namespace settings

        /**
         * @brief RFC 9114 Section 7.2.4 HTTP/3 SETTINGS 帧参数实体
         */
        struct Settings
        {
            uint64_t maxFieldSectionSize = 65536; // 默认 64 KiB
            uint64_t qpackMaxTableCapacity = 0;   // 默认关闭动态表
            uint64_t qpackBlockedStreams = 0;

            /**
             * @brief 序列化为 SETTINGS 帧的载荷字节序列
             */
            void encode(std::string &out) const
            {
                appendVarint(out, settings::kMaxFieldSectionSize);
                appendVarint(out, maxFieldSectionSize);
                appendVarint(out, settings::kQpackMaxTableCapacity);
                appendVarint(out, qpackMaxTableCapacity);
                appendVarint(out, settings::kQpackBlockedStreams);
                appendVarint(out, qpackBlockedStreams);
            }

            /**
             * @brief 从 SETTINGS 帧载荷中解析出设置项
             */
            static std::expected<Settings, H3_ERROR> decode(std::string_view payload)
            {
                Settings s;
                const auto *ptr = reinterpret_cast<const uint8_t *>(payload.data());
                size_t rem = payload.size();

                while (rem > 0)
                {
                    auto idRes = readVarint(ptr, rem);
                    if (!idRes)
                    {
                        return std::unexpected(H3_ERROR::H3_SETTINGS_ERROR);
                    }
                    auto valRes = readVarint(ptr, rem);
                    if (!valRes)
                    {
                        return std::unexpected(H3_ERROR::H3_SETTINGS_ERROR);
                    }

                    const uint64_t id = *idRes;
                    const uint64_t val = *valRes;

                    switch (id)
                    {
                    case settings::kMaxFieldSectionSize:
                        s.maxFieldSectionSize = val;
                        break;
                    case settings::kQpackMaxTableCapacity:
                        s.qpackMaxTableCapacity = val;
                        break;
                    case settings::kQpackBlockedStreams:
                        s.qpackBlockedStreams = val;
                        break;
                    default:
                        // RFC 9114: 未知设置项必须被忽略以支持向前兼容
                        break;
                    }
                }
                return s;
            }
        };

    } // namespace http::v3
} // namespace mynet
