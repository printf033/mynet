#pragma once

/**
 * @file http/v3/quic.hpp
 * @brief RFC 9000 QUIC 报文封装与传输帧原语（短首部报文、STREAM 帧与连接管理）。
 */

#include "varint.hpp"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <optional>
#include <string>
#include <string_view>

namespace mynet
{
    namespace http::v3
    {
        /**
         * @brief QUIC 连接标识符 (Connection ID, 最大 20 字节)
         */
        struct ConnectionId
        {
            static constexpr size_t kMaxLen = 20;
            uint8_t data[kMaxLen]{};
            uint8_t length = 0;

            bool operator==(const ConnectionId &o) const noexcept
            {
                if (length != o.length)
                {
                    return false;
                }
                return std::memcmp(data, o.data, length) == 0;
            }

            bool operator!=(const ConnectionId &o) const noexcept { return !(*this == o); }

            bool operator<(const ConnectionId &o) const noexcept
            {
                if (length != o.length)
                {
                    return length < o.length;
                }
                return std::memcmp(data, o.data, length) < 0;
            }

            [[nodiscard]] std::string toHex() const
            {
                static constexpr char kHexChars[] = "0123456789abcdef";
                std::string s;
                s.reserve(length * 2);
                for (size_t i = 0; i < length; ++i)
                {
                    s.push_back(kHexChars[(data[i] >> 4) & 0x0f]);
                    s.push_back(kHexChars[data[i] & 0x0f]);
                }
                return s;
            }

            static ConnectionId fromBytes(const void *src, uint8_t len) noexcept
            {
                ConnectionId cid;
                cid.length = std::min(len, static_cast<uint8_t>(kMaxLen));
                if (src != nullptr && cid.length > 0)
                {
                    std::memcpy(cid.data, src, cid.length);
                }
                return cid;
            }
        };

        /**
         * @brief RFC 9000 Section 19 QUIC 传输帧类型枚举
         */
        enum class QUIC_FRAME_TYPE : uint64_t
        {
            PADDING = 0x00,
            PING = 0x01,
            ACK = 0x02,
            ACK_ECN = 0x03,
            RESET_STREAM = 0x04,
            STOP_SENDING = 0x05,
            CRYPTO = 0x06,
            NEW_TOKEN = 0x07,
            STREAM_BASE = 0x08, // 0x08 - 0x0f: OFF(0x04), LEN(0x02), FIN(0x01)
            MAX_DATA = 0x10,
            MAX_STREAM_DATA = 0x11,
            MAX_STREAMS_BIDI = 0x12,
            MAX_STREAMS_UNI = 0x13,
            DATA_BLOCKED = 0x14,
            STREAM_DATA_BLOCKED = 0x15,
            CONNECTION_CLOSE_QUIC = 0x1c,
            CONNECTION_CLOSE_APP = 0x1d,
            HANDSHAKE_DONE = 0x1e
        };

        /**
         * @brief QUIC 解析错误枚举
         */
        enum class QUIC_ERROR : uint8_t
        {
            BUFFER_TOO_SHORT = 0,
            INVALID_PACKET_HEADER = 1,
            INVALID_FRAME_TYPE = 2,
            FRAME_PARSE_FAILED = 3
        };

        [[nodiscard]] constexpr std::string_view toString(QUIC_ERROR err) noexcept
        {
            switch (err)
            {
            case QUIC_ERROR::BUFFER_TOO_SHORT:
                return "insufficient packet bytes";
            case QUIC_ERROR::INVALID_PACKET_HEADER:
                return "invalid quic packet header";
            case QUIC_ERROR::INVALID_FRAME_TYPE:
                return "unsupported or unexpected quic frame type";
            case QUIC_ERROR::FRAME_PARSE_FAILED:
                return "quic frame decode failed";
            }
            return "unknown quic error";
        }

        /**
         * @brief QUIC STREAM 帧解析结果结构体
         */
        struct StreamFrame
        {
            uint64_t streamId = 0;
            uint64_t offset = 0;
            bool fin = false;
            std::string_view data{};
        };

        /**
         * @brief 构造并序列化一个 RFC 9000 Section 19.8 STREAM 传输帧
         */
        inline void appendStreamFrame(std::string &out, uint64_t streamId, uint64_t offset, std::string_view data,
                                      bool fin)
        {
            uint8_t type = 0x08; // 基础 STREAM 帧类型
            if (offset > 0)
            {
                type |= 0x04; // OFF 标志位
            }
            type |= 0x02; // LEN 标志位（显式携带载荷长度，保证多帧复用安全）
            if (fin)
            {
                type |= 0x01; // FIN 标志位
            }

            out.push_back(static_cast<char>(type));
            appendVarint(out, streamId);
            if (offset > 0)
            {
                appendVarint(out, offset);
            }
            appendVarint(out, data.size());
            out.append(data);
        }

        /**
         * @brief 从缓冲区解析一个 QUIC STREAM 帧
         */
        [[nodiscard]] inline std::expected<StreamFrame, QUIC_ERROR> parseStreamFrame(const uint8_t *&ptr,
                                                                                     size_t &rem) noexcept
        {
            if (rem == 0) [[unlikely]]
            {
                return std::unexpected(QUIC_ERROR::BUFFER_TOO_SHORT);
            }
            const uint8_t type = *ptr++;
            --rem;

            if (type < 0x08 || type > 0x0f) [[unlikely]]
            {
                return std::unexpected(QUIC_ERROR::INVALID_FRAME_TYPE);
            }

            const bool hasOff = (type & 0x04u) != 0;
            const bool hasLen = (type & 0x02u) != 0;
            const bool fin = (type & 0x01u) != 0;

            auto streamIdRes = readVarint(ptr, rem);
            if (!streamIdRes) [[unlikely]]
            {
                return std::unexpected(QUIC_ERROR::FRAME_PARSE_FAILED);
            }

            uint64_t offset = 0;
            if (hasOff)
            {
                auto offRes = readVarint(ptr, rem);
                if (!offRes) [[unlikely]]
                {
                    return std::unexpected(QUIC_ERROR::FRAME_PARSE_FAILED);
                }
                offset = *offRes;
            }

            size_t dataLen = rem;
            if (hasLen)
            {
                auto lenRes = readVarint(ptr, rem);
                if (!lenRes) [[unlikely]]
                {
                    return std::unexpected(QUIC_ERROR::FRAME_PARSE_FAILED);
                }
                dataLen = static_cast<size_t>(*lenRes);
                if (rem < dataLen) [[unlikely]]
                {
                    return std::unexpected(QUIC_ERROR::BUFFER_TOO_SHORT);
                }
            }

            StreamFrame sf;
            sf.streamId = *streamIdRes;
            sf.offset = offset;
            sf.fin = fin;
            sf.data = std::string_view(reinterpret_cast<const char *>(ptr), dataLen);

            ptr += dataLen;
            rem -= dataLen;

            return sf;
        }

        /**
         * @brief 构造 RFC 9000 Section 19.19 CONNECTION_CLOSE (应用层 HTTP/3 错误)
         */
        inline void appendConnectionCloseApp(std::string &out, uint64_t errorCode, std::string_view reason)
        {
            out.push_back(static_cast<char>(0x1d)); // CONNECTION_CLOSE (0x1d)
            appendVarint(out, errorCode);
            appendVarint(out, reason.size());
            out.append(reason);
        }

        /**
         * @brief 1-RTT 短首部报文解析结构体 (RFC 9000 Section 17.3)
         */
        struct ShortHeaderPacket
        {
            ConnectionId dcid{};
            uint32_t packetNumber = 0;
            std::string_view payload{};
        };

        /**
         * @brief 构造并封装 RFC 9000 1-RTT 短首部数据报
         *
         * @param out 输出报文字符串
         * @param dcid 目的连接标识符
         * @param packetNum 报文序号 (4 字节大端格式)
         * @param payload 封装的应用层载荷（包含 QUIC 帧序列）
         */
        inline void appendShortHeaderPacket(std::string &out, const ConnectionId &dcid, uint32_t packetNum,
                                            std::string_view payload)
        {
            // 首字节：0b01000011 (Header Form=0, Fixed=1, Spin=0, Reserved=00, KeyPhase=0, PN_Len=11表示4字节PN)
            const uint8_t headerByte = 0x43;
            out.reserve(out.size() + 1 + dcid.length + 4 + payload.size());
            out.push_back(static_cast<char>(headerByte));
            if (dcid.length > 0)
            {
                out.append(reinterpret_cast<const char *>(dcid.data), dcid.length);
            }
            const uint32_t bePn = std::byteswap(packetNum);
            out.append(reinterpret_cast<const char *>(&bePn), sizeof(bePn));
            out.append(payload);
        }

        /**
         * @brief 解析 1-RTT 短首部报文
         *
         * @param pkt 接收到的原始 UDP 报文字节
         * @param dcidLen 协商的 DCID 长度（默认 8 字节）
         * @return 成功交付 ShortHeaderPacket；格式不符交付错误码
         */
        [[nodiscard]] inline std::expected<ShortHeaderPacket, QUIC_ERROR>
        parseShortHeaderPacket(std::string_view pkt, uint8_t dcidLen = 8) noexcept
        {
            if (pkt.size() < 1ULL + dcidLen + 4ULL) [[unlikely]]
            {
                return std::unexpected(QUIC_ERROR::BUFFER_TOO_SHORT);
            }
            const auto *ptr = reinterpret_cast<const uint8_t *>(pkt.data());
            const uint8_t headerByte = *ptr++;

            // 验证 Header Form=0 且 Fixed Bit=1
            if ((headerByte & 0x80u) != 0 || (headerByte & 0x40u) == 0) [[unlikely]]
            {
                return std::unexpected(QUIC_ERROR::INVALID_PACKET_HEADER);
            }

            ShortHeaderPacket shp;
            shp.dcid = ConnectionId::fromBytes(ptr, dcidLen);
            ptr += dcidLen;

            uint32_t rawPn = 0;
            std::memcpy(&rawPn, ptr, sizeof(rawPn));
            ptr += sizeof(rawPn);
            shp.packetNumber = std::byteswap(rawPn);

            const size_t headerLen = 1ULL + dcidLen + 4ULL;
            shp.payload = pkt.substr(headerLen);

            return shp;
        }

    } // namespace http::v3
} // namespace mynet
