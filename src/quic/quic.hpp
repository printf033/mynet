#pragma once

/**
 * @file quic/quic.hpp
 * @brief RFC 9000 QUIC 报文封装与传输帧原语（短首部报文、STREAM 帧与连接管理）。
 */

#include "../encoding.hpp"
#include "varint.hpp"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace mynet::quic
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
            return mynet::encoding::toHex(std::span<const uint8_t>(data, length));
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
    inline void appendStreamFrame(std::string &out, uint64_t streamId, uint64_t offset, std::string_view data, bool fin)
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
     * @brief 构造 RFC 9000 Section 19.19 CONNECTION_CLOSE (应用层错误)
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

    // =========================================================================
    // RFC 9000 Section 2.1: 流 ID 分类原语
    // =========================================================================

    [[nodiscard]] constexpr bool isUnidirectionalStream(uint64_t streamId) noexcept { return (streamId & 0x02u) != 0; }

    [[nodiscard]] constexpr bool isServerInitiatedStream(uint64_t streamId) noexcept { return (streamId & 0x01u) != 0; }

    [[nodiscard]] constexpr bool isClientInitiatedStream(uint64_t streamId) noexcept { return (streamId & 0x01u) == 0; }

    [[nodiscard]] constexpr bool isClientBidirectionalStream(uint64_t streamId) noexcept
    {
        return (streamId & 0x03u) == 0;
    }

    // =========================================================================
    // RFC 9000 Section 19: 补齐常用传输帧编解码与通用跳过
    // =========================================================================

    struct AckFrame
    {
        uint64_t largestAcked = 0;
        uint64_t ackDelay = 0;
        uint64_t ackRangeCount = 0;
        uint64_t firstAckRange = 0;
    };

    inline void appendAckFrame(std::string &out, const AckFrame &ack)
    {
        appendVarint(out, std::to_underlying(QUIC_FRAME_TYPE::ACK));
        appendVarint(out, ack.largestAcked);
        appendVarint(out, ack.ackDelay);
        appendVarint(out, 0); // ackRangeCount = 0
        appendVarint(out, ack.firstAckRange);
    }

    [[nodiscard]] inline std::expected<AckFrame, QUIC_ERROR> parseAckFrame(const uint8_t *&ptr, size_t &rem) noexcept
    {
        auto typeOpt = readVarint(ptr, rem);
        if (!typeOpt || (*typeOpt != 0x02 && *typeOpt != 0x03))
        {
            return std::unexpected(QUIC_ERROR::INVALID_FRAME_TYPE);
        }
        auto largest = readVarint(ptr, rem);
        auto delay = readVarint(ptr, rem);
        auto rangeCnt = readVarint(ptr, rem);
        auto firstRange = readVarint(ptr, rem);
        if (!largest || !delay || !rangeCnt || !firstRange)
        {
            return std::unexpected(QUIC_ERROR::BUFFER_TOO_SHORT);
        }
        for (uint64_t i = 0; i < *rangeCnt; ++i)
        {
            if (!readVarint(ptr, rem) || !readVarint(ptr, rem))
            {
                return std::unexpected(QUIC_ERROR::BUFFER_TOO_SHORT);
            }
        }
        if (*typeOpt == 0x03)
        {
            if (!readVarint(ptr, rem) || !readVarint(ptr, rem) || !readVarint(ptr, rem))
            {
                return std::unexpected(QUIC_ERROR::BUFFER_TOO_SHORT);
            }
        }
        return AckFrame{*largest, *delay, *rangeCnt, *firstRange};
    }

    struct ResetStreamFrame
    {
        uint64_t streamId = 0;
        uint64_t errorCode = 0;
        uint64_t finalSize = 0;
    };

    inline void appendResetStreamFrame(std::string &out, const ResetStreamFrame &f)
    {
        appendVarint(out, std::to_underlying(QUIC_FRAME_TYPE::RESET_STREAM));
        appendVarint(out, f.streamId);
        appendVarint(out, f.errorCode);
        appendVarint(out, f.finalSize);
    }

    [[nodiscard]] inline std::expected<ResetStreamFrame, QUIC_ERROR> parseResetStreamFrame(const uint8_t *&ptr,
                                                                                           size_t &rem) noexcept
    {
        auto typeOpt = readVarint(ptr, rem);
        if (!typeOpt || *typeOpt != 0x04)
        {
            return std::unexpected(QUIC_ERROR::INVALID_FRAME_TYPE);
        }
        auto sid = readVarint(ptr, rem);
        auto err = readVarint(ptr, rem);
        auto sz = readVarint(ptr, rem);
        if (!sid || !err || !sz)
        {
            return std::unexpected(QUIC_ERROR::BUFFER_TOO_SHORT);
        }
        return ResetStreamFrame{*sid, *err, *sz};
    }

    struct StopSendingFrame
    {
        uint64_t streamId = 0;
        uint64_t errorCode = 0;
    };

    inline void appendStopSendingFrame(std::string &out, const StopSendingFrame &f)
    {
        appendVarint(out, std::to_underlying(QUIC_FRAME_TYPE::STOP_SENDING));
        appendVarint(out, f.streamId);
        appendVarint(out, f.errorCode);
    }

    [[nodiscard]] inline std::expected<StopSendingFrame, QUIC_ERROR> parseStopSendingFrame(const uint8_t *&ptr,
                                                                                           size_t &rem) noexcept
    {
        auto typeOpt = readVarint(ptr, rem);
        if (!typeOpt || *typeOpt != 0x05)
        {
            return std::unexpected(QUIC_ERROR::INVALID_FRAME_TYPE);
        }
        auto sid = readVarint(ptr, rem);
        auto err = readVarint(ptr, rem);
        if (!sid || !err)
        {
            return std::unexpected(QUIC_ERROR::BUFFER_TOO_SHORT);
        }
        return StopSendingFrame{*sid, *err};
    }

    inline void appendMaxDataFrame(std::string &out, uint64_t maxData)
    {
        appendVarint(out, std::to_underlying(QUIC_FRAME_TYPE::MAX_DATA));
        appendVarint(out, maxData);
    }

    inline void appendMaxStreamDataFrame(std::string &out, uint64_t streamId, uint64_t maxStreamData)
    {
        appendVarint(out, std::to_underlying(QUIC_FRAME_TYPE::MAX_STREAM_DATA));
        appendVarint(out, streamId);
        appendVarint(out, maxStreamData);
    }

    struct ConnectionCloseFrame
    {
        bool isApplication = false;
        uint64_t errorCode = 0;
        uint64_t frameType = 0;
        std::string_view reason{};
    };

    [[nodiscard]] inline std::expected<ConnectionCloseFrame, QUIC_ERROR>
    parseConnectionCloseFrame(const uint8_t *&ptr, size_t &rem) noexcept
    {
        auto typeOpt = readVarint(ptr, rem);
        if (!typeOpt || (*typeOpt != 0x1c && *typeOpt != 0x1d))
        {
            return std::unexpected(QUIC_ERROR::INVALID_FRAME_TYPE);
        }
        ConnectionCloseFrame f{};
        f.isApplication = (*typeOpt == 0x1d);
        auto err = readVarint(ptr, rem);
        if (!err)
        {
            return std::unexpected(QUIC_ERROR::BUFFER_TOO_SHORT);
        }
        f.errorCode = *err;
        if (!f.isApplication)
        {
            auto ft = readVarint(ptr, rem);
            if (!ft)
            {
                return std::unexpected(QUIC_ERROR::BUFFER_TOO_SHORT);
            }
            f.frameType = *ft;
        }
        auto rlen = readVarint(ptr, rem);
        if (!rlen || rem < *rlen)
        {
            return std::unexpected(QUIC_ERROR::BUFFER_TOO_SHORT);
        }
        f.reason = std::string_view(reinterpret_cast<const char *>(ptr), *rlen);
        ptr += *rlen;
        rem -= *rlen;
        return f;
    }

    /**
     * @brief 跳过单个非 STREAM 传输帧，保证后续同一报文内的 STREAM 帧不被误截断
     */
    [[nodiscard]] inline bool skipFrame(const uint8_t *&ptr, size_t &rem) noexcept
    {
        if (rem == 0)
        {
            return false;
        }
        const uint8_t t = *ptr;
        if (t == 0x00 || t == 0x01 || t == 0x1e) // PADDING, PING, HANDSHAKE_DONE
        {
            ++ptr;
            --rem;
            return true;
        }
        if (t == 0x02 || t == 0x03)
        {
            return parseAckFrame(ptr, rem).has_value();
        }
        if (t == 0x04)
        {
            return parseResetStreamFrame(ptr, rem).has_value();
        }
        if (t == 0x05)
        {
            return parseStopSendingFrame(ptr, rem).has_value();
        }
        if (t == 0x06) // CRYPTO: offset + len + bytes
        {
            ++ptr;
            --rem;
            auto off = readVarint(ptr, rem);
            auto len = readVarint(ptr, rem);
            if (!off || !len || rem < *len)
            {
                return false;
            }
            ptr += *len;
            rem -= *len;
            return true;
        }
        if (t == 0x07) // NEW_TOKEN: len + bytes
        {
            ++ptr;
            --rem;
            auto len = readVarint(ptr, rem);
            if (!len || rem < *len)
            {
                return false;
            }
            ptr += *len;
            rem -= *len;
            return true;
        }
        if (t == 0x10 || t == 0x12 || t == 0x13 || t == 0x14) // 1 varint arg
        {
            ++ptr;
            --rem;
            return readVarint(ptr, rem).has_value();
        }
        if (t == 0x11 || t == 0x15) // 2 varint args
        {
            ++ptr;
            --rem;
            return readVarint(ptr, rem).has_value() && readVarint(ptr, rem).has_value();
        }
        if (t == 0x1c || t == 0x1d)
        {
            return parseConnectionCloseFrame(ptr, rem).has_value();
        }
        return false;
    }

    // =========================================================================
    // RFC 9000 Section 8.1 & RFC 9002: 抗放大守卫、ACK 追踪与 RTT 估算器
    // =========================================================================

    struct AntiAmplificationGuard
    {
        size_t bytesReceived = 0;
        size_t bytesSent = 0;
        bool addressValidated = false;

        inline void recordReceived(size_t n) noexcept { bytesReceived += n; }
        inline void markValidated() noexcept { addressValidated = true; }

        [[nodiscard]] inline bool canSend(size_t n) const noexcept
        {
            return addressValidated || (bytesSent + n <= 3 * bytesReceived);
        }

        inline void recordSent(size_t n) noexcept { bytesSent += n; }

        inline void reset() noexcept
        {
            bytesReceived = 0;
            bytesSent = 0;
            addressValidated = false;
        }
    };

    struct AckTracker
    {
        uint64_t largestReceived = 0;
        bool hasReceived = false;
        bool ackPending = false;

        inline void onPacketReceived(uint64_t pn, bool ackEliciting = true) noexcept
        {
            if (!hasReceived || pn > largestReceived)
            {
                largestReceived = pn;
                hasReceived = true;
            }
            if (ackEliciting)
            {
                ackPending = true;
            }
        }

        [[nodiscard]] inline std::optional<AckFrame> consumeAckPending(uint64_t ackDelay = 0) noexcept
        {
            if (!ackPending || !hasReceived)
            {
                return std::nullopt;
            }
            ackPending = false;
            return AckFrame{.largestAcked = largestReceived, .ackDelay = ackDelay, .ackRangeCount = 0, .firstAckRange = 0};
        }

        inline void reset() noexcept
        {
            largestReceived = 0;
            hasReceived = false;
            ackPending = false;
        }
    };

    struct RttEstimator
    {
        uint64_t smoothedRttUs = 333000; // RFC 9002 初始 RTT = 333ms
        uint64_t rttVarUs = 166500;
        uint64_t minRttUs = 0;
        uint64_t latestRttUs = 0;
        bool hasSample = false;

        inline void update(uint64_t latestUs, uint64_t ackDelayUs = 0) noexcept
        {
            latestRttUs = latestUs;
            if (!hasSample)
            {
                minRttUs = latestUs;
                smoothedRttUs = latestUs;
                rttVarUs = latestUs / 2;
                hasSample = true;
                return;
            }
            if (latestUs < minRttUs)
            {
                minRttUs = latestUs;
            }
            uint64_t adjusted = latestUs;
            if (adjusted > minRttUs + ackDelayUs)
            {
                adjusted -= ackDelayUs;
            }
            const uint64_t diff = (smoothedRttUs > adjusted) ? (smoothedRttUs - adjusted) : (adjusted - smoothedRttUs);
            rttVarUs = (3 * rttVarUs + diff) / 4;
            smoothedRttUs = (7 * smoothedRttUs + adjusted) / 8;
        }

        [[nodiscard]] inline uint64_t ptoUs(uint64_t maxAckDelayUs = 25000) const noexcept
        {
            return smoothedRttUs + std::max<uint64_t>(4 * rttVarUs, 1000) + maxAckDelayUs;
        }
    };

    // =========================================================================
    // RFC 9000 Section 17.2: Long Header 报文解析与构造
    // =========================================================================

    enum class LongPacketType : uint8_t
    {
        INITIAL = 0x00,
        ZERO_RTT = 0x01,
        HANDSHAKE = 0x02,
        RETRY = 0x03
    };

    struct LongHeaderPacket
    {
        LongPacketType type = LongPacketType::INITIAL;
        uint32_t version = 1;
        ConnectionId dcid{};
        ConnectionId scid{};
        std::string_view payload{};
    };

    [[nodiscard]] inline std::expected<LongHeaderPacket, QUIC_ERROR> parseLongHeaderPacket(std::string_view pkt) noexcept
    {
        if (pkt.size() < 7) [[unlikely]]
        {
            return std::unexpected(QUIC_ERROR::BUFFER_TOO_SHORT);
        }
        const auto *ptr = reinterpret_cast<const uint8_t *>(pkt.data());
        const uint8_t b0 = ptr[0];
        if ((b0 & 0x80u) == 0 || (b0 & 0x40u) == 0) [[unlikely]]
        {
            return std::unexpected(QUIC_ERROR::INVALID_PACKET_HEADER);
        }
        LongHeaderPacket lhp{};
        lhp.type = static_cast<LongPacketType>((b0 & 0x30u) >> 4);
        lhp.version = (static_cast<uint32_t>(ptr[1]) << 24) | (static_cast<uint32_t>(ptr[2]) << 16) |
                      (static_cast<uint32_t>(ptr[3]) << 8) | static_cast<uint32_t>(ptr[4]);
        size_t off = 5;
        const uint8_t dcidLen = ptr[off++];
        if (dcidLen > ConnectionId::kMaxLen || off + dcidLen >= pkt.size())
        {
            return std::unexpected(QUIC_ERROR::INVALID_PACKET_HEADER);
        }
        lhp.dcid = ConnectionId::fromBytes(ptr + off, dcidLen);
        off += dcidLen;
        const uint8_t scidLen = ptr[off++];
        if (scidLen > ConnectionId::kMaxLen || off + scidLen > pkt.size())
        {
            return std::unexpected(QUIC_ERROR::INVALID_PACKET_HEADER);
        }
        lhp.scid = ConnectionId::fromBytes(ptr + off, scidLen);
        off += scidLen;
        lhp.payload = pkt.substr(off);
        return lhp;
    }

} // namespace mynet::quic
