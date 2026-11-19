#pragma once

#include "error.hpp"
#include "requestBuffer.hpp"
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace mynet
{

    namespace frame
    {
        /// @brief HTTP/2 标准 9 字节帧头长度
        inline constexpr size_t kHeaderBytes = 9;

        /// @brief HTTP/2 默认协商的最大帧载荷大小 (16 KiB)
        inline constexpr uint32_t kDefaultMaxFrameSize = 16 << 10;

        /// @brief 流标识符第 32 位保留掩码
        inline constexpr uint8_t kStreamIdReservedMask = 0x80;
        inline constexpr uint32_t kStreamIdMask = 0x7fffffffu;

        /**
         * @brief 高性能大端网络序 32 位整数追加（单指令 bswap 转换）
         */
        inline void appendBigEndian32(std::string &out, uint32_t value)
        {
            const uint32_t be = std::byteswap(value);
            out.append(reinterpret_cast<const char *>(&be), sizeof(be));
        }

        /**
         * @brief 高性能读取大端网络序 32 位整数（单指令 bswap 反转）
         */
        [[nodiscard]] inline uint32_t readBigEndian32(const char *p) noexcept
        {
            uint32_t val = 0;
            std::memcpy(&val, p, sizeof(val));
            return std::byteswap(val);
        }
    } // namespace frame

    /**
     * @brief HTTP/2 标准协议帧类型枚举
     */
    enum class FRAME_TYPE : uint8_t
    {
        DATA = 0x0,
        HEADERS = 0x1,
        PRIORITY = 0x2,
        RESET = 0x3,
        SETTINGS = 0x4,
        PUSH_PROMISE = 0x5,
        PING = 0x6,
        GOAWAY = 0x7,
        WINDOW_UPDATE = 0x8,
        CONTINUATION = 0x9
    };

    namespace FrameFlags
    {
        inline constexpr uint8_t kEndStream = 0x1;
        inline constexpr uint8_t kAck = 0x1;
        inline constexpr uint8_t kEndHeaders = 0x4;
        inline constexpr uint8_t kPadded = 0x8;
        inline constexpr uint8_t kPriority = 0x20;
    } // namespace FrameFlags

    /**
     * @brief 协议分帧解析错误枚举
     */
    enum class FRAME_ERROR : uint8_t
    {
        FRAME_TOO_LARGE = 0,
        RESERVED_BIT_SET = 1
    };

    [[nodiscard]] constexpr std::string_view toString(FRAME_ERROR err) noexcept
    {
        switch (err)
        {
        case FRAME_ERROR::FRAME_TOO_LARGE:
            return "frame length exceeds the configured maximum";
        case FRAME_ERROR::RESERVED_BIT_SET:
            return "the reserved bit of the stream identifier was set";
        }
        return "unknown framing error";
    }

    struct Frame;

    /**
     * @brief HTTP/2 标准协议帧零拷贝视图结构体
     *
     * 载荷使用 std::string_view 直接切片底层接收缓冲区或常量存储，彻底消除帧解析时的堆内存分配。
     */
    struct FrameView
    {
        uint32_t streamId = 0;
        FRAME_TYPE type = FRAME_TYPE::DATA;
        uint8_t flags = 0;
        std::string_view payload{};

        [[nodiscard]] inline bool hasFlag(uint8_t flag) const noexcept { return (flags & flag) != 0; }

        [[nodiscard]] inline operator Frame() const;
    };

    /**
     * @brief HTTP/2 标准协议帧实体结构体（按值持有独立 payload 副本，支持聚合初始化）
     */
    struct Frame
    {
        uint32_t streamId = 0;
        FRAME_TYPE type = FRAME_TYPE::DATA;
        uint8_t flags = 0;
        std::string payload{};

        [[nodiscard]] inline bool hasFlag(uint8_t flag) const noexcept { return (flags & flag) != 0; }

        [[nodiscard]] inline FrameView view() const noexcept
        {
            return FrameView{.streamId = streamId, .type = type, .flags = flags, .payload = payload};
        }
    };

    inline FrameView::operator Frame() const
    {
        return Frame{.streamId = streamId, .type = type, .flags = flags, .payload = std::string(payload)};
    }

    /**
     * @brief 无状态极速协议帧解析器
     *
     * 针对流式拆包优化：若数据未达完整帧边界则保持只读游标不推进，杜绝中间状态维护；
     * 一旦收敛完整帧则直接消耗缓冲区并以 std::expected 交付。
     */
    class FrameDecoder
    {
    public:
        FrameDecoder() noexcept = default;

        inline void setMaxFrameSize(uint32_t n) noexcept { maxFrameSize_ = (n == 0) ? frame::kDefaultMaxFrameSize : n; }

        [[nodiscard]] inline uint32_t maxFrameSize() const noexcept { return maxFrameSize_; }

        /**
         * @brief 从缓冲区中零拷贝解析下一个完整协议帧视图（直通底层缓冲区）
         *
         * @param in 待解析的输入缓冲区引用
         * @return std::expected<std::optional<FrameView>, FRAME_ERROR>
         *         nullopt 表示数据尚不足一帧；有值表示解析出的完整帧切片；unexpected 表示协议契约破损错误。
         */
        [[nodiscard]] inline std::expected<std::optional<FrameView>, FRAME_ERROR> nextView(RequestBuffer &in) const
        {
            const size_t available = in.readableBytes();
            if (available < frame::kHeaderBytes) [[unlikely]]
            {
                return std::optional<FrameView>{};
            }

            const char *src = in.readableBegin();
            const uint32_t b0_3 = frame::readBigEndian32(src);
            const uint32_t length = b0_3 >> 8;

            if (length > maxFrameSize_) [[unlikely]]
            {
                return std::unexpected(FRAME_ERROR::FRAME_TOO_LARGE);
            }
            if (available < frame::kHeaderBytes + static_cast<size_t>(length))
            {
                return std::optional<FrameView>{};
            }

            const uint32_t b5_8 = frame::readBigEndian32(src + 5);
            if ((b5_8 & 0x80000000u) != 0) [[unlikely]]
            {
                return std::unexpected(FRAME_ERROR::RESERVED_BIT_SET);
            }

            FrameView fv;
            fv.streamId = b5_8 & frame::kStreamIdMask;
            fv.type = static_cast<FRAME_TYPE>(b0_3 & 0xffu);
            fv.flags = static_cast<uint8_t>(src[4]);
            fv.payload = std::string_view(src + frame::kHeaderBytes, length);
            in.retrieveNoCompact(frame::kHeaderBytes + static_cast<size_t>(length));
            return std::optional<FrameView>{fv};
        }

        /**
         * @brief 从缓冲区中解析下一个完整协议帧实体（包含独立 payload 副本）
         *
         * @param in 待解析的输入缓冲区引用
         * @return std::expected<std::optional<Frame>, FRAME_ERROR>
         *         nullopt 表示数据尚不足一帧；有值表示解析出的完整帧；unexpected 表示协议契约破损错误。
         */
        [[nodiscard]] inline std::expected<std::optional<Frame>, FRAME_ERROR> next(RequestBuffer &in) const
        {
            auto viewRes = nextView(in);
            if (!viewRes) [[unlikely]]
            {
                return std::unexpected(viewRes.error());
            }
            if (!viewRes->has_value())
            {
                return std::optional<Frame>{};
            }
            Frame frame(**viewRes);
            in.maybeCompact();
            return std::optional<Frame>{std::move(frame)};
        }

    private:
        uint32_t maxFrameSize_ = frame::kDefaultMaxFrameSize;
    };

    /**
     * @brief 按照大端网络序高速序列化并打包追加一个协议帧视图（就地成帧零临时拷贝）
     */
    inline void appendFrame(std::string &out, const FrameView &frame)
    {
        // 24 位长度域上限是线路硬约束：超限 payload 无法编码，必须在线上失步前失败
        contract_assert(frame.payload.size() <= 0xffffffu);
        const uint32_t length = static_cast<uint32_t>(frame.payload.size());
        const uint32_t streamId = frame.streamId & frame::kStreamIdMask;

        out.reserve(out.size() + frame::kHeaderBytes + length);

        char hdr[frame::kHeaderBytes];
        const uint32_t b0_3 = std::byteswap((length << 8) | static_cast<uint32_t>(std::to_underlying(frame.type)));
        std::memcpy(hdr, &b0_3, sizeof(b0_3));
        hdr[4] = static_cast<char>(frame.flags);
        const uint32_t beStream = std::byteswap(streamId);
        std::memcpy(hdr + 5, &beStream, sizeof(beStream));

        out.append(hdr, frame::kHeaderBytes);
        if (!frame.payload.empty())
        {
            out.append(frame.payload.data(), frame.payload.size());
        }
    }

    /**
     * @brief 按照大端网络序高速序列化并打包追加一个协议帧实体
     */
    inline void appendFrame(std::string &out, const Frame &frame)
    {
        appendFrame(out, frame.view());
    }

} // namespace mynet
