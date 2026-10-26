#pragma once

/**
 * @file http/v3/varint.hpp
 * @brief RFC 9000 Section 16 QUIC / HTTP/3 变长整数 (Variable-Length Integer) 编解码器。
 */

#include "buffer.hpp"
#include "error.hpp"
#include <bit>
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
        /// @brief 变长整数各长度梯度的最大编码值 (RFC 9000 Table 4)
        inline constexpr uint64_t kMaxVarint1Byte = 63ULL;                // 2^6 - 1
        inline constexpr uint64_t kMaxVarint2Bytes = 16383ULL;            // 2^14 - 1
        inline constexpr uint64_t kMaxVarint4Bytes = 1073741823ULL;       // 2^30 - 1
        inline constexpr uint64_t kMaxVarint8Bytes = (1ULL << 62) - 1ULL; // 2^62 - 1

        /**
         * @brief 变长整数解析错误枚举
         */
        enum class VARINT_ERROR : uint8_t
        {
            INSUFFICIENT_BYTES = 0,
            VALUE_OVERFLOW = 1
        };

        [[nodiscard]] constexpr std::string_view toString(VARINT_ERROR err) noexcept
        {
            switch (err)
            {
            case VARINT_ERROR::INSUFFICIENT_BYTES:
                return "insufficient bytes available to decode varint";
            case VARINT_ERROR::VALUE_OVERFLOW:
                return "varint value exceeds maximum 62-bit representable limit";
            }
            return "unknown varint error";
        }

        /**
         * @brief 根据首字节的最高 2 位确定变长整数的总编码字节长度
         *
         * @param firstByte 变长整数序列的首字节
         * @return 编码长度 (1, 2, 4 或 8)
         */
        [[nodiscard]] constexpr size_t varintLengthFromPrefix(uint8_t firstByte) noexcept
        {
            return size_t{1} << (firstByte >> 6);
        }

        /**
         * @brief 计算无符号 64 位整数编码为变长整数所需的字节数
         *
         * @param val 待编码数值
         * @return 所需字节数 (1, 2, 4 或 8)
         */
        [[nodiscard]] constexpr size_t varintLength(uint64_t val) noexcept
        {
            if (val <= kMaxVarint1Byte)
            {
                return 1;
            }
            if (val <= kMaxVarint2Bytes)
            {
                return 2;
            }
            if (val <= kMaxVarint4Bytes)
            {
                return 4;
            }
            return 8;
        }

        /**
         * @brief 将无符号 64 位整数按照 RFC 9000 规范序列化为网络大端序变长整数并追加到输出字符串
         *
         * @param out 输出字符串缓冲区引用
         * @param val 待编码数值 (必须 <= 2^62 - 1)
         */
        inline void appendVarint(std::string &out, uint64_t val)
        {
            contract_assert(val <= kMaxVarint8Bytes);
            if (val <= kMaxVarint1Byte)
            {
                out.push_back(static_cast<char>(static_cast<uint8_t>(val)));
            }
            else if (val <= kMaxVarint2Bytes)
            {
                const uint16_t v = static_cast<uint16_t>(val) | 0x4000u;
                const uint16_t be = std::byteswap(v);
                out.append(reinterpret_cast<const char *>(&be), sizeof(be));
            }
            else if (val <= kMaxVarint4Bytes)
            {
                const uint32_t v = static_cast<uint32_t>(val) | 0x80000000u;
                const uint32_t be = std::byteswap(v);
                out.append(reinterpret_cast<const char *>(&be), sizeof(be));
            }
            else
            {
                const uint64_t v = val | 0xc000000000000000ULL;
                const uint64_t be = std::byteswap(v);
                out.append(reinterpret_cast<const char *>(&be), sizeof(be));
            }
        }

        /**
         * @brief 从内存指针处安全解码一个变长整数，若成功则前移指针并扣减剩余字节计数
         *
         * @param ptr 内存游标指针引用
         * @param remaining 剩余有效字节数引用
         * @return 解码出的数值，或错误状态码
         */
        [[nodiscard]] inline std::expected<uint64_t, VARINT_ERROR> readVarint(const uint8_t *&ptr,
                                                                              size_t &remaining) noexcept
        {
            if (remaining == 0) [[unlikely]]
            {
                return std::unexpected(VARINT_ERROR::INSUFFICIENT_BYTES);
            }
            const uint8_t b0 = *ptr;
            const size_t len = varintLengthFromPrefix(b0);
            if (remaining < len) [[unlikely]]
            {
                return std::unexpected(VARINT_ERROR::INSUFFICIENT_BYTES);
            }
            uint64_t val = 0;
            if (len == 1)
            {
                val = b0 & 0x3fu;
            }
            else if (len == 2)
            {
                uint16_t raw = 0;
                std::memcpy(&raw, ptr, sizeof(raw));
                val = std::byteswap(raw) & 0x3fffu;
            }
            else if (len == 4)
            {
                uint32_t raw = 0;
                std::memcpy(&raw, ptr, sizeof(raw));
                val = std::byteswap(raw) & 0x3fffffffu;
            }
            else
            {
                uint64_t raw = 0;
                std::memcpy(&raw, ptr, sizeof(raw));
                val = std::byteswap(raw) & 0x3fffffffffffffffull;
            }
            ptr += len;
            remaining -= len;
            return val;
        }

        /**
         * @brief 从滑动窗口缓冲区中解码下一个变长整数（成功时消费缓冲区）
         *
         * @param in 输入数据缓冲区
         * @return 成功且完整交付数值；数据不足时交付 nullopt；协议破损交付错误状态码
         */
        [[nodiscard]] inline std::expected<std::optional<uint64_t>, VARINT_ERROR> decodeVarint(Buffer &in) noexcept
        {
            const size_t available = in.readableBytes();
            if (available == 0) [[unlikely]]
            {
                return std::optional<uint64_t>{};
            }
            const auto *p = reinterpret_cast<const uint8_t *>(in.readableBegin());
            const size_t len = varintLengthFromPrefix(*p);
            if (available < len)
            {
                return std::optional<uint64_t>{};
            }
            size_t rem = len;
            const uint8_t *cur = p;
            auto res = readVarint(cur, rem);
            if (!res) [[unlikely]]
            {
                return std::unexpected(res.error());
            }
            in.retrieve(len);
            return std::optional<uint64_t>{*res};
        }

    } // namespace http::v3
} // namespace mynet
