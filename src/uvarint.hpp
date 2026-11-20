#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace mynet
{

    /**
     * @brief 标准 LEB128 / Protobuf / Go binary.Uvarint 无符号变长整数编解码器 (Single Source of Truth)
     */
    namespace uvarint
    {

        /**
         * @brief 计算编码该整数所需的字节数 (1 ~ 10 字节)
         */
        [[nodiscard]] constexpr size_t encodedLen(uint64_t x) noexcept
        {
            size_t n = 0;
            do
            {
                n++;
                x >>= 7;
            } while (x != 0);
            return n;
        }

        /**
         * @brief 将整数编码至预分配缓冲区并返回写入字节数
         */
        inline size_t encode(uint8_t *buf, uint64_t x) noexcept
        {
            size_t i = 0;
            while (x >= 0x80)
            {
                buf[i++] = static_cast<uint8_t>(x | 0x80);
                x >>= 7;
            }
            buf[i++] = static_cast<uint8_t>(x);
            return i;
        }

        /**
         * @brief 向字节流容器追加编码的变长整数
         */
        inline void append(std::vector<uint8_t> &buf, uint64_t x)
        {
            while (x >= 0x80)
            {
                buf.push_back(static_cast<uint8_t>(x | 0x80));
                x >>= 7;
            }
            buf.push_back(static_cast<uint8_t>(x));
        }

        /**
         * @brief 从内存切片解码无符号变长整数
         *
         * @return std::pair<uint64_t, size_t> 数值与实际消费的字节数（若溢出或缓冲区不足返回 {0, 0}）
         */
        [[nodiscard]] inline std::pair<uint64_t, size_t> decode(std::span<const uint8_t> data) noexcept
        {
            uint64_t x = 0;
            size_t s = 0;
            for (size_t i = 0; i < data.size() && i < 10; ++i)
            {
                const uint8_t b = data[i];
                if (b < 0x80)
                {
                    if (i == 9 && b > 1)
                    {
                        return {0, 0}; // 64位无符号整数溢出
                    }
                    return {x | (static_cast<uint64_t>(b) << s), i + 1};
                }
                x |= static_cast<uint64_t>(b & 0x7F) << s;
                s += 7;
            }
            return {0, 0};
        }

    } // namespace uvarint

} // namespace mynet
