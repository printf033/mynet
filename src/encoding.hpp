#pragma once

/**
 * @file encoding.hpp
 * @brief 通用文本与二进制编解码、格式转换及常量时间安全比较工具（零外部第三方依赖）。
 */

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mynet::encoding
{

    /**
     * @brief 恒定时间字节数组比较（防御时序攻击，无第三方库依赖）
     */
    [[nodiscard]] inline bool constantTimeEqual(std::span<const uint8_t> a, std::span<const uint8_t> b) noexcept
    {
        if (a.size() != b.size())
        {
            return false;
        }
        volatile uint8_t diff = 0;
        for (size_t i = 0; i < a.size(); ++i)
        {
            diff |= static_cast<uint8_t>(a[i] ^ b[i]);
        }
        return diff == 0;
    }

    /**
     * @brief 恒定时间字符串比较（防御时序攻击）
     */
    [[nodiscard]] inline bool constantTimeEqual(std::string_view a, std::string_view b) noexcept
    {
        return constantTimeEqual(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(a.data()), a.size()),
                                 std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(b.data()), b.size()));
    }

    /**
     * @brief 十六进制字符转 4-bit 数值 (Single Source of Truth)
     */
    [[nodiscard]] constexpr int hexCharToNibble(char c) noexcept
    {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return -1;
    }

    /**
     * @brief 二进制转小写十六进制字符串
     */
    [[nodiscard]] inline std::string toHex(std::span<const uint8_t> data)
    {
        static constexpr char kHexDigits[] = "0123456789abcdef";
        std::string s;
        s.reserve(data.size() * 2);
        for (uint8_t b : data)
        {
            s.push_back(kHexDigits[(b >> 4) & 0x0F]);
            s.push_back(kHexDigits[b & 0x0F]);
        }
        return s;
    }

    /**
     * @brief 解析 36 字符标准 UUID 字符串 (如 "de04add9-5c1a-4b08-8e65-244e45cf5483") 为 16 字节数组
     */
    [[nodiscard]] inline std::optional<std::array<uint8_t, 16>> parseUuid(std::string_view str) noexcept
    {
        std::array<uint8_t, 16> result{};
        size_t byteIdx = 0;
        int highNibble = -1;

        for (char c : str)
        {
            if (c == '-')
            {
                continue;
            }
            int val = hexCharToNibble(c);
            if (val < 0)
            {
                return std::nullopt;
            }
            if (highNibble < 0)
            {
                highNibble = val;
            }
            else
            {
                if (byteIdx >= 16)
                {
                    return std::nullopt;
                }
                result[byteIdx++] = static_cast<uint8_t>((highNibble << 4) | val);
                highNibble = -1;
            }
        }

        if (byteIdx != 16 || highNibble >= 0)
        {
            return std::nullopt;
        }
        return result;
    }

    /**
     * @brief 将 16 字节数组转换为标准 UUID 字符串
     */
    [[nodiscard]] inline std::string uuidToString(const std::array<uint8_t, 16> &uuid)
    {
        static constexpr char kHex[] = "0123456789abcdef";
        std::string s;
        s.reserve(36);
        for (size_t i = 0; i < 16; ++i)
        {
            if (i == 4 || i == 6 || i == 8 || i == 10)
            {
                s.push_back('-');
            }
            s.push_back(kHex[(uuid[i] >> 4) & 0x0F]);
            s.push_back(kHex[uuid[i] & 0x0F]);
        }
        return s;
    }

    /**
     * @brief 标准 Base64 编码器
     */
    [[nodiscard]] inline std::string base64Encode(std::span<const uint8_t> in)
    {
        static constexpr char kTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        out.reserve(((in.size() + 2) / 3) * 4);
        size_t i = 0;
        for (; i + 2 < in.size(); i += 3)
        {
            const uint32_t n = (static_cast<uint32_t>(in[i]) << 16) | (static_cast<uint32_t>(in[i + 1]) << 8) |
                               static_cast<uint32_t>(in[i + 2]);
            out.push_back(kTable[(n >> 18) & 0x3F]);
            out.push_back(kTable[(n >> 12) & 0x3F]);
            out.push_back(kTable[(n >> 6) & 0x3F]);
            out.push_back(kTable[n & 0x3F]);
        }
        if (i < in.size())
        {
            if (in.size() - i == 1)
            {
                const uint32_t n = static_cast<uint32_t>(in[i]) << 16;
                out.push_back(kTable[(n >> 18) & 0x3F]);
                out.push_back(kTable[(n >> 12) & 0x3F]);
                out.push_back('=');
                out.push_back('=');
            }
            else if (in.size() - i == 2)
            {
                const uint32_t n = (static_cast<uint32_t>(in[i]) << 16) | (static_cast<uint32_t>(in[i + 1]) << 8);
                out.push_back(kTable[(n >> 18) & 0x3F]);
                out.push_back(kTable[(n >> 12) & 0x3F]);
                out.push_back(kTable[(n >> 6) & 0x3F]);
                out.push_back('=');
            }
        }
        return out;
    }

    /**
     * @brief 简易 Base64 解码器（用于 HTTP Basic 认证等）
     */
    inline bool base64Decode(std::string_view in, std::string &out)
    {
        static const auto kDecodeTable = []()
        {
            std::array<int, 256> table{};
            table.fill(-1);
            for (int i = 0; i < 26; ++i)
            {
                table[static_cast<uint8_t>('A' + i)] = i;
                table[static_cast<uint8_t>('a' + i)] = i + 26;
            }
            for (int i = 0; i < 10; ++i)
            {
                table[static_cast<uint8_t>('0' + i)] = i + 52;
            }
            table[static_cast<uint8_t>('+')] = 62;
            table[static_cast<uint8_t>('/')] = 63;
            return table;
        }();

        out.clear();
        uint32_t val = 0;
        int valb = -8;
        for (char c : in)
        {
            if (c == '=' || c == '\r' || c == '\n' || c == ' ')
            {
                continue;
            }
            int d = kDecodeTable[static_cast<uint8_t>(c)];
            if (d < 0)
            {
                return false;
            }
            val = (val << 6) | d;
            valb += 6;
            if (valb >= 0)
            {
                out.push_back(static_cast<char>((val >> valb) & 0xFF));
                valb -= 8;
            }
        }
        return true;
    }

} // namespace mynet::encoding

namespace mynet
{
    namespace encoding = mynet::encoding;
}

namespace mynet::handler
{
    namespace encoding = mynet::encoding;
}
