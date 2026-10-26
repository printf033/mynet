#pragma once

/**
 * @file http/v3/qpack.hpp
 * @brief RFC 9204 QPACK 头部压缩静态表与字段编解码器。
 */

#include "frame.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace mynet
{
    namespace http::v3
    {
        /**
         * @brief 单个 HTTP 首部键值对
         */
        struct Header
        {
            std::string name{};
            std::string value{};
        };

        /**
         * @brief RFC 9204 Appendix A QPACK 静态表项
         */
        struct StaticEntry
        {
            std::string_view name;
            std::string_view value;
        };

        inline constexpr std::array<StaticEntry, 99> kStaticTable = {{
            {":authority", ""},
            {":path", "/"},
            {"age", "0"},
            {"content-disposition", ""},
            {"content-length", "0"},
            {"cookie", ""},
            {"date", ""},
            {"etag", ""},
            {"if-modified-since", ""},
            {"if-none-match", ""},
            {"last-modified", ""},
            {"link", ""},
            {"location", ""},
            {"referer", ""},
            {"set-cookie", ""},
            {":method", "CONNECT"},
            {":method", "DELETE"},
            {":method", "GET"},
            {":method", "HEAD"},
            {":method", "OPTIONS"},
            {":method", "POST"},
            {":method", "PUT"},
            {":scheme", "http"},
            {":scheme", "https"},
            {":status", "103"},
            {":status", "200"},
            {":status", "304"},
            {":status", "404"},
            {":status", "503"},
            {"accept", "*/*"},
            {"accept", "application/dns-message"},
            {"accept-encoding", "gzip, deflate, br"},
            {"accept-ranges", "bytes"},
            {"access-control-allow-headers", "cache-control"},
            {"access-control-allow-headers", "content-type"},
            {"access-control-allow-origin", "*"},
            {"cache-control", "max-age=0"},
            {"cache-control", "max-age=2592000"},
            {"cache-control", "max-age=604800"},
            {"cache-control", "no-cache"},
            {"cache-control", "no-store"},
            {"cache-control", "public, max-age=31536000"},
            {"content-encoding", "br"},
            {"content-encoding", "gzip"},
            {"content-type", "application/dns-message"},
            {"content-type", "application/javascript"},
            {"content-type", "application/json"},
            {"content-type", "application/x-www-form-urlencoded"},
            {"content-type", "image/gif"},
            {"content-type", "image/jpeg"},
            {"content-type", "image/png"},
            {"content-type", "text/css"},
            {"content-type", "text/html; charset=utf-8"},
            {"content-type", "text/plain"},
            {"content-type", "text/plain; charset=utf-8"},
            {"range", "bytes=0-"},
            {"strict-transport-security", "max-age=31536000"},
            {"strict-transport-security", "max-age=31536000; includesubdomains; preload"},
            {"vary", "accept-encoding"},
            {"vary", "origin"},
            {"x-content-type-options", "nosniff"},
            {"x-xss-protection", "1; mode=block"},
            {":status", "100"},
            {":status", "204"},
            {":status", "206"},
            {":status", "302"},
            {":status", "400"},
            {":status", "403"},
            {":status", "421"},
            {":status", "425"},
            {":status", "500"},
            {"accept-language", ""},
            {"access-control-allow-credentials", "FALSE"},
            {"access-control-allow-credentials", "TRUE"},
            {"access-control-allow-headers", "*"},
            {"access-control-allow-methods", "get"},
            {"access-control-allow-methods", "get, post, options"},
            {"access-control-allow-methods", "options"},
            {"access-control-expose-headers", "content-length"},
            {"access-control-request-headers", "content-type"},
            {"access-control-request-method", "get"},
            {"access-control-request-method", "post"},
            {"alt-svc", "clear"},
            {"authorization", ""},
            {"content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none';"},
            {"early-data", "1"},
            {"expect-ct", ""},
            {"forwarded", ""},
            {"if-range", ""},
            {"origin", ""},
            {"purpose", "prefetch"},
            {"server", ""},
            {"timing-allow-origin", "*"},
            {"upgrade-insecure-requests", "1"},
            {"user-agent", ""},
            {"x-forwarded-for", ""},
            {"x-frame-options", "deny"},
            {"x-frame-options", "sameorigin"},
            {":status", "502"},
        }};

        /**
         * @brief 静态表快速查找
         */
        struct StaticMatch
        {
            std::optional<size_t> exactIndex{};
            std::optional<size_t> nameIndex{};
        };

        [[nodiscard]] inline StaticMatch findStaticEntry(std::string_view name, std::string_view value) noexcept
        {
            StaticMatch match{};
            for (size_t i = 0; i < kStaticTable.size(); ++i)
            {
                if (kStaticTable[i].name == name)
                {
                    if (!match.nameIndex)
                    {
                        match.nameIndex = i;
                    }
                    if (kStaticTable[i].value == value)
                    {
                        match.exactIndex = i;
                        return match;
                    }
                }
            }
            return match;
        }

        /**
         * @brief RFC 9204 Section 4.1.1 前缀整数编码
         */
        inline void encodePrefixedInt(std::string &out, uint8_t prefixBits, uint8_t prefixPattern, uint64_t val)
        {
            const uint64_t maxPrefix = (1ULL << prefixBits) - 1ULL;
            if (val < maxPrefix)
            {
                out.push_back(static_cast<char>(prefixPattern | static_cast<uint8_t>(val)));
                return;
            }
            out.push_back(static_cast<char>(prefixPattern | static_cast<uint8_t>(maxPrefix)));
            val -= maxPrefix;
            while (val >= 128)
            {
                out.push_back(static_cast<char>((val & 0x7fu) | 0x80u));
                val >>= 7;
            }
            out.push_back(static_cast<char>(val));
        }

        /**
         * @brief RFC 9204 Section 4.1.1 前缀整数解码
         */
        [[nodiscard]] inline std::expected<uint64_t, H3_ERROR> decodePrefixedInt(const uint8_t *&ptr, size_t &rem,
                                                                                 uint8_t prefixBits) noexcept
        {
            if (rem == 0) [[unlikely]]
            {
                return std::unexpected(H3_ERROR::H3_FRAME_ERROR);
            }
            const uint64_t maxPrefix = (1ULL << prefixBits) - 1ULL;
            const uint8_t b0 = *ptr++;
            --rem;
            uint64_t val = b0 & static_cast<uint8_t>(maxPrefix);
            if (val < maxPrefix)
            {
                return val;
            }
            uint64_t m = 0;
            while (rem > 0)
            {
                const uint8_t b = *ptr++;
                --rem;
                if (m > 62) [[unlikely]]
                {
                    return std::unexpected(H3_ERROR::H3_EXCESSIVE_LOAD);
                }
                const uint64_t chunk = static_cast<uint64_t>(b & 0x7fu);
                if (m == 63 && chunk > 1) [[unlikely]]
                {
                    return std::unexpected(H3_ERROR::H3_EXCESSIVE_LOAD);
                }
                const uint64_t addend = chunk << m;
                if (val > (std::numeric_limits<uint64_t>::max)() - addend) [[unlikely]]
                {
                    return std::unexpected(H3_ERROR::H3_EXCESSIVE_LOAD);
                }
                val += addend;
                m += 7;
                if ((b & 0x80u) == 0)
                {
                    return val;
                }
            }
            return std::unexpected(H3_ERROR::H3_FRAME_ERROR);
        }

        inline constexpr size_t kMaxHeaderEntries = 256;
        inline constexpr size_t kMaxHeaderBlockBytes = 64 << 10; // 64 KiB
        inline constexpr size_t kPerHeaderOverhead = 32;         // RFC 9114 Section 4.2.2 标准每首部开销

        /**
         * @brief 写入字符串字面量（RFC 9204 Section 4.1.2，H=0 明文字节）
         */
        inline void appendStringLiteral(std::string &out, std::string_view s)
        {
            encodePrefixedInt(out, 7, 0x00, s.size());
            out.append(s);
        }

        /**
         * @brief 读取字符串字面量
         */
        [[nodiscard]] inline std::expected<std::string, H3_ERROR> readStringLiteral(const uint8_t *&ptr,
                                                                                    size_t &rem) noexcept
        {
            if (rem == 0) [[unlikely]]
            {
                return std::unexpected(H3_ERROR::H3_FRAME_ERROR);
            }
            // RFC 9204 Section 4.1.2: 最高位为 H 标志（Huffman 压缩）
            if ((*ptr & 0x80u) != 0) [[unlikely]]
            {
                // 基线实现不支持 Huffman 压缩字面量，依规以协议帧错误拒绝
                return std::unexpected(H3_ERROR::H3_FRAME_ERROR);
            }
            auto lenRes = decodePrefixedInt(ptr, rem, 7);
            if (!lenRes)
            {
                return std::unexpected(lenRes.error());
            }
            const size_t len = static_cast<size_t>(*lenRes);
            if (len > kMaxHeaderBlockBytes) [[unlikely]]
            {
                return std::unexpected(H3_ERROR::H3_EXCESSIVE_LOAD);
            }
            if (rem < len) [[unlikely]]
            {
                return std::unexpected(H3_ERROR::H3_FRAME_ERROR);
            }
            std::string s(reinterpret_cast<const char *>(ptr), len);
            ptr += len;
            rem -= len;
            return s;
        }

        /**
         * @brief 将 HTTP 首部列表编码为 QPACK 头部块字节序列 (HEADERS 载荷)
         */
        inline void encodeHeaders(std::string &out, const std::vector<Header> &headers)
        {
            // RFC 9204 Section 4.5.1: 头部块前缀 (RIC = 0, Delta Base = 0)
            out.push_back('\0');
            out.push_back('\0');

            for (const auto &h : headers)
            {
                auto match = findStaticEntry(h.name, h.value);
                if (match.exactIndex)
                {
                    // 1. 完全匹配：Indexed Field Line with Static Reference (RFC 9204 Section 4.5.2)
                    // 模式: 1 1 Index (6 位前缀)
                    encodePrefixedInt(out, 6, 0xc0, *match.exactIndex);
                }
                else if (match.nameIndex)
                {
                    // 2. 键名匹配：Literal with Static Name Reference (RFC 9204 Section 4.5.4)
                    // 模式: 0 1 N 1 Index (4 位前缀, N=0, T=1 -> 0x50)
                    encodePrefixedInt(out, 4, 0x50, *match.nameIndex);
                    appendStringLiteral(out, h.value);
                }
                else
                {
                    // 3. 全字面量：Literal Without Name Reference (RFC 9204 Section 4.5.6)
                    // 模式: 0 0 1 0 N 0 NameLen (3 位前缀, N=0 -> 0x20)
                    encodePrefixedInt(out, 3, 0x20, h.name.size());
                    out.append(h.name);
                    appendStringLiteral(out, h.value);
                }
            }
        }

        /**
         * @brief 解码 QPACK 头部块字节序列为 HTTP 首部列表
         */
        [[nodiscard]] inline std::expected<std::vector<Header>, H3_ERROR> decodeHeaders(std::string_view block)
        {
            if (block.size() < 2) [[unlikely]]
            {
                return std::unexpected(H3_ERROR::H3_FRAME_ERROR);
            }
            const auto *ptr = reinterpret_cast<const uint8_t *>(block.data());
            size_t rem = block.size();

            // 跳过 RIC 与 Delta Base 前缀
            ptr += 2;
            rem -= 2;

            // QPACK 头部炸弹 (Decompression Bomb / CVE-2025-64702 Header Accordions) 防御
            size_t totalBytes = 0;

            std::vector<Header> result;
            result.reserve(8);

            while (rem > 0)
            {
                if (result.size() >= kMaxHeaderEntries) [[unlikely]]
                {
                    return std::unexpected(H3_ERROR::H3_EXCESSIVE_LOAD);
                }

                const uint8_t b = *ptr;
                if ((b & 0x80u) != 0)
                {
                    // Indexed Field Line (Section 4.5.2)
                    const bool isStatic = (b & 0x40u) != 0;
                    auto idxRes = decodePrefixedInt(ptr, rem, 6);
                    if (!idxRes)
                    {
                        return std::unexpected(idxRes.error());
                    }
                    if (!isStatic || *idxRes >= kStaticTable.size())
                    {
                        return std::unexpected(H3_ERROR::H3_FRAME_ERROR);
                    }
                    const auto &entry = kStaticTable[*idxRes];
                    totalBytes += entry.name.size() + entry.value.size() + kPerHeaderOverhead;
                    if (totalBytes > kMaxHeaderBlockBytes) [[unlikely]]
                    {
                        return std::unexpected(H3_ERROR::H3_EXCESSIVE_LOAD);
                    }
                    result.push_back(Header{std::string(entry.name), std::string(entry.value)});
                }
                else if ((b & 0x40u) != 0)
                {
                    // Literal with Name Reference (Section 4.5.4)
                    const bool isStatic = (b & 0x10u) != 0;
                    auto idxRes = decodePrefixedInt(ptr, rem, 4);
                    if (!idxRes)
                    {
                        return std::unexpected(idxRes.error());
                    }
                    if (!isStatic || *idxRes >= kStaticTable.size())
                    {
                        return std::unexpected(H3_ERROR::H3_FRAME_ERROR);
                    }
                    auto valRes = readStringLiteral(ptr, rem);
                    if (!valRes)
                    {
                        return std::unexpected(valRes.error());
                    }
                    const auto &entry = kStaticTable[*idxRes];
                    totalBytes += entry.name.size() + valRes->size() + kPerHeaderOverhead;
                    if (totalBytes > kMaxHeaderBlockBytes) [[unlikely]]
                    {
                        return std::unexpected(H3_ERROR::H3_EXCESSIVE_LOAD);
                    }
                    result.push_back(Header{std::string(entry.name), std::move(*valRes)});
                }
                else if ((b & 0x20u) != 0)
                {
                    // Literal Without Name Reference (Section 4.5.6)
                    // 模式: 0 0 1 0 N 0 NameLen (3 位前缀, N=0 -> 0x20)
                    // 第 3 位 (0x08) 为名称 Huffman 压缩标志 H
                    if ((b & 0x08u) != 0) [[unlikely]]
                    {
                        return std::unexpected(H3_ERROR::H3_FRAME_ERROR);
                    }
                    auto nameLenRes = decodePrefixedInt(ptr, rem, 3);
                    if (!nameLenRes)
                    {
                        return std::unexpected(nameLenRes.error());
                    }
                    const size_t nameLen = static_cast<size_t>(*nameLenRes);
                    if (nameLen > kMaxHeaderBlockBytes) [[unlikely]]
                    {
                        return std::unexpected(H3_ERROR::H3_EXCESSIVE_LOAD);
                    }
                    if (rem < nameLen) [[unlikely]]
                    {
                        return std::unexpected(H3_ERROR::H3_FRAME_ERROR);
                    }
                    std::string name(reinterpret_cast<const char *>(ptr), nameLen);
                    ptr += nameLen;
                    rem -= nameLen;

                    auto valRes = readStringLiteral(ptr, rem);
                    if (!valRes)
                    {
                        return std::unexpected(valRes.error());
                    }
                    totalBytes += name.size() + valRes->size() + kPerHeaderOverhead;
                    if (totalBytes > kMaxHeaderBlockBytes) [[unlikely]]
                    {
                        return std::unexpected(H3_ERROR::H3_EXCESSIVE_LOAD);
                    }
                    result.push_back(Header{std::move(name), std::move(*valRes)});
                }
                else
                {
                    // 其他指令（如动态表容量调整等），在无动态表基线实现中跳过后续
                    break;
                }
            }

            return result;
        }

    } // namespace http::v3
} // namespace mynet
