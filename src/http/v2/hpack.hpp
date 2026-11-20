#pragma once

/**
 * @file handler/http/v2/hpack.hpp
 * @brief RFC 7541 HPACK 首部压缩编解码器（静态表、动态表与 Huffman 解码）。
 *
 * 真实的 HTTP/2 客户端（curl/nghttp2、浏览器）总是以 HPACK 压缩首部块发送请求，
 * 并以 HPACK 解码服务端响应。缺少这一层时，帧层再正确也无法与任何标准客户端
 * 完成一次请求/响应。本文件补齐该层：
 *
 * - 解码：静态索引、带增量索引/不索引/从不索引的字面量、动态表大小更新，
 *   以及 Huffman 编码字符串（客户端默认开启）。
 * - 编码：静态表精确匹配走索引，其余走不索引字面量，避免污染对端动态表。
 *
 * 动态表是连接级状态：同一连接上的所有流共享一个 HpackDecoder 实例。
 */

#include "../common.hpp"
#include "../huffman.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <expected>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace mynet
{
    namespace http::v2
    {
        using Header = mynet::http::Header;

        /**
         * @brief HPACK 解码错误
         */
        enum class HPACK_ERROR : uint8_t
        {
            TRUNCATED = 0,            ///< 首部块在字段中途结束
            INVALID_INTEGER = 1,      ///< 前缀整数溢出或编码非法
            INVALID_INDEX = 2,        ///< 静态/动态表索引越界
            INVALID_HUFFMAN = 3,      ///< Huffman 码字非法、出现 EOS 或填充不合法
            INVALID_TABLE_SIZE = 4,   ///< 动态表大小更新超出本端宣告上限或位置非法
            HEADER_LIST_TOO_LARGE = 5 ///< 首部列表超过本端可接受的规模
        };

        [[nodiscard]] constexpr std::string_view toString(HPACK_ERROR err) noexcept
        {
            switch (err)
            {
            case HPACK_ERROR::TRUNCATED:
                return "the header block ended in the middle of a field";
            case HPACK_ERROR::INVALID_INTEGER:
                return "an HPACK prefix integer is malformed";
            case HPACK_ERROR::INVALID_INDEX:
                return "an HPACK table index is out of range";
            case HPACK_ERROR::INVALID_HUFFMAN:
                return "an HPACK Huffman string is malformed";
            case HPACK_ERROR::INVALID_TABLE_SIZE:
                return "an HPACK dynamic table size update is not acceptable";
            case HPACK_ERROR::HEADER_LIST_TOO_LARGE:
                return "the decoded header list exceeds the configured maximum";
            }
            return "unknown HPACK error";
        }

        namespace hpack
        {
            /// @brief RFC 7541 默认动态表大小 (SETTINGS_HEADER_TABLE_SIZE)
            inline constexpr uint32_t kDefaultDynamicTableSize = 4096;

            /// @brief 解码后首部列表的字节上限（name+value+32 计入），防 HPACK 膨胀
            inline constexpr size_t kMaxHeaderListBytes = 64 << 10;

            /// @brief 单次首部块允许的字段数量上限
            inline constexpr size_t kMaxHeaderCount = 256;

            /// @brief 动态表条目固定开销（RFC 7541 Section 4.1）
            inline constexpr size_t kEntryOverhead = 32;

            /// @brief RFC 7541 Appendix A 静态表条目
            struct StaticEntry
            {
                std::string_view name;
                std::string_view value;
            };

            inline constexpr std::array<StaticEntry, 61> kStaticTable = {{
                {":authority", ""},
                {":method", "GET"},
                {":method", "POST"},
                {":path", "/"},
                {":path", "/index.html"},
                {":scheme", "http"},
                {":scheme", "https"},
                {":status", "200"},
                {":status", "204"},
                {":status", "206"},
                {":status", "304"},
                {":status", "400"},
                {":status", "404"},
                {":status", "500"},
                {"accept-charset", ""},
                {"accept-encoding", "gzip, deflate"},
                {"accept-language", ""},
                {"accept-ranges", ""},
                {"accept", ""},
                {"access-control-allow-origin", ""},
                {"age", ""},
                {"allow", ""},
                {"authorization", ""},
                {"cache-control", ""},
                {"content-disposition", ""},
                {"content-encoding", ""},
                {"content-language", ""},
                {"content-length", ""},
                {"content-location", ""},
                {"content-range", ""},
                {"content-type", ""},
                {"cookie", ""},
                {"date", ""},
                {"etag", ""},
                {"expect", ""},
                {"expires", ""},
                {"from", ""},
                {"host", ""},
                {"if-match", ""},
                {"if-modified-since", ""},
                {"if-none-match", ""},
                {"if-range", ""},
                {"if-unmodified-since", ""},
                {"last-modified", ""},
                {"link", ""},
                {"location", ""},
                {"max-forwards", ""},
                {"proxy-authenticate", ""},
                {"proxy-authorization", ""},
                {"range", ""},
                {"referer", ""},
                {"refresh", ""},
                {"retry-after", ""},
                {"server", ""},
                {"set-cookie", ""},
                {"strict-transport-security", ""},
                {"transfer-encoding", ""},
                {"user-agent", ""},
                {"vary", ""},
                {"via", ""},
                {"www-authenticate", ""},
            }};

            /**
             * @brief RFC 7541 Section 5.2 Huffman 解码
             */
            [[nodiscard]] inline std::expected<std::string, HPACK_ERROR> huffmanDecode(std::string_view in) noexcept
            {
                auto res = http::huffman::decode(in);
                if (!res) [[unlikely]]
                {
                    return std::unexpected(HPACK_ERROR::INVALID_HUFFMAN);
                }
                return std::move(*res);
            }

            /**
             * @brief RFC 7541 Section 5.1 前缀整数解码
             */
            [[nodiscard]] inline std::expected<uint64_t, HPACK_ERROR> decodeInteger(const uint8_t *&p, size_t &rem,
                                                                                    uint8_t prefixBits) noexcept
            {
                if (rem == 0) [[unlikely]]
                {
                    return std::unexpected(HPACK_ERROR::TRUNCATED);
                }
                const uint64_t maxPrefix = (1ull << prefixBits) - 1ull;
                uint64_t value = static_cast<uint64_t>(*p) & maxPrefix;
                ++p;
                --rem;
                if (value < maxPrefix)
                {
                    return value;
                }
                uint64_t shift = 0;
                while (true)
                {
                    if (rem == 0) [[unlikely]]
                    {
                        return std::unexpected(HPACK_ERROR::TRUNCATED);
                    }
                    const uint8_t byte = *p;
                    ++p;
                    --rem;
                    if (shift > 56) [[unlikely]]
                    {
                        return std::unexpected(HPACK_ERROR::INVALID_INTEGER);
                    }
                    value += static_cast<uint64_t>(byte & 0x7fu) << shift;
                    shift += 7;
                    if ((byte & 0x80u) == 0)
                    {
                        break;
                    }
                }
                return value;
            }

            /**
             * @brief RFC 7541 Section 5.2 字符串字面量解码（自动识别 Huffman 标志）
             */
            [[nodiscard]] inline std::expected<std::string, HPACK_ERROR> decodeString(const uint8_t *&p,
                                                                                      size_t &rem) noexcept
            {
                if (rem == 0) [[unlikely]]
                {
                    return std::unexpected(HPACK_ERROR::TRUNCATED);
                }
                const bool huffman = (*p & 0x80u) != 0;
                const auto len = decodeInteger(p, rem, 7);
                if (!len)
                {
                    return std::unexpected(len.error());
                }
                if (*len > rem) [[unlikely]]
                {
                    return std::unexpected(HPACK_ERROR::TRUNCATED);
                }
                // 单个字符串的长度不单独设限：这里拒绝会让首部块解析**中途**失败，
                // 后续字段的增量索引项无法插入动态表，连接级压缩状态随之失步。
                // 列表规模统一由 append() 在完整解析之后裁决（见 decode()）。
                const std::string_view raw(reinterpret_cast<const char *>(p), static_cast<size_t>(*len));
                p += *len;
                rem -= static_cast<size_t>(*len);
                if (huffman)
                {
                    return huffmanDecode(raw);
                }
                return std::string(raw);
            }

            /**
             * @brief RFC 7541 Section 5.1 前缀整数编码
             */
            inline void encodeInteger(std::string &out, uint8_t prefixBits, uint8_t pattern, uint64_t value)
            {
                const uint64_t maxPrefix = (1ull << prefixBits) - 1ull;
                if (value < maxPrefix)
                {
                    out.push_back(static_cast<char>(pattern | static_cast<uint8_t>(value)));
                    return;
                }
                out.push_back(static_cast<char>(pattern | static_cast<uint8_t>(maxPrefix)));
                value -= maxPrefix;
                while (value >= 128)
                {
                    out.push_back(static_cast<char>((value & 0x7fu) | 0x80u));
                    value >>= 7;
                }
                out.push_back(static_cast<char>(value));
            }
        } // namespace hpack

        /**
         * @class HpackDecoder
         * @brief 连接级 HPACK 解码器，维护动态表状态。
         */
        class HpackDecoder
        {
        public:
            HpackDecoder() noexcept = default;

            /**
             * @brief 复位动态表（新连接 / 连接拆除时调用）
             */
            void reset() noexcept
            {
                dynamic_.clear();
                dynamicBytes_ = 0;
                tableMax_ = hpack::kDefaultDynamicTableSize;
                settingsMaxTable_ = hpack::kDefaultDynamicTableSize;
                sawField_ = false;
            }

            /**
             * @brief 设置本端 SETTINGS_HEADER_TABLE_SIZE 宣告的动态表上限
             */
            void setMaxTableSize(uint32_t n) noexcept
            {
                settingsMaxTable_ = n == 0 ? 0 : n;
                if (tableMax_ > settingsMaxTable_)
                {
                    tableMax_ = settingsMaxTable_;
                    evict();
                }
            }

            /**
             * @brief 解码一个完整的首部块
             */
            [[nodiscard]] std::expected<std::vector<Header>, HPACK_ERROR> decode(std::string_view block)
            {
                std::vector<Header> headers;
                const auto *p = reinterpret_cast<const uint8_t *>(block.data());
                size_t rem = block.size();
                size_t listBytes = 0;
                sawField_ = false;
                // 首部列表超限后**不能**提前返回：动态表是连接级状态，跳过剩余字段
                // 的增量索引项会让本端与对端索引空间整体错位，后续请求会静默解出
                // 错误的伪首部。因此继续解析（不收集）以保持表同步，最后再报错。
                bool overflow = false;

                while (rem > 0)
                {
                    const uint8_t b = *p;
                    if ((b & 0x80u) != 0) // Section 6.1 索引首部字段
                    {
                        auto index = hpack::decodeInteger(p, rem, 7);
                        if (!index)
                        {
                            return std::unexpected(index.error());
                        }
                        auto entry = entryAt(*index);
                        if (!entry)
                        {
                            return std::unexpected(entry.error());
                        }
                        sawField_ = true;
                        if (!overflow && !append(headers, *entry, listBytes)) [[unlikely]]
                        {
                            overflow = true;
                        }
                        continue;
                    }
                    if ((b & 0xe0u) == 0x20u) // Section 6.3 动态表大小更新
                    {
                        if (sawField_) [[unlikely]]
                        {
                            return std::unexpected(HPACK_ERROR::INVALID_TABLE_SIZE);
                        }
                        auto size = hpack::decodeInteger(p, rem, 5);
                        if (!size)
                        {
                            return std::unexpected(size.error());
                        }
                        if (*size > settingsMaxTable_) [[unlikely]]
                        {
                            return std::unexpected(HPACK_ERROR::INVALID_TABLE_SIZE);
                        }
                        tableMax_ = static_cast<uint32_t>(*size);
                        evict();
                        continue;
                    }

                    // Section 6.2 字面量首部字段：01 增量索引 / 0000 不索引 / 0001 从不索引
                    const bool incremental = (b & 0xc0u) == 0x40u;
                    const uint8_t namePrefix = incremental ? 6 : 4;
                    auto nameIndex = hpack::decodeInteger(p, rem, namePrefix);
                    if (!nameIndex)
                    {
                        return std::unexpected(nameIndex.error());
                    }

                    Header header;
                    if (*nameIndex == 0)
                    {
                        auto name = hpack::decodeString(p, rem);
                        if (!name)
                        {
                            return std::unexpected(name.error());
                        }
                        header.name = std::move(*name);
                    }
                    else
                    {
                        auto name = nameAt(*nameIndex);
                        if (!name)
                        {
                            return std::unexpected(name.error());
                        }
                        header.name = std::move(*name);
                    }
                    auto value = hpack::decodeString(p, rem);
                    if (!value)
                    {
                        return std::unexpected(value.error());
                    }
                    header.value = std::move(*value);

                    sawField_ = true;
                    if (!overflow && !append(headers, header, listBytes)) [[unlikely]]
                    {
                        overflow = true;
                    }
                    if (incremental)
                    {
                        // 即使因超限而不再收集，也必须插入动态表：对端已按同一规则插入
                        addEntry(header);
                    }
                }
                if (overflow) [[unlikely]]
                {
                    headers.clear(); // 截断的首部列表没有语义价值，交由调用方按超限处理
                    return std::unexpected(HPACK_ERROR::HEADER_LIST_TOO_LARGE);
                }
                return headers;
            }

        private:
            [[nodiscard]] std::expected<Header, HPACK_ERROR> entryAt(uint64_t index) const
            {
                if (index == 0) [[unlikely]]
                {
                    return std::unexpected(HPACK_ERROR::INVALID_INDEX);
                }
                if (index <= hpack::kStaticTable.size())
                {
                    const auto &entry = hpack::kStaticTable[static_cast<size_t>(index - 1)];
                    return Header{std::string(entry.name), std::string(entry.value)};
                }
                const uint64_t dyn = index - hpack::kStaticTable.size() - 1;
                if (dyn >= dynamic_.size()) [[unlikely]]
                {
                    return std::unexpected(HPACK_ERROR::INVALID_INDEX);
                }
                return dynamic_[static_cast<size_t>(dyn)];
            }

            [[nodiscard]] std::expected<std::string, HPACK_ERROR> nameAt(uint64_t index) const
            {
                if (index == 0) [[unlikely]]
                {
                    return std::unexpected(HPACK_ERROR::INVALID_INDEX);
                }
                if (index <= hpack::kStaticTable.size())
                {
                    return std::string(hpack::kStaticTable[static_cast<size_t>(index - 1)].name);
                }
                const uint64_t dyn = index - hpack::kStaticTable.size() - 1;
                if (dyn >= dynamic_.size()) [[unlikely]]
                {
                    return std::unexpected(HPACK_ERROR::INVALID_INDEX);
                }
                return dynamic_[static_cast<size_t>(dyn)].name;
            }

            static size_t entrySize(const Header &header) noexcept
            {
                return header.name.size() + header.value.size() + hpack::kEntryOverhead;
            }

            [[nodiscard]] static bool append(std::vector<Header> &headers, const Header &header, size_t &listBytes)
            {
                if (headers.size() >= hpack::kMaxHeaderCount)
                {
                    return false;
                }
                if (listBytes + entrySize(header) > hpack::kMaxHeaderListBytes)
                {
                    return false;
                }
                listBytes += entrySize(header);
                headers.push_back(header);
                return true;
            }

            void addEntry(const Header &header)
            {
                const size_t size = entrySize(header);
                if (size > tableMax_)
                {
                    dynamic_.clear();
                    dynamicBytes_ = 0;
                    return;
                }
                while (dynamicBytes_ + size > tableMax_ && !dynamic_.empty())
                {
                    dynamicBytes_ -= entrySize(dynamic_.back());
                    dynamic_.pop_back();
                }
                dynamic_.push_front(header);
                dynamicBytes_ += size;
            }

            void evict() noexcept
            {
                while (dynamicBytes_ > tableMax_ && !dynamic_.empty())
                {
                    dynamicBytes_ -= entrySize(dynamic_.back());
                    dynamic_.pop_back();
                }
            }

            std::deque<Header> dynamic_{};
            size_t dynamicBytes_ = 0;
            uint32_t tableMax_ = hpack::kDefaultDynamicTableSize;
            uint32_t settingsMaxTable_ = hpack::kDefaultDynamicTableSize;
            bool sawField_ = false;
        };

        /**
         * @class HpackEncoder
         * @brief 响应首部编码器：静态表命中走索引，其余走不索引字面量。
         *
         * 不使用动态表与 Huffman：响应首部通常只有几个字段，避免维护连接级编码状态
         * 换来的是无状态、可预测的输出，对端（nghttp2/浏览器）都能正确解码。
         */
        class HpackEncoder
        {
        public:
            HpackEncoder() noexcept = default;

            void reset() noexcept {}

            [[nodiscard]] static std::string encode(const std::vector<Header> &headers)
            {
                std::string out;
                for (const Header &header : headers)
                {
                    encodeHeader(out, header);
                }
                return out;
            }

            [[nodiscard]] static std::string encode(const Header &header)
            {
                std::string out;
                encodeHeader(out, header);
                return out;
            }

        private:
            static void encodeString(std::string &out, std::string_view value)
            {
                // H=0：不做 Huffman 压缩，长度按 7 位前缀整数编码
                hpack::encodeInteger(out, 7, 0x00, value.size());
                out.append(value);
            }

            static void encodeHeader(std::string &out, const Header &header)
            {
                for (size_t i = 0; i < hpack::kStaticTable.size(); ++i)
                {
                    if (hpack::kStaticTable[i].name == header.name && hpack::kStaticTable[i].value == header.value)
                    {
                        hpack::encodeInteger(out, 7, 0x80, i + 1);
                        return;
                    }
                }
                for (size_t i = 0; i < hpack::kStaticTable.size(); ++i)
                {
                    if (hpack::kStaticTable[i].name == header.name)
                    {
                        hpack::encodeInteger(out, 4, 0x00, i + 1);
                        encodeString(out, header.value);
                        return;
                    }
                }
                hpack::encodeInteger(out, 4, 0x00, 0);
                encodeString(out, header.name);
                encodeString(out, header.value);
            }
        };
    } // namespace http::v2
} // namespace mynet
