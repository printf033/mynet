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
        /**
         * @brief 解码后的单个 HTTP 首部字段
         */
        struct Header
        {
            std::string name{};
            std::string value{};
        };

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

            /// @brief RFC 7541 Appendix B Huffman 码字（符号 256 为 EOS）
            inline constexpr std::array<uint32_t, 257> kHuffmanCodes = {{
                0x00001ff8u, 0x007fffd8u, 0x0fffffe2u, 0x0fffffe3u, 0x0fffffe4u, 0x0fffffe5u, 0x0fffffe6u, 0x0fffffe7u,
                0x0fffffe8u, 0x00ffffeau, 0x3ffffffcu, 0x0fffffe9u, 0x0fffffeau, 0x3ffffffdu, 0x0fffffebu, 0x0fffffecu,
                0x0fffffedu, 0x0fffffeeu, 0x0fffffefu, 0x0ffffff0u, 0x0ffffff1u, 0x0ffffff2u, 0x3ffffffeu, 0x0ffffff3u,
                0x0ffffff4u, 0x0ffffff5u, 0x0ffffff6u, 0x0ffffff7u, 0x0ffffff8u, 0x0ffffff9u, 0x0ffffffau, 0x0ffffffbu,
                0x00000014u, 0x000003f8u, 0x000003f9u, 0x00000ffau, 0x00001ff9u, 0x00000015u, 0x000000f8u, 0x000007fau,
                0x000003fau, 0x000003fbu, 0x000000f9u, 0x000007fbu, 0x000000fau, 0x00000016u, 0x00000017u, 0x00000018u,
                0x00000000u, 0x00000001u, 0x00000002u, 0x00000019u, 0x0000001au, 0x0000001bu, 0x0000001cu, 0x0000001du,
                0x0000001eu, 0x0000001fu, 0x0000005cu, 0x000000fbu, 0x00007ffcu, 0x00000020u, 0x00000ffbu, 0x000003fcu,
                0x00001ffau, 0x00000021u, 0x0000005du, 0x0000005eu, 0x0000005fu, 0x00000060u, 0x00000061u, 0x00000062u,
                0x00000063u, 0x00000064u, 0x00000065u, 0x00000066u, 0x00000067u, 0x00000068u, 0x00000069u, 0x0000006au,
                0x0000006bu, 0x0000006cu, 0x0000006du, 0x0000006eu, 0x0000006fu, 0x00000070u, 0x00000071u, 0x00000072u,
                0x000000fcu, 0x00000073u, 0x000000fdu, 0x00001ffbu, 0x0007fff0u, 0x00001ffcu, 0x00003ffcu, 0x00000022u,
                0x00007ffdu, 0x00000003u, 0x00000023u, 0x00000004u, 0x00000024u, 0x00000005u, 0x00000025u, 0x00000026u,
                0x00000027u, 0x00000006u, 0x00000074u, 0x00000075u, 0x00000028u, 0x00000029u, 0x0000002au, 0x00000007u,
                0x0000002bu, 0x00000076u, 0x0000002cu, 0x00000008u, 0x00000009u, 0x0000002du, 0x00000077u, 0x00000078u,
                0x00000079u, 0x0000007au, 0x0000007bu, 0x00007ffeu, 0x000007fcu, 0x00003ffdu, 0x00001ffdu, 0x0ffffffcu,
                0x000fffe6u, 0x003fffd2u, 0x000fffe7u, 0x000fffe8u, 0x003fffd3u, 0x003fffd4u, 0x003fffd5u, 0x007fffd9u,
                0x003fffd6u, 0x007fffdau, 0x007fffdbu, 0x007fffdcu, 0x007fffddu, 0x007fffdeu, 0x00ffffebu, 0x007fffdfu,
                0x00ffffecu, 0x00ffffedu, 0x003fffd7u, 0x007fffe0u, 0x00ffffeeu, 0x007fffe1u, 0x007fffe2u, 0x007fffe3u,
                0x007fffe4u, 0x001fffdcu, 0x003fffd8u, 0x007fffe5u, 0x003fffd9u, 0x007fffe6u, 0x007fffe7u, 0x00ffffefu,
                0x003fffdau, 0x001fffddu, 0x000fffe9u, 0x003fffdbu, 0x003fffdcu, 0x007fffe8u, 0x007fffe9u, 0x001fffdeu,
                0x007fffeau, 0x003fffddu, 0x003fffdeu, 0x00fffff0u, 0x001fffdfu, 0x003fffdfu, 0x007fffebu, 0x007fffecu,
                0x001fffe0u, 0x001fffe1u, 0x003fffe0u, 0x001fffe2u, 0x007fffedu, 0x003fffe1u, 0x007fffeeu, 0x007fffefu,
                0x000fffeau, 0x003fffe2u, 0x003fffe3u, 0x003fffe4u, 0x007ffff0u, 0x003fffe5u, 0x003fffe6u, 0x007ffff1u,
                0x03ffffe0u, 0x03ffffe1u, 0x000fffebu, 0x0007fff1u, 0x003fffe7u, 0x007ffff2u, 0x003fffe8u, 0x01ffffecu,
                0x03ffffe2u, 0x03ffffe3u, 0x03ffffe4u, 0x07ffffdeu, 0x07ffffdfu, 0x03ffffe5u, 0x00fffff1u, 0x01ffffedu,
                0x0007fff2u, 0x001fffe3u, 0x03ffffe6u, 0x07ffffe0u, 0x07ffffe1u, 0x03ffffe7u, 0x07ffffe2u, 0x00fffff2u,
                0x001fffe4u, 0x001fffe5u, 0x03ffffe8u, 0x03ffffe9u, 0x0ffffffdu, 0x07ffffe3u, 0x07ffffe4u, 0x07ffffe5u,
                0x000fffecu, 0x00fffff3u, 0x000fffedu, 0x001fffe6u, 0x003fffe9u, 0x001fffe7u, 0x001fffe8u, 0x007ffff3u,
                0x003fffeau, 0x003fffebu, 0x01ffffeeu, 0x01ffffefu, 0x00fffff4u, 0x00fffff5u, 0x03ffffeau, 0x007ffff4u,
                0x03ffffebu, 0x07ffffe6u, 0x03ffffecu, 0x03ffffedu, 0x07ffffe7u, 0x07ffffe8u, 0x07ffffe9u, 0x07ffffeau,
                0x07ffffebu, 0x0ffffffeu, 0x07ffffecu, 0x07ffffedu, 0x07ffffeeu, 0x07ffffefu, 0x07fffff0u, 0x03ffffeeu,
                0x3fffffffu,
            }};

            /// @brief 与 kHuffmanCodes 一一对应的码长（bit）
            inline constexpr std::array<uint8_t, 257> kHuffmanCodeLengths = {{
                13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28, 28, 28,
                28, 28, 28, 28, 28, 28, 6,  10, 10, 12, 13, 6,  8,  11, 10, 10, 8,  11, 8,  6,  6,  6,  5,  5,  5,  6,
                6,  6,  6,  6,  6,  6,  7,  8,  15, 6,  12, 10, 13, 6,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,
                7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  8,  7,  8,  13, 19, 13, 14, 6,  15, 5,  6,  5,  6,  5,  6,  6,
                6,  5,  7,  7,  6,  6,  6,  5,  6,  7,  6,  5,  5,  6,  7,  7,  7,  7,  7,  15, 11, 14, 13, 28, 20, 22,
                20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23,
                22, 23, 23, 24, 22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22,
                23, 23, 20, 22, 22, 22, 23, 22, 22, 23, 26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
                19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22, 22,
                25, 25, 24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26, 30,
            }};

            /// @brief 解码树节点数上限：257 个叶子最多产生 256 个内部节点
            inline constexpr size_t kHuffmanMaxNodes = 600;

            struct HuffmanNode
            {
                int16_t child[2]{-1, -1};
                int16_t symbol{-1}; ///< 叶子节点为符号值，内部节点为 -1
            };

            struct HuffmanTree
            {
                std::array<HuffmanNode, kHuffmanMaxNodes> nodes{};
                size_t count{0};
            };

            /**
             * @brief 由码表构建 Huffman 解码树（编译期完成，运行时零构建开销）
             */
            [[nodiscard]] constexpr HuffmanTree buildHuffmanTree() noexcept
            {
                HuffmanTree tree{};
                tree.count = 1; // 索引 0 为根
                for (size_t sym = 0; sym < kHuffmanCodes.size(); ++sym)
                {
                    const uint32_t code = kHuffmanCodes[sym];
                    const uint8_t len = kHuffmanCodeLengths[sym];
                    size_t node = 0;
                    for (int i = static_cast<int>(len) - 1; i >= 0; --i)
                    {
                        const int bit = static_cast<int>((code >> static_cast<unsigned>(i)) & 1u);
                        if (tree.nodes[node].child[bit] < 0)
                        {
                            const size_t next = tree.count;
                            if (next >= kHuffmanMaxNodes)
                            {
                                return tree; // 码表损坏时提前退出，解码会被 node<0 拒绝
                            }
                            tree.nodes[next] = HuffmanNode{};
                            tree.nodes[node].child[bit] = static_cast<int16_t>(next);
                            ++tree.count;
                        }
                        node = static_cast<size_t>(tree.nodes[node].child[bit]);
                    }
                    tree.nodes[node].symbol = static_cast<int16_t>(sym);
                }
                return tree;
            }

            inline constexpr HuffmanTree kHuffmanTree = buildHuffmanTree();

            /**
             * @brief RFC 7541 Section 5.2 Huffman 解码
             *
             * 尾部不足 8 bit 的剩余位必须是 EOS 的前缀（全 1），否则属于非法填充；
             * 出现 EOS 本身同样是解码错误。
             */
            [[nodiscard]] inline std::expected<std::string, HPACK_ERROR> huffmanDecode(std::string_view in) noexcept
            {
                std::string out;
                out.reserve(in.size() * 2);
                size_t node = 0;
                uint32_t pendingBits = 0;
                uint32_t pendingValue = 0;

                for (const unsigned char byte : in)
                {
                    for (int i = 7; i >= 0; --i)
                    {
                        const int bit = static_cast<int>((byte >> i) & 1u);
                        const int16_t next = kHuffmanTree.nodes[node].child[bit];
                        if (next < 0) [[unlikely]]
                        {
                            return std::unexpected(HPACK_ERROR::INVALID_HUFFMAN);
                        }
                        node = static_cast<size_t>(next);
                        ++pendingBits;
                        pendingValue = (pendingValue << 1) | static_cast<uint32_t>(bit);

                        const int16_t sym = kHuffmanTree.nodes[node].symbol;
                        if (sym >= 0)
                        {
                            if (sym == 256) [[unlikely]]
                            {
                                return std::unexpected(HPACK_ERROR::INVALID_HUFFMAN); // EOS 不得出现
                            }
                            out.push_back(static_cast<char>(sym));
                            node = 0;
                            pendingBits = 0;
                            pendingValue = 0;
                        }
                    }
                }

                if (pendingBits > 7) [[unlikely]]
                {
                    // 不完整的码字，或超过 7 bit 的填充
                    return std::unexpected(HPACK_ERROR::INVALID_HUFFMAN);
                }
                if (pendingBits > 0)
                {
                    const uint32_t mask = (1u << pendingBits) - 1u;
                    if ((pendingValue & mask) != mask) [[unlikely]]
                    {
                        return std::unexpected(HPACK_ERROR::INVALID_HUFFMAN);
                    }
                }
                return out;
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
