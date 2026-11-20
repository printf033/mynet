#pragma once

/**
 * @file http/huffman.hpp
 * @brief RFC 7541 / RFC 9204 共享的标准 HTTP Huffman 静态编解码树实现。
 *
 * HPACK (RFC 7541 Appendix B) 与 QPACK (RFC 9204 Section 4.1.2)
 * 共享完全一致的规范 Huffman 码表与前缀填充约定。
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>

namespace mynet::http::huffman
{
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
                        return tree;
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
     * @brief RFC 7541 Section 5.2 / RFC 9204 Section 4.1.2 Huffman 解码
     */
    [[nodiscard]] inline std::expected<std::string, bool> decode(std::string_view in) noexcept
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
                    return std::unexpected(false);
                }
                node = static_cast<size_t>(next);
                ++pendingBits;
                pendingValue = (pendingValue << 1) | static_cast<uint32_t>(bit);

                const int16_t sym = kHuffmanTree.nodes[node].symbol;
                if (sym >= 0)
                {
                    if (sym == 256) [[unlikely]]
                    {
                        return std::unexpected(false); // EOS 不得出现
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
            return std::unexpected(false);
        }
        if (pendingBits > 0)
        {
            const uint32_t mask = (1u << pendingBits) - 1u;
            if ((pendingValue & mask) != mask) [[unlikely]]
            {
                return std::unexpected(false);
            }
        }
        return out;
    }

} // namespace mynet::http::huffman
