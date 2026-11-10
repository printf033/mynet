// RFC 7541 HPACK 编解码器：以附录 C 的规范字节序列为黄金用例，覆盖静态索引、
// 动态表、Huffman 字符串、表大小更新与畸形输入。
#include "handler/http/v2/hpack.hpp"
#include <gtest/gtest.h>
#include <string>
#include <vector>

using namespace mynet;
using namespace mynet::http::v2;

namespace
{
    [[nodiscard]] std::string bytes(std::initializer_list<int> values)
    {
        std::string out;
        out.reserve(values.size());
        for (const int value : values)
        {
            out.push_back(static_cast<char>(value));
        }
        return out;
    }

    [[nodiscard]] std::string headerName(const std::vector<Header> &headers, size_t i)
    {
        return i < headers.size() ? headers[i].name : std::string();
    }

    [[nodiscard]] std::string headerValue(const std::vector<Header> &headers, size_t i)
    {
        return i < headers.size() ? headers[i].value : std::string();
    }
} // namespace

TEST(Hpack, StaticIndexedFieldDecodes)
{
    HpackDecoder decoder;
    const auto headers = decoder.decode(bytes({0x88})); // :status 200
    ASSERT_TRUE(headers.has_value());
    ASSERT_EQ(headers->size(), 1u);
    EXPECT_EQ(headerName(*headers, 0), ":status");
    EXPECT_EQ(headerValue(*headers, 0), "200");
}

TEST(Hpack, Rfc7541RequestWithoutHuffman)
{
    // RFC 7541 Appendix C.3.1: 第一个请求，:authority 以明文发送
    HpackDecoder decoder;
    const auto headers = decoder.decode(bytes({
        0x82, 0x86, 0x84, 0x41, 0x0f, 'w', 'w', 'w', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
    }));
    ASSERT_TRUE(headers.has_value());
    ASSERT_EQ(headers->size(), 4u);
    EXPECT_EQ(headerName(*headers, 0), ":method");
    EXPECT_EQ(headerValue(*headers, 0), "GET");
    EXPECT_EQ(headerName(*headers, 1), ":scheme");
    EXPECT_EQ(headerValue(*headers, 1), "http");
    EXPECT_EQ(headerName(*headers, 2), ":path");
    EXPECT_EQ(headerValue(*headers, 2), "/");
    EXPECT_EQ(headerName(*headers, 3), ":authority");
    EXPECT_EQ(headerValue(*headers, 3), "www.example.com");
}

TEST(Hpack, Rfc7541RequestWithHuffman)
{
    // RFC 7541 Appendix C.4.1: Huffman 编码的 :authority
    HpackDecoder decoder;
    const auto headers = decoder.decode(bytes({
        0x82,
        0x86,
        0x84,
        0x41,
        0x8c,
        0xf1,
        0xe3,
        0xc2,
        0xe5,
        0xf2,
        0x3a,
        0x6b,
        0xa0,
        0xab,
        0x90,
        0xf4,
        0xff,
    }));
    ASSERT_TRUE(headers.has_value());
    ASSERT_EQ(headers->size(), 4u);
    EXPECT_EQ(headerValue(*headers, 3), "www.example.com");
}

TEST(Hpack, Rfc7541SecondRequestUsesTheDynamicTable)
{
    // RFC 7541 Appendix C.4.2: 第一请求插入动态表，第二请求用索引 62 引用
    HpackDecoder decoder;
    const auto first = decoder.decode(bytes({
        0x82,
        0x86,
        0x84,
        0x41,
        0x8c,
        0xf1,
        0xe3,
        0xc2,
        0xe5,
        0xf2,
        0x3a,
        0x6b,
        0xa0,
        0xab,
        0x90,
        0xf4,
        0xff,
    }));
    ASSERT_TRUE(first.has_value());
    ASSERT_EQ(first->size(), 4u);

    const auto second = decoder.decode(bytes({
        0x82,
        0x86,
        0x84,
        0xbe,
        0x58,
        0x86,
        0xa8,
        0xeb,
        0x10,
        0x64,
        0x9c,
        0xbf,
    }));
    ASSERT_TRUE(second.has_value());
    ASSERT_EQ(second->size(), 5u);
    EXPECT_EQ(headerName(*second, 3), ":authority");
    EXPECT_EQ(headerValue(*second, 3), "www.example.com");
    EXPECT_EQ(headerName(*second, 4), "cache-control");
    EXPECT_EQ(headerValue(*second, 4), "no-cache");
}

TEST(Hpack, DynamicTableSizeUpdateClearsTheTable)
{
    HpackDecoder decoder;
    const auto headers = decoder.decode(bytes({0x20, 0x82})); // size update 0, 然后 :method GET
    ASSERT_TRUE(headers.has_value());
    ASSERT_EQ(headers->size(), 1u);
    EXPECT_EQ(headerValue(*headers, 0), "GET");
}

TEST(Hpack, DynamicTableSizeUpdateAboveTheAdvertisedLimitIsRejected)
{
    HpackDecoder decoder;
    // 0x3f 0xe2 0x1f = 前缀 5 位整数 4097，超过默认 4096
    const auto headers = decoder.decode(bytes({0x3f, 0xe2, 0x1f}));
    ASSERT_FALSE(headers.has_value());
    EXPECT_EQ(headers.error(), HPACK_ERROR::INVALID_TABLE_SIZE);
}

TEST(Hpack, DynamicTableSizeUpdateAfterAFieldIsRejected)
{
    HpackDecoder decoder;
    const auto headers = decoder.decode(bytes({0x82, 0x20}));
    ASSERT_FALSE(headers.has_value());
    EXPECT_EQ(headers.error(), HPACK_ERROR::INVALID_TABLE_SIZE);
}

TEST(Hpack, TruncatedBlockIsRejected)
{
    HpackDecoder decoder;
    const auto headers = decoder.decode(bytes({0x41})); // 字面量声明了名称索引但缺值
    ASSERT_FALSE(headers.has_value());
    EXPECT_EQ(headers.error(), HPACK_ERROR::TRUNCATED);
}

TEST(Hpack, InvalidIndexIsRejected)
{
    HpackDecoder decoder;
    const auto headers = decoder.decode(bytes({0xff, 0x00})); // 索引 127，超出静态表
    ASSERT_FALSE(headers.has_value());
    EXPECT_EQ(headers.error(), HPACK_ERROR::INVALID_INDEX);
}

TEST(Hpack, InvalidHuffmanPaddingIsRejected)
{
    HpackDecoder decoder;
    // 0x81 长度 1，Huffman 字节 0x00：'0' 的码字是 5 位 00000，
    // 剩余 3 位必须全 1 才算合法 EOS 前缀，这里全 0。
    const auto headers = decoder.decode(bytes({0x41, 0x81, 0x00}));
    ASSERT_FALSE(headers.has_value());
    EXPECT_EQ(headers.error(), HPACK_ERROR::INVALID_HUFFMAN);
}

TEST(Hpack, EncoderUsesStaticIndexForStatus200)
{
    EXPECT_EQ(HpackEncoder::encode(Header{":status", "200"}), bytes({0x88}));
}

TEST(Hpack, EncoderRoundTripsANonStaticStatus)
{
    const std::string block = HpackEncoder::encode(Header{":status", "302"});
    HpackDecoder decoder;
    const auto headers = decoder.decode(block);
    ASSERT_TRUE(headers.has_value());
    ASSERT_EQ(headers->size(), 1u);
    EXPECT_EQ(headerName(*headers, 0), ":status");
    EXPECT_EQ(headerValue(*headers, 0), "302");
}

TEST(Hpack, EncoderRoundTripsCustomHeaders)
{
    const std::vector<Header> original = {
        {":status", "200"},
        {"content-length", "5"},
        {"content-type", "text/plain; charset=utf-8"},
    };
    const std::string block = HpackEncoder::encode(original);
    HpackDecoder decoder;
    const auto headers = decoder.decode(block);
    ASSERT_TRUE(headers.has_value());
    ASSERT_EQ(headers->size(), original.size());
    for (size_t i = 0; i < original.size(); ++i)
    {
        EXPECT_EQ(headerName(*headers, i), original[i].name);
        EXPECT_EQ(headerValue(*headers, i), original[i].value);
    }
}

TEST(Hpack, OversizedHeaderListKeepsTheDynamicTableInSync)
{
    // RFC 7541 §4.3：压缩状态是连接级的。首部列表超限时若提前放弃解析，
    // 该块里以增量索引插入的字段就不会进入本端动态表，而对端已经插入，
    // 双方索引空间随即错位 —— 后续请求会静默解出错误的首部。
    HpackDecoder decoder;
    std::string block;
    std::string lastValue;
    for (int i = 0; i < 300; ++i) // 超过 kMaxHeaderCount
    {
        const std::string name = "x-f" + std::to_string(i);
        const std::string value = "v" + std::to_string(i);
        block.push_back('\x40'); // 增量索引字面量 + 新名称
        block.push_back(static_cast<char>(name.size()));
        block += name;
        block.push_back(static_cast<char>(value.size()));
        block += value;
        lastValue = value;
    }

    const auto first = decoder.decode(block);
    ASSERT_FALSE(first.has_value());
    EXPECT_EQ(first.error(), HPACK_ERROR::HEADER_LIST_TOO_LARGE);

    // 索引 62 指向动态表最新一项：超限块的最后一条必须仍在那里
    const auto second = decoder.decode(bytes({0xbe}));
    ASSERT_TRUE(second.has_value());
    ASSERT_EQ(second->size(), 1u);
    EXPECT_EQ((*second)[0].value, lastValue);
}
