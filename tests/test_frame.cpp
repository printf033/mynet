// FrameDecoder 与 appendFrame：三态契约（"数据不足暂无"、"成功解码一帧"、
// "协议错误永不成帧"）以及两函数共享的底层字节布局。
#include "http/v2/frame.hpp"
#include <gtest/gtest.h>
#include <string>
#include <vector>

using namespace mynet;

namespace
{
    using Decoded = std::expected<std::optional<Frame>, FRAME_ERROR>;

    std::string makeHeader(uint32_t length, FRAME_TYPE type, uint8_t flags, uint32_t streamId, bool reserved = false)
    {
        const uint32_t id = (streamId & frame::kStreamIdMask) | (reserved ? 0x80000000u : 0u);
        std::string out;
        out.push_back(static_cast<char>((length >> 16) & 0xffu));
        out.push_back(static_cast<char>((length >> 8) & 0xffu));
        out.push_back(static_cast<char>(length & 0xffu));
        out.push_back(static_cast<char>(std::to_underlying(type)));
        out.push_back(static_cast<char>(flags));
        out.push_back(static_cast<char>((id >> 24) & 0xffu));
        out.push_back(static_cast<char>((id >> 16) & 0xffu));
        out.push_back(static_cast<char>((id >> 8) & 0xffu));
        out.push_back(static_cast<char>(id & 0xffu));
        return out;
    }

    Buffer bufferOf(const std::string &bytes)
    {
        Buffer b;
        [[maybe_unused]] auto _ = b.append(bytes.data(), bytes.size());
        return b;
    }
} // namespace

TEST(FrameDecoder, IncompleteHeaderAsksForMoreBytes)
{
    FrameDecoder decoder;
    Buffer in = bufferOf(std::string(8, 'x')); // 比 9 字节帧头少 1 字节
    const Decoded result = decoder.next(in);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->has_value());
    EXPECT_EQ(in.readableBytes(), size_t{8}); // 等待数据期间不消费任何字节
}

TEST(FrameDecoder, EmptyBufferIsNotAnError)
{
    FrameDecoder decoder;
    Buffer in;
    const Decoded result = decoder.next(in);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->has_value());
}

TEST(FrameDecoder, PayloadSplitAcrossReadsStaysUnconsumed)
{
    FrameDecoder decoder;
    const std::string header = makeHeader(10, FRAME_TYPE::DATA, 0, 1);
    Buffer in = bufferOf(header + "abc"); // 10 字节载荷中仅到达 3 字节
    const Decoded result = decoder.next(in);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->has_value());
    EXPECT_EQ(in.readableBytes(), header.size() + 3); // 下次到达时重新从帧头起读取
}

TEST(FrameDecoder, WholeFrameCarriesItsFieldsAndIsConsumed)
{
    FrameDecoder decoder;
    const std::string bytes = makeHeader(5, FRAME_TYPE::DATA, 0x1, 3) + "hello";
    Buffer in = bufferOf(bytes);
    const Decoded result = decoder.next(in);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->has_value());
    EXPECT_EQ((*result)->streamId, 3u);
    EXPECT_EQ((*result)->type, FRAME_TYPE::DATA);
    EXPECT_EQ((*result)->flags, 0x1);
    EXPECT_TRUE((*result)->hasFlag(FrameFlags::kEndStream));
    EXPECT_EQ((*result)->payload, "hello");
    EXPECT_TRUE(in.empty());
}

TEST(FrameDecoder, ZeroLengthFrameIsComplete)
{
    FrameDecoder decoder;
    Buffer in = bufferOf(makeHeader(0, FRAME_TYPE::PING, FrameFlags::kAck, 0));
    const Decoded result = decoder.next(in);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->has_value());
    EXPECT_EQ((*result)->payload, "");
    EXPECT_TRUE(in.empty());
}

TEST(FrameDecoder, OversizedFrameIsRejectedBeforeItsPayloadArrives)
{
    FrameDecoder decoder;
    Buffer in = bufferOf(makeHeader(frame::kDefaultMaxFrameSize + 1, FRAME_TYPE::DATA, 0, 1));
    const Decoded result = decoder.next(in);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), FRAME_ERROR::FRAME_TOO_LARGE);
}

TEST(FrameDecoder, MaxFrameSizeIsConfigurableAndZeroRestoresTheDefault)
{
    FrameDecoder decoder;
    EXPECT_EQ(decoder.maxFrameSize(), frame::kDefaultMaxFrameSize);

    decoder.setMaxFrameSize(1 << 10);
    EXPECT_EQ(decoder.maxFrameSize(), 1 << 10);
    Buffer big = bufferOf(makeHeader((1 << 10) + 1, FRAME_TYPE::DATA, 0, 1));
    ASSERT_FALSE(decoder.next(big).has_value());
    EXPECT_EQ(decoder.next(big).error(), FRAME_ERROR::FRAME_TOO_LARGE);

    Buffer fits = bufferOf(makeHeader(1 << 10, FRAME_TYPE::DATA, 0, 1) + std::string(1 << 10, 'z'));
    const Decoded ok = decoder.next(fits);
    ASSERT_TRUE(ok.has_value());
    EXPECT_TRUE(ok->has_value());

    decoder.setMaxFrameSize(0);
    EXPECT_EQ(decoder.maxFrameSize(), frame::kDefaultMaxFrameSize);
}

TEST(FrameDecoder, ReservedBitIsAnErrorOnceTheFrameIsWhole)
{
    FrameDecoder decoder;
    Buffer in = bufferOf(makeHeader(0, FRAME_TYPE::DATA, 0, 1, /*reserved=*/true));
    const Decoded result = decoder.next(in);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), FRAME_ERROR::RESERVED_BIT_SET);
}

TEST(FrameDecoder, ReservedBitWaitsForTheWholeFrame)
{
    // 校验顺序是刻意设计的：仅部分到达的不完整帧返回“暂无帧”，
    // 即使其帧头已携带保留位，因此偷窥半到达的帧绝不会导致连接被误断开。
    FrameDecoder decoder;
    Buffer in = bufferOf(makeHeader(4, FRAME_TYPE::DATA, 0, 1, true) + "ab");
    const Decoded result = decoder.next(in);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->has_value());
}

TEST(FrameDecoder, TwoFramesInOneBufferComeOutInOrder)
{
    FrameDecoder decoder;
    Buffer in =
        bufferOf(makeHeader(1, FRAME_TYPE::HEADERS, 0x4, 1) + "a" + makeHeader(2, FRAME_TYPE::DATA, 0, 1) + "bc");
    const Decoded first = decoder.next(in);
    ASSERT_TRUE(first.has_value() && first->has_value());
    EXPECT_EQ((*first)->type, FRAME_TYPE::HEADERS);
    EXPECT_EQ((*first)->payload, "a");

    const Decoded second = decoder.next(in);
    ASSERT_TRUE(second.has_value() && second->has_value());
    EXPECT_EQ((*second)->type, FRAME_TYPE::DATA);
    EXPECT_EQ((*second)->payload, "bc");
    EXPECT_TRUE(in.empty());
}

TEST(FrameDecoder, BytesAfterTheFrameStayInTheBuffer)
{
    FrameDecoder decoder;
    Buffer in = bufferOf(makeHeader(1, FRAME_TYPE::DATA, 0, 1) + "a" + "ZZ");
    const Decoded result = decoder.next(in);
    ASSERT_TRUE(result.has_value() && result->has_value());
    EXPECT_EQ(in.readableBytes(), size_t{2});
    EXPECT_EQ(std::string(in.readableBegin(), in.readableBytes()), "ZZ");
}

TEST(AppendFrame, RoundTripsEveryField)
{
    Frame original;
    original.streamId = 7;
    original.type = FRAME_TYPE::PING;
    original.flags = 0x5;
    original.payload = std::string(1 << 10, 'q');

    std::string wire;
    appendFrame(wire, original);
    ASSERT_EQ(wire.size(), frame::kHeaderBytes + original.payload.size());

    Buffer in = bufferOf(wire);
    FrameDecoder decoder;
    const Decoded result = decoder.next(in);
    ASSERT_TRUE(result.has_value() && result->has_value());
    EXPECT_EQ((*result)->streamId, original.streamId);
    EXPECT_EQ((*result)->type, original.type);
    EXPECT_EQ((*result)->flags, original.flags);
    EXPECT_EQ((*result)->payload, original.payload);
    EXPECT_TRUE(in.empty());
}

TEST(AppendFrame, MasksTheReservedBitOfTheStreamIdentifier)
{
    Frame frame;
    frame.streamId = 0x80000001u; // 意外设置了最高位的保留位
    frame.type = FRAME_TYPE::DATA;
    std::string wire;
    appendFrame(wire, frame);
    EXPECT_EQ(static_cast<unsigned char>(wire[5]) & frame::kStreamIdReservedMask, 0u);

    // 相同的字节能被正常解码，保留位被清除而非报错：
    // 在出站时进行掩码处理保证了往返传输的合规性。
    Buffer in = bufferOf(wire);
    FrameDecoder decoder;
    const Decoded result = decoder.next(in);
    ASSERT_TRUE(result.has_value() && result->has_value());
    EXPECT_EQ((*result)->streamId, 1u);
}

TEST(AppendFrame, EmptyPayloadProducesAHeaderOnly)
{
    Frame frame;
    frame.streamId = 0;
    frame.type = FRAME_TYPE::SETTINGS;
    std::string wire;
    appendFrame(wire, frame);
    EXPECT_EQ(wire.size(), frame::kHeaderBytes);
}

TEST(FrameHeader, BigEndian32RoundTrips)
{
    for (uint32_t value : {0u, 1u, 0x7fffffffu, 0xffffffffu, 0x80000000u, 0x01020304u})
    {
        std::string out;
        frame::appendBigEndian32(out, value);
        ASSERT_EQ(out.size(), size_t{4});
        EXPECT_EQ(frame::readBigEndian32(out.data()), value);
    }
}

TEST(FRAME_ERROR, EveryErrorHasText)
{
    EXPECT_EQ(toString(FRAME_ERROR::FRAME_TOO_LARGE), "frame length exceeds the configured maximum");
    EXPECT_EQ(toString(FRAME_ERROR::RESERVED_BIT_SET), "the reserved bit of the stream identifier was set");
    EXPECT_EQ(toString(static_cast<FRAME_ERROR>(0xff)), "unknown framing error");
}

TEST(FrameType, ContinuationFrameTypeIsNine)
{
    EXPECT_EQ(std::to_underlying(FRAME_TYPE::CONTINUATION), 0x9);
}
