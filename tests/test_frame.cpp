// FrameDecoder and appendFrame: the three-outcome contract ("not yet", "one
// frame", "never a frame") and the byte layout the two functions share.
#include "frame.hpp"
#include <gtest/gtest.h>
#include <string>
#include <vector>

namespace
{
    using Decoded = std::expected<std::optional<Frame>, FrameError>;

    std::string makeHeader(uint32_t length, FrameType type, uint8_t flags, uint32_t streamId, bool reserved = false)
    {
        const uint32_t id = (streamId & mynetframe::kStreamIdMask) | (reserved ? 0x80000000u : 0u);
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
        b.append(bytes.data(), bytes.size());
        return b;
    }
} // namespace

TEST(FrameDecoder, IncompleteHeaderAsksForMoreBytes)
{
    FrameDecoder decoder;
    Buffer in = bufferOf(std::string(8, 'x')); // one byte short of a header
    const Decoded result = decoder.next(in);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->has_value());
    EXPECT_EQ(in.readableBytes(), size_t{8}); // nothing consumed while waiting
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
    const std::string header = makeHeader(10, FrameType::data, 0, 1);
    Buffer in = bufferOf(header + "abc"); // 3 of the 10 payload bytes
    const Decoded result = decoder.next(in);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->has_value());
    EXPECT_EQ(in.readableBytes(), header.size() + 3); // the header is re-read next time
}

TEST(FrameDecoder, WholeFrameCarriesItsFieldsAndIsConsumed)
{
    FrameDecoder decoder;
    const std::string bytes = makeHeader(5, FrameType::data, 0x1, 3) + "hello";
    Buffer in = bufferOf(bytes);
    const Decoded result = decoder.next(in);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->has_value());
    EXPECT_EQ((*result)->streamId, 3u);
    EXPECT_EQ((*result)->type, FrameType::data);
    EXPECT_EQ((*result)->flags, 0x1);
    EXPECT_TRUE((*result)->hasFlag(FrameFlags::kEndStream));
    EXPECT_EQ((*result)->payload, "hello");
    EXPECT_TRUE(in.empty());
}

TEST(FrameDecoder, ZeroLengthFrameIsComplete)
{
    FrameDecoder decoder;
    Buffer in = bufferOf(makeHeader(0, FrameType::ping, FrameFlags::kAck, 0));
    const Decoded result = decoder.next(in);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->has_value());
    EXPECT_EQ((*result)->payload, "");
    EXPECT_TRUE(in.empty());
}

TEST(FrameDecoder, OversizedFrameIsRejectedBeforeItsPayloadArrives)
{
    FrameDecoder decoder;
    Buffer in = bufferOf(makeHeader(mynetframe::kDefaultMaxFrameSize + 1, FrameType::data, 0, 1));
    const Decoded result = decoder.next(in);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), FrameError::frameTooLarge);
}

TEST(FrameDecoder, MaxFrameSizeIsConfigurableAndZeroRestoresTheDefault)
{
    FrameDecoder decoder;
    EXPECT_EQ(decoder.maxFrameSize(), mynetframe::kDefaultMaxFrameSize);

    decoder.setMaxFrameSize(1024);
    EXPECT_EQ(decoder.maxFrameSize(), 1024u);
    Buffer big = bufferOf(makeHeader(1025, FrameType::data, 0, 1));
    ASSERT_FALSE(decoder.next(big).has_value());
    EXPECT_EQ(decoder.next(big).error(), FrameError::frameTooLarge);

    Buffer fits = bufferOf(makeHeader(1024, FrameType::data, 0, 1) + std::string(1024, 'z'));
    const Decoded ok = decoder.next(fits);
    ASSERT_TRUE(ok.has_value());
    EXPECT_TRUE(ok->has_value());

    decoder.setMaxFrameSize(0);
    EXPECT_EQ(decoder.maxFrameSize(), mynetframe::kDefaultMaxFrameSize);
}

TEST(FrameDecoder, ReservedBitIsAnErrorOnceTheFrameIsWhole)
{
    FrameDecoder decoder;
    Buffer in = bufferOf(makeHeader(0, FrameType::data, 0, 1, /*reserved=*/true));
    const Decoded result = decoder.next(in);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), FrameError::reservedBitSet);
}

TEST(FrameDecoder, ReservedBitWaitsForTheWholeFrame)
{
    // The order is deliberate: a frame that is merely incomplete is "not yet"
    // even when its header already carries the reserved bit, so a peek at a
    // half-arrived frame never tears the connection down.
    FrameDecoder decoder;
    Buffer in = bufferOf(makeHeader(4, FrameType::data, 0, 1, true) + "ab");
    const Decoded result = decoder.next(in);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->has_value());
}

TEST(FrameDecoder, TwoFramesInOneBufferComeOutInOrder)
{
    FrameDecoder decoder;
    Buffer in = bufferOf(makeHeader(1, FrameType::headers, 0x4, 1) + "a" + makeHeader(2, FrameType::data, 0, 1) + "bc");
    const Decoded first = decoder.next(in);
    ASSERT_TRUE(first.has_value() && first->has_value());
    EXPECT_EQ((*first)->type, FrameType::headers);
    EXPECT_EQ((*first)->payload, "a");

    const Decoded second = decoder.next(in);
    ASSERT_TRUE(second.has_value() && second->has_value());
    EXPECT_EQ((*second)->type, FrameType::data);
    EXPECT_EQ((*second)->payload, "bc");
    EXPECT_TRUE(in.empty());
}

TEST(FrameDecoder, BytesAfterTheFrameStayInTheBuffer)
{
    FrameDecoder decoder;
    Buffer in = bufferOf(makeHeader(1, FrameType::data, 0, 1) + "a" + "ZZ");
    const Decoded result = decoder.next(in);
    ASSERT_TRUE(result.has_value() && result->has_value());
    EXPECT_EQ(in.readableBytes(), size_t{2});
    EXPECT_EQ(std::string(in.readableBegin(), in.readableBytes()), "ZZ");
}

TEST(AppendFrame, RoundTripsEveryField)
{
    Frame original;
    original.streamId = 7;
    original.type = FrameType::ping;
    original.flags = 0x5;
    original.payload = std::string(1024, 'q');

    std::string wire;
    appendFrame(wire, original);
    ASSERT_EQ(wire.size(), mynetframe::kHeaderBytes + original.payload.size());

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
    frame.streamId = 0x80000001u; // the reserved bit set by accident
    frame.type = FrameType::data;
    std::string wire;
    appendFrame(wire, frame);
    EXPECT_EQ(static_cast<unsigned char>(wire[5]) & mynetframe::kStreamIdReservedMask, 0u);

    // The same bytes decode cleanly, with the reserved bit gone rather than
    // reported: masking on the way out is what keeps the round trip legal.
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
    frame.type = FrameType::settings;
    std::string wire;
    appendFrame(wire, frame);
    EXPECT_EQ(wire.size(), mynetframe::kHeaderBytes);
}

TEST(FrameHeader, BigEndian32RoundTrips)
{
    for (uint32_t value : {0u, 1u, 0x7fffffffu, 0xffffffffu, 0x80000000u, 0x01020304u})
    {
        std::string out;
        mynetframe::appendBigEndian32(out, value);
        ASSERT_EQ(out.size(), size_t{4});
        EXPECT_EQ(mynetframe::readBigEndian32(out.data()), value);
    }
}

TEST(FrameError, EveryErrorHasText)
{
    EXPECT_EQ(to_string(FrameError::frameTooLarge), "frame length exceeds the configured maximum");
    EXPECT_EQ(to_string(FrameError::reservedBitSet), "the reserved bit of the stream identifier was set");
    EXPECT_EQ(to_string(static_cast<FrameError>(0xff)), "unknown framing error");
}
