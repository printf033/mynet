// Multiplexer<HandlerBase>: one byte stream carrying many exchanges. These
// tests drive it the way a connection would -- whole frames appended to the
// request buffer -- and read its answer back off the response queue, which is
// the only interface the layer above actually relies on.
#include "frame.hpp"
#include "handler.hpp"
#include "multiplexer.hpp"
#include <algorithm>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{
    [[nodiscard]] Frame makeFrame(FrameType type, uint32_t streamId, uint8_t flags = 0, std::string payload = {})
    {
        Frame frame;
        frame.streamId = streamId;
        frame.type = type;
        frame.flags = flags;
        frame.payload = std::move(payload);
        return frame;
    }

    // A minimal 6 byte settings entry.
    [[nodiscard]] std::string setting(uint16_t id, uint32_t value)
    {
        std::string out;
        out.push_back(static_cast<char>((id >> 8) & 0xffu));
        out.push_back(static_cast<char>(id & 0xffu));
        mynetframe::appendBigEndian32(out, value);
        return out;
    }

    [[nodiscard]] uint16_t settingIdAt(std::string_view payload, size_t off)
    {
        const auto *p = reinterpret_cast<const unsigned char *>(payload.data() + off);
        return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
    }

    // Records the hooks a protocol front end would override, so a test can assert
    // on what the layer above was told rather than on internals.
    class ProbeMux : public Multiplexer<HandlerBase>
    {
    public:
        std::vector<uint32_t> opens;
        std::vector<uint32_t> closes;
        std::vector<std::pair<uint32_t, std::string>> headers;
        std::vector<std::pair<uint32_t, std::string>> data;
        std::optional<StreamError> error;
        std::string why;

        void onStreamOpen(uint32_t id) noexcept override { opens.push_back(id); }
        void onStreamClose(uint32_t id) noexcept override { closes.push_back(id); }
        void onStreamHeaders(uint32_t id, std::string_view block) noexcept override
        {
            headers.emplace_back(id, std::string(block));
        }
        void onStreamData(uint32_t id, std::string_view bytes) noexcept override
        {
            data.emplace_back(id, std::string(bytes));
        }
        void onProtocolError(StreamError code, std::string_view reason) noexcept override
        {
            error = code;
            why.assign(reason);
        }

        // Append one whole frame, then let the multiplexer read whatever it can.
        void push(const Frame &frame)
        {
            std::string bytes;
            appendFrame(bytes, frame);
            appendRequest(bytes.data(), static_cast<ssize_t>(bytes.size()));
            process();
        }

        // Everything the multiplexer has written, decoded back into frames.
        std::vector<Frame> takeFrames()
        {
            std::string bytes;
            while (hasResponse())
                bytes += takeResponse();
            std::vector<Frame> frames;
            Buffer in;
            if (!bytes.empty())
                in.append(bytes.data(), static_cast<ssize_t>(bytes.size()));
            FrameDecoder decoder;
            while (in.readableBytes() > 0)
            {
                auto parsed = decoder.next(in);
                if (!parsed || !parsed->has_value())
                    break;
                frames.push_back(std::move(parsed->value()));
            }
            return frames;
        }

        // Send our own SETTINGS and swallow it, so later assertions see only the
        // frames the case under test produced.
        void warmUp()
        {
            process();
            takeFrames();
        }
    };

    [[nodiscard]] size_t countOfType(const std::vector<Frame> &frames, FrameType type)
    {
        return static_cast<size_t>(
            std::count_if(frames.begin(), frames.end(), [type](const Frame &f) { return f.type == type; }));
    }
} // namespace

TEST(Multiplexer, FirstProcessAnnouncesSettings)
{
    ProbeMux mux;
    mux.process();
    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FrameType::settings);
    EXPECT_EQ(frames[0].streamId, 0u);
    EXPECT_EQ(frames[0].flags, 0);
    ASSERT_EQ(frames[0].payload.size() % 6, 0u);
    EXPECT_EQ(frames[0].payload.size(), 18u); // three settings

    bool sawStreams = false;
    bool sawWindow = false;
    bool sawFrameSize = false;
    for (size_t off = 0; off + 6 <= frames[0].payload.size(); off += 6)
    {
        const uint16_t id = settingIdAt(frames[0].payload, off);
        const uint32_t value = mynetframe::readBigEndian32(frames[0].payload.data() + off + 2);
        if (id == mynetmux::kSettingMaxConcurrentStreams)
        {
            sawStreams = true;
            EXPECT_EQ(value, static_cast<uint32_t>(mux.maxConcurrentStreams()));
        }
        if (id == mynetmux::kSettingInitialWindowSize)
        {
            sawWindow = true;
            EXPECT_EQ(value, mynetmux::kInitialWindowSize);
        }
        if (id == mynetmux::kSettingMaxFrameSize)
        {
            sawFrameSize = true;
            EXPECT_EQ(value, mynetframe::kDefaultMaxFrameSize);
        }
    }
    EXPECT_TRUE(sawStreams);
    EXPECT_TRUE(sawWindow);
    EXPECT_TRUE(sawFrameSize);

    mux.process(); // the settings were announced once, not per call
    EXPECT_FALSE(mux.hasResponse());
}

TEST(Multiplexer, SettingsFromThePeerIsAcknowledgedAndNothingElseIsSent)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FrameType::settings, 0, 0, setting(mynetmux::kSettingMaxConcurrentStreams, 8)));
    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FrameType::settings);
    EXPECT_TRUE(frames[0].hasFlag(FrameFlags::kAck));
    EXPECT_TRUE(frames[0].payload.empty());
}

TEST(Multiplexer, SettingsAckWithAPayloadIsAProtocolError)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FrameType::settings, 0, FrameFlags::kAck, std::string(1, 'x')));
    EXPECT_EQ(mux.error, StreamError::protocolError);
    EXPECT_TRUE(mux.closeAfterResponse());
    EXPECT_EQ(countOfType(mux.takeFrames(), FrameType::goaway), 1u);
}

TEST(Multiplexer, HeadersOpenAStreamAndItsDataEchoesBack)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FrameType::headers, 1, FrameFlags::kEndHeaders, "hdrs"));
    EXPECT_EQ(mux.openStreams(), 1u);
    EXPECT_EQ(mux.lastPeerStreamId(), 1u);
    ASSERT_EQ(mux.opens.size(), 1u);
    EXPECT_EQ(mux.opens[0], 1u);
    ASSERT_EQ(mux.headers.size(), 1u);
    EXPECT_EQ(mux.headers[0].first, 1u);
    EXPECT_EQ(mux.headers[0].second, "hdrs");
    EXPECT_TRUE(mux.takeFrames().empty()); // headers alone produce no frame

    mux.push(makeFrame(FrameType::data, 1, 0, "ping"));
    ASSERT_EQ(mux.data.size(), 1u);
    EXPECT_EQ(mux.data[0].first, 1u);
    EXPECT_EQ(mux.data[0].second, "ping");

    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FrameType::data);
    EXPECT_EQ(frames[0].streamId, 1u);
    EXPECT_EQ(frames[0].payload, "ping");
    EXPECT_FALSE(frames[0].hasFlag(FrameFlags::kEndStream));
    EXPECT_EQ(mux.openStreams(), 1u);
    EXPECT_EQ(mux.connectionSendWindow(), mynetmux::kInitialWindowSize - 4u);
    EXPECT_TRUE(mux.closes.empty());
}

TEST(Multiplexer, EndStreamAfterTheEchoClosesTheStream)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FrameType::headers, 1, 0, "h"));
    mux.takeFrames();
    mux.push(makeFrame(FrameType::data, 1, FrameFlags::kEndStream, "bye"));

    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 2u);
    EXPECT_EQ(frames[0].payload, "bye");
    EXPECT_FALSE(frames[0].hasFlag(FrameFlags::kEndStream));
    EXPECT_TRUE(frames[1].payload.empty());
    EXPECT_TRUE(frames[1].hasFlag(FrameFlags::kEndStream));
    EXPECT_EQ(frames[1].streamId, 1u);
    EXPECT_EQ(mux.openStreams(), 0u);
    ASSERT_EQ(mux.closes.size(), 1u);
    EXPECT_EQ(mux.closes[0], 1u);
}

TEST(Multiplexer, HeadersWithEndStreamCloseAnIdleStream)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FrameType::headers, 1, FrameFlags::kEndHeaders | FrameFlags::kEndStream, "h"));
    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FrameType::data);
    EXPECT_EQ(frames[0].streamId, 1u);
    EXPECT_TRUE(frames[0].hasFlag(FrameFlags::kEndStream));
    EXPECT_TRUE(frames[0].payload.empty());
    EXPECT_EQ(mux.openStreams(), 0u);
}

TEST(Multiplexer, PingIsAcknowledgedWithTheSamePayload)
{
    ProbeMux mux;
    mux.warmUp();

    const std::string opaque(8, '\x2a');
    mux.push(makeFrame(FrameType::ping, 0, 0, opaque));
    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FrameType::ping);
    EXPECT_TRUE(frames[0].hasFlag(FrameFlags::kAck));
    EXPECT_EQ(frames[0].payload, opaque);

    // An ACK from the peer is the end of it, not another ping.
    mux.push(makeFrame(FrameType::ping, 0, FrameFlags::kAck, opaque));
    EXPECT_TRUE(mux.takeFrames().empty());
}

TEST(Multiplexer, PingWithTheWrongPayloadLengthIsAProtocolError)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FrameType::ping, 0, 0, "short"));
    EXPECT_EQ(mux.error, StreamError::protocolError);
}

TEST(Multiplexer, AnEvenStreamIdIsAProtocolError)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FrameType::headers, 2, 0, "h"));
    EXPECT_EQ(mux.error, StreamError::protocolError);
    EXPECT_TRUE(mux.closeAfterResponse());
    EXPECT_FALSE(mux.goawayReceived());

    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(countOfType(frames, FrameType::goaway), 1u);
    EXPECT_NE(mux.why.find("the peer may not open"), std::string::npos);
    EXPECT_TRUE(mux.opens.empty());
}

TEST(Multiplexer, DataOnAStreamThatWasNeverOpenedIsAProtocolError)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FrameType::data, 1, 0, "bytes"));
    EXPECT_EQ(mux.error, StreamError::protocolError);
    EXPECT_EQ(countOfType(mux.takeFrames(), FrameType::goaway), 1u);
}

TEST(Multiplexer, ResetOnAFinishedStreamIsOnlyAReset)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FrameType::headers, 1, FrameFlags::kEndStream, "h"));
    mux.takeFrames(); // stream 1 is now closed and below lastPeerStreamId_
    ASSERT_EQ(mux.openStreams(), 0u);

    mux.push(makeFrame(FrameType::data, 1, 0, "late"));
    EXPECT_FALSE(mux.error.has_value()); // a race the peer can recover from
    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FrameType::reset);
    EXPECT_EQ(frames[0].streamId, 1u);
    EXPECT_EQ(mynetframe::readBigEndian32(frames[0].payload.data()), std::to_underlying(StreamError::streamClosed));
}

TEST(Multiplexer, DataBiggerThanTheReceiveWindowIsAFlowControlError)
{
    ProbeMux mux;
    mux.warmUp();

    // Raise the frame size ceiling first, or the decoder refuses the bytes
    // before the flow-control check ever sees them.
    mux.push(makeFrame(FrameType::settings, 0, 0, setting(mynetmux::kSettingMaxFrameSize, 1u << 20)));
    mux.takeFrames();
    mux.push(makeFrame(FrameType::headers, 1, 0, "h"));
    mux.takeFrames();

    mux.push(makeFrame(FrameType::data, 1, 0, std::string(mynetmux::kInitialWindowSize + 1, 'x')));
    EXPECT_EQ(mux.error, StreamError::flowControlError);
    EXPECT_TRUE(mux.closeAfterResponse());
    EXPECT_EQ(countOfType(mux.takeFrames(), FrameType::goaway), 1u);
}

TEST(Multiplexer, WindowUpdateForTheConnectionGrowsTheSendWindow)
{
    ProbeMux mux;
    mux.warmUp();

    std::string increment;
    mynetframe::appendBigEndian32(increment, 4096);
    mux.push(makeFrame(FrameType::windowUpdate, 0, 0, increment));
    EXPECT_EQ(mux.connectionSendWindow(), mynetmux::kInitialWindowSize + 4096u);

    std::string zero;
    mynetframe::appendBigEndian32(zero, 0);
    mux.push(makeFrame(FrameType::windowUpdate, 0, 0, zero));
    EXPECT_EQ(mux.error, StreamError::protocolError);
}

TEST(Multiplexer, PushPromiseIsAProtocolErrorOnAServer)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FrameType::pushPromise, 1, 0, "h"));
    EXPECT_EQ(mux.error, StreamError::protocolError);
    EXPECT_NE(mux.why.find("PUSH_PROMISE"), std::string::npos);
}

TEST(Multiplexer, PriorityIsIgnoredAndLeavesTheConnectionAlone)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FrameType::priority, 1, 0, std::string(5, '\0')));
    EXPECT_FALSE(mux.error.has_value());
    EXPECT_FALSE(mux.closeAfterResponse());
    EXPECT_FALSE(mux.hasResponse());
    EXPECT_TRUE(mux.opens.empty()); // a hint is not a stream
}

TEST(Multiplexer, GoawayFromThePeerRefusesNewStreams)
{
    ProbeMux mux;
    mux.warmUp();

    std::string payload;
    mynetframe::appendBigEndian32(payload, 1u);
    mynetframe::appendBigEndian32(payload, 0u);
    mux.push(makeFrame(FrameType::goaway, 0, 0, payload));
    EXPECT_TRUE(mux.goawayReceived());
    EXPECT_TRUE(mux.takeFrames().empty());

    mux.push(makeFrame(FrameType::headers, 3, 0, "h"));
    EXPECT_EQ(mux.openStreams(), 0u);
    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FrameType::reset);
    EXPECT_EQ(frames[0].streamId, 3u);
    EXPECT_EQ(mynetframe::readBigEndian32(frames[0].payload.data()), std::to_underlying(StreamError::refusedStream));
}

TEST(Multiplexer, ShortGoawayPayloadIsAProtocolError)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FrameType::goaway, 0, 0, "abc"));
    EXPECT_EQ(mux.error, StreamError::protocolError);
}

TEST(Multiplexer, MaxConcurrentStreamsBoundsTheStreamTable)
{
    ProbeMux mux;
    mux.setMaxConcurrentStreams(2);
    EXPECT_EQ(mux.maxConcurrentStreams(), 2u);
    mux.warmUp();

    mux.push(makeFrame(FrameType::headers, 1, 0, "h"));
    mux.push(makeFrame(FrameType::headers, 3, 0, "h"));
    EXPECT_EQ(mux.openStreams(), 2u);
    mux.takeFrames();

    mux.push(makeFrame(FrameType::headers, 5, 0, "h"));
    EXPECT_EQ(mux.openStreams(), 2u);
    EXPECT_FALSE(mux.error.has_value()); // refused, not a broken connection
    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FrameType::reset);
    EXPECT_EQ(frames[0].streamId, 5u);
    EXPECT_EQ(mynetframe::readBigEndian32(frames[0].payload.data()), std::to_underlying(StreamError::refusedStream));
    ASSERT_EQ(mux.opens.size(), 2u);
}

TEST(Multiplexer, AZeroStreamLimitIsClampedToOne)
{
    ProbeMux mux;
    mux.setMaxConcurrentStreams(0);
    EXPECT_EQ(mux.maxConcurrentStreams(), 1u);
    EXPECT_EQ(mux.streamPoolCapacity(), 1u);
}

TEST(Multiplexer, AFrameSplitAcrossAppendsIsBufferedUntilWhole)
{
    ProbeMux mux;
    mux.warmUp();

    std::string bytes;
    appendFrame(bytes, makeFrame(FrameType::headers, 1, FrameFlags::kEndHeaders, "hello"));
    ASSERT_GT(bytes.size(), size_t{5});

    mux.appendRequest(bytes.data(), 5);
    mux.process();
    EXPECT_EQ(mux.openStreams(), 0u);
    EXPECT_TRUE(mux.headers.empty());

    mux.appendRequest(bytes.data() + 5, static_cast<ssize_t>(bytes.size() - 5));
    mux.process();
    EXPECT_EQ(mux.openStreams(), 1u);
    ASSERT_EQ(mux.headers.size(), 1u);
    EXPECT_EQ(mux.headers[0].second, "hello");
}

TEST(Multiplexer, AFrameLongerThanTheCeilingEndsTheConnection)
{
    ProbeMux mux;
    mux.warmUp();

    // 16385 bytes is one past the default maximum, and the frame itself is
    // well formed: what fails is the length it claims.
    mux.push(makeFrame(FrameType::data, 1, 0, std::string(mynetframe::kDefaultMaxFrameSize + 1, 'x')));
    EXPECT_EQ(mux.error, StreamError::protocolError);
    EXPECT_TRUE(mux.closeAfterResponse());
    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(countOfType(frames, FrameType::goaway), 1u);
}

TEST(Multiplexer, ResetReturnsTheConnectionToAFreshState)
{
    ProbeMux mux;
    mux.warmUp();
    mux.push(makeFrame(FrameType::headers, 1, 0, "h"));
    mux.takeFrames();
    ASSERT_EQ(mux.openStreams(), 1u);

    mux.reset();
    EXPECT_EQ(mux.openStreams(), 0u);
    EXPECT_EQ(mux.lastPeerStreamId(), 0u);
    EXPECT_EQ(mux.connectionSendWindow(), mynetmux::kInitialWindowSize);
    EXPECT_FALSE(mux.goawayReceived());

    mux.process(); // a recycled connection announces itself again
    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FrameType::settings);
}

TEST(Multiplexer, PaddedDataHasItsPaddingRemovedBeforeTheHandlerSeesIt)
{
    ProbeMux mux;
    mux.warmUp();
    mux.push(makeFrame(FrameType::headers, 1, 0, "h"));
    mux.takeFrames();

    std::string payload;
    payload.push_back('\x03'); // three bytes of padding follow the content
    payload += "body";
    payload.append(3, '\0');
    mux.push(makeFrame(FrameType::data, 1, FrameFlags::kPadded, payload));

    ASSERT_EQ(mux.data.size(), 1u);
    EXPECT_EQ(mux.data[0].second, "body");
    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].payload, "body");
}

TEST(Multiplexer, PaddingLongerThanThePayloadIsAProtocolError)
{
    ProbeMux mux;
    mux.warmUp();
    mux.push(makeFrame(FrameType::headers, 1, 0, "h"));
    mux.takeFrames();

    std::string payload;
    payload.push_back('\x7f'); // claims 127 bytes of padding in a 1 byte payload
    mux.push(makeFrame(FrameType::data, 1, FrameFlags::kPadded, payload));
    EXPECT_EQ(mux.error, StreamError::protocolError);
    EXPECT_NE(mux.why.find("padding"), std::string::npos);
}
