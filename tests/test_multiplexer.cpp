// HandlerHttp2<HandlerConnection>：在单条物理字节流上承载多个独立的流式交互。
// 这些测试模拟网络连接的行为驱动它——将完整的帧追加到请求缓冲区，
// 并从响应队列中读回其回复，这是上层唯一实际依赖的接口。
#include "connection.hpp"
#include "http/v2/frame.hpp"
#include "http/v2/handler.hpp"
#include <algorithm>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace mynet;

// 入口头文件的转发必须与实现指向同一实体，且默认模板实参可用（HandlerHttp2<>）。
static_assert(std::same_as<mynet::HandlerHttp2<HandlerConnection>, mynet::http::v2::HandlerHttp2<HandlerConnection>>);
static_assert(std::same_as<HandlerHttp2<>, HandlerHttp2<HandlerConnection>>);

namespace
{
    [[nodiscard]] Frame makeFrame(FRAME_TYPE type, uint32_t streamId, uint8_t flags = 0, std::string payload = {})
    {
        Frame frame;
        frame.streamId = streamId;
        frame.type = type;
        frame.flags = flags;
        frame.payload = std::move(payload);
        return frame;
    }

    // 极简 6 字节 SETTINGS 设置项条目。
    [[nodiscard]] std::string setting(uint16_t id, uint32_t value)
    {
        std::string out;
        out.push_back(static_cast<char>((id >> 8) & 0xffu));
        out.push_back(static_cast<char>(id & 0xffu));
        frame::appendBigEndian32(out, value);
        return out;
    }

    [[nodiscard]] uint16_t settingIdAt(std::string_view payload, size_t off)
    {
        const auto *p = reinterpret_cast<const unsigned char *>(payload.data() + off);
        return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
    }

    // 记录上层协议前端可重写的钩子函数，
    // 以便测试能针对通知上层的事件进行断言，而非侵入内部实现。
    class TwoPartHandler : public HandlerConnection
    {
    public:
        void process()
        {
            if (requestBytes() > 0)
            {
                [[maybe_unused]] auto _1 = pushResponse("part1_");
                [[maybe_unused]] auto _2 = pushResponse("part2");
                requestClear();
            }
        }
    };

    class TwoPartMux : public HandlerHttp2<TwoPartHandler>
    {
    public:
        void push(const Frame &frame)
        {
            std::string bytes;
            appendFrame(bytes, frame);
            [[maybe_unused]] auto _ = appendRequest(bytes.data(), static_cast<ssize_t>(bytes.size()));
            process();
        }

        std::vector<Frame> takeFrames()
        {
            std::string bytes;
            while (hasResponse())
                bytes += takeResponse();
            std::vector<Frame> frames;
            Buffer in;
            if (!bytes.empty())
            {
                [[maybe_unused]] auto _ = in.append(bytes);
            }
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

        void warmUp()
        {
            process();
            [[maybe_unused]] auto _ = takeFrames();
            push(makeFrame(FRAME_TYPE::SETTINGS, 0, FrameFlags::kAck, {}));
        }
    };

    class ProbeMux : public HandlerHttp2<HandlerConnection>
    {
    public:
        std::vector<uint32_t> opens;
        std::vector<uint32_t> closes;
        std::vector<std::pair<uint32_t, std::string>> headers;
        std::vector<std::pair<uint32_t, std::string>> data;
        std::optional<STREAM_ERROR> error;
        std::string why;

        using HandlerHttp2<HandlerConnection>::connRecvWindow_;
        using HandlerHttp2<HandlerConnection>::stream;

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
        void onProtocolError(STREAM_ERROR code, std::string_view reason) noexcept override
        {
            error = code;
            why.assign(reason);
        }

        // 追加一个完整帧，然后让多路复用器尽可能读取并处理。
        void push(const Frame &frame)
        {
            std::string bytes;
            appendFrame(bytes, frame);
            [[maybe_unused]] auto _ = appendRequest(bytes.data(), static_cast<ssize_t>(bytes.size()));
            process();
        }

        // 获取多路复用器写入的所有数据，并将其重新解码为帧列表。
        std::vector<Frame> takeFrames()
        {
            std::string bytes;
            while (hasResponse())
                bytes += takeResponse();
            std::vector<Frame> frames;
            Buffer in;
            if (!bytes.empty())
            {
                [[maybe_unused]] auto _ = in.append(bytes);
            }
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

        // 预先发送本端 SETTINGS 并消费其输出，
        // 使得后续断言仅关注被测场景自身生成的帧。
        void warmUp()
        {
            process();
            takeFrames();
        }
    };

    [[nodiscard]] size_t countOfType(const std::vector<Frame> &frames, FRAME_TYPE type)
    {
        return static_cast<size_t>(
            std::count_if(frames.begin(), frames.end(), [type](const Frame &f) { return f.type == type; }));
    }
} // namespace

TEST(HandlerHttp2, FirstProcessAnnouncesSettings)
{
    ProbeMux mux;
    mux.process();
    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FRAME_TYPE::SETTINGS);
    EXPECT_EQ(frames[0].streamId, 0u);
    EXPECT_EQ(frames[0].flags, 0);
    ASSERT_EQ(frames[0].payload.size() % 6, 0u);
    EXPECT_EQ(frames[0].payload.size(), 18u); // 包含 3 项设置（每项 6 字节）

    bool sawStreams = false;
    bool sawWindow = false;
    bool sawFrameSize = false;
    for (size_t off = 0; off + 6 <= frames[0].payload.size(); off += 6)
    {
        const uint16_t id = settingIdAt(frames[0].payload, off);
        const uint32_t value = frame::readBigEndian32(frames[0].payload.data() + off + 2);
        if (id == mux::kSettingMaxConcurrentStreams)
        {
            sawStreams = true;
            EXPECT_EQ(value, static_cast<uint32_t>(mux.maxConcurrentStreams()));
        }
        if (id == mux::kSettingInitialWindowSize)
        {
            sawWindow = true;
            EXPECT_EQ(value, mux::kInitialWindowSize);
        }
        if (id == mux::kSettingMaxFrameSize)
        {
            sawFrameSize = true;
            EXPECT_EQ(value, frame::kDefaultMaxFrameSize);
        }
    }
    EXPECT_TRUE(sawStreams);
    EXPECT_TRUE(sawWindow);
    EXPECT_TRUE(sawFrameSize);

    mux.process(); // 设置帧仅宣告一次，而非每次调用都重复宣告
    EXPECT_FALSE(mux.hasResponse());
}

TEST(HandlerHttp2, SettingsFromThePeerIsAcknowledgedAndNothingElseIsSent)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::SETTINGS, 0, 0, setting(mux::kSettingMaxConcurrentStreams, 8)));
    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FRAME_TYPE::SETTINGS);
    EXPECT_TRUE(frames[0].hasFlag(FrameFlags::kAck));
    EXPECT_TRUE(frames[0].payload.empty());
}

TEST(HandlerHttp2, SettingsAckWithAPayloadIsAProtocolError)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::SETTINGS, 0, FrameFlags::kAck, std::string(1, 'x')));
    EXPECT_EQ(mux.error, STREAM_ERROR::PROTOCOL_ERROR);
    EXPECT_TRUE(mux.closeAfterResponse());
    EXPECT_EQ(countOfType(mux.takeFrames(), FRAME_TYPE::GOAWAY), 1u);
}

TEST(HandlerHttp2, HeadersOpenAStreamAndItsDataEchoesBack)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, "hdrs"));
    EXPECT_EQ(mux.openStreams(), 1u);
    EXPECT_EQ(mux.lastPeerStreamId(), 1u);
    ASSERT_EQ(mux.opens.size(), 1u);
    EXPECT_EQ(mux.opens[0], 1u);
    ASSERT_EQ(mux.headers.size(), 1u);
    EXPECT_EQ(mux.headers[0].first, 1u);
    EXPECT_EQ(mux.headers[0].second, "hdrs");
    EXPECT_TRUE(mux.takeFrames().empty()); // 仅收到首部帧时不产生回复帧

    mux.push(makeFrame(FRAME_TYPE::DATA, 1, 0, "ping"));
    ASSERT_EQ(mux.data.size(), 1u);
    EXPECT_EQ(mux.data[0].first, 1u);
    EXPECT_EQ(mux.data[0].second, "ping");

    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FRAME_TYPE::DATA);
    EXPECT_EQ(frames[0].streamId, 1u);
    EXPECT_EQ(frames[0].payload, "ping");
    EXPECT_FALSE(frames[0].hasFlag(FrameFlags::kEndStream));
    EXPECT_EQ(mux.openStreams(), 1u);
    EXPECT_EQ(mux.connectionSendWindow(), mux::kInitialWindowSize - 4u);
    EXPECT_TRUE(mux.closes.empty());
}

TEST(HandlerHttp2, EndStreamAfterTheEchoClosesTheStream)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, "h"));
    mux.takeFrames();
    mux.push(makeFrame(FRAME_TYPE::DATA, 1, FrameFlags::kEndStream, "bye"));

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

TEST(HandlerHttp2, HeadersWithEndStreamCloseAnIdleStream)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders | FrameFlags::kEndStream, "h"));
    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FRAME_TYPE::DATA);
    EXPECT_EQ(frames[0].streamId, 1u);
    EXPECT_TRUE(frames[0].hasFlag(FrameFlags::kEndStream));
    EXPECT_TRUE(frames[0].payload.empty());
    EXPECT_EQ(mux.openStreams(), 0u);
}

TEST(HandlerHttp2, AReusedTombstoneSlotStartsWithCleanStreamFlags)
{
    ProbeMux mux;
    mux.setMaxConcurrentStreams(1);
    mux.warmUp();

    // 流 1 开启，完成一轮交互并关闭。其流表槽位
    // 变为带有历史状态（remoteEnded/finalSent）的墓碑标记。
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, "h"));
    mux.takeFrames();
    mux.push(makeFrame(FRAME_TYPE::DATA, 1, FrameFlags::kEndStream, "bye"));
    mux.takeFrames();
    ASSERT_EQ(mux.openStreams(), 0u);

    // 后续流 ID 更大、探测序列起始于同一槽位的流
    // （在 8 槽位表中流 ID 1 与 17 哈希值相同）复用该墓碑槽位。
    // 复用的槽位必须表现得如全新流一般：HEADERS 之后的 DATA 正常回显，
    // 不会误判为 END_STREAM 之后的非法流量，最终的 DATA 帧仍可顺利发送。
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 17, FrameFlags::kEndHeaders, "h2"));
    mux.push(makeFrame(FRAME_TYPE::DATA, 17, 0, "again"));
    ASSERT_FALSE(mux.error.has_value()) << mux.why;
    mux.push(makeFrame(FRAME_TYPE::DATA, 17, FrameFlags::kEndStream, ""));

    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 2u);
    EXPECT_EQ(frames[0].payload, "again");
    EXPECT_FALSE(frames[0].hasFlag(FrameFlags::kEndStream));
    EXPECT_EQ(frames[1].streamId, 17u);
    EXPECT_TRUE(frames[1].hasFlag(FrameFlags::kEndStream));
    EXPECT_EQ(mux.openStreams(), 0u);
    ASSERT_EQ(mux.opens.size(), 2u);
    EXPECT_EQ(mux.opens[1], 17u);
    ASSERT_EQ(mux.closes.size(), 2u);
    EXPECT_EQ(mux.closes[1], 17u);
}

TEST(HandlerHttp2, PingIsAcknowledgedWithTheSamePayload)
{
    ProbeMux mux;
    mux.warmUp();

    const std::string opaque(8, '\x2a');
    mux.push(makeFrame(FRAME_TYPE::PING, 0, 0, opaque));
    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FRAME_TYPE::PING);
    EXPECT_TRUE(frames[0].hasFlag(FrameFlags::kAck));
    EXPECT_EQ(frames[0].payload, opaque);

    // 收到对端的 ACK 即宣告此轮 PING 结束，不应再次回复 PING。
    mux.push(makeFrame(FRAME_TYPE::PING, 0, FrameFlags::kAck, opaque));
    EXPECT_TRUE(mux.takeFrames().empty());
}

TEST(HandlerHttp2, PingWithTheWrongPayloadLengthIsAProtocolError)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::PING, 0, 0, "short"));
    EXPECT_EQ(mux.error, STREAM_ERROR::PROTOCOL_ERROR);
}

TEST(HandlerHttp2, AnEvenStreamIdIsAProtocolError)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 2, FrameFlags::kEndHeaders, "h"));
    EXPECT_EQ(mux.error, STREAM_ERROR::PROTOCOL_ERROR);
    EXPECT_TRUE(mux.closeAfterResponse());
    EXPECT_FALSE(mux.goawayReceived());

    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(countOfType(frames, FRAME_TYPE::GOAWAY), 1u);
    EXPECT_NE(mux.why.find("the peer may not open"), std::string::npos);
    EXPECT_TRUE(mux.opens.empty());
}

TEST(HandlerHttp2, DataOnAStreamThatWasNeverOpenedIsAProtocolError)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::DATA, 1, 0, "bytes"));
    EXPECT_EQ(mux.error, STREAM_ERROR::PROTOCOL_ERROR);
    EXPECT_EQ(countOfType(mux.takeFrames(), FRAME_TYPE::GOAWAY), 1u);
}

TEST(HandlerHttp2, ResetOnAFinishedStreamIsOnlyAReset)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders | FrameFlags::kEndStream, "h"));
    mux.takeFrames(); // 流 1 已关闭，且编号小于等于 lastPeerStreamId_
    ASSERT_EQ(mux.openStreams(), 0u);

    mux.push(makeFrame(FRAME_TYPE::DATA, 1, 0, "late"));
    EXPECT_FALSE(mux.error.has_value()); // 属于对端可自行恢复的竞态，非连接级错误
    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FRAME_TYPE::RESET);
    EXPECT_EQ(frames[0].streamId, 1u);
    EXPECT_EQ(frame::readBigEndian32(frames[0].payload.data()), std::to_underlying(STREAM_ERROR::STREAM_CLOSED));
}

TEST(HandlerHttp2, DataBiggerThanTheReceiveWindowIsAFlowControlError)
{
    ProbeMux mux;
    mux.warmUp();

    // 首先调高帧大小上限，否则解码器在流控检查之前就会直接拒绝该字节流。
    mux.push(makeFrame(FRAME_TYPE::SETTINGS, 0, 0, setting(mux::kSettingMaxFrameSize, 1 << 20)));
    mux.takeFrames();
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, "h"));
    mux.takeFrames();

    mux.push(makeFrame(FRAME_TYPE::DATA, 1, 0, std::string(mux::kInitialWindowSize + 1, 'x')));
    EXPECT_EQ(mux.error, STREAM_ERROR::FLOW_CONTROL_ERROR);
    EXPECT_TRUE(mux.closeAfterResponse());
    EXPECT_EQ(countOfType(mux.takeFrames(), FRAME_TYPE::GOAWAY), 1u);
}

TEST(HandlerHttp2, WindowUpdateForTheConnectionGrowsTheSendWindow)
{
    ProbeMux mux;
    mux.warmUp();

    std::string increment;
    frame::appendBigEndian32(increment, 4 << 10);
    mux.push(makeFrame(FRAME_TYPE::WINDOW_UPDATE, 0, 0, increment));
    EXPECT_EQ(mux.connectionSendWindow(), mux::kInitialWindowSize + (4 << 10));

    std::string zero;
    frame::appendBigEndian32(zero, 0);
    mux.push(makeFrame(FRAME_TYPE::WINDOW_UPDATE, 0, 0, zero));
    EXPECT_EQ(mux.error, STREAM_ERROR::PROTOCOL_ERROR);
}

TEST(HandlerHttp2, PushPromiseIsAProtocolErrorOnAServer)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::PUSH_PROMISE, 1, 0, "h"));
    EXPECT_EQ(mux.error, STREAM_ERROR::PROTOCOL_ERROR);
    EXPECT_NE(mux.why.find("PUSH_PROMISE"), std::string::npos);
}

TEST(HandlerHttp2, PriorityIsIgnoredAndLeavesTheConnectionAlone)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::PRIORITY, 1, 0, std::string(5, '\0')));
    EXPECT_FALSE(mux.error.has_value());
    EXPECT_FALSE(mux.closeAfterResponse());
    EXPECT_FALSE(mux.hasResponse());
    EXPECT_TRUE(mux.opens.empty()); // 优先级提示帧不构成新流
}

TEST(HandlerHttp2, GoawayFromThePeerRefusesNewStreams)
{
    ProbeMux mux;
    mux.warmUp();

    std::string payload;
    frame::appendBigEndian32(payload, 1u);
    frame::appendBigEndian32(payload, 0u);
    mux.push(makeFrame(FRAME_TYPE::GOAWAY, 0, 0, payload));
    EXPECT_TRUE(mux.goawayReceived());
    EXPECT_TRUE(mux.takeFrames().empty());

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 3, FrameFlags::kEndHeaders, "h"));
    EXPECT_EQ(mux.openStreams(), 0u);
    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FRAME_TYPE::RESET);
    EXPECT_EQ(frames[0].streamId, 3u);
    EXPECT_EQ(frame::readBigEndian32(frames[0].payload.data()), std::to_underlying(STREAM_ERROR::REFUSED_STREAM));
}

TEST(HandlerHttp2, ShortGoawayPayloadIsAProtocolError)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::GOAWAY, 0, 0, "abc"));
    EXPECT_EQ(mux.error, STREAM_ERROR::PROTOCOL_ERROR);
}

TEST(HandlerHttp2, MaxConcurrentStreamsBoundsTheStreamTable)
{
    ProbeMux mux;
    mux.setMaxConcurrentStreams(2);
    EXPECT_EQ(mux.maxConcurrentStreams(), 2u);
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, "h"));
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 3, FrameFlags::kEndHeaders, "h"));
    EXPECT_EQ(mux.openStreams(), 2u);
    mux.takeFrames();

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 5, FrameFlags::kEndHeaders, "h"));
    EXPECT_EQ(mux.openStreams(), 2u);
    EXPECT_FALSE(mux.error.has_value()); // 仅拒绝该流，不破坏连接
    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FRAME_TYPE::RESET);
    EXPECT_EQ(frames[0].streamId, 5u);
    EXPECT_EQ(frame::readBigEndian32(frames[0].payload.data()), std::to_underlying(STREAM_ERROR::REFUSED_STREAM));
    ASSERT_EQ(mux.opens.size(), 2u);
}

TEST(HandlerHttp2, AZeroStreamLimitIsClampedToOne)
{
    ProbeMux mux;
    mux.setMaxConcurrentStreams(0);
    EXPECT_EQ(mux.maxConcurrentStreams(), 1u);
    EXPECT_EQ(mux.streamPoolCapacity(), 1u);
}

TEST(HandlerHttp2, AFrameSplitAcrossAppendsIsBufferedUntilWhole)
{
    ProbeMux mux;
    mux.warmUp();

    std::string bytes;
    appendFrame(bytes, makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, "hello"));
    ASSERT_GT(bytes.size(), size_t{5});

    [[maybe_unused]] auto _ = mux.appendRequest(bytes.data(), 5);
    mux.process();
    EXPECT_EQ(mux.openStreams(), 0u);
    EXPECT_TRUE(mux.headers.empty());

    [[maybe_unused]] auto _ = mux.appendRequest(bytes.data() + 5, static_cast<ssize_t>(bytes.size() - 5));
    mux.process();
    EXPECT_EQ(mux.openStreams(), 1u);
    ASSERT_EQ(mux.headers.size(), 1u);
    EXPECT_EQ(mux.headers[0].second, "hello");
}

TEST(HandlerHttp2, AFrameLongerThanTheCeilingEndsTheConnection)
{
    ProbeMux mux;
    mux.warmUp();

    // 16385 字节比默认上限多 1 字节，帧结构本身合法：报错点在于其声明的载荷超长。
    mux.push(makeFrame(FRAME_TYPE::DATA, 1, 0, std::string(frame::kDefaultMaxFrameSize + 1, 'x')));
    EXPECT_EQ(mux.error, STREAM_ERROR::PROTOCOL_ERROR);
    EXPECT_TRUE(mux.closeAfterResponse());
    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(countOfType(frames, FRAME_TYPE::GOAWAY), 1u);
}

TEST(HandlerHttp2, ResetReturnsTheConnectionToAFreshState)
{
    ProbeMux mux;
    mux.warmUp();
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, "h"));
    mux.takeFrames();
    ASSERT_EQ(mux.openStreams(), 1u);

    mux.reset();
    EXPECT_EQ(mux.openStreams(), 0u);
    EXPECT_EQ(mux.lastPeerStreamId(), 0u);
    EXPECT_EQ(mux.connectionSendWindow(), mux::kInitialWindowSize);
    EXPECT_FALSE(mux.goawayReceived());

    mux.process(); // 重置后的连接重新对外宣告自身的设置帧
    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FRAME_TYPE::SETTINGS);
}

TEST(HandlerHttp2, PaddedDataHasItsPaddingRemovedBeforeTheHandlerSeesIt)
{
    ProbeMux mux;
    mux.warmUp();
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, "h"));
    mux.takeFrames();

    std::string payload;
    payload.push_back('\x03'); // 载荷内容之后紧跟 3 字节填充
    payload += "body";
    payload.append(3, '\0');
    mux.push(makeFrame(FRAME_TYPE::DATA, 1, FrameFlags::kPadded, payload));

    ASSERT_EQ(mux.data.size(), 1u);
    EXPECT_EQ(mux.data[0].second, "body");
    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].payload, "body");
}

TEST(HandlerHttp2, PaddingLongerThanThePayloadIsAProtocolError)
{
    ProbeMux mux;
    mux.warmUp();
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, "h"));
    mux.takeFrames();

    std::string payload;
    payload.push_back('\x7f'); // 1 字节载荷却声明含有 127 字节填充（越界）
    mux.push(makeFrame(FRAME_TYPE::DATA, 1, FrameFlags::kPadded, payload));
    EXPECT_EQ(mux.error, STREAM_ERROR::PROTOCOL_ERROR);
    EXPECT_NE(mux.why.find("padding"), std::string::npos);
}

TEST(HandlerHttp2, WindowUpdateConnectionOverflowIsFlowControlError)
{
    ProbeMux mux;
    mux.warmUp();

    std::string increment;
    frame::appendBigEndian32(increment, 0x7fffffffu);
    mux.push(makeFrame(FRAME_TYPE::WINDOW_UPDATE, 0, 0, increment));
    EXPECT_EQ(mux.error, STREAM_ERROR::FLOW_CONTROL_ERROR);
    EXPECT_TRUE(mux.closeAfterResponse());
}

TEST(HandlerHttp2, WindowUpdateStreamOverflowIsReset)
{
    ProbeMux mux;
    mux.warmUp();
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, "h"));
    mux.takeFrames();

    std::string increment;
    frame::appendBigEndian32(increment, 0x7fffffffu);
    mux.push(makeFrame(FRAME_TYPE::WINDOW_UPDATE, 1, 0, increment));

    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FRAME_TYPE::RESET);
    EXPECT_EQ(frames[0].streamId, 1u);
    EXPECT_EQ(frame::readBigEndian32(frames[0].payload.data()), std::to_underlying(STREAM_ERROR::FLOW_CONTROL_ERROR));
    EXPECT_EQ(mux.stream(1), nullptr); // 流发生流控错误后必须被关闭回收，防止槽位泄漏
}

TEST(HandlerHttp2, StreamWindowUpdateZeroIncrementResetsAndClosesStream)
{
    ProbeMux mux;
    mux.warmUp();
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, "h"));
    mux.takeFrames();
    ASSERT_NE(mux.stream(1), nullptr);

    std::string zero;
    frame::appendBigEndian32(zero, 0);
    mux.push(makeFrame(FRAME_TYPE::WINDOW_UPDATE, 1, 0, zero));

    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FRAME_TYPE::RESET);
    EXPECT_EQ(frames[0].streamId, 1u);
    EXPECT_EQ(frame::readBigEndian32(frames[0].payload.data()), std::to_underlying(STREAM_ERROR::PROTOCOL_ERROR));
    EXPECT_EQ(mux.stream(1), nullptr); // 增量为 0 的流控错误同样必须关闭回收流槽位
}

TEST(HandlerHttp2, PriorityFrameWrongPayloadLengthSendsFrameSizeError)
{
    ProbeMux mux;
    mux.warmUp();
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, "h"));
    mux.takeFrames();

    // PRIORITY 帧载荷必须精确为 5 字节，若不符则应发送 FRAME_SIZE_ERROR 重置流
    mux.push(makeFrame(FRAME_TYPE::PRIORITY, 1, 0, "1234")); // 4 字节
    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FRAME_TYPE::RESET);
    EXPECT_EQ(frames[0].streamId, 1u);
    EXPECT_EQ(frame::readBigEndian32(frames[0].payload.data()), std::to_underlying(STREAM_ERROR::FRAME_SIZE_ERROR));
}

TEST(HandlerHttp2, RstStreamOnIdleStreamIsProtocolError)
{
    ProbeMux mux;
    mux.warmUp();

    std::string errCode;
    frame::appendBigEndian32(errCode, std::to_underlying(STREAM_ERROR::CANCEL));
    mux.push(makeFrame(FRAME_TYPE::RESET, 99, 0, errCode));
    EXPECT_EQ(mux.error, STREAM_ERROR::PROTOCOL_ERROR);
    EXPECT_TRUE(mux.closeAfterResponse());
}

TEST(HandlerHttp2, SettingsInitialWindowSizeOverflowIsFlowControlError)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::SETTINGS, 0, 0, setting(mux::kSettingInitialWindowSize, 0x80000000u)));
    EXPECT_EQ(mux.error, STREAM_ERROR::FLOW_CONTROL_ERROR);
    EXPECT_TRUE(mux.closeAfterResponse());
}

TEST(HandlerHttp2, SettingsInvalidMaxFrameSizeIsProtocolError)
{
    ProbeMux mux;
    mux.warmUp();

    // HTTP/2 规范中最大帧大小小于 16384 是非法的
    mux.push(makeFrame(FRAME_TYPE::SETTINGS, 0, 0, setting(mux::kSettingMaxFrameSize, 1024)));
    EXPECT_EQ(mux.error, STREAM_ERROR::PROTOCOL_ERROR);
    EXPECT_TRUE(mux.closeAfterResponse());
}

TEST(HandlerHttp2, DataOnConnectionStreamIsProtocolError)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::DATA, 0, 0, "payload"));
    EXPECT_EQ(mux.error, STREAM_ERROR::PROTOCOL_ERROR);
    EXPECT_TRUE(mux.closeAfterResponse());
}

TEST(HandlerHttp2, PriorityOnConnectionStreamIsProtocolError)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::PRIORITY, 0, 0, "12345"));
    EXPECT_EQ(mux.error, STREAM_ERROR::PROTOCOL_ERROR);
    EXPECT_TRUE(mux.closeAfterResponse());
}

TEST(HandlerHttp2, WindowUpdateOnIdleStreamIsProtocolError)
{
    ProbeMux mux;
    mux.warmUp();

    std::string increment;
    frame::appendBigEndian32(increment, 1024);
    mux.push(makeFrame(FRAME_TYPE::WINDOW_UPDATE, 77, 0, increment));
    EXPECT_EQ(mux.error, STREAM_ERROR::PROTOCOL_ERROR);
    EXPECT_TRUE(mux.closeAfterResponse());
}

TEST(HandlerHttp2, UnexpectedContinuationFrameIsProtocolError)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::CONTINUATION, 1, 0, "headerblock"));
    EXPECT_EQ(mux.error, STREAM_ERROR::PROTOCOL_ERROR);
    EXPECT_TRUE(mux.closeAfterResponse());
}

TEST(HandlerHttp2, InitialWindowReductionPausesStreamUntilWindowUpdate)
{
    ProbeMux mux;
    mux.warmUp();

    // 发送 HEADERS 开启流 1
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, "h"));
    mux.takeFrames();

    // 将初始流控窗口大小缩小至 0
    mux.push(makeFrame(FRAME_TYPE::SETTINGS, 0, 0, setting(mux::kSettingInitialWindowSize, 0)));
    mux.takeFrames();

    // 向流 1 发送数据——因 sendWindow <= 0，数据应排队挂起
    mux.push(makeFrame(FRAME_TYPE::DATA, 1, 0, "hello"));
    EXPECT_TRUE(mux.takeFrames().empty()); // 不应发出 DATA 帧

    // 发送 WINDOW_UPDATE 恢复发送窗口
    std::string increment;
    frame::appendBigEndian32(increment, 1000);
    mux.push(makeFrame(FRAME_TYPE::WINDOW_UPDATE, 1, 0, increment));

    // 此时挂起的数据应被正常推送发送
    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FRAME_TYPE::DATA);
    EXPECT_EQ(frames[0].payload, "hello");
}

TEST(HandlerHttp2, StreamWithMultipleResponsesSendsAllPartsBeforeEndStream)
{
    TwoPartMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, "headers"));
    [[maybe_unused]] auto _ = mux.takeFrames();

    mux.push(makeFrame(FRAME_TYPE::DATA, 1, FrameFlags::kEndStream, "ping"));
    const std::vector<Frame> frames = mux.takeFrames();

    ASSERT_EQ(frames.size(), 3u);
    EXPECT_EQ(frames[0].streamId, 1u);
    EXPECT_EQ(frames[0].type, FRAME_TYPE::DATA);
    EXPECT_EQ(frames[0].payload, "part1_");

    EXPECT_EQ(frames[1].streamId, 1u);
    EXPECT_EQ(frames[1].type, FRAME_TYPE::DATA);
    EXPECT_EQ(frames[1].payload, "part2");

    EXPECT_EQ(frames[2].streamId, 1u);
    EXPECT_EQ(frames[2].type, FRAME_TYPE::DATA);
    EXPECT_TRUE(frames[2].hasFlag(FrameFlags::kEndStream));
    EXPECT_TRUE(frames[2].payload.empty());
}

TEST(HandlerHttp2, SettingsInitialWindowDeltaOverflowIsFlowControlError)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, "h"));
    [[maybe_unused]] auto _ = mux.takeFrames();

    std::string increment;
    frame::appendBigEndian32(increment, 1000);
    mux.push(makeFrame(FRAME_TYPE::WINDOW_UPDATE, 1, 0, increment));

    mux.push(makeFrame(FRAME_TYPE::SETTINGS, 0, 0, setting(mux::kSettingInitialWindowSize, 0x7fffffff)));

    EXPECT_EQ(mux.error, STREAM_ERROR::FLOW_CONTROL_ERROR);
    EXPECT_TRUE(mux.closeAfterResponse());
}

TEST(HandlerHttp2, RapidResetFloodTriggersEnhanceYourCalm)
{
    ProbeMux mux;
    mux.warmUp();

    std::string resetPayload;
    frame::appendBigEndian32(resetPayload, std::to_underlying(STREAM_ERROR::CANCEL));

    for (uint32_t i = 1; i <= 205; i += 2)
    {
        mux.push(makeFrame(FRAME_TYPE::HEADERS, i, FrameFlags::kEndHeaders, "h"));
        mux.push(makeFrame(FRAME_TYPE::RESET, i, 0, resetPayload));
        if (mux.error.has_value())
            break;
    }

    EXPECT_EQ(mux.error, STREAM_ERROR::ENHANCE_YOUR_CALM);
    EXPECT_TRUE(mux.closeAfterResponse());
}

TEST(HandlerHttp2, PingFloodTriggersEnhanceYourCalm)
{
    ProbeMux mux;
    mux.warmUp();

    for (int i = 0; i < 70; ++i)
    {
        mux.push(makeFrame(FRAME_TYPE::PING, 0, 0, "12345678"));
        if (mux.error.has_value())
            break;
    }

    EXPECT_EQ(mux.error, STREAM_ERROR::ENHANCE_YOUR_CALM);
    EXPECT_TRUE(mux.closeAfterResponse());
}

TEST(HandlerHttp2, HeadersMissingEndHeadersFlagIsProtocolError)
{
    ProbeMux mux;
    mux.warmUp();

    // CVE-2024-27983 Continuation Flood 防御验证：缺少 END_HEADERS 标志直接按协议错误拒绝
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, 0, "h"));
    EXPECT_EQ(mux.error, STREAM_ERROR::PROTOCOL_ERROR);
    EXPECT_TRUE(mux.closeAfterResponse());
}

TEST(HandlerHttp2, SettingsFloodTriggersEnhanceYourCalm)
{
    ProbeMux mux;
    mux.warmUp();

    // CVE-2019-9515 Settings Flood 防御验证：连续未确认的 SETTINGS 帧触发限流
    for (int i = 0; i < 20; ++i)
    {
        mux.push(makeFrame(FRAME_TYPE::SETTINGS, 0, 0, {}));
        if (mux.error.has_value())
            break;
    }

    EXPECT_EQ(mux.error, STREAM_ERROR::ENHANCE_YOUR_CALM);
    EXPECT_TRUE(mux.closeAfterResponse());
}

TEST(HandlerHttp2, EmptyFrameFloodTriggersEnhanceYourCalm)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, "h"));
    mux.takeFrames();

    // CVE-2019-9518 Empty Frame Flood 防御验证：连续空 DATA 帧触发限流
    for (int i = 0; i < 40; ++i)
    {
        mux.push(makeFrame(FRAME_TYPE::DATA, 1, 0, ""));
        if (mux.error.has_value())
            break;
    }

    EXPECT_EQ(mux.error, STREAM_ERROR::ENHANCE_YOUR_CALM);
    EXPECT_TRUE(mux.closeAfterResponse());
}

TEST(HandlerHttp2, WindowUpdateFloodTriggersEnhanceYourCalm)
{
    ProbeMux mux;
    mux.warmUp();

    std::string increment;
    frame::appendBigEndian32(increment, 1);

    // CVE-2019-9511 / CVE-2019-9513 Window Update Flood 防御验证
    for (int i = 0; i < 110; ++i)
    {
        mux.push(makeFrame(FRAME_TYPE::WINDOW_UPDATE, 0, 0, increment));
        if (mux.error.has_value())
            break;
    }

    EXPECT_EQ(mux.error, STREAM_ERROR::ENHANCE_YOUR_CALM);
    EXPECT_TRUE(mux.closeAfterResponse());
}

TEST(HandlerHttp2, PriorityFloodTriggersEnhanceYourCalm)
{
    ProbeMux mux;
    mux.warmUp();

    // CVE-2019-9513 Priority Flood 防御验证
    for (int i = 0; i < 70; ++i)
    {
        mux.push(makeFrame(FRAME_TYPE::PRIORITY, 1, 0, std::string(5, '\0')));
        if (mux.error.has_value())
            break;
    }

    EXPECT_EQ(mux.error, STREAM_ERROR::ENHANCE_YOUR_CALM);
    EXPECT_TRUE(mux.closeAfterResponse());
}

TEST(HandlerHttp2, PaddedDataDeductsEntirePayloadFromWindow)
{
    ProbeMux mux;
    mux.warmUp();
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, "h"));
    mux.takeFrames();

    const uint32_t connWinBefore = mux.connRecvWindow_;
    const uint32_t streamWinBefore = mux.stream(1)->recvWindow;

    // 载荷构成: 1 字节 padlen(=10) + 4 字节数据("data") + 10 字节填充 = 15 字节
    std::string payload;
    payload.push_back('\x0a'); // 10 字节填充
    payload += "data";
    payload.append(10, '\0');

    mux.push(makeFrame(FRAME_TYPE::DATA, 1, FrameFlags::kPadded, payload));

    // RFC 7540 §6.1 要求扣减全部 15 字节，而非剥离后的 4 字节
    EXPECT_EQ(connWinBefore - mux.connRecvWindow_, 15u);
    EXPECT_EQ(streamWinBefore - mux.stream(1)->recvWindow, 15u);
}

TEST(HandlerHttp2, GoawayClosesStreamsAboveLastStreamId)
{
    ProbeMux mux;
    mux.warmUp();

    // 开启流 1 和流 3
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, "h1"));
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 3, FrameFlags::kEndHeaders, "h3"));
    mux.takeFrames();

    EXPECT_EQ(mux.openStreams(), 2u);

    // 对端发送 GOAWAY，lastStreamId = 1
    std::string goawayPayload;
    frame::appendBigEndian32(goawayPayload, 1); // lastStreamId = 1
    frame::appendBigEndian32(goawayPayload, std::to_underlying(STREAM_ERROR::NO_ERROR));
    mux.push(makeFrame(FRAME_TYPE::GOAWAY, 0, 0, goawayPayload));

    // RFC 7540 §6.8: 流 3 (> lastStreamId) 必须已被关闭
    EXPECT_NE(mux.stream(1), nullptr);
    EXPECT_EQ(mux.stream(3), nullptr);
    EXPECT_EQ(mux.openStreams(), 1u);
}

// ---- 慢读背压（readPaused）：出站响应未排空时暂停流级窗口信用恢复 ----

// process() 一次性产出 128KiB 响应：超出对端默认发送窗口（65535），
// 迫使出站数据驻留在流槽位（pending / handler 队列）中，模拟慢读对端。
class BigReplyHandler : public HandlerConnection
{
public:
    void process()
    {
        if (requestBytes() > 0)
        {
            requestClear();
            [[maybe_unused]] auto _ = pushResponse(std::string(69632, 'r')); // 65535+4097：必驻留且一轮可排空
        }
    }
};

class BigReplyMux : public HandlerHttp2<BigReplyHandler>
{
public:
    using HandlerHttp2<BigReplyHandler>::connRecvWindow_;
    using HandlerHttp2<BigReplyHandler>::stream;

    std::optional<STREAM_ERROR> error;
    std::string why;

    void onProtocolError(STREAM_ERROR code, std::string_view reason) noexcept override
    {
        error = code;
        why.assign(reason);
    }

    void push(const Frame &frame)
    {
        std::string bytes;
        appendFrame(bytes, frame);
        [[maybe_unused]] auto _ = appendRequest(bytes.data(), static_cast<ssize_t>(bytes.size()));
        process();
    }

    std::vector<Frame> takeFrames()
    {
        std::string bytes;
        while (hasResponse())
            bytes += takeResponse();
        std::vector<Frame> frames;
        Buffer in;
        if (!bytes.empty())
        {
            [[maybe_unused]] auto _ = in.append(bytes);
        }
        // 本地解码上限对齐测试注入的 SETTINGS_MAX_FRAME_SIZE（1MiB）：
        // mux 按协商上限发送大 DATA 帧（65535/69632 字节），默认 16KiB 解码上限会误判 FRAME_TOO_LARGE。
        FrameDecoder decoder;
        decoder.setMaxFrameSize(1u << 20);
        while (in.readableBytes() > 0)
        {
            auto parsed = decoder.next(in);
            if (!parsed || !parsed->has_value())
                break;
            frames.push_back(std::move(parsed->value()));
        }
        return frames;
    }

    void warmUp()
    {
        process();
        [[maybe_unused]] auto _ = takeFrames();
        push(makeFrame(FRAME_TYPE::SETTINGS, 0, FrameFlags::kAck, {}));
    }
};

TEST(HandlerHttp2, SlowReaderPausesStreamLevelWindowCredit)
{
    BigReplyMux mux;
    mux.warmUp();

    // 调高帧大小上限；InitialWindowSize 保持默认 65535。
    mux.push(makeFrame(FRAME_TYPE::SETTINGS, 0, 0, setting(mux::kSettingMaxFrameSize, 1 << 20)));
    mux.takeFrames();
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, "h"));
    mux.takeFrames();

    auto countStreamWindowUpdates = [&mux] {
        size_t n = 0;
        for (const Frame &f : mux.takeFrames())
        {
            if (f.type == FRAME_TYPE::WINDOW_UPDATE && f.streamId == 1u)
                ++n;
        }
        return n;
    };

    // 第一轮注入：响应 69632 > 对端发送窗口 65535，出站驻留 → 置 readPaused。
    // 本轮窗口信用照常恢复（对已收数据负责），流级 WINDOW_UPDATE 正常发出。
    mux.push(makeFrame(FRAME_TYPE::DATA, 1, 0, std::string(40u * 1024u, 'a')));
    ASSERT_NE(mux.stream(1), nullptr);
    EXPECT_EQ(mux.stream(1)->recvWindow, mux::kInitialWindowSize);
    EXPECT_EQ(countStreamWindowUpdates(), 1u);

    // 第二轮注入（readPaused 生效）：窗口跌破阈值但不再恢复、不发流级 WINDOW_UPDATE。
    // 修复前此处会恢复到 65535 并发 WINDOW_UPDATE —— 慢读放大正是从这一步开始。
    mux.push(makeFrame(FRAME_TYPE::DATA, 1, 0, std::string(40u * 1024u, 'b')));
    ASSERT_NE(mux.stream(1), nullptr);
    EXPECT_EQ(mux.stream(1)->recvWindow, mux::kInitialWindowSize - 40u * 1024u);
    EXPECT_EQ(countStreamWindowUpdates(), 0u);

    // 榨干剩余流级窗口（24575）：窗口归零且依然不被恢复。
    mux.push(makeFrame(FRAME_TYPE::DATA, 1, 0, std::string(24575u, 'c')));
    ASSERT_NE(mux.stream(1), nullptr);
    EXPECT_EQ(mux.stream(1)->recvWindow, 0u);
    EXPECT_EQ(countStreamWindowUpdates(), 0u);

    // 窗口为 0 后再注入即触发流控错误：对端被真正阻断，放大链路被切断。
    mux.push(makeFrame(FRAME_TYPE::DATA, 1, 0, "x"));
    EXPECT_EQ(mux.error, STREAM_ERROR::FLOW_CONTROL_ERROR);
}

TEST(HandlerHttp2, DrainingOutboundRestoresPausedStreamWindow)
{
    BigReplyMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::SETTINGS, 0, 0, setting(mux::kSettingMaxFrameSize, 1 << 20)));
    mux.takeFrames();
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, "h"));
    mux.takeFrames();

    // 第一轮注入：出站驻留 4097 字节，readPaused 置位，流级窗口恢复到 65535。
    mux.push(makeFrame(FRAME_TYPE::DATA, 1, 0, std::string(40u * 1024u, 'a')));
    ASSERT_NE(mux.stream(1), nullptr);
    ASSERT_EQ(mux.stream(1)->recvWindow, mux::kInitialWindowSize);
    mux.takeFrames();

    // 第二轮注入：readPaused 生效，流级窗口停在 24575。
    mux.push(makeFrame(FRAME_TYPE::DATA, 1, 0, std::string(40u * 1024u, 'b')));
    ASSERT_NE(mux.stream(1), nullptr);
    ASSERT_EQ(mux.stream(1)->recvWindow, mux::kInitialWindowSize - 40u * 1024u);
    mux.takeFrames();

    // 对端补发送侧信用（连接级先恢复 pumpAll 的推进条件，流级随后真正推进发送），
    // 多路复用器把驻留响应（4097 + 69632）全部排空。
    std::string connInc;
    frame::appendBigEndian32(connInc, 1u << 20);
    mux.push(makeFrame(FRAME_TYPE::WINDOW_UPDATE, 0, 0, connInc));
    std::string streamInc;
    frame::appendBigEndian32(streamInc, 1u << 20);
    mux.push(makeFrame(FRAME_TYPE::WINDOW_UPDATE, 1, 0, streamInc));

    // 出站排空后补发流级窗口恢复：increment = 65535 - 24575 = 40960。
    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 3u);
    EXPECT_EQ(frames[0].type, FRAME_TYPE::DATA);
    EXPECT_EQ(frames[0].payload.size(), 4097u);
    EXPECT_EQ(frames[1].type, FRAME_TYPE::DATA);
    EXPECT_EQ(frames[1].payload.size(), 69632u);
    EXPECT_EQ(frames[2].type, FRAME_TYPE::WINDOW_UPDATE);
    EXPECT_EQ(frames[2].streamId, 1u);
    const auto *p = reinterpret_cast<const unsigned char *>(frames[2].payload.data());
    const uint32_t increment = (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
                               (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
    EXPECT_EQ(increment, 40u * 1024u);
    ASSERT_NE(mux.stream(1), nullptr);
    EXPECT_EQ(mux.stream(1)->recvWindow, mux::kInitialWindowSize);
}
