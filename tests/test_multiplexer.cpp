// Multiplexer<HandlerBase>：在单条物理字节流上承载多个独立的流式交互。
// 这些测试模拟网络连接的行为驱动它——将完整的帧追加到请求缓冲区，
// 并从响应队列中读回其回复，这是上层唯一实际依赖的接口。
#include "handler.hpp"
#include "http/v2/frame.hpp"
#include "http/v2/multiplexer.hpp"
#include <algorithm>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace mynet;

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
    class TwoPartHandler : public HandlerBase
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

    class TwoPartMux : public Multiplexer<TwoPartHandler>
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

    class ProbeMux : public Multiplexer<HandlerBase>
    {
    public:
        std::vector<uint32_t> opens;
        std::vector<uint32_t> closes;
        std::vector<std::pair<uint32_t, std::string>> headers;
        std::vector<std::pair<uint32_t, std::string>> data;
        std::optional<STREAM_ERROR> error;
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

TEST(Multiplexer, FirstProcessAnnouncesSettings)
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

TEST(Multiplexer, SettingsFromThePeerIsAcknowledgedAndNothingElseIsSent)
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

TEST(Multiplexer, SettingsAckWithAPayloadIsAProtocolError)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::SETTINGS, 0, FrameFlags::kAck, std::string(1, 'x')));
    EXPECT_EQ(mux.error, STREAM_ERROR::PROTOCOL_ERROR);
    EXPECT_TRUE(mux.closeAfterResponse());
    EXPECT_EQ(countOfType(mux.takeFrames(), FRAME_TYPE::GOAWAY), 1u);
}

TEST(Multiplexer, HeadersOpenAStreamAndItsDataEchoesBack)
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

TEST(Multiplexer, EndStreamAfterTheEchoClosesTheStream)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, 0, "h"));
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

TEST(Multiplexer, HeadersWithEndStreamCloseAnIdleStream)
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

TEST(Multiplexer, AReusedTombstoneSlotStartsWithCleanStreamFlags)
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

TEST(Multiplexer, PingIsAcknowledgedWithTheSamePayload)
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

TEST(Multiplexer, PingWithTheWrongPayloadLengthIsAProtocolError)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::PING, 0, 0, "short"));
    EXPECT_EQ(mux.error, STREAM_ERROR::PROTOCOL_ERROR);
}

TEST(Multiplexer, AnEvenStreamIdIsAProtocolError)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 2, 0, "h"));
    EXPECT_EQ(mux.error, STREAM_ERROR::PROTOCOL_ERROR);
    EXPECT_TRUE(mux.closeAfterResponse());
    EXPECT_FALSE(mux.goawayReceived());

    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(countOfType(frames, FRAME_TYPE::GOAWAY), 1u);
    EXPECT_NE(mux.why.find("the peer may not open"), std::string::npos);
    EXPECT_TRUE(mux.opens.empty());
}

TEST(Multiplexer, DataOnAStreamThatWasNeverOpenedIsAProtocolError)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::DATA, 1, 0, "bytes"));
    EXPECT_EQ(mux.error, STREAM_ERROR::PROTOCOL_ERROR);
    EXPECT_EQ(countOfType(mux.takeFrames(), FRAME_TYPE::GOAWAY), 1u);
}

TEST(Multiplexer, ResetOnAFinishedStreamIsOnlyAReset)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndStream, "h"));
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

TEST(Multiplexer, DataBiggerThanTheReceiveWindowIsAFlowControlError)
{
    ProbeMux mux;
    mux.warmUp();

    // 首先调高帧大小上限，否则解码器在流控检查之前就会直接拒绝该字节流。
    mux.push(makeFrame(FRAME_TYPE::SETTINGS, 0, 0, setting(mux::kSettingMaxFrameSize, 1 << 20)));
    mux.takeFrames();
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, 0, "h"));
    mux.takeFrames();

    mux.push(makeFrame(FRAME_TYPE::DATA, 1, 0, std::string(mux::kInitialWindowSize + 1, 'x')));
    EXPECT_EQ(mux.error, STREAM_ERROR::FLOW_CONTROL_ERROR);
    EXPECT_TRUE(mux.closeAfterResponse());
    EXPECT_EQ(countOfType(mux.takeFrames(), FRAME_TYPE::GOAWAY), 1u);
}

TEST(Multiplexer, WindowUpdateForTheConnectionGrowsTheSendWindow)
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

TEST(Multiplexer, PushPromiseIsAProtocolErrorOnAServer)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::PUSH_PROMISE, 1, 0, "h"));
    EXPECT_EQ(mux.error, STREAM_ERROR::PROTOCOL_ERROR);
    EXPECT_NE(mux.why.find("PUSH_PROMISE"), std::string::npos);
}

TEST(Multiplexer, PriorityIsIgnoredAndLeavesTheConnectionAlone)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::PRIORITY, 1, 0, std::string(5, '\0')));
    EXPECT_FALSE(mux.error.has_value());
    EXPECT_FALSE(mux.closeAfterResponse());
    EXPECT_FALSE(mux.hasResponse());
    EXPECT_TRUE(mux.opens.empty()); // 优先级提示帧不构成新流
}

TEST(Multiplexer, GoawayFromThePeerRefusesNewStreams)
{
    ProbeMux mux;
    mux.warmUp();

    std::string payload;
    frame::appendBigEndian32(payload, 1u);
    frame::appendBigEndian32(payload, 0u);
    mux.push(makeFrame(FRAME_TYPE::GOAWAY, 0, 0, payload));
    EXPECT_TRUE(mux.goawayReceived());
    EXPECT_TRUE(mux.takeFrames().empty());

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 3, 0, "h"));
    EXPECT_EQ(mux.openStreams(), 0u);
    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FRAME_TYPE::RESET);
    EXPECT_EQ(frames[0].streamId, 3u);
    EXPECT_EQ(frame::readBigEndian32(frames[0].payload.data()), std::to_underlying(STREAM_ERROR::REFUSED_STREAM));
}

TEST(Multiplexer, ShortGoawayPayloadIsAProtocolError)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::GOAWAY, 0, 0, "abc"));
    EXPECT_EQ(mux.error, STREAM_ERROR::PROTOCOL_ERROR);
}

TEST(Multiplexer, MaxConcurrentStreamsBoundsTheStreamTable)
{
    ProbeMux mux;
    mux.setMaxConcurrentStreams(2);
    EXPECT_EQ(mux.maxConcurrentStreams(), 2u);
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, 0, "h"));
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 3, 0, "h"));
    EXPECT_EQ(mux.openStreams(), 2u);
    mux.takeFrames();

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 5, 0, "h"));
    EXPECT_EQ(mux.openStreams(), 2u);
    EXPECT_FALSE(mux.error.has_value()); // 仅拒绝该流，不破坏连接
    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FRAME_TYPE::RESET);
    EXPECT_EQ(frames[0].streamId, 5u);
    EXPECT_EQ(frame::readBigEndian32(frames[0].payload.data()), std::to_underlying(STREAM_ERROR::REFUSED_STREAM));
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

TEST(Multiplexer, AFrameLongerThanTheCeilingEndsTheConnection)
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

TEST(Multiplexer, ResetReturnsTheConnectionToAFreshState)
{
    ProbeMux mux;
    mux.warmUp();
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, 0, "h"));
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

TEST(Multiplexer, PaddedDataHasItsPaddingRemovedBeforeTheHandlerSeesIt)
{
    ProbeMux mux;
    mux.warmUp();
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, 0, "h"));
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

TEST(Multiplexer, PaddingLongerThanThePayloadIsAProtocolError)
{
    ProbeMux mux;
    mux.warmUp();
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, 0, "h"));
    mux.takeFrames();

    std::string payload;
    payload.push_back('\x7f'); // 1 字节载荷却声明含有 127 字节填充（越界）
    mux.push(makeFrame(FRAME_TYPE::DATA, 1, FrameFlags::kPadded, payload));
    EXPECT_EQ(mux.error, STREAM_ERROR::PROTOCOL_ERROR);
    EXPECT_NE(mux.why.find("padding"), std::string::npos);
}

TEST(Multiplexer, WindowUpdateConnectionOverflowIsFlowControlError)
{
    ProbeMux mux;
    mux.warmUp();

    std::string increment;
    frame::appendBigEndian32(increment, 0x7fffffffu);
    mux.push(makeFrame(FRAME_TYPE::WINDOW_UPDATE, 0, 0, increment));
    EXPECT_EQ(mux.error, STREAM_ERROR::FLOW_CONTROL_ERROR);
    EXPECT_TRUE(mux.closeAfterResponse());
}

TEST(Multiplexer, WindowUpdateStreamOverflowIsReset)
{
    ProbeMux mux;
    mux.warmUp();
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, 0, "h"));
    mux.takeFrames();

    std::string increment;
    frame::appendBigEndian32(increment, 0x7fffffffu);
    mux.push(makeFrame(FRAME_TYPE::WINDOW_UPDATE, 1, 0, increment));

    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FRAME_TYPE::RESET);
    EXPECT_EQ(frames[0].streamId, 1u);
    EXPECT_EQ(frame::readBigEndian32(frames[0].payload.data()), std::to_underlying(STREAM_ERROR::FLOW_CONTROL_ERROR));
}

TEST(Multiplexer, RstStreamOnIdleStreamIsProtocolError)
{
    ProbeMux mux;
    mux.warmUp();

    std::string errCode;
    frame::appendBigEndian32(errCode, std::to_underlying(STREAM_ERROR::CANCEL));
    mux.push(makeFrame(FRAME_TYPE::RESET, 99, 0, errCode));
    EXPECT_EQ(mux.error, STREAM_ERROR::PROTOCOL_ERROR);
    EXPECT_TRUE(mux.closeAfterResponse());
}

TEST(Multiplexer, SettingsInitialWindowSizeOverflowIsFlowControlError)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::SETTINGS, 0, 0, setting(mux::kSettingInitialWindowSize, 0x80000000u)));
    EXPECT_EQ(mux.error, STREAM_ERROR::FLOW_CONTROL_ERROR);
    EXPECT_TRUE(mux.closeAfterResponse());
}

TEST(Multiplexer, SettingsInvalidMaxFrameSizeIsProtocolError)
{
    ProbeMux mux;
    mux.warmUp();

    // HTTP/2 规范中最大帧大小小于 16384 是非法的
    mux.push(makeFrame(FRAME_TYPE::SETTINGS, 0, 0, setting(mux::kSettingMaxFrameSize, 1024)));
    EXPECT_EQ(mux.error, STREAM_ERROR::PROTOCOL_ERROR);
    EXPECT_TRUE(mux.closeAfterResponse());
}

TEST(Multiplexer, DataOnConnectionStreamIsProtocolError)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::DATA, 0, 0, "payload"));
    EXPECT_EQ(mux.error, STREAM_ERROR::PROTOCOL_ERROR);
    EXPECT_TRUE(mux.closeAfterResponse());
}

TEST(Multiplexer, PriorityOnConnectionStreamIsProtocolError)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::PRIORITY, 0, 0, "12345"));
    EXPECT_EQ(mux.error, STREAM_ERROR::PROTOCOL_ERROR);
    EXPECT_TRUE(mux.closeAfterResponse());
}

TEST(Multiplexer, WindowUpdateOnIdleStreamIsProtocolError)
{
    ProbeMux mux;
    mux.warmUp();

    std::string increment;
    frame::appendBigEndian32(increment, 1024);
    mux.push(makeFrame(FRAME_TYPE::WINDOW_UPDATE, 77, 0, increment));
    EXPECT_EQ(mux.error, STREAM_ERROR::PROTOCOL_ERROR);
    EXPECT_TRUE(mux.closeAfterResponse());
}

TEST(Multiplexer, UnexpectedContinuationFrameIsProtocolError)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::CONTINUATION, 1, 0, "headerblock"));
    EXPECT_EQ(mux.error, STREAM_ERROR::PROTOCOL_ERROR);
    EXPECT_TRUE(mux.closeAfterResponse());
}

TEST(Multiplexer, InitialWindowReductionPausesStreamUntilWindowUpdate)
{
    ProbeMux mux;
    mux.warmUp();

    // 发送 HEADERS 开启流 1
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, 0, "h"));
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

TEST(Multiplexer, StreamWithMultipleResponsesSendsAllPartsBeforeEndStream)
{
    TwoPartMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, 0, "headers"));
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

TEST(Multiplexer, SettingsInitialWindowDeltaOverflowIsFlowControlError)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, 0, "h"));
    [[maybe_unused]] auto _ = mux.takeFrames();

    std::string increment;
    frame::appendBigEndian32(increment, 1000);
    mux.push(makeFrame(FRAME_TYPE::WINDOW_UPDATE, 1, 0, increment));

    mux.push(makeFrame(FRAME_TYPE::SETTINGS, 0, 0, setting(mux::kSettingInitialWindowSize, 0x7fffffff)));

    EXPECT_EQ(mux.error, STREAM_ERROR::FLOW_CONTROL_ERROR);
    EXPECT_TRUE(mux.closeAfterResponse());
}
