// HandlerHttp2<HandlerConnection>：在单条物理字节流上承载多个独立的流式交互。
// 这些测试模拟网络连接的行为驱动它——将完整的帧追加到请求缓冲区，
// 并从响应队列中读回其回复，这是上层唯一实际依赖的接口。
#include "configHolder.hpp"
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
    // 合法的最小 HPACK 首部块：:method GET（静态索引 2）+ :path /（静态索引 4）。
    // HEADERS 载荷是压缩后的首部块，任意文本都会被 HPACK 解码器判为非法。
    const std::string kGetHeadersBlock = std::string("\x82\x84", 2);

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

    [[nodiscard]] uint32_t settingValueAt(std::string_view payload, size_t off)
    {
        const auto *p = reinterpret_cast<const unsigned char *>(payload.data() + off + 2);
        return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
               (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
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
            RequestBuffer in;
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
            [[maybe_unused]] auto preface = appendRequest(kClientPreface);
            process();
            [[maybe_unused]] auto _ = takeFrames();
            push(makeFrame(FRAME_TYPE::SETTINGS, 0, FrameFlags::kAck, {}));
        }
    };

    // 用于验证 initialWindowSize 配置真的落到协议状态上：
    // SETTINGS 宣告、连接级 WINDOW_UPDATE 抬升、流级接收窗口初值。
    class WindowMux : public HandlerHttp2<HandlerConnection>
    {
    public:
        using HandlerHttp2<HandlerConnection>::connRecvWindow_;
        using HandlerHttp2<HandlerConnection>::stream;

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
            RequestBuffer in;
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

        [[nodiscard]] uint32_t streamRecvLimit() const noexcept { return streamRecvLimit_; }

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
            RequestBuffer in;
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
            [[maybe_unused]] auto preface = appendRequest(kClientPreface);
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
    EXPECT_EQ(frames[0].payload.size(), 24u); // 包含 4 项设置（每项 6 字节）

    bool sawStreams = false;
    bool sawWindow = false;
    bool sawFrameSize = false;
    bool sawHeaderList = false;
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
        if (id == mux::kSettingMaxHeaderListSize)
        {
            sawHeaderList = true;
            // 宣告值必须与解码侧真正执行的上限一致，否则对端按宣告发送仍会被拒
            EXPECT_EQ(value, static_cast<uint32_t>(http::v2::hpack::kMaxHeaderListBytes));
        }
    }
    EXPECT_TRUE(sawStreams);
    EXPECT_TRUE(sawWindow);
    EXPECT_TRUE(sawFrameSize);
    EXPECT_TRUE(sawHeaderList);

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

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
    EXPECT_EQ(mux.openStreams(), 1u);
    EXPECT_EQ(mux.lastPeerStreamId(), 1u);
    ASSERT_EQ(mux.opens.size(), 1u);
    EXPECT_EQ(mux.opens[0], 1u);
    ASSERT_EQ(mux.headers.size(), 1u);
    EXPECT_EQ(mux.headers[0].first, 1u);
    EXPECT_EQ(mux.headers[0].second, kGetHeadersBlock);
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

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
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

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders | FrameFlags::kEndStream, kGetHeadersBlock));
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
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
    mux.takeFrames();
    mux.push(makeFrame(FRAME_TYPE::DATA, 1, FrameFlags::kEndStream, "bye"));
    mux.takeFrames();
    ASSERT_EQ(mux.openStreams(), 0u);

    // 后续流 ID 更大、探测序列起始于同一槽位的流
    // （在 8 槽位表中流 ID 1 与 17 哈希值相同）复用该墓碑槽位。
    // 复用的槽位必须表现得如全新流一般：HEADERS 之后的 DATA 正常回显，
    // 不会误判为 END_STREAM 之后的非法流量，最终的 DATA 帧仍可顺利发送。
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 17, FrameFlags::kEndHeaders, kGetHeadersBlock));
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

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 2, FrameFlags::kEndHeaders, kGetHeadersBlock));
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

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders | FrameFlags::kEndStream, kGetHeadersBlock));
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
    // SETTINGS_MAX_FRAME_SIZE 只约束本端出站分片。要注入超过默认 16 KiB 的
    // 入站帧，必须抬高本端的接收上限（配置 -> applyHttp2Config）。
    const mynet::NetConfig saved = mynet::getNetConfig();
    mynet::NetConfig cfg = saved;
    cfg.http2.maxFrameSize = 1 << 20;
    mynet::publishNetConfig(cfg);

    ProbeMux mux;
    mux.applyHttp2Config();
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
    mux.takeFrames();

    mux.push(makeFrame(FRAME_TYPE::DATA, 1, 0, std::string(mux::kInitialWindowSize + 1, 'x')));
    const bool closed = mux.closeAfterResponse();
    const auto goaways = countOfType(mux.takeFrames(), FRAME_TYPE::GOAWAY);
    mynet::publishNetConfig(saved);

    EXPECT_EQ(mux.error, STREAM_ERROR::FLOW_CONTROL_ERROR);
    EXPECT_TRUE(closed);
    EXPECT_EQ(goaways, 1u);
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

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 3, FrameFlags::kEndHeaders, kGetHeadersBlock));
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

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 3, FrameFlags::kEndHeaders, kGetHeadersBlock));
    EXPECT_EQ(mux.openStreams(), 2u);
    mux.takeFrames();

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 5, FrameFlags::kEndHeaders, kGetHeadersBlock));
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
    appendFrame(bytes, makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
    ASSERT_GT(bytes.size(), size_t{5});

    [[maybe_unused]] auto _ = mux.appendRequest(bytes.data(), 5);
    mux.process();
    EXPECT_EQ(mux.openStreams(), 0u);
    EXPECT_TRUE(mux.headers.empty());

    [[maybe_unused]] auto _ = mux.appendRequest(bytes.data() + 5, static_cast<ssize_t>(bytes.size() - 5));
    mux.process();
    EXPECT_EQ(mux.openStreams(), 1u);
    ASSERT_EQ(mux.headers.size(), 1u);
    EXPECT_EQ(mux.headers[0].second, kGetHeadersBlock);
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
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
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
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
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
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
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
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
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
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
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
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
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
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
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

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
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

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
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
        mux.push(makeFrame(FRAME_TYPE::HEADERS, i, FrameFlags::kEndHeaders, kGetHeadersBlock));
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
        // 连接层在每次 process() 之后搬运响应；这里同样每轮取走 ACK，
        // 否则出站背压会先停住解码，PING 泛洪就无从累积。
        mux.takeFrames();
        if (mux.error.has_value())
            break;
    }

    EXPECT_EQ(mux.error, STREAM_ERROR::ENHANCE_YOUR_CALM);
    EXPECT_TRUE(mux.closeAfterResponse());
}

TEST(HandlerHttp2, HeadersAreAssembledAcrossContinuations)
{
    ProbeMux mux;
    mux.warmUp();

    // 首部块拆成 HEADERS + 两片 CONTINUATION，只有最后一片带 END_HEADERS。
    // 分片边界可以落在 HPACK 字段中间，重组后必须能正常解码。
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, 0, kGetHeadersBlock.substr(0, 1)));
    EXPECT_FALSE(mux.error.has_value());
    EXPECT_TRUE(mux.headers.empty()); // 未收齐前不通知应用

    mux.push(makeFrame(FRAME_TYPE::CONTINUATION, 1, 0, kGetHeadersBlock.substr(1, 1)));
    EXPECT_FALSE(mux.error.has_value());

    mux.push(makeFrame(FRAME_TYPE::CONTINUATION, 1, FrameFlags::kEndHeaders, ""));
    ASSERT_FALSE(mux.error.has_value()) << mux.why;
    ASSERT_EQ(mux.headers.size(), 1u);
    EXPECT_EQ(mux.headers[0].second, kGetHeadersBlock);
    EXPECT_EQ(mux.openStreams(), 1u);
}

TEST(HandlerHttp2, APriorityFlagSurvivesHeaderBlockFragmentation)
{
    ProbeMux mux;
    mux.warmUp();

    // HEADERS 带 PRIORITY(0x20) 时开头是 5 字节优先级字段，重组前必须先剥离。
    std::string first = std::string(5, '\0') + std::string(kGetHeadersBlock.substr(0, 1));
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kPriority, first));
    mux.push(makeFrame(FRAME_TYPE::CONTINUATION, 1, FrameFlags::kEndHeaders, kGetHeadersBlock.substr(1)));

    ASSERT_FALSE(mux.error.has_value()) << mux.why;
    ASSERT_EQ(mux.headers.size(), 1u);
    EXPECT_EQ(mux.headers[0].second, kGetHeadersBlock);
}

TEST(HandlerHttp2, AnInterleavedFrameEndsTheConnection)
{
    ProbeMux mux;
    mux.warmUp();

    // RFC 9113 §6.2：首部块分片期间不允许插入任何其他帧（其他流或连接级都不行）。
    // 这也是 CVE-2024-27983 的防线：不能靠穿插廉价帧重置首部累积状态。
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, 0, kGetHeadersBlock.substr(0, 1)));
    mux.push(makeFrame(FRAME_TYPE::PING, 0, 0, "12345678"));
    EXPECT_EQ(mux.error, STREAM_ERROR::PROTOCOL_ERROR);
    EXPECT_TRUE(mux.closeAfterResponse());
    EXPECT_NE(mux.why.find("fragmented header block"), std::string::npos);
}

TEST(HandlerHttp2, ContinuationOnAnotherStreamEndsTheConnection)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, 0, kGetHeadersBlock.substr(0, 1)));
    mux.push(makeFrame(FRAME_TYPE::CONTINUATION, 3, FrameFlags::kEndHeaders, kGetHeadersBlock.substr(1)));
    EXPECT_EQ(mux.error, STREAM_ERROR::PROTOCOL_ERROR);
    EXPECT_TRUE(mux.closeAfterResponse());
}

TEST(HandlerHttp2, ContinuationFloodTriggersEnhanceYourCalm)
{
    ProbeMux mux;
    mux.warmUp();

    // 零长 CONTINUATION 洪水：字节上限拦不住，由专门的空帧计数上限拦截
    // （总片数上限只是兜底，不应用来误杀"片小而合规"的客户端）。
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, 0, kGetHeadersBlock.substr(0, 1)));
    for (int i = 0; i < 300 && !mux.error.has_value(); ++i)
    {
        mux.push(makeFrame(FRAME_TYPE::CONTINUATION, 1, 0, ""));
    }
    EXPECT_EQ(mux.error, STREAM_ERROR::ENHANCE_YOUR_CALM);
    EXPECT_TRUE(mux.closeAfterResponse());
}

namespace
{
    // 增量索引字面量（新名称）：D. huffman 关闭，便于精确控制字节数
    [[nodiscard]] std::string indexedLiteral(std::string_view name, std::string_view value)
    {
        std::string out;
        out.push_back('\x40');
        http::v2::hpack::encodeInteger(out, 7, 0x00, name.size());
        out += name;
        http::v2::hpack::encodeInteger(out, 7, 0x00, value.size());
        out += value;
        return out;
    }
} // namespace

TEST(HandlerHttp2, AnOversizedFragmentedHeaderBlockResetsOnlyThatStream)
{
    ProbeMux mux;
    mux.warmUp();

    // 合法 HPACK、但解压后列表规模超过 64 KiB 的首部块，分 4 片送到。
    // 块本身必须真的被解码：跳过它会让动态表与对端失步。超限只能重置该流。
    std::string block(3, '\0');
    block[0] = static_cast<char>(0x82); // :method GET
    block[1] = static_cast<char>(0x86); // :scheme http
    block[2] = static_cast<char>(0x84); // :path /
    const std::string value(200, 'v');
    for (int i = 0; i < 300; ++i) // 300 * (7+200+32) ≈ 71 KiB 列表开销
    {
        block += indexedLiteral("x-f" + std::to_string(i), value);
    }
    ASSERT_GT(block.size(), size_t{0});

    constexpr size_t kChunk = 16384;
    const size_t fragments = (block.size() + kChunk - 1) / kChunk;
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, 0, block.substr(0, kChunk)));
    for (size_t i = 1; i < fragments; ++i)
    {
        const bool last = (i + 1 == fragments);
        mux.push(makeFrame(FRAME_TYPE::CONTINUATION, 1, last ? FrameFlags::kEndHeaders : 0,
                           block.substr(i * kChunk, kChunk)));
    }

    EXPECT_FALSE(mux.error.has_value()) << "an oversized header list is a stream error, not a connection one: "
                                        << mux.why;
    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FRAME_TYPE::RESET);
    EXPECT_EQ(frames[0].streamId, 1u);
    EXPECT_EQ(frame::readBigEndian32(frames[0].payload.data()), std::to_underlying(STREAM_ERROR::ENHANCE_YOUR_CALM));

    // 连接仍然可用：解码器已完整走过该块，动态表保持同步
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 3, FrameFlags::kEndHeaders, kGetHeadersBlock));
    EXPECT_FALSE(mux.error.has_value()) << mux.why;
    EXPECT_EQ(mux.openStreams(), 1u);
}

TEST(HandlerHttp2, ThePeerHeaderListLimitBoundsResponseHeaders)
{
    ProbeMux mux;
    mux.warmUp();
    EXPECT_TRUE(mux.sendHeaders(1, "h", false) == false); // 流尚不存在

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
    mux.takeFrames();

    // 对端宣告 64 字节的首部列表上限：超限的响应首部应在本地就被拒绝，
    // 而不是发出去等对方用 GOAWAY/ENHANCE_YOUR_CALM 拆连接。
    mux.push(makeFrame(FRAME_TYPE::SETTINGS, 0, 0, setting(mux::kSettingMaxHeaderListSize, 64)));
    mux.takeFrames();

    const http::v2::Header big[] = {{"x-big", std::string(200, 'a')}};
    EXPECT_FALSE(mux.sendResponse(1, 200, "", big));

    // 绝不能静默丢响应：那会在对端留下"没有 HEADERS 的 END_STREAM"，
    // 只能按连接级协议错误处理。显式 RST 才是可恢复结果。
    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FRAME_TYPE::RESET);
    EXPECT_EQ(frames[0].streamId, 1u);
    EXPECT_EQ(frame::readBigEndian32(frames[0].payload.data()), std::to_underlying(STREAM_ERROR::ENHANCE_YOUR_CALM));
    EXPECT_EQ(mux.openStreams(), 0u);
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

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
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
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
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
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 3, FrameFlags::kEndHeaders, kGetHeadersBlock));
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
        RequestBuffer in;
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
        [[maybe_unused]] auto preface = appendRequest(kClientPreface);
        process();
        [[maybe_unused]] auto _ = takeFrames();
        push(makeFrame(FRAME_TYPE::SETTINGS, 0, FrameFlags::kAck, {}));
    }
};

TEST(HandlerHttp2, SlowReaderPausesStreamLevelWindowCredit)
{
    // 本端接收上限抬到 1 MiB：测试注入 40 KiB 的 DATA 帧，超过默认 16 KiB
    // 会被（正确地）判为超长帧。对端 SETTINGS 只影响本端出站分片。
    const mynet::NetConfig saved = mynet::getNetConfig();
    mynet::NetConfig cfg = saved;
    cfg.http2.maxFrameSize = 1 << 20;
    mynet::publishNetConfig(cfg);

    BigReplyMux mux;
    mux.applyHttp2Config();
    mux.warmUp();

    // 对端宣告 1 MiB 的接收上限，允许本端以单帧发出 69632 字节响应。
    mux.push(makeFrame(FRAME_TYPE::SETTINGS, 0, 0, setting(mux::kSettingMaxFrameSize, 1 << 20)));
    mux.takeFrames();
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
    mux.takeFrames();

    auto countStreamWindowUpdates = [&mux]
    {
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
    mynet::publishNetConfig(saved);
    EXPECT_EQ(mux.error, STREAM_ERROR::FLOW_CONTROL_ERROR);
}

TEST(HandlerHttp2, DrainingOutboundRestoresPausedStreamWindow)
{
    // 本端接收上限抬到 1 MiB：测试注入 40 KiB 的 DATA 帧，超过默认 16 KiB
    // 会被（正确地）判为超长帧。对端 SETTINGS 只影响本端出站分片。
    const mynet::NetConfig saved = mynet::getNetConfig();
    mynet::NetConfig cfg = saved;
    cfg.http2.maxFrameSize = 1 << 20;
    mynet::publishNetConfig(cfg);

    BigReplyMux mux;
    mux.applyHttp2Config();
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::SETTINGS, 0, 0, setting(mux::kSettingMaxFrameSize, 1 << 20)));
    mux.takeFrames();
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
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
    mynet::publishNetConfig(saved);
    ASSERT_NE(mux.stream(1), nullptr);
    EXPECT_EQ(mux.stream(1)->recvWindow, mux::kInitialWindowSize);
}

TEST(HandlerHttp2, LifecycleAndFd)
{
    HandlerHttp2 mux;
    EXPECT_EQ(mux.fd(), -1);

    mux.onConnect(55);
    EXPECT_EQ(mux.fd(), 55);

    mux.reset();
    EXPECT_EQ(mux.fd(), -1);
}

TEST(HandlerHttp2, SendHeadersDataAndResponse)
{
    TwoPartMux mux;
    mux.warmUp();
    // 建立流 1
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
    mux.takeFrames(); // 清空初始化响应

    // 1. sendHeaders 发送首部块
    EXPECT_TRUE(mux.sendHeaders(1, "custom-headers", false));
    auto frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FRAME_TYPE::HEADERS);
    EXPECT_EQ(frames[0].streamId, 1u);
    EXPECT_EQ(frames[0].payload, "custom-headers");

    // 2. sendData 发送数据
    EXPECT_TRUE(mux.sendData(1, "custom-data", false));
    frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FRAME_TYPE::DATA);
    EXPECT_EQ(frames[0].streamId, 1u);
    EXPECT_EQ(frames[0].payload, "custom-data");

    // 3. sendResponse 完整发送首部与数据（流终结模式下由 pumpStream 产生 HEADERS、DATA 与 END_STREAM 帧）
    EXPECT_TRUE(mux.sendResponse(1, "headers2", "body2"));
    frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 3u);
    EXPECT_EQ(frames[0].type, FRAME_TYPE::HEADERS);
    EXPECT_EQ(frames[0].payload, "headers2");
    EXPECT_EQ(frames[1].type, FRAME_TYPE::DATA);
    EXPECT_EQ(frames[1].payload, "body2");
    EXPECT_EQ(frames[2].type, FRAME_TYPE::DATA);
    EXPECT_TRUE(frames[2].hasFlag(FrameFlags::kEndStream));

    // 4. 对不存在的流发送失败
    EXPECT_FALSE(mux.sendHeaders(99, "h", false));
    EXPECT_FALSE(mux.sendData(99, "d", false));
}

TEST(HandlerHttp2, EchoMultiStream)
{
    class TestHttp2EchoMux : public HandlerHttp2<HandlerConnection>
    {
    public:
        using HandlerHttp2::stream;
    };

    TestHttp2EchoMux mux;
    // 建立流 1
    std::string bytes(TestHttp2EchoMux::kClientPreface);
    appendFrame(bytes, makeFrame(FRAME_TYPE::SETTINGS, 0, 0, {}));
    appendFrame(bytes, makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
    [[maybe_unused]] auto _ = mux.appendRequest(bytes.data(), bytes.size());
    mux.process();
    while (mux.hasResponse())
    {
        [[maybe_unused]] auto dummy = mux.takeResponse();
    }

    auto *slot = mux.stream(1);
    ASSERT_NE(slot, nullptr);
    ASSERT_NE(slot->handler, nullptr);

    // 向流 1 缓冲区灌入待回显数据
    [[maybe_unused]] auto _2 = slot->handler->appendRequest("echo-test-bytes", 15);

    // 触发 HTTP/2 级多流 echo
    mux.echo();
    ASSERT_TRUE(mux.hasResponse());
    std::string resp = mux.takeResponse();
    EXPECT_FALSE(resp.empty());

    // 解析回复中的 DATA 帧
    RequestBuffer in;
    [[maybe_unused]] auto _3 = in.append(resp);
    FrameDecoder decoder;
    auto parsed = decoder.next(in);
    ASSERT_TRUE(parsed.has_value());
    ASSERT_TRUE(parsed->has_value());
    EXPECT_EQ((*parsed)->type, FRAME_TYPE::DATA);
    EXPECT_EQ((*parsed)->streamId, 1u);
    EXPECT_EQ((*parsed)->payload, "echo-test-bytes");
}

TEST(HandlerHttp2, ConfiguredInitialWindowIsAdvertisedAndApplied)
{
    // initialWindowSize 不是"配了就算"：它必须同时出现在 SETTINGS 里、
    // 真正提升 connection 级接收窗口、并成为新流的接收窗口初值。
    // 漏掉任何一环，配置都可能让上传在 64 KiB 处卡死或越过对端额度。
    const mynet::NetConfig saved = mynet::getNetConfig();

    mynet::NetConfig cfg = saved;
    cfg.http2.initialWindowSize = 131072;
    mynet::publishNetConfig(cfg);

    WindowMux mux;
    mux.applyHttp2Config();
    mux.process();
    const std::vector<Frame> frames = mux.takeFrames();

    // 1) SETTINGS 必须宣告配置值
    bool advertised = false;
    for (const Frame &frame : frames)
    {
        if (frame.type != FRAME_TYPE::SETTINGS)
        {
            continue;
        }
        for (size_t off = 0; off + 6 <= frame.payload.size(); off += 6)
        {
            if (settingIdAt(frame.payload, off) == mux::kSettingInitialWindowSize)
            {
                advertised = true;
                EXPECT_EQ(settingValueAt(frame.payload, off), 131072u);
            }
        }
    }
    EXPECT_TRUE(advertised) << "SETTINGS must advertise the configured initial window";

    // 2) connection 级窗口只能靠 WINDOW_UPDATE 提升（SETTINGS 只管 stream 级）
    bool raisedConnectionWindow = false;
    for (const Frame &frame : frames)
    {
        if (frame.type == FRAME_TYPE::WINDOW_UPDATE && frame.streamId == 0)
        {
            const auto *p = reinterpret_cast<const unsigned char *>(frame.payload.data());
            const uint32_t increment = (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
                                       (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
            EXPECT_EQ(increment, 131072u - mux::kInitialWindowSize);
            raisedConnectionWindow = true;
        }
    }
    EXPECT_TRUE(raisedConnectionWindow) << "a connection-level WINDOW_UPDATE must raise stream-0 credit";
    EXPECT_EQ(mux.connRecvWindow_, 131072u);

    mynet::publishNetConfig(saved);
}

TEST(HandlerHttp2, ConfiguredInitialWindowDoesNotInflateTheSendWindow)
{
    // connSendWindow_ 是对端给我们的额度，connection 级只受 WINDOW_UPDATE 影响。
    // 用本端接收配置去初始化它，会让服务器越过对端窗口直接触发 FLOW_CONTROL_ERROR。
    const mynet::NetConfig saved = mynet::getNetConfig();

    mynet::NetConfig cfg = saved;
    cfg.http2.initialWindowSize = 131072;
    mynet::publishNetConfig(cfg);

    WindowMux mux;
    mux.applyHttp2Config();
    EXPECT_EQ(mux.connectionSendWindow(), mux::kInitialWindowSize)
        << "outbound credit must start from the protocol default, not our receive configuration";

    mynet::publishNetConfig(saved);
}

TEST(HandlerHttp2, SmallInitialWindowDoesNotShrinkConnectionLevelCredit)
{
    // connection 级窗口在 RFC 9113 里无法被"缩小"：对端始终以 65535 起算，
    // SETTINGS_INITIAL_WINDOW_SIZE 只作用于 stream 级。若本端把连接级记账值
    // 也设成小值，回补阈值就会算错，且与对端的实际视角不一致。
    const mynet::NetConfig saved = mynet::getNetConfig();

    mynet::NetConfig cfg = saved;
    cfg.http2.initialWindowSize = 4096;
    mynet::publishNetConfig(cfg);

    WindowMux mux;
    mux.applyHttp2Config();
    mux.process();
    const std::vector<Frame> frames = mux.takeFrames();

    EXPECT_EQ(mux.connRecvWindow_, mux::kInitialWindowSize)
        << "connection-level credit must stay at the protocol default when the configured window is smaller";

    // 配置值不大于 65535 时不应发连接级 WINDOW_UPDATE（没有可提升的额度）。
    for (const Frame &frame : frames)
    {
        EXPECT_FALSE(frame.type == FRAME_TYPE::WINDOW_UPDATE && frame.streamId == 0)
            << "no connection-level WINDOW_UPDATE is needed when the configured window is below the default";
    }

    // 但 SETTINGS 必须宣告缩小后的 stream 级窗口。
    bool advertised = false;
    for (const Frame &frame : frames)
    {
        if (frame.type != FRAME_TYPE::SETTINGS)
        {
            continue;
        }
        for (size_t off = 0; off + 6 <= frame.payload.size(); off += 6)
        {
            if (settingIdAt(frame.payload, off) == mux::kSettingInitialWindowSize)
            {
                EXPECT_EQ(settingValueAt(frame.payload, off), 4096u);
                advertised = true;
            }
        }
    }
    EXPECT_TRUE(advertised);

    mynet::publishNetConfig(saved);
}

TEST(HandlerHttp2, SmallInitialWindowDoesNotRejectCompliantPeerDataFrames)
{
    // SETTINGS_INITIAL_WINDOW_SIZE 可以调小，但只在对端**收到并处理我们的 SETTINGS**
    // 之后生效。在此之前对端仍按协议默认 65535 发送；若本地流级窗口一开始就是
    // 4096，一个完整的 16 KiB DATA 帧会被判成 FLOW_CONTROL_ERROR 并触发 GOAWAY。
    const mynet::NetConfig saved = mynet::getNetConfig();

    mynet::NetConfig cfg = saved;
    cfg.http2.initialWindowSize = 4096;
    mynet::publishNetConfig(cfg);

    ProbeMux mux;
    mux.applyHttp2Config();
    mux.warmUp();

    EXPECT_EQ(mux.streamRecvLimit(), mux::kInitialWindowSize)
        << "stream credit must not drop below the protocol default before the peer sees our SETTINGS";

    // 打开一条流，然后推入一个超过 4096 但不超过 65535 的 DATA 帧。
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
    ASSERT_EQ(mux.openStreams(), 1u);

    mux.push(makeFrame(FRAME_TYPE::DATA, 1, 0, std::string(16384, 'a')));
    EXPECT_FALSE(mux.error.has_value()) << "a compliant peer's 16 KiB frame must not be rejected";
    EXPECT_FALSE(mux.closeAfterResponse());

    mynet::publishNetConfig(saved);
}

// ---- 真实客户端字节序列回归：前言 + HPACK(Huffman) + DATA -> 200 响应 ----

namespace
{
    // 不自动回显的流处理器：请求体留在 RequestBuffer 中由 onStreamEnd 统一响应。
    class QuietStream : public HandlerConnection
    {
    public:
        void process() noexcept {}
    };

    class EchoMux : public HandlerHttp2<QuietStream>
    {
    public:
        std::optional<STREAM_ERROR> error;
        std::string why;

        void onProtocolError(STREAM_ERROR code, std::string_view reason) noexcept override
        {
            error = code;
            why.assign(reason);
        }

        void onStreamEnd(uint32_t id) noexcept override
        {
            const Stream *stream = streamHandler(id);
            const std::string_view body = stream == nullptr
                                              ? std::string_view{}
                                              : std::string_view(stream->requestBegin(), stream->requestBytes());
            (void)sendResponse(id, 200, body);
        }

        void feed(std::string_view wire)
        {
            [[maybe_unused]] auto _ = appendRequest(wire);
            process();
        }

        [[nodiscard]] std::vector<Frame> drain()
        {
            std::string bytes;
            while (hasResponse())
                bytes += takeResponse();
            std::vector<Frame> frames;
            RequestBuffer in;
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
    };
} // namespace

TEST(HandlerHttp2, ARealClientRequestGetsAnHttp2Response)
{
    EchoMux mux;

    // RFC 7541 Appendix C.4.1 的首部块（curl/nghttp2 实际发送形状）：
    // :method GET, :scheme http, :path /, :authority www.example.com（Huffman）
    const unsigned char rawHeaders[] = {0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5,
                                        0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff};
    const std::string headers(reinterpret_cast<const char *>(rawHeaders), sizeof(rawHeaders));

    std::string wire(EchoMux::kClientPreface);
    appendFrame(wire, makeFrame(FRAME_TYPE::SETTINGS, 0, 0, {}));
    appendFrame(wire, makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, headers));
    appendFrame(wire, makeFrame(FRAME_TYPE::DATA, 1, FrameFlags::kEndStream, "hello"));

    mux.feed(wire);
    ASSERT_FALSE(mux.error.has_value()) << mux.why;

    const std::vector<Frame> frames = mux.drain();

    bool sawStatus = false;
    bool sawBody = false;
    bool sawEnd = false;
    for (const Frame &frame : frames)
    {
        if (frame.type == FRAME_TYPE::HEADERS && frame.streamId == 1)
        {
            auto decoded = http::v2::HpackDecoder().decode(frame.payload);
            ASSERT_TRUE(decoded.has_value());
            ASSERT_FALSE(decoded->empty());
            EXPECT_EQ((*decoded)[0].name, ":status");
            EXPECT_EQ((*decoded)[0].value, "200");
            sawStatus = true;
        }
        if (frame.type == FRAME_TYPE::DATA && frame.streamId == 1)
        {
            if (frame.payload == "hello")
            {
                sawBody = true;
            }
            if (frame.hasFlag(FrameFlags::kEndStream) && frame.payload.empty())
            {
                sawEnd = true;
            }
        }
    }
    EXPECT_TRUE(sawStatus) << "a standard client requires an HPACK-encoded :status header";
    EXPECT_TRUE(sawBody);
    EXPECT_TRUE(sawEnd);
    EXPECT_EQ(mux.openStreams(), 0u);
}

TEST(HandlerHttp2, PrefaceIsValidatedAndMayArriveInPieces)
{
    EchoMux mux;
    // 分两段到达的前言：仍未收齐时既不解帧也不报错
    mux.feed(std::string_view(EchoMux::kClientPreface).substr(0, 10));
    EXPECT_FALSE(mux.error.has_value());
    mux.feed(std::string_view(EchoMux::kClientPreface).substr(10));
    EXPECT_FALSE(mux.error.has_value());

    // 收齐后正常解帧
    std::string wire;
    appendFrame(wire, makeFrame(FRAME_TYPE::SETTINGS, 0, 0, {}));
    mux.feed(wire);
    EXPECT_FALSE(mux.error.has_value());
}

TEST(HandlerHttp2, AMalformedPrefaceEndsTheConnection)
{
    EchoMux mux;
    std::string wire("PRI * HTTP/1.1\r\n\r\nSM\r\n\r\n", 24);
    mux.feed(wire);
    EXPECT_EQ(mux.error, STREAM_ERROR::PROTOCOL_ERROR);
    EXPECT_NE(mux.why.find("preface"), std::string::npos);
}

// ---- 复核回归：每流缓冲上限 / 小窗口回补 / 窗口更新进展 / 连接复用状态 ----

TEST(HandlerHttp2, OversizedStreamRequestBodyIsRefused)
{
    // connection.maxRequestBytes 只管连接级 handler；HTTP/2 的请求体驻留在
    // per-stream handler 里，必须由多路复用器显式拦截，否则单个上传可吃满内存。
    const mynet::NetConfig saved = mynet::getNetConfig();
    mynet::NetConfig cfg = saved;
    cfg.connection.maxRequestBytes = 1024;
    mynet::publishNetConfig(cfg);

    ProbeMux mux;
    mux.applyHttp2Config();
    mux.warmUp();
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
    mux.takeFrames();

    mux.push(makeFrame(FRAME_TYPE::DATA, 1, 0, std::string(2048, 'x')));
    const std::vector<Frame> frames = mux.takeFrames();
    mynet::publishNetConfig(saved);

    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FRAME_TYPE::RESET);
    EXPECT_EQ(frames[0].streamId, 1u);
    EXPECT_EQ(frame::readBigEndian32(frames[0].payload.data()), std::to_underlying(STREAM_ERROR::ENHANCE_YOUR_CALM));
    EXPECT_EQ(mux.openStreams(), 0u);
}

class BufferedProbeMux : public HandlerHttp2<QuietStream>
{
public:
    using HandlerHttp2<QuietStream>::stream;
    using HandlerHttp2<QuietStream>::connRecvWindow_;

    void push(const Frame &frame)
    {
        std::string bytes;
        appendFrame(bytes, frame);
        [[maybe_unused]] auto _ = this->appendRequest(bytes.data(), static_cast<ssize_t>(bytes.size()));
        this->process();
    }

    std::vector<Frame> takeFrames()
    {
        std::string bytes;
        while (this->hasResponse())
            bytes += this->takeResponse();
        std::vector<Frame> frames;
        RequestBuffer in;
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
        this->appendRequest(HandlerHttp2<QuietStream>::kClientPreface);
        this->process();
        [[maybe_unused]] auto _ = takeFrames();
    }
};

TEST(HandlerHttp2, AggregateStreamRequestBodyLimitIsEnforced)
{
    // 验证连接级聚合上限：即使单流未达到 maxRequestBytes，多流并发累积
    // 超过连接级总配额时，超出预算的流将被 ENHANCE_YOUR_CALM 拒绝，
    // 而已缓冲的正常流与连接级流控记账完好无损。
    const mynet::NetConfig saved = mynet::getNetConfig();
    mynet::NetConfig cfg = saved;
    cfg.connection.maxRequestBytes = 2048;
    mynet::publishNetConfig(cfg);

    BufferedProbeMux mux;
    mux.applyHttp2Config();
    mux.warmUp();

    // 流 1：打开并写入 1200 字节（单流合规：1200 <= 2048；聚合合规：1200 <= 2048）
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
    mux.takeFrames();
    mux.push(makeFrame(FRAME_TYPE::DATA, 1, 0, std::string(1200, 'a')));
    EXPECT_TRUE(mux.takeFrames().empty());
    EXPECT_EQ(mux.openStreams(), 1u);
    EXPECT_EQ(mux.aggregateStreamRequestBytes(), 1200u);

    // 流 3：打开并尝试写入 1200 字节（单流合规：1200 <= 2048；但聚合 1200 + 1200 = 2400 > 2048）
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 3, FrameFlags::kEndHeaders, kGetHeadersBlock));
    mux.takeFrames();
    mux.push(makeFrame(FRAME_TYPE::DATA, 3, 0, std::string(1200, 'b')));
    const std::vector<Frame> frames = mux.takeFrames();

    // 流 3 必须被 RST_STREAM(ENHANCE_YOUR_CALM) 拒绝并关闭
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FRAME_TYPE::RESET);
    EXPECT_EQ(frames[0].streamId, 3u);
    EXPECT_EQ(frame::readBigEndian32(frames[0].payload.data()), std::to_underlying(STREAM_ERROR::ENHANCE_YOUR_CALM));

    // 流 1 仍然完好在线，聚合驻留字节仍为流 1 的 1200 字节
    EXPECT_EQ(mux.openStreams(), 1u);
    EXPECT_NE(mux.stream(1), nullptr);
    EXPECT_EQ(mux.aggregateStreamRequestBytes(), 1200u);

    mynet::publishNetConfig(saved);
}

TEST(HandlerHttp2, SetMaxRequestBytesHotReloadPropagatesToStreams)
{
    // 验证配置热更与动态 setMaxRequestBytes 能穿透到每流处理器与聚合判定：
    // 对象池构造时是 4 MiB 默认值，动态设置为 1024 后，新开流与当前连接立即受新限约束。
    BufferedProbeMux mux;
    mux.warmUp();
    EXPECT_GT(mux.maxRequestBytes(), 1024u);

    // 动态将连接与流上限下调为 1024
    mux.setMaxRequestBytes(1024);
    EXPECT_EQ(mux.maxRequestBytes(), 1024u);

    // 打开流 1 并发送 1500 字节：超过 1024，必须立即被拒
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
    mux.takeFrames();
    mux.push(makeFrame(FRAME_TYPE::DATA, 1, 0, std::string(1500, 'x')));
    const std::vector<Frame> frames = mux.takeFrames();

    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FRAME_TYPE::RESET);
    EXPECT_EQ(frames[0].streamId, 1u);
    EXPECT_EQ(frame::readBigEndian32(frames[0].payload.data()), std::to_underlying(STREAM_ERROR::ENHANCE_YOUR_CALM));
    EXPECT_EQ(mux.openStreams(), 0u);
}

TEST(HandlerHttp2, SmallAdvertisedWindowStillGrantsCredit)
{
    // 宣告 16 KiB 时，对端发满 16 KiB 后本端必须回补：若回补阈值仍按本地
    // 记账基准 65535 的一半计算，窗口会停在 49151 且永不再涨，上传直接挂死。
    const mynet::NetConfig saved = mynet::getNetConfig();
    mynet::NetConfig cfg = saved;
    cfg.http2.initialWindowSize = 16384;
    mynet::publishNetConfig(cfg);

    ProbeMux mux;
    mux.applyHttp2Config();
    mux.warmUp();
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
    mux.takeFrames();

    mux.push(makeFrame(FRAME_TYPE::DATA, 1, 0, std::string(9216, 'a'))); // 超过 16384/2
    const std::vector<Frame> frames = mux.takeFrames();
    mynet::publishNetConfig(saved);

    bool sawStreamUpdate = false;
    for (const Frame &frame : frames)
    {
        if (frame.type == FRAME_TYPE::WINDOW_UPDATE && frame.streamId == 1u)
        {
            sawStreamUpdate = true;
            EXPECT_EQ(frame::readBigEndian32(frame.payload.data()), 9216u);
        }
    }
    EXPECT_TRUE(sawStreamUpdate) << "credit must be returned once half of the advertised window is consumed";
}

// 2 MiB 响应：足以让连续 WINDOW_UPDATE 每次都推进出站发送。
class LargeReplyHandler : public HandlerConnection
{
public:
    void process()
    {
        if (requestBytes() > 0)
        {
            requestClear();
            [[maybe_unused]] auto _ = pushResponse(std::string(2u << 20, 'r'));
        }
    }
};

class LargeReplyMux : public HandlerHttp2<LargeReplyHandler>
{
public:
    std::optional<STREAM_ERROR> error;
    void onProtocolError(STREAM_ERROR code, std::string_view) noexcept override { error = code; }

    void push(const Frame &frame)
    {
        std::string bytes;
        appendFrame(bytes, frame);
        [[maybe_unused]] auto _ = appendRequest(bytes.data(), static_cast<ssize_t>(bytes.size()));
        process();
    }

    [[nodiscard]] std::vector<Frame> takeFrames()
    {
        std::string bytes;
        while (hasResponse())
            bytes += takeResponse();
        std::vector<Frame> frames;
        RequestBuffer in;
        if (!bytes.empty())
        {
            [[maybe_unused]] auto _ = in.append(bytes);
        }
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
        [[maybe_unused]] auto preface = appendRequest(kClientPreface);
        process();
        [[maybe_unused]] auto _ = takeFrames();
        push(makeFrame(FRAME_TYPE::SETTINGS, 0, FrameFlags::kAck, {}));
    }
};

TEST(HandlerHttp2, WindowUpdatesThatMakeProgressAreNotAFlood)
{
    // 真实下载里对端每补一次信用，服务端就推进一次发送。这类 WINDOW_UPDATE
    // 连续出现数百次是正常的；把"连续帧数"当洪水判据会在约 1.6 MB 处误杀连接。
    LargeReplyMux mux;
    mux.warmUp();
    mux.push(makeFrame(FRAME_TYPE::SETTINGS, 0, 0, setting(mux::kSettingMaxFrameSize, 1 << 20)));
    mux.takeFrames();
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
    mux.takeFrames();
    mux.push(makeFrame(FRAME_TYPE::DATA, 1, FrameFlags::kEndStream, "go"));
    mux.takeFrames();

    // 真实客户端在连接级与流级各补一次信用（两级的窗口都在消耗）。
    std::string increment;
    frame::appendBigEndian32(increment, 4096);
    for (int i = 0; i < 150; ++i) // 远超 kMaxConsecutiveWindowUpdates = 100
    {
        mux.push(makeFrame(FRAME_TYPE::WINDOW_UPDATE, 0, 0, increment));
        mux.push(makeFrame(FRAME_TYPE::WINDOW_UPDATE, 1, 0, increment));
        mux.takeFrames();
    }

    EXPECT_FALSE(mux.error.has_value()) << "window updates that advance the response are not a flood";
}

TEST(HandlerHttp2, ResetDropsThePeerInitialSendWindow)
{
    // 连接对象来自对象池，会跨连接复用：reset() 漏复位 initialSendWindow_
    // 会让新连接的流沿用上一条连接对端宣告的初始窗口。
    ProbeMux mux;
    mux.warmUp();
    mux.push(makeFrame(FRAME_TYPE::SETTINGS, 0, 0, setting(mux::kSettingInitialWindowSize, 131072)));
    mux.takeFrames();
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
    mux.takeFrames();
    ASSERT_NE(mux.stream(1), nullptr);
    EXPECT_EQ(mux.stream(1)->sendWindow, 131072);

    mux.reset();
    mux.warmUp();
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
    mux.takeFrames();
    ASSERT_NE(mux.stream(1), nullptr);
    EXPECT_EQ(mux.stream(1)->sendWindow, mux::kInitialWindowSize);
}

TEST(HandlerHttp2, LargeResponseResumesAfterTheResponseQueueDrains)
{
    // 响应 2 MiB 远超响应队列容量（64 项 × 16 KiB）。多路复用器在队列压满时停泵，
    // 必须能在连接层搬空队列后继续，否则客户端只会收到约 1 MiB 就永久停住。
    LargeReplyMux mux;
    mux.warmUp();
    mux.push(makeFrame(FRAME_TYPE::SETTINGS, 0, 0, setting(mux::kSettingMaxFrameSize, 1 << 20)));
    mux.takeFrames();
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
    mux.takeFrames();
    mux.push(makeFrame(FRAME_TYPE::DATA, 1, FrameFlags::kEndStream, "go"));

    std::string increment;
    frame::appendBigEndian32(increment, 32u * 1024u);

    size_t received = 0;
    bool ended = false;
    for (int guard = 0; guard < 4096 && !ended; ++guard)
    {
        for (const Frame &frame : mux.takeFrames()) // 模拟连接层的 collectResponses
        {
            if (frame.type == FRAME_TYPE::DATA && frame.streamId == 1u)
            {
                received += frame.payload.size();
                ended = frame.hasFlag(FrameFlags::kEndStream);
            }
        }
        // 模拟客户端补窗口（连接级与流级）
        mux.push(makeFrame(FRAME_TYPE::WINDOW_UPDATE, 0, 0, increment));
        mux.push(makeFrame(FRAME_TYPE::WINDOW_UPDATE, 1, 0, increment));
        if (!mux.needsProcess() && !ended)
        {
            mux.process();
        }
    }

    EXPECT_EQ(received, 2u << 20);
    EXPECT_TRUE(ended) << "the terminal DATA frame must not be stranded in the outbound scratch";
}

TEST(HandlerHttp2, ManySmallContinuationFragmentsAreAccepted)
{
    ProbeMux mux;
    mux.warmUp();

    // 合规客户端可以用任意小的分片。40 KB 首部块按 1 KiB 切分需要 40 片，
    // 不能因为"片数多"就判成洪水——洪水判据必须留给零长帧。
    const std::string value(40u * 1024u, 'v');
    std::string block;
    block.push_back('\x82');                           // :method GET
    block.push_back('\x86');                           // :scheme http
    block.push_back('\x84');                           // :path /
    http::v2::hpack::encodeInteger(block, 4, 0x00, 0); // 不索引字面量 + 新名称
    http::v2::hpack::encodeInteger(block, 7, 0x00, 7);
    block += "x-large";
    http::v2::hpack::encodeInteger(block, 7, 0x00, value.size());
    block += value;

    constexpr size_t kChunk = 1024;
    const size_t fragments = (block.size() + kChunk - 1) / kChunk;
    ASSERT_GT(fragments, size_t{32});

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndStream, block.substr(0, kChunk)));
    for (size_t i = 1; i < fragments; ++i)
    {
        const std::string piece = block.substr(i * kChunk, kChunk);
        const bool last = (i + 1 == fragments);
        mux.push(makeFrame(FRAME_TYPE::CONTINUATION, 1, last ? FrameFlags::kEndHeaders : 0, piece));
    }

    ASSERT_FALSE(mux.error.has_value()) << mux.why;
    ASSERT_EQ(mux.headers.size(), 1u);
    EXPECT_EQ(mux.headers[0].second, block);
}

TEST(HandlerHttp2, ARefusedFragmentedHeadersDoesNotBreakTheConnection)
{
    ProbeMux mux;
    mux.setMaxConcurrentStreams(1);
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
    ASSERT_EQ(mux.openStreams(), 1u);
    mux.takeFrames();

    // 并发已满，流 3 的首部又是分片的：必须先无条件进入 CONTINUATION 等待状态，
    // 收齐后只拒绝该流。少记这一步就会把随后的同流 CONTINUATION 判成连接级错误，
    // 把流 1 上正在进行的交互一起拆掉。
    std::string block(3, '\0');
    block[0] = static_cast<char>(0x82);
    block[1] = static_cast<char>(0x86);
    block[2] = static_cast<char>(0x84);
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 3, 0, block.substr(0, 1)));
    mux.push(makeFrame(FRAME_TYPE::CONTINUATION, 3, FrameFlags::kEndHeaders, block.substr(1)));

    EXPECT_FALSE(mux.error.has_value()) << mux.why;
    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FRAME_TYPE::RESET);
    EXPECT_EQ(frames[0].streamId, 3u);
    EXPECT_EQ(frame::readBigEndian32(frames[0].payload.data()), std::to_underlying(STREAM_ERROR::REFUSED_STREAM));
    EXPECT_EQ(mux.openStreams(), 1u); // 流 1 不受影响
}

TEST(HandlerHttp2, InFlightFramesAfterARefusedStreamDoNotEndTheConnection)
{
    ProbeMux mux;
    mux.warmUp();

    // 超限首部被 RST 之后，对端在本流上仍未落地的 DATA / RST_STREAM 会接踵而至。
    // 若拒绝路径没有推进"已见流标识"，这些帧会被判成 idle-stream 连接错误，
    // 一次超限请求就拖垮同连接上的所有其他流。
    const std::string value(200, 'v');
    std::string block;
    block.push_back('\x83'); // :method POST
    block.push_back('\x86'); // :scheme http
    block.push_back('\x84'); // :path /
    for (int i = 0; i < 300; ++i)
    {
        block += indexedLiteral("x-f" + std::to_string(i), value);
    }
    constexpr size_t kChunk = 16384;
    const size_t fragments = (block.size() + kChunk - 1) / kChunk;
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, 0, block.substr(0, kChunk)));
    for (size_t i = 1; i < fragments; ++i)
    {
        const bool last = (i + 1 == fragments);
        mux.push(makeFrame(FRAME_TYPE::CONTINUATION, 1, last ? FrameFlags::kEndHeaders : 0,
                           block.substr(i * kChunk, kChunk)));
    }
    ASSERT_FALSE(mux.error.has_value()) << mux.why;
    mux.takeFrames(); // 取走 RST_STREAM

    // 对端在途的请求体
    mux.push(makeFrame(FRAME_TYPE::DATA, 1, 0, "late-body"));
    EXPECT_FALSE(mux.error.has_value()) << mux.why;
    const std::vector<Frame> frames = mux.takeFrames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FRAME_TYPE::RESET);
    EXPECT_EQ(frame::readBigEndian32(frames[0].payload.data()), std::to_underlying(STREAM_ERROR::STREAM_CLOSED));

    // 对端随后取消
    std::string cancel;
    frame::appendBigEndian32(cancel, std::to_underlying(STREAM_ERROR::CANCEL));
    mux.push(makeFrame(FRAME_TYPE::RESET, 1, 0, cancel));
    EXPECT_FALSE(mux.error.has_value()) << mux.why;

    // 同连接上的新流照常可用
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 3, FrameFlags::kEndHeaders, kGetHeadersBlock));
    EXPECT_FALSE(mux.error.has_value()) << mux.why;
    EXPECT_EQ(mux.openStreams(), 1u);
}

TEST(HandlerHttp2, HeadersOnAClosedStreamIsAProtocolError)
{
    ProbeMux mux;
    mux.warmUp();

    // 流 1 完整走完并关闭（墓碑槽位）。
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders | FrameFlags::kEndStream, kGetHeadersBlock));
    ASSERT_FALSE(mux.error.has_value()) << mux.why;
    mux.takeFrames();
    ASSERT_EQ(mux.openStreams(), 0u);

    // 对端用同一 id 重开：标识不递增，属于协议违约。
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
    EXPECT_EQ(mux.error, STREAM_ERROR::PROTOCOL_ERROR);
    EXPECT_NE(mux.why.find("does not increase"), std::string::npos);
}

TEST(HandlerHttp2, ASecondHeadersMustEndTheStreamAsTrailers)
{
    ProbeMux mux;
    mux.warmUp();

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
    ASSERT_EQ(mux.headers.size(), 1u);
    mux.takeFrames();

    // 不带 END_STREAM 的第二个 HEADERS：不是 trailers，必须拒绝
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
    EXPECT_EQ(mux.error, STREAM_ERROR::PROTOCOL_ERROR);
    EXPECT_NE(mux.why.find("second HEADERS"), std::string::npos);
}

TEST(HandlerHttp2, TrailersEndTheStreamWithoutLookingLikeASecondRequest)
{
    class TrailerMux : public HandlerHttp2<HandlerConnection>
    {
    public:
        size_t requests = 0;
        size_t trailers = 0;

        void onStreamHeadersDecoded(uint32_t, const std::vector<http::v2::Header> &) noexcept override { ++requests; }
        void onStreamTrailers(uint32_t, const std::vector<http::v2::Header> &) noexcept override { ++trailers; }

        void push(const Frame &frame)
        {
            std::string bytes;
            appendFrame(bytes, frame);
            [[maybe_unused]] auto _ = appendRequest(bytes.data(), static_cast<ssize_t>(bytes.size()));
            process();
        }
    };

    TrailerMux mux;
    [[maybe_unused]] auto preface = mux.appendRequest(TrailerMux::kClientPreface);
    mux.process();
    while (mux.hasResponse())
        mux.takeResponse();

    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders, kGetHeadersBlock));
    mux.push(makeFrame(FRAME_TYPE::DATA, 1, 0, "body"));
    mux.push(makeFrame(FRAME_TYPE::HEADERS, 1, FrameFlags::kEndHeaders | FrameFlags::kEndStream, kGetHeadersBlock));

    EXPECT_FALSE(mux.closeAfterResponse());
    EXPECT_EQ(mux.requests, 1u) << "trailers must not be reported as a second request";
    EXPECT_EQ(mux.trailers, 1u);
    EXPECT_EQ(mux.openStreams(), 0u);
}
