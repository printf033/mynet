#include "http/v3/handler.hpp"
#include <gtest/gtest.h>

using namespace mynet;
using namespace mynet::http::v3;

// ============================================================================
// 1. Varint Tests (RFC 9000 Section 16)
// ============================================================================

TEST(Http3Varint, RoundTripVariousLengths)
{
    const std::vector<uint64_t> testValues = {
        0,
        1,
        25,
        63, // 1-byte
        64,
        100,
        1000,
        16383, // 2-byte
        16384,
        65536,
        1000000,
        1073741823, // 4-byte
        1073741824ULL,
        1ULL << 32,
        1ULL << 40,
        (1ULL << 62) - 1 // 8-byte
    };

    for (uint64_t val : testValues)
    {
        std::string buf;
        appendVarint(buf, val);
        EXPECT_EQ(buf.size(), varintLength(val));

        const auto *ptr = reinterpret_cast<const uint8_t *>(buf.data());
        size_t rem = buf.size();
        auto res = readVarint(ptr, rem);
        ASSERT_TRUE(res.has_value()) << "Failed to decode val=" << val;
        EXPECT_EQ(*res, val);
        EXPECT_EQ(rem, 0u);
    }
}

TEST(Http3Varint, DecodeVarintFromBuffer)
{
    Buffer buf;
    std::string s;
    appendVarint(s, 15213);
    [[maybe_unused]] auto _ = buf.append(s.data(), s.size());

    auto res = decodeVarint(buf);
    ASSERT_TRUE(res.has_value());
    ASSERT_TRUE(res->has_value());
    EXPECT_EQ(**res, 15213u);
    EXPECT_EQ(buf.readableBytes(), 0u);
}

TEST(Http3Varint, IncompleteBytesReturnsNullopt)
{
    Buffer buf;
    // 写入一个需要 4 字节的数字的前 2 字节
    std::string full;
    appendVarint(full, 100000);
    ASSERT_EQ(full.size(), 4u);

    [[maybe_unused]] auto _ = buf.append(full.data(), 2);
    auto res = decodeVarint(buf);
    ASSERT_TRUE(res.has_value());
    EXPECT_FALSE(res->has_value()); // 字节不足一完整变长整数
    EXPECT_EQ(buf.readableBytes(), 2u);
}

// ============================================================================
// 2. HTTP/3 Frame Tests (RFC 9114 Section 7)
// ============================================================================

TEST(Http3Frame, AppendAndDecodeSingleFrame)
{
    std::string frameBytes;
    appendFrame(frameBytes, std::to_underlying(FRAME_TYPE::DATA), "hello http3 data");

    Buffer buf;
    [[maybe_unused]] auto _ = buf.append(frameBytes.data(), frameBytes.size());

    FrameDecoder decoder;
    auto res = decoder.next(buf);
    ASSERT_TRUE(res.has_value());
    ASSERT_TRUE(res->has_value());

    const Frame &f = **res;
    EXPECT_EQ(f.type, std::to_underlying(FRAME_TYPE::DATA));
    EXPECT_EQ(f.payload, "hello http3 data");
    EXPECT_EQ(buf.readableBytes(), 0u);
}

TEST(Http3Frame, ReservedGreaseDetection)
{
    EXPECT_TRUE(isReservedGreaseFrame(0x21));
    EXPECT_TRUE(isReservedGreaseFrame(0x21 + 0x1f));
    EXPECT_TRUE(isReservedGreaseFrame(0x21 + 2 * 0x1f));
    EXPECT_FALSE(isReservedGreaseFrame(0x00));
    EXPECT_FALSE(isReservedGreaseFrame(0x01));
    EXPECT_FALSE(isReservedGreaseFrame(0x04));
}

TEST(Http3Frame, FrameTooLargeReturnsError)
{
    std::string frameBytes;
    appendFrame(frameBytes, std::to_underlying(FRAME_TYPE::DATA), "payload");

    Buffer buf;
    [[maybe_unused]] auto _ = buf.append(frameBytes.data(), frameBytes.size());

    FrameDecoder decoder;
    decoder.setMaxFrameSize(3); // 限制小于 payload 尺寸 (7)
    auto res = decoder.next(buf);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error(), FRAME_DECODE_ERROR::FRAME_TOO_LARGE);
}

// ============================================================================
// 3. Settings Tests (RFC 9114 Section 7.2.4)
// ============================================================================

TEST(Http3Settings, EncodeAndDecodeSettings)
{
    Settings s;
    s.maxFieldSectionSize = 131072;
    s.qpackMaxTableCapacity = 4096;
    s.qpackBlockedStreams = 16;

    std::string payload;
    s.encode(payload);

    auto decodedRes = Settings::decode(payload);
    ASSERT_TRUE(decodedRes.has_value());
    EXPECT_EQ(decodedRes->maxFieldSectionSize, 131072u);
    EXPECT_EQ(decodedRes->qpackMaxTableCapacity, 4096u);
    EXPECT_EQ(decodedRes->qpackBlockedStreams, 16u);
}

// ============================================================================
// 4. QPACK Tests (RFC 9204)
// ============================================================================

TEST(Http3Qpack, StaticTableIndexedAndLiteralRoundtrip)
{
    std::vector<Header> headers = {{":method", "GET"},
                                   {":scheme", "https"},
                                   {":path", "/index.html"},
                                   {":status", "200"},
                                   {"custom-header", "custom-value"}};

    std::string encoded;
    encodeHeaders(encoded, headers);

    auto decodedRes = decodeHeaders(encoded);
    ASSERT_TRUE(decodedRes.has_value());
    const auto &decoded = *decodedRes;
    ASSERT_EQ(decoded.size(), 5u);

    EXPECT_EQ(decoded[0].name, ":method");
    EXPECT_EQ(decoded[0].value, "GET");

    EXPECT_EQ(decoded[1].name, ":scheme");
    EXPECT_EQ(decoded[1].value, "https");

    EXPECT_EQ(decoded[2].name, ":path");
    EXPECT_EQ(decoded[2].value, "/index.html");

    EXPECT_EQ(decoded[3].name, ":status");
    EXPECT_EQ(decoded[3].value, "200");

    EXPECT_EQ(decoded[4].name, "custom-header");
    EXPECT_EQ(decoded[4].value, "custom-value");
}

// ============================================================================
// 5. QUIC Primitives Tests (RFC 9000)
// ============================================================================

TEST(Http3Quic, ConnectionIdToHexAndComparison)
{
    const uint8_t rawCid[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    ConnectionId cid = ConnectionId::fromBytes(rawCid, sizeof(rawCid));
    EXPECT_EQ(cid.length, 8u);
    EXPECT_EQ(cid.toHex(), "0123456789abcdef");

    ConnectionId cid2 = ConnectionId::fromBytes(rawCid, sizeof(rawCid));
    EXPECT_EQ(cid, cid2);
}

TEST(Http3Quic, StreamFrameSerializationAndParsing)
{
    std::string out;
    appendStreamFrame(out, 4, 1024, "stream data payload", true);

    const auto *ptr = reinterpret_cast<const uint8_t *>(out.data());
    size_t rem = out.size();

    auto sfRes = parseStreamFrame(ptr, rem);
    ASSERT_TRUE(sfRes.has_value());
    const StreamFrame &sf = *sfRes;

    EXPECT_EQ(sf.streamId, 4u);
    EXPECT_EQ(sf.offset, 1024u);
    EXPECT_TRUE(sf.fin);
    EXPECT_EQ(sf.data, "stream data payload");
    EXPECT_EQ(rem, 0u);
}

TEST(Http3Quic, ShortHeaderPacketRoundtrip)
{
    const uint8_t rawCid[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    ConnectionId dcid = ConnectionId::fromBytes(rawCid, sizeof(rawCid));

    std::string pkt;
    appendShortHeaderPacket(pkt, dcid, 42, "quic frames payload");

    auto shpRes = parseShortHeaderPacket(pkt, 8);
    ASSERT_TRUE(shpRes.has_value());
    const ShortHeaderPacket &shp = *shpRes;

    EXPECT_EQ(shp.dcid, dcid);
    EXPECT_EQ(shp.packetNumber, 42u);
    EXPECT_EQ(shp.payload, "quic frames payload");
}

// ============================================================================
// 6. HandlerHttp3 Tests
// ============================================================================

TEST(HandlerHttp3, ConceptConformance)
{
    static_assert(ProtocolHandler<HandlerHttp3>);
    static_assert(DerivedFromHandlerBase<HandlerHttp3>);
    static_assert(DerivedFromDatagramHandler<HandlerHttp3>);
    static_assert(Resettable<HandlerHttp3>);

    EXPECT_TRUE(ProtocolHandler<HandlerHttp3>);
    EXPECT_TRUE(DerivedFromHandlerBase<HandlerHttp3>);
    EXPECT_TRUE(DerivedFromDatagramHandler<HandlerHttp3>);
    EXPECT_TRUE(Resettable<HandlerHttp3>);
}

TEST(HandlerHttp3, ProcessStreamFramesGeneratesResponse)
{
    HandlerHttp3 handler;

    std::vector<Header> reqHeaders = {{":method", "GET"}, {":path", "/test"}};
    std::string headerBytes;
    encodeHeaders(headerBytes, reqHeaders);

    std::string frames;
    appendFrame(frames, std::to_underlying(FRAME_TYPE::HEADERS), headerBytes);
    appendFrame(frames, std::to_underlying(FRAME_TYPE::DATA), "request payload");

    [[maybe_unused]] auto _ = handler.appendRequest(frames.data(), static_cast<ssize_t>(frames.size()));
    handler.process();

    ASSERT_TRUE(handler.hasResponse());
    std::string resp = handler.takeResponse();
    EXPECT_FALSE(resp.empty());

    // 解析响应帧
    Buffer respBuf;
    [[maybe_unused]] auto _2 = respBuf.append(resp.data(), resp.size());

    FrameDecoder decoder;
    auto f1Res = decoder.next(respBuf);
    ASSERT_TRUE(f1Res.has_value() && f1Res->has_value());
    EXPECT_EQ((*f1Res)->type, std::to_underlying(FRAME_TYPE::HEADERS));

    auto decodedHeadersRes = decodeHeaders((*f1Res)->payload);
    ASSERT_TRUE(decodedHeadersRes.has_value());
    bool foundStatus = false;
    for (const auto &h : *decodedHeadersRes)
    {
        if (h.name == ":status")
        {
            foundStatus = true;
            EXPECT_EQ(h.value, "200");
        }
    }
    EXPECT_TRUE(foundStatus);

    auto f2Res = decoder.next(respBuf);
    ASSERT_TRUE(f2Res.has_value() && f2Res->has_value());
    EXPECT_EQ((*f2Res)->type, std::to_underlying(FRAME_TYPE::DATA));
    EXPECT_EQ((*f2Res)->payload, "request payload"); // 回显了请求体
}

TEST(HandlerHttp3, OnDatagramProcessesQuicPacketAndReplies)
{
    HandlerHttp3 handler;

    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    peer.sin_port = htons(54321);
    inet_pton(AF_INET, "127.0.0.1", &peer.sin_addr);

    // 1. 构造客户端 HTTP/3 请求帧
    std::vector<Header> reqHeaders = {{":method", "POST"}, {":path", "/api/echo"}};
    std::string headerPayload;
    encodeHeaders(headerPayload, reqHeaders);

    std::string h3Frames;
    appendFrame(h3Frames, std::to_underlying(FRAME_TYPE::HEADERS), headerPayload);
    appendFrame(h3Frames, std::to_underlying(FRAME_TYPE::DATA), "ping udp quic");

    // 2. 封装为 QUIC STREAM 帧 (streamId = 0, fin = true)
    std::string quicStream;
    appendStreamFrame(quicStream, 0, 0, h3Frames, true);

    // 3. 封装为 1-RTT 短首部数据报
    const uint8_t rawCid[] = {1, 2, 3, 4, 5, 6, 7, 8};
    ConnectionId dcid = ConnectionId::fromBytes(rawCid, sizeof(rawCid));
    std::string packet;
    appendShortHeaderPacket(packet, dcid, 1, quicStream);

    // 4. 输入给 onDatagram
    EXPECT_FALSE(handler.hasReply());
    handler.onDatagram(peer, packet.data(), packet.size());
    EXPECT_TRUE(handler.hasReply());

    // 5. 校验回复
    auto reply = handler.takeReply();
    EXPECT_EQ(reply.peer.sin_port, htons(54321));

    // 解析回复的短首部报文
    auto shpRes = parseShortHeaderPacket(reply.bytes, 8);
    ASSERT_TRUE(shpRes.has_value());
    EXPECT_EQ(shpRes->dcid, dcid);

    // 解析回复的 STREAM 帧
    const auto *p = reinterpret_cast<const uint8_t *>(shpRes->payload.data());
    size_t rem = shpRes->payload.size();
    auto sfRes = parseStreamFrame(p, rem);
    ASSERT_TRUE(sfRes.has_value());
    EXPECT_EQ(sfRes->streamId, 0u);
    EXPECT_TRUE(sfRes->fin);

    // 解析内部的 HTTP/3 帧
    Buffer respBuf;
    [[maybe_unused]] auto _ = respBuf.append(sfRes->data.data(), sfRes->data.size());
    FrameDecoder decoder;
    auto h1Res = decoder.next(respBuf);
    ASSERT_TRUE(h1Res.has_value() && h1Res->has_value());
    EXPECT_EQ((*h1Res)->type, std::to_underlying(FRAME_TYPE::HEADERS));

    auto h2Res = decoder.next(respBuf);
    ASSERT_TRUE(h2Res.has_value() && h2Res->has_value());
    EXPECT_EQ((*h2Res)->type, std::to_underlying(FRAME_TYPE::DATA));
    EXPECT_EQ((*h2Res)->payload, "ping udp quic");
}

TEST(Http3Qpack, RejectsHeaderBomb)
{
    std::string block;
    block.push_back('\0');
    block.push_back('\0');

    // 尝试解码超出上限 (256 项) 的海量首部，触发防 DoS 截断
    for (int i = 0; i < 300; ++i)
    {
        encodePrefixedInt(block, 6, 0xc0, 17); // :method GET (静态表项 17)
    }

    auto res = decodeHeaders(block);
    EXPECT_FALSE(res.has_value());
    EXPECT_EQ(res.error(), H3_ERROR::H3_EXCESSIVE_LOAD);
}

TEST(Http3Qpack, RejectsHeaderAccordionsOverheadInflation)
{
    std::string block;
    block.push_back('\0');
    block.push_back('\0');

    // CVE-2025-64702 Header Accordions 防御验证：
    // 每项首部计入 32 字节 RFC 9114 标准开销，防止海量小首部利用展开后内存膨胀进行 DoS 攻击
    // 构造足够多的字面量首部使得总开销越过 64 KiB
    for (int i = 0; i < 200; ++i)
    {
        // 模式: 0 0 1 0 N 0 NameLen
        encodePrefixedInt(block, 3, 0x20, 10);
        block.append("x-cust-hdr");
        // 写入 300 字节的值
        appendStringLiteral(block, std::string(300, 'x'));
    }

    auto res = decodeHeaders(block);
    EXPECT_FALSE(res.has_value());
    EXPECT_EQ(res.error(), H3_ERROR::H3_EXCESSIVE_LOAD);
}

TEST(HandlerHttp3, RejectsServerInitiatedStreamIdFromClient)
{
    HandlerHttp3 handler;
    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    peer.sin_port = htons(12345);

    // 构造 QUIC 报文：携带服务端发起的流编号 (streamId = 1, RFC 9000 规定客户端不得主动发起奇数流)
    std::string quicPayload;
    appendStreamFrame(quicPayload, 1, 0, "illegal server-initiated stream", true);

    ConnectionId dcid = ConnectionId::fromBytes("12345678", 8);
    std::string pkt;
    appendShortHeaderPacket(pkt, dcid, 1, quicPayload);

    handler.onDatagram(peer, pkt.data(), pkt.size());
    EXPECT_EQ(handler.activeStreams(), 0u);
    EXPECT_FALSE(handler.hasReply());
}

class LargeResponseHttp3Handler : public HandlerHttp3
{
public:
    void onRequest([[maybe_unused]] uint64_t streamId, [[maybe_unused]] const std::vector<Header> &headers,
                   [[maybe_unused]] std::string_view body, std::string &responseBody) override
    {
        // 返回 1000 字节响应，远超 50 字节请求的 3 倍反弹阈值 (~150 字节)
        responseBody.assign(1000, 'X');
    }
};

TEST(HandlerHttp3, AntiAmplificationLimitBlocksReflectedAmplificationUntilValidated)
{
    LargeResponseHttp3Handler handler;
    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    peer.sin_port = htons(11223);
    inet_pton(AF_INET, "192.0.2.1", &peer.sin_addr);

    std::vector<Header> reqHeaders = {{":method", "GET"}, {":path", "/amplified"}};
    std::string headerPayload;
    encodeHeaders(headerPayload, reqHeaders);

    std::string h3Frames;
    appendFrame(h3Frames, std::to_underlying(FRAME_TYPE::HEADERS), headerPayload);

    std::string quicStream;
    appendStreamFrame(quicStream, 0, 0, h3Frames, true);

    ConnectionId dcid = ConnectionId::fromBytes("11112222", 8);
    std::string packet;
    appendShortHeaderPacket(packet, dcid, 1, quicStream);

    // 报文长度约 40-50 字节，未通过地址验证前服务端最多允许回复 3x 字节 (~150 字节)
    ASSERT_LT(packet.size(), 60u);

    // 输入给 onDatagram：触发 onRequest 生成 1000 字节响应，但被 RFC 9000 Section 8.1 抗放大防护阻断
    handler.onDatagram(peer, packet.data(), packet.size());
    EXPECT_FALSE(handler.hasReply());

    // 对该 peer 实施地址验证后，抗放大限制解除
    handler.validateAddress(peer);
    // 再次发送请求
    handler.onDatagram(peer, packet.data(), packet.size());
    EXPECT_TRUE(handler.hasReply());
    auto reply = handler.takeReply();
    EXPECT_GT(reply.bytes.size(), 1000u);
}

TEST(HandlerHttp3, PerConnectionSessionIsolationPreventsCrosstalk)
{
    HandlerHttp3 handler;

    sockaddr_in peerA{};
    peerA.sin_family = AF_INET;
    peerA.sin_port = htons(10001);
    inet_pton(AF_INET, "10.0.0.1", &peerA.sin_addr);
    ConnectionId dcidA = ConnectionId::fromBytes("AAAA1111", 8);

    sockaddr_in peerB{};
    peerB.sin_family = AF_INET;
    peerB.sin_port = htons(10002);
    inet_pton(AF_INET, "10.0.0.2", &peerB.sin_addr);
    ConnectionId dcidB = ConnectionId::fromBytes("BBBB2222", 8);

    // 客户端 A：发送 stream 0 的 HEADERS (无 FIN，headersComplete = false)
    std::vector<Header> headersA = {{":method", "GET"}, {":path", "/alice"}};
    std::string hpA;
    encodeHeaders(hpA, headersA);
    std::string h3A;
    appendFrame(h3A, std::to_underlying(FRAME_TYPE::HEADERS), hpA);
    std::string qsA;
    appendStreamFrame(qsA, 0, 0, h3A, false); // fin = false
    std::string pktA;
    appendShortHeaderPacket(pktA, dcidA, 1, qsA);

    handler.onDatagram(peerA, pktA.data(), pktA.size());
    EXPECT_FALSE(handler.hasReply());

    // 客户端 B：发送同 stream 0 的 HEADERS + DATA (fin = true)
    std::vector<Header> headersB = {{":method", "POST"}, {":path", "/bob"}};
    std::string hpB;
    encodeHeaders(hpB, headersB);
    std::string h3B;
    appendFrame(h3B, std::to_underlying(FRAME_TYPE::HEADERS), hpB);
    appendFrame(h3B, std::to_underlying(FRAME_TYPE::DATA), "bob-body");
    std::string qsB;
    appendStreamFrame(qsB, 0, 0, h3B, true); // fin = true
    std::string pktB;
    appendShortHeaderPacket(pktB, dcidB, 1, qsB);

    handler.onDatagram(peerB, pktB.data(), pktB.size());
    // 客户端 B 收到应答，且应答发往 peerB，携带 dcidB
    ASSERT_TRUE(handler.hasReply());
    auto replyB = handler.takeReply();
    EXPECT_EQ(replyB.peer.sin_port, htons(10002));
    auto shpB = parseShortHeaderPacket(replyB.bytes, 8);
    ASSERT_TRUE(shpB.has_value());
    EXPECT_EQ(shpB->dcid, dcidB);

    // 验证客户端 A 的流不受客户端 B 影响
    EXPECT_FALSE(handler.hasReply());
}
