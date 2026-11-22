#include "address.hpp"
#include "direct/direct.hpp"
#include "forwarder.hpp"
#include "socks/socks5.hpp"
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

using namespace mynet;
using namespace mynet::handler;

// =============================================================================
// 1. 流式处理器桥接与双向数据泵送测试 (Stream Bridge & Buffer Pump)
// =============================================================================

TEST(ForwarderTest, StreamBridgeAndPump)
{
    Forwarder forwarder;

    HandlerInboundDirect inbound;
    HandlerOutboundDirect outbound;

    auto session = forwarder.bridge(inbound, outbound);
    ASSERT_NE(session, nullptr);
    EXPECT_TRUE(session->isEstablished());
    EXPECT_EQ(session->state(), ForwardSessionState::STREAMING);
    EXPECT_EQ(forwarder.activeStreamSessions(), 1u);

    // 1. 上行传输测试：入站接收数据 -> 泵送至出站
    const std::string clientData = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    [[maybe_unused]] auto resUp = inbound.appendRequest(clientData);
    inbound.handle();

    EXPECT_GT(inbound.requestBytes(), 0u);
    EXPECT_FALSE(outbound.hasResponse());

    size_t pumpedUp = forwarder.pumpSession(*session);
    EXPECT_EQ(pumpedUp, clientData.size());
    EXPECT_EQ(inbound.requestBytes(), 0u);
    ASSERT_TRUE(outbound.hasResponse());

    std::string sentToRemote = outbound.takeResponse();
    EXPECT_EQ(sentToRemote, clientData);
    EXPECT_EQ(session->stats().bytesUp, clientData.size());
    EXPECT_EQ(session->stats().packetsUp, 1u);

    // 2. 下行传输测试：出站接收响应 -> 泵送至入站
    const std::string remoteData = "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!";
    [[maybe_unused]] auto resDown = outbound.appendRequest(remoteData);
    outbound.handle();

    EXPECT_GT(outbound.requestBytes(), 0u);
    EXPECT_FALSE(inbound.hasResponse());

    size_t pumpedDown = forwarder.pumpSession(*session);
    EXPECT_EQ(pumpedDown, remoteData.size());
    EXPECT_EQ(outbound.requestBytes(), 0u);
    ASSERT_TRUE(inbound.hasResponse());

    std::string sentToClient = inbound.takeResponse();
    EXPECT_EQ(sentToClient, remoteData);
    EXPECT_EQ(session->stats().bytesDown, remoteData.size());
    EXPECT_EQ(session->stats().packetsDown, 1u);
    EXPECT_EQ(session->stats().totalBytes(), clientData.size() + remoteData.size());
}

// =============================================================================
// 2. 握手阶段预读残余数据自动排空测试 (Pre-buffered Handshake Flush)
// =============================================================================

TEST(ForwarderTest, PrebufferedHandshakeFlush)
{
    Forwarder forwarder;

    HandlerInboundDirect inbound;
    HandlerOutboundDirect outbound;

    // 模拟客户端在 bridge 建立前就已经发送了早期数据 (Early Data)
    const std::string earlyPayload = "EARLY_PAYLOAD_DATA_STREAM";
    [[maybe_unused]] auto res = inbound.appendRequest(earlyPayload);
    inbound.handle();
    ASSERT_EQ(inbound.requestBytes(), earlyPayload.size());

    // 建立桥接时应当自动触发 flushPrebuffered
    auto session = forwarder.bridge(inbound, outbound);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(inbound.requestBytes(), 0u);
    ASSERT_TRUE(outbound.hasResponse());
    EXPECT_EQ(outbound.takeResponse(), earlyPayload);
    EXPECT_EQ(session->stats().bytesUp, earlyPayload.size());
}

// =============================================================================
// 3. 半关闭与全关闭级联测试 (Half-Close & Full-Close Propagation)
// =============================================================================

TEST(ForwarderTest, ClosePropagation)
{
    Forwarder forwarder;

    HandlerInboundDirect inbound;
    HandlerOutboundDirect outbound;

    ForwarderConfig opts;
    opts.propagateClose = true;
    auto session = forwarder.bridge(inbound, outbound, opts);

    // 客户端发送完毕并标记关闭写入端 (FIN)
    inbound.setCloseAfterResponse(true);

    // 驱动一轮泵送检测关闭状态级联
    [[maybe_unused]] auto _ = forwarder.pumpSession(*session);

    EXPECT_TRUE(outbound.closeAfterResponse());
    EXPECT_TRUE(session->isInboundClosed());
    EXPECT_TRUE(session->isOutboundClosed());
    EXPECT_EQ(session->state(), ForwardSessionState::CLOSED);
}

// =============================================================================
// 4. Linux 内核零拷贝 Direct Splice 测试 (SocketPair Zero-Copy Splice)
// =============================================================================

TEST(ForwarderTest, SpliceDirectSocketPair)
{
    int sp1[2] = {-1, -1}; // sp1[0]: client, sp1[1]: proxy Inbound
    int sp2[2] = {-1, -1}; // sp2[0]: proxy Outbound, sp2[1]: remote server

    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sp1), 0);
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sp2), 0);

    // Client 发送数据至 sp1[0]
    const std::string msg = "KERNEL_SPLICE_ZERO_COPY_DATA_STREAM_TEST";
    ssize_t wn = ::write(sp1[0], msg.data(), msg.size());
    ASSERT_EQ(wn, static_cast<ssize_t>(msg.size()));

    // 使用 Forwarder 提供的静态零拷贝函数从 sp1[1] 直通至 sp2[0]
    SpliceResult res = Forwarder::spliceDirect(sp1[1], sp2[0], 65536);
    EXPECT_EQ(res.err, 0);
    EXPECT_EQ(res.bytesSpliced, static_cast<ssize_t>(msg.size()));
    EXPECT_FALSE(res.eof);

    // Remote Server 从 sp2[1] 读取，检验数据完整性
    char buf[128]{};
    ssize_t rn = ::read(sp2[1], buf, sizeof(buf));
    ASSERT_EQ(rn, static_cast<ssize_t>(msg.size()));
    EXPECT_EQ(std::string_view(buf, static_cast<size_t>(rn)), msg);

    ::close(sp1[0]);
    ::close(sp1[1]);
    ::close(sp2[0]);
    ::close(sp2[1]);
}

// =============================================================================
// 5. Connection 对象桥接与自动检测模式测试 (Connection<Handler> Bridge)
// =============================================================================

TEST(ForwarderTest, ConnectionObjectBridge)
{
    Forwarder forwarder;

    ConnectionBase inConn;
    HandlerInboundDirect inHandler;
    inConn.setHandler(&inHandler);

    ConnectionBase outConn;
    HandlerOutboundDirect outHandler;
    outConn.setHandler(&outHandler);

    int sp[2] = {-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sp), 0);
    inConn.setFd(sp[0]);
    outConn.setFd(sp[1]);

    auto session = forwarder.bridge(inConn, outConn);
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->activeMode(), ForwardMode::ZERO_COPY_SPLICE);
    EXPECT_TRUE(inHandler.isSpliceActive());
    EXPECT_EQ(inHandler.spliceTarget(), sp[1]);
    EXPECT_TRUE(outHandler.isSpliceActive());
    EXPECT_EQ(outHandler.spliceTarget(), sp[0]);

    inConn.reset();
    outConn.reset();
    ::close(sp[0]);
    ::close(sp[1]);
}

// =============================================================================
// 6. 数据报/UDP 转发会话与生命周期测试 (Datagram Forwarding)
// =============================================================================

TEST(ForwarderTest, DatagramForwardingAndSweep)
{
    Forwarder forwarder;

    sockaddr_in client{};
    client.sin_family = AF_INET;
    client.sin_port = htons(12345);
    client.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    sockaddr_in remote{};
    remote.sin_family = AF_INET;
    remote.sin_port = htons(53);
    remote.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    auto session = forwarder.getOrCreateDatagramSession(client, remote);
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(forwarder.activeDatagramSessions(), 1u);

    // 模拟数据报回复回写给客户端
    HandlerInboundDatagramBase inbound;
    const std::string dnsResp = "DNS_PACKET_RESPONSE_PAYLOAD";
    auto res = forwarder.forwardDatagramToClient(inbound, client, dnsResp, session.get());
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(*res, dnsResp.size());
    EXPECT_EQ(session->stats().bytesDown, dnsResp.size());
    EXPECT_EQ(session->stats().packetsDown, 1u);

    ASSERT_TRUE(inbound.hasOutgoing());
    auto outgoing = inbound.takeOutgoing();
    EXPECT_EQ(outgoing.bytes, dnsResp);

    // 超时排空测试 (0 秒强制超时)
    size_t swept = forwarder.sweepIdleDatagramSessions(std::chrono::seconds(0));
    EXPECT_EQ(swept, 1u);
    EXPECT_EQ(forwarder.activeDatagramSessions(), 0u);
    EXPECT_EQ(forwarder.totalBytesDown(), dnsResp.size());
}

// =============================================================================
// 7. 会话管理器聚合统计与批量清理测试 (Forwarder Aggregated Stats)
// =============================================================================

TEST(ForwarderTest, AggregatedMetricsAndCloseAll)
{
    Forwarder forwarder;

    HandlerInboundDirect in1, in2;
    HandlerOutboundDirect out1, out2;

    auto s1 = forwarder.bridge(in1, out1);
    auto s2 = forwarder.bridge(in2, out2);

    EXPECT_EQ(forwarder.activeStreamSessions(), 2u);

    // 泵送一些数据
    [[maybe_unused]] auto _1 = in1.appendRequest("DATA_1");
    in1.handle();
    [[maybe_unused]] auto _2 = in2.appendRequest("DATA_22");
    in2.handle();

    size_t pumped = forwarder.pumpAll();
    EXPECT_EQ(pumped, 13u); // 6 + 7 = 13

    EXPECT_EQ(forwarder.findStreamSession(s1->id()), s1);
    EXPECT_EQ(forwarder.findStreamSession(s2->id()), s2);

    forwarder.closeStreamSession(s1->id());
    EXPECT_EQ(forwarder.activeStreamSessions(), 1u);
    EXPECT_EQ(forwarder.findStreamSession(s1->id()), nullptr);

    forwarder.closeAll();
    EXPECT_EQ(forwarder.activeStreamSessions(), 0u);
    EXPECT_EQ(forwarder.totalBytesUp(), 13u);
}

// =============================================================================
// 8. 分散-聚集向量写入与前缀冲刷测试 (借鉴 dae writev scatter-gather header prefixing)
// =============================================================================

TEST(ForwarderTest, ScatterGatherPrefixedFlushing)
{
    int fds[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    int tx = fds[0];
    int rx = fds[1];

    std::vector<uint8_t> header = {'S', 'S', '-', 'H', 'D', 'R', ':'};
    std::vector<uint8_t> payload = {'G', 'E', 'T', ' ', '/', ' ', 'H', 'T', 'T', 'P', '/', '1', '.', '1'};

    ssize_t written = ScatterGatherFlusher::writePrefixed(tx, header, payload);
    EXPECT_EQ(written, static_cast<ssize_t>(header.size() + payload.size()));

    char recvBuf[64] = {};
    ssize_t n = ::read(rx, recvBuf, sizeof(recvBuf));
    ASSERT_EQ(n, static_cast<ssize_t>(header.size() + payload.size()));

    std::string received(recvBuf, static_cast<size_t>(n));
    EXPECT_EQ(received, "SS-HDR:GET / HTTP/1.1");

    ::close(tx);
    ::close(rx);
}

// =============================================================================
// 9. FIONREAD 动态就绪载荷聚集前缀写入测试 (机制 71: tryRelayGatherWrite)
// =============================================================================

TEST(ForwarderTest, ScatterGatherPrefixedWithFionread)
{
    // 模拟三方套接字：srcClient -> srcServer (中继读端) / dstClient (中继写端) -> dstServer
    int srcPair[2];
    int dstPair[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, srcPair), 0);
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, dstPair), 0);

    int clientWriter = srcPair[0];
    int relaySrcReader = srcPair[1];
    int relayDstWriter = dstPair[0];
    int upstreamReader = dstPair[1];

    // 客户端先写入一段后续载荷
    const std::string payload = "HTTP_PAYLOAD_BODY_READY";
    ASSERT_EQ(::write(clientWriter, payload.data(), payload.size()), static_cast<ssize_t>(payload.size()));

    // 中继使用 writePrefixedWithGather 将协议前缀与源端待读载荷单次 writev 发送
    std::vector<uint8_t> header = {'P', 'R', 'O', 'T', 'O', ':'};
    std::vector<uint8_t> scratch(1024);

    ssize_t written = ScatterGatherFlusher::writePrefixedWithGather(relayDstWriter, header, relaySrcReader, scratch);
    EXPECT_EQ(written, static_cast<ssize_t>(header.size() + payload.size()));

    char recvBuf[128] = {};
    ssize_t n = ::read(upstreamReader, recvBuf, sizeof(recvBuf));
    ASSERT_EQ(n, static_cast<ssize_t>(header.size() + payload.size()));
    std::string result(recvBuf, static_cast<size_t>(n));
    EXPECT_EQ(result, "PROTO:HTTP_PAYLOAD_BODY_READY");

    ::close(clientWriter);
    ::close(relaySrcReader);
    ::close(relayDstWriter);
    ::close(upstreamReader);
}
