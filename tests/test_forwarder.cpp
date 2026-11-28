#include "address.hpp"
#include "direct/direct.hpp"
#include "forwarder.hpp"
#include "shadowsocks/shadowsocks.hpp"
#include "socks/socks5.hpp"
#include <chrono>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <thread>
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
// 5. Connection 对象桥接与自动检测模式测试 (Connection<Handler> Bridge)
// =============================================================================

TEST(ForwarderTest, ConnectionObjectBridge)
{
    Forwarder forwarder;

    Connection inConn;
    auto inHandlerPtr = std::make_unique<HandlerInboundDirect>();
    auto *inHandler = inHandlerPtr.get();
    inConn.setHandler(std::move(inHandlerPtr));

    Connection outConn;
    auto outHandlerPtr = std::make_unique<HandlerOutboundDirect>();
    auto *outHandler = outHandlerPtr.get();
    outConn.setHandler(std::move(outHandlerPtr));

    int sp[2] = {-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sp), 0);
    inConn.setFd(sp[0]);
    outConn.setFd(sp[1]);

    auto session = forwarder.bridge(inConn, outConn);
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->activeMode(), ForwardMode::ZERO_COPY_SPLICE);
    EXPECT_TRUE(inHandler->canSplice());
    EXPECT_TRUE(outHandler->canSplice());

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
    Handler inbound;
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

TEST(ForwarderTest, ShadowsocksCodecSymmetricRelayViaPump)
{
    Address target;
    target.type = AddressType::DOMAIN;
    target.host = "example.com";
    target.port = 443;

    HandlerInboundShadowsocks ssServer("aes-128-gcm", "test-secret");
    HandlerOutboundShadowsocks ssClient("aes-128-gcm", "test-secret", target);
    ssClient.handle();

    // 1. 客户端发送首包 (salt + target addr chunk) 给入站完成 Shadowsocks 解码握手
    while (ssClient.hasResponse())
    {
        std::string wire = ssClient.takeResponse();
        ASSERT_TRUE(ssServer.appendRequest(wire.data(), static_cast<ssize_t>(wire.size())).has_value());
    }
    ssServer.drive();
    ASSERT_TRUE(ssServer.isEstablished());
    EXPECT_EQ(ssServer.target().host, "example.com");
    EXPECT_EQ(ssServer.target().port, 443);
    EXPECT_FALSE(ssServer.canSplice());

    Handler upstream;
    Forwarder forwarder;
    auto session = forwarder.bridge(ssServer, upstream);
    EXPECT_EQ(session->activeMode(), ForwardMode::BUFFER_PUMP);

    // 2. 上行载荷：ssClient.sendPayload -> wire -> ssServer decode -> Forwarder -> upstream
    ASSERT_TRUE(ssClient.sendPayload("ss-uplink-payload").has_value());
    while (ssClient.hasResponse())
    {
        std::string wire = ssClient.takeResponse();
        ASSERT_TRUE(ssServer.appendRequest(wire.data(), static_cast<ssize_t>(wire.size())).has_value());
    }
    (void)forwarder.pumpSession(*session);
    ASSERT_TRUE(upstream.hasResponse());
    EXPECT_EQ(upstream.takeResponse(), "ss-uplink-payload");

    // 3. 下行载荷：upstream -> Forwarder -> ssServer.sendPayload (AEAD 加密) -> wire -> ssClient 解密
    ASSERT_TRUE(upstream.appendRequest("ss-downlink-reply").has_value());
    (void)forwarder.pumpSession(*session);
    ASSERT_TRUE(ssServer.hasResponse());
    while (ssServer.hasResponse())
    {
        std::string wire = ssServer.takeResponse();
        ASSERT_TRUE(ssClient.appendRequest(wire.data(), static_cast<ssize_t>(wire.size())).has_value());
    }
    ssClient.drive();
    EXPECT_EQ(std::string_view(ssClient.requestBegin(), ssClient.requestBytes()), "ss-downlink-reply");
}

namespace
{
    class MemoryStreamChannel final : public IStreamChannel
    {
    public:
        std::string rxQueue{};
        std::string txSink{};
        bool open{true};

        [[nodiscard]] int fd() const noexcept override { return -1; }
        [[nodiscard]] bool isOpen() const noexcept override { return open; }
        [[nodiscard]] bool isPassthrough() const noexcept override { return false; }

        [[nodiscard]] Result<size_t> readBytes(std::span<uint8_t> dst) noexcept override
        {
            if (!open)
                return std::unexpected(ERR::CONNECT_FAILED);
            const size_t n = std::min(dst.size(), rxQueue.size());
            if (n > 0)
            {
                std::memcpy(dst.data(), rxQueue.data(), n);
                rxQueue.erase(0, n);
            }
            return n;
        }

        [[nodiscard]] Result<size_t> writeBytes(std::span<const uint8_t> src) noexcept override
        {
            if (!open)
                return std::unexpected(ERR::CONNECT_FAILED);
            txSink.append(reinterpret_cast<const char *>(src.data()), src.size());
            return src.size();
        }

        void closeChannel() noexcept override { open = false; }
    };
} // namespace

TEST(ForwarderTest, VirtualStreamChannelNonFdBidirectionalBridge)
{
    auto inCh = std::make_shared<MemoryStreamChannel>();
    auto outCh = std::make_shared<MemoryStreamChannel>();
    inCh->rxQueue = "virtual-up";
    outCh->rxQueue = "virtual-down";

    Handler inbound;
    Handler outbound;
    Forwarder forwarder;
    auto session = forwarder.bridgeChannels(inbound, inCh, outbound, outCh);
    EXPECT_EQ(session->activeMode(), ForwardMode::BUFFER_PUMP);

    (void)forwarder.pumpSession(*session);
    EXPECT_EQ(outCh->txSink, "virtual-up");
    EXPECT_EQ(inCh->txSink, "virtual-down");
}

TEST(ForwarderTest, ProactorManagedSessionHooksConnectSendRecvSpliceAndRetire)
{
    int sv[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sv), 0);

    Forwarder forwarder;
    uint64_t registeredId = 0;
    int notifyCount = 0;
    uint64_t retiredId = 0;
    bool transferredOwnership = false;

    ForwarderLoopHooks hooks;
    hooks.deferOutboundConnect = true;
    hooks.registerSession = [&](const std::shared_ptr<ForwarderStreamSession> &s)
    {
        registeredId = s->id();
        return true;
    };
    hooks.notifySession = [&](uint64_t sid)
    {
        EXPECT_EQ(sid, registeredId);
        ++notifyCount;
    };
    hooks.retireSession = [&](uint64_t sid, bool ownsFd)
    {
        retiredId = sid;
        transferredOwnership = ownsFd;
        if (ownsFd)
        {
            ::close(sv[0]);
        }
        return true;
    };
    forwarder.setLoopHooks(std::move(hooks));

    HandlerInboundDirect inbound;
    HandlerOutboundDirect outbound;
    auto session = forwarder.bridge(inbound, outbound);
    ASSERT_NE(session, nullptr);

    sockaddr_in targetAddr{};
    targetAddr.sin_family = AF_INET;
    targetAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    targetAddr.sin_port = htons(18080);

    session->setOutboundFd(sv[0]);
    session->setOwnsOutboundFd(true);
    session->setOutboundConnectState(true, true, targetAddr);

    EXPECT_TRUE(forwarder.activateLoopWatch(session));
    EXPECT_EQ(registeredId, session->id());
    EXPECT_TRUE(session->proactorManaged());
    EXPECT_TRUE(session->isOutboundConnecting());
    EXPECT_TRUE(session->isOutboundConnectDeferred());
    EXPECT_EQ(session->outboundTargetAddr().sin_port, htons(18080));

    // 连接完成回调
    session->onProactorConnectComplete(0);
    EXPECT_FALSE(session->isOutboundConnecting());
    EXPECT_FALSE(session->isOutboundConnectDeferred());

    // 在 Proactor 托管模式下，pump() 不得再同步 recv/send，而是桥接内存并通知 Proactor
    ASSERT_TRUE(inbound.appendRequest("hello-proactor-send").has_value());
    (void)session->pump();
    EXPECT_GT(notifyCount, 0);
    EXPECT_TRUE(session->hasOutboundPendingToSend());

    // 模拟 io_uring_prep_send 部分写出与 O(1) 游标推进
    std::string_view part1 = session->beginProactorOutboundSend(4096);
    EXPECT_EQ(part1, "hello-proactor-send");
    EXPECT_TRUE(session->finishProactorOutboundSend(6));
    std::string_view part2 = session->beginProactorOutboundSend(4096);
    EXPECT_EQ(part2, "proactor-send");
    EXPECT_FALSE(session->finishProactorOutboundSend(static_cast<ssize_t>(part2.size())));
    EXPECT_EQ(session->stats().bytesUp, 19u);

    // 模拟 io_uring_prep_recv 收到对端回包 -> 自动桥接推入 inbound 响应队列
    constexpr char kDown[] = "downlink-from-uring";
    session->onProactorOutboundRecv(kDown, sizeof(kDown) - 1);
    ASSERT_TRUE(inbound.hasResponse());
    EXPECT_EQ(inbound.takeResponse(), "downlink-from-uring");
    EXPECT_EQ(session->stats().bytesDown, 19u);

    // 模拟 io_uring_prep_splice 统计与 EOF 收敛
    session->onProactorSpliceResult(false, 64);
    session->onProactorSpliceResult(true, 128);
    EXPECT_EQ(session->stats().bytesUp, 19u + 64u);
    EXPECT_EQ(session->stats().bytesDown, 19u + 128u);

    // 关闭时应通过 retireSession 异步移交 fd 所有权
    session->close(true);
    EXPECT_EQ(retiredId, session->id());
    EXPECT_TRUE(transferredOwnership);
    EXPECT_EQ(session->outboundFd(), -1);
    ::close(sv[1]);
}

TEST(ForwarderTest, DatagramReuseNatKeyAndSendViaDatagramEndpoint)
{
    auto remote = Datagram::bind("127.0.0.1", 0);
    auto outEp = Datagram::bind("127.0.0.1", 0);
    ASSERT_TRUE(remote.has_value());
    ASSERT_TRUE(outEp.has_value());

    sockaddr_in clientPeer{};
    clientPeer.sin_family = AF_INET;
    clientPeer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    clientPeer.sin_port = htons(41234);

    Forwarder forwarder;
    auto s1 = forwarder.getOrCreateDatagramSession(clientPeer, remote->localAddr(), outEp->release());
    ASSERT_NE(s1, nullptr);
    EXPECT_TRUE(s1->outbound().valid());
    EXPECT_EQ(forwarder.activeDatagramSessions(), 1u);

    // 相同五元组必须复用同一 NAT 会话；额外传入的多余 fd 必须被安全关断不泄漏
    auto extraEp = Datagram::create(true);
    ASSERT_TRUE(extraEp.has_value());
    auto s2 = forwarder.getOrCreateDatagramSession(clientPeer, remote->localAddr(), extraEp->release());
    EXPECT_EQ(s2, s1);
    EXPECT_EQ(forwarder.activeDatagramSessions(), 1u);
    EXPECT_EQ(forwarder.findDatagramSession(clientPeer, remote->localAddr()), s1);

    auto sent = forwarder.forwardDatagramToRemote(*s1, "udp-nat-reuse");
    ASSERT_TRUE(sent.has_value());
    EXPECT_EQ(*sent, 13u);
    EXPECT_EQ(s1->stats().bytesUp, 13u);

    char buf[64]{};
    sockaddr_in from{};
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    auto rn = remote->recvFrom(buf, sizeof(buf), from);
    ASSERT_TRUE(rn.has_value());
    EXPECT_EQ(std::string_view(buf, *rn), "udp-nat-reuse");

    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    EXPECT_EQ(forwarder.sweepIdleDatagramSessions(std::chrono::seconds(0)), 1u);
    EXPECT_EQ(forwarder.activeDatagramSessions(), 0u);
    EXPECT_EQ(forwarder.findDatagramSession(clientPeer, remote->localAddr()), nullptr);
}

TEST(ForwarderTest, DeferredConnectPromotesAfterConnectAndDrain)
{
    int spIn[2] = {-1, -1};
    int spOut[2] = {-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, spIn), 0);
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, spOut), 0);

    handler::HandlerInboundDirect in;
    in.onConnect(spIn[1]);
    Forwarder forwarder;
    sockaddr_in targetAddr{};
    targetAddr.sin_family = AF_INET;
    targetAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    targetAddr.sin_port = htons(18080);
    auto session = forwarder.bridgeDispatched(
        in, std::make_unique<handler::HandlerOutboundDirect>(), spIn[1], spOut[0], false, true, true, targetAddr,
        Address::fromIPv4(htonl(INADDR_LOOPBACK), 18080), "direct");
    ASSERT_NE(session, nullptr);
    // 尚在延迟建连阶段，不得提前激活 KERNEL_SOCKMAP/ZERO_COPY_SPLICE
    EXPECT_EQ(session->activeMode(), ForwardMode::BUFFER_PUMP);

    session->onProactorConnectComplete(0);
    EXPECT_FALSE(session->isOutboundConnecting());
    EXPECT_FALSE(session->isOutboundConnectDeferred());
    EXPECT_EQ(session->activeMode(), ForwardMode::ZERO_COPY_SPLICE);

    session->close(true);
    ::close(spIn[0]);
    ::close(spIn[1]);
    ::close(spOut[0]);
    ::close(spOut[1]);
}

TEST(ForwarderTest, SpliceUnsupportedTargetTriggersLosslessBufferFallback)
{
    int spIn[2] = {-1, -1};
    int badOut[2] = {-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, spIn), 0);
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, badOut), 0);
    // 将出站描述符置为 O_APPEND，使 splice(pipe -> badOut[0]) 返回 EINVAL，而 ::send 仍可正常工作
    const int flags = ::fcntl(badOut[0], F_GETFL, 0);
    ASSERT_GE(flags, 0);
    ASSERT_EQ(::fcntl(badOut[0], F_SETFL, flags | O_APPEND), 0);

    handler::HandlerInboundDirect in;
    handler::HandlerOutboundDirect out;
    in.onConnect(spIn[1]);
    out.onConnect(badOut[0]);
    Forwarder forwarder;
    auto session = forwarder.bridge(in, out);
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->activeMode(), ForwardMode::ZERO_COPY_SPLICE);

    constexpr std::string_view kMsg = "payload-survives-splice-fallback";
    ASSERT_EQ(::send(spIn[0], kMsg.data(), kMsg.size(), 0), static_cast<ssize_t>(kMsg.size()));

    // pump() 从 spIn[1] splice 到 pipeUp_，再 splice 到 O_APPEND 目标端返回 EINVAL，无损排空管道并降级至 BUFFER_PUMP 送达
    (void)session->pump();
    EXPECT_EQ(session->activeMode(), ForwardMode::BUFFER_PUMP);

    char rbuf[128]{};
    const ssize_t n = ::recv(badOut[1], rbuf, sizeof(rbuf), 0);
    ASSERT_EQ(n, static_cast<ssize_t>(kMsg.size()));
    EXPECT_EQ(std::string_view(rbuf, static_cast<size_t>(n)), kMsg);

    session->close(true);
    ::close(spIn[0]);
    ::close(spIn[1]);
    ::close(badOut[0]);
    ::close(badOut[1]);
}
