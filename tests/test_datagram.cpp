// Datagram<H>：UDP 路径的传输层会话（Connection<H> 的对等物）。
//
// 覆盖三件事：编译期槽位选择、接收窗口的定容与超界截断、回复排空。
// 收发一律走真实 UDP 套接字，避免用桩件验证桩件。
#include "connection.hpp"
#include "datagram.hpp"
#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <limits>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

using namespace mynet;

namespace
{
    /// 记录最后一次交付的报文，便于断言内容与长度。
    struct RecordingHandler : HandlerDatagram
    {
        void onDatagram(const sockaddr_in &peer, const char *data, size_t n) noexcept override
        {
            lastPeer = peer;
            lastPayload.assign(data, n);
            ++calls;
        }

        sockaddr_in lastPeer{};
        std::string lastPayload{};
        size_t calls = 0;
    };

    /// 只具备流式能力、不满足 MandatoryMethodDatagram 的处理器。
    struct StreamOnlyHandler : HandlerConnection
    {
        void handle() {}
    };

    /// 同时具备两种传输能力（与 HandlerHttp3 同构）。
    struct DualHandler : HandlerConnection, HandlerDatagram
    {
        void reset() noexcept override
        {
            HandlerConnection::reset();
            HandlerDatagram::reset();
        }
        void onMessageComplete() noexcept override
        {
            HandlerConnection::onMessageComplete();
            HandlerDatagram::onMessageComplete();
        }
        void onParseError(const char *reason) noexcept override
        {
            HandlerConnection::onParseError(reason);
            HandlerDatagram::onParseError(reason);
        }
        void onDatagram(const sockaddr_in &, const char *, size_t) noexcept override {}
    };

    [[nodiscard]] sockaddr_in loopbackPeer(uint16_t port)
    {
        sockaddr_in peer{};
        peer.sin_family = AF_INET;
        peer.sin_port = htons(port);
        inet_pton(AF_INET, "127.0.0.1", &peer.sin_addr);
        return peer;
    }

    /// 一对已连通的本地 UDP 套接字：first 用于发送，second 已绑定且可接收。
    struct UdpPair
    {
        int tx = -1;
        int rx = -1;
        sockaddr_in rxAddr{};

        UdpPair()
        {
            rx = ::socket(AF_INET, SOCK_DGRAM, 0);
            if (rx < 0)
            {
                return;
            }
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port = 0;
            if (::bind(rx, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr)) < 0)
            {
                ::close(rx);
                rx = -1;
                return;
            }
            socklen_t len = static_cast<socklen_t>(sizeof(rxAddr));
            if (::getsockname(rx, reinterpret_cast<sockaddr *>(&rxAddr), &len) < 0)
            {
                ::close(rx);
                rx = -1;
                return;
            }
            tx = ::socket(AF_INET, SOCK_DGRAM, 0);
            // 接收超时：一旦 flushTo 回归导致对端收不到包，测试应在 2 秒内失败，
            // 而不是阻塞到 ctest 的 120 秒超时。
            if (rx >= 0)
            {
                timeval tv{};
                tv.tv_sec = 2;
                [[maybe_unused]] auto _ =
                    ::setsockopt(rx, SOL_SOCKET, SO_RCVTIMEO, &tv, static_cast<socklen_t>(sizeof(tv)));
            }
        }

        ~UdpPair()
        {
            if (tx >= 0)
            {
                ::close(tx);
            }
            if (rx >= 0)
            {
                ::close(rx);
            }
        }

        UdpPair(const UdpPair &) = delete;
        UdpPair &operator=(const UdpPair &) = delete;

        [[nodiscard]] bool ok() const noexcept { return tx >= 0 && rx >= 0; }
    };
} // namespace

TEST(DatagramSlot, SelectsSessionTypeAtCompileTime)
{
    // 纯流式处理器没有数据报会话，退化为空壳；纯报文与双传输处理器都得到真实会话。
    static_assert(std::same_as<typename DatagramSlot<StreamOnlyHandler>::Type, NoDatagram>);
    static_assert(std::same_as<typename DatagramSlot<RecordingHandler>::Type, Datagram<RecordingHandler>>);
    static_assert(std::same_as<typename DatagramSlot<DualHandler>::Type, Datagram<DualHandler>>);

    // 与流式一侧的选择器互为镜像：纯报文处理器拿不到 Connection。
    static_assert(std::same_as<typename ConnectionSlot<RecordingHandler>::Type, NoConnection>);
    static_assert(std::same_as<typename ConnectionSlot<StreamOnlyHandler>::Type, Connection<StreamOnlyHandler>>);
}

TEST(Datagram, UnboundSessionIsInertAndSafe)
{
    Datagram<RecordingHandler> session;
    EXPECT_FALSE(session.bound());
    EXPECT_EQ(session.handler(), nullptr);
    EXPECT_EQ(session.maxDatagramBytes(), size_t{0});
    EXPECT_EQ(session.recvBuffer(), nullptr);
    EXPECT_EQ(session.recvCapacity(), size_t{0});

    // 未绑定时所有传输接口都是无操作，不解引用空处理器
    sockaddr_in peer = loopbackPeer(1234);
    session.receiveFrom(peer, "x", 1);
    EXPECT_EQ(session.receivedDatagrams(), uint64_t{0});
    EXPECT_EQ(session.flushTo(-1), size_t{0});
}

TEST(Datagram, NoDatagramShellIsInert)
{
    // 流式路径会实例化到这些调用点，空壳必须全部可用且返回中性值。
    NoDatagram shell;
    shell.reset();
    EXPECT_FALSE(shell.bound());
    EXPECT_EQ(shell.maxDatagramBytes(), size_t{0});
    EXPECT_EQ(shell.recvBuffer(), nullptr);
    EXPECT_EQ(shell.recvCapacity(), size_t{0});
    sockaddr_in peer = loopbackPeer(1);
    shell.receiveFrom(peer, nullptr, 0);
    EXPECT_EQ(shell.flushTo(-1), size_t{0});
}

TEST(Datagram, BindSizesWindowFromHandlerLimit)
{
    RecordingHandler handler;
    handler.setMaxDatagramBytes(2048);

    Datagram<RecordingHandler> session;
    session.bind(handler);

    ASSERT_TRUE(session.bound());
    EXPECT_EQ(session.handler(), &handler);
    EXPECT_EQ(session.maxDatagramBytes(), size_t{2048});
    // 多留一个字节作为「超出上界」的可观测信号
    EXPECT_EQ(session.recvCapacity(), size_t{2049});
    EXPECT_NE(session.recvBuffer(), nullptr);
}

TEST(Datagram, BindHonoursPreferredCapacity)
{
    RecordingHandler handler;
    handler.setMaxDatagramBytes(64);

    Datagram<RecordingHandler> session;
    session.bind(handler, 4096);
    EXPECT_EQ(session.recvCapacity(), size_t{4096});

    // 更小的 preferredCapacity 不会把窗口压到上界以下
    session.bind(handler, 8);
    EXPECT_EQ(session.recvCapacity(), size_t{65});
}

TEST(Datagram, BindResetsStatistics)
{
    RecordingHandler handler;
    Datagram<RecordingHandler> session;
    session.bind(handler);

    sockaddr_in peer = loopbackPeer(5353);
    session.receiveFrom(peer, "abc", 3);
    ASSERT_EQ(session.receivedDatagrams(), uint64_t{1});

    session.bind(handler);
    EXPECT_EQ(session.receivedDatagrams(), uint64_t{0});
    EXPECT_EQ(session.receivedBytes(), uint64_t{0});
}

TEST(Datagram, ResetUnbindsAndClears)
{
    RecordingHandler handler;
    Datagram<RecordingHandler> session;
    session.bind(handler);
    session.receiveFrom(loopbackPeer(1), "abc", 3);

    session.reset();
    EXPECT_FALSE(session.bound());
    EXPECT_EQ(session.recvCapacity(), size_t{0});
    EXPECT_EQ(session.receivedDatagrams(), uint64_t{0});
    EXPECT_EQ(session.handler(), nullptr);
}

TEST(Datagram, ReceiveFromDispatchesToHandler)
{
    RecordingHandler handler;
    handler.setMaxDatagramBytes(1024);
    Datagram<RecordingHandler> session;
    session.bind(handler);

    sockaddr_in peer = loopbackPeer(7777);
    session.receiveFrom(peer, "hello", 5);

    EXPECT_EQ(handler.calls, size_t{1});
    EXPECT_EQ(handler.lastPayload, "hello");
    EXPECT_EQ(handler.lastPeer.sin_port, htons(7777));
    EXPECT_EQ(session.receivedDatagrams(), uint64_t{1});
    EXPECT_EQ(session.receivedBytes(), uint64_t{5});
    EXPECT_EQ(session.truncatedDatagrams(), uint64_t{0});
}

TEST(Datagram, ReceiveFromTruncatesAtHandlerLimit)
{
    RecordingHandler handler;
    handler.setMaxDatagramBytes(4);
    Datagram<RecordingHandler> session;
    session.bind(handler);

    session.receiveFrom(loopbackPeer(1), "0123456789", 10);

    EXPECT_EQ(handler.lastPayload, "0123"); // 按上界截断后交付
    EXPECT_EQ(session.truncatedDatagrams(), uint64_t{1});
    EXPECT_EQ(session.receivedBytes(), uint64_t{10}); // 统计按实际收到计数
}

TEST(Datagram, FlushToDrainsRepliesOverRealSocket)
{
    UdpPair pair;
    ASSERT_TRUE(pair.ok());

    RecordingHandler handler;
    Datagram<RecordingHandler> session;
    session.bind(handler);

    handler.sendTo(pair.rxAddr, "pong", 4);
    ASSERT_TRUE(handler.hasOutgoing());

    EXPECT_EQ(session.flushTo(pair.tx), size_t{1});
    EXPECT_FALSE(handler.hasOutgoing());
    EXPECT_EQ(session.sentDatagrams(), uint64_t{1});

    char buf[64] = {};
    ssize_t n = ::recv(pair.rx, buf, sizeof(buf), 0);
    ASSERT_GT(n, 0);
    EXPECT_EQ(std::string(buf, static_cast<size_t>(n)), "pong");
}

TEST(Datagram, FlushToSendsNothingWhenQueueIsEmpty)
{
    UdpPair pair;
    ASSERT_TRUE(pair.ok());

    RecordingHandler handler;
    Datagram<RecordingHandler> session;
    session.bind(handler);

    EXPECT_EQ(session.flushTo(pair.tx), size_t{0});
    EXPECT_EQ(session.sentDatagrams(), uint64_t{0});
}

TEST(Datagram, FlushToCountsSendFailures)
{
    RecordingHandler handler;
    Datagram<RecordingHandler> session;
    session.bind(handler);

    handler.sendTo(loopbackPeer(9), "x", 1);
    // 无效描述符：发送必然失败，报文仍会被取出
    EXPECT_EQ(session.flushTo(-1), size_t{0});
    EXPECT_EQ(session.sendFailures(), uint64_t{1});
    EXPECT_FALSE(handler.hasOutgoing());
}

TEST(Datagram, ReceiveFromAtExactLimitIsNotTruncation)
{
    // 边界：恰好等于上界的报文必须原样交付，不能算截断。
    RecordingHandler handler;
    handler.setMaxDatagramBytes(4);
    Datagram<RecordingHandler> session;
    session.bind(handler);

    session.receiveFrom(loopbackPeer(1), "0123", 4);

    EXPECT_EQ(handler.lastPayload, "0123");
    EXPECT_EQ(session.truncatedDatagrams(), uint64_t{0});
    EXPECT_EQ(session.receivedBytes(), uint64_t{4});

    // 上界 +1 才算截断
    session.receiveFrom(loopbackPeer(1), "01234", 5);
    EXPECT_EQ(handler.lastPayload, "0123");
    EXPECT_EQ(session.truncatedDatagrams(), uint64_t{1});
}

TEST(Datagram, ZeroLimitTruncatesEveryNonEmptyDatagram)
{
    RecordingHandler handler;
    handler.setMaxDatagramBytes(0);
    Datagram<RecordingHandler> session;
    session.bind(handler);

    // 上界为 0 时窗口仍至少 1 字节，非空报文一律截断为 0 长度
    EXPECT_GE(session.recvCapacity(), size_t{1});
    session.receiveFrom(loopbackPeer(1), "x", 1);
    EXPECT_EQ(handler.lastPayload, "");
    EXPECT_EQ(session.truncatedDatagrams(), uint64_t{1});
}

TEST(Datagram, WindowCapacityForHandlesBoundaries)
{
    using Session = Datagram<RecordingHandler>;

    // 常规：上界 + 1
    EXPECT_EQ(Session::windowCapacityFor(1000), size_t{1001});
    EXPECT_EQ(Session::windowCapacityFor(0), size_t{1});

    // preferredCapacity 只能抬高窗口，不能压低
    EXPECT_EQ(Session::windowCapacityFor(64, 4096), size_t{4096});
    EXPECT_EQ(Session::windowCapacityFor(64, 8), size_t{65});

    // 上界为 SIZE_MAX 时饱和而非回绕：回绕成 0 会让窗口塌缩到 1 字节，
    // 于是每条报文都被判成截断。这里只验证计算，不实际分配。
    EXPECT_EQ(Session::windowCapacityFor(std::numeric_limits<size_t>::max()), std::numeric_limits<size_t>::max());
}

TEST(Datagram, FlushToAccumulatesCountsAcrossReplies)
{
    UdpPair pair;
    ASSERT_TRUE(pair.ok());

    RecordingHandler handler;
    Datagram<RecordingHandler> session;
    session.bind(handler);

    for (int i = 0; i < 5; ++i)
    {
        handler.sendTo(pair.rxAddr, "r", 1);
    }
    ASSERT_EQ(handler.outgoingCount(), size_t{5});

    EXPECT_EQ(session.flushTo(pair.tx), size_t{5});
    EXPECT_EQ(session.sentDatagrams(), uint64_t{5});
    EXPECT_FALSE(handler.hasOutgoing());

    for (int i = 0; i < 5; ++i)
    {
        char buf[8] = {};
        EXPECT_EQ(::recv(pair.rx, buf, sizeof(buf), 0), ssize_t{1}) << "packet " << i << " missing";
    }
}

TEST(Datagram, UdpEchoHandlerEchoWorksInSession)
{
    // 回显作为协议级业务处理：由派生回显处理器在 onDatagram 中调用 sendTo
    struct TestDatagramEchoHandler : HandlerDatagram
    {
        void onDatagram(const sockaddr_in &peer, const char *data, size_t n) noexcept override
        {
            sendTo(peer, data, n);
        }
    };

    TestDatagramEchoHandler echoHandler;
    Datagram<TestDatagramEchoHandler> session;
    session.bind(echoHandler);

    sockaddr_in peer = loopbackPeer(23456);
    const char data[] = "ping-udp-echo";
    session.receiveFrom(peer, data, sizeof(data) - 1);

    EXPECT_EQ(session.receivedDatagrams(), 1u);
    EXPECT_EQ(session.receivedBytes(), sizeof(data) - 1);
    ASSERT_TRUE(echoHandler.hasOutgoing());
    EXPECT_EQ(echoHandler.outgoingCount(), 1u);

    auto pkt = echoHandler.takeOutgoing();
    EXPECT_EQ(pkt.bytes, "ping-udp-echo");
    EXPECT_EQ(pkt.peer.sin_port, peer.sin_port);
}

TEST(Datagram, BaseHandlerDatagramDoesNotEchoByDefault)
{
    // 基类 HandlerDatagram 属于纯协议底座，默认不写死 Echo 回显行为
    HandlerDatagram baseHandler;
    Datagram<HandlerDatagram> session;
    session.bind(baseHandler);

    sockaddr_in peer = loopbackPeer(23456);
    const char data[] = "no-auto-echo";
    session.receiveFrom(peer, data, sizeof(data) - 1);

    EXPECT_EQ(session.receivedDatagrams(), 1u);
    EXPECT_EQ(session.receivedBytes(), sizeof(data) - 1);
    EXPECT_FALSE(baseHandler.hasOutgoing());
    EXPECT_EQ(baseHandler.outgoingCount(), 0u);
}

TEST(Datagram, DecoupledSendForwardBroadcastApis)
{
    HandlerDatagram handler;
    sockaddr_in peer1 = loopbackPeer(10001);
    sockaddr_in peer2 = loopbackPeer(10002);
    sockaddr_in peer3 = loopbackPeer(10003);

    // 1. sendTo 字节与 string
    handler.sendTo(peer1, "pkt1", 4);
    handler.sendTo(peer2, std::string("pkt2"));
    EXPECT_TRUE(handler.hasOutgoing());
    EXPECT_EQ(handler.outgoingCount(), 2u);

    // 2. forwardTo 转发代理
    handler.forwardTo(peer3, "forward_data", 12);
    EXPECT_EQ(handler.outgoingCount(), 3u);

    // 3. broadcastTo 广播/多播
    std::vector<sockaddr_in> targets = {peer1, peer2};
    handler.broadcastTo(targets, "multicast", 9);
    EXPECT_EQ(handler.outgoingCount(), 5u);

    // 校验队列出队与 Protocol<HandlerDatagram>
    Protocol<HandlerDatagram> p1 = handler.takeOutgoing();
    EXPECT_EQ(p1.bytes, "pkt1");
    EXPECT_EQ(p1.peer.sin_port, peer1.sin_port);

    Protocol<HandlerDatagram> p2 = handler.takeOutgoing();
    EXPECT_EQ(p2.bytes, "pkt2");
    EXPECT_EQ(p2.peer.sin_port, peer2.sin_port);

    Protocol<HandlerDatagram> p3 = handler.takeOutgoing();
    EXPECT_EQ(p3.bytes, "forward_data");
    EXPECT_EQ(p3.peer.sin_port, peer3.sin_port);

    Protocol<HandlerDatagram> p4 = handler.takeOutgoing();
    EXPECT_EQ(p4.bytes, "multicast");
    EXPECT_EQ(p4.peer.sin_port, peer1.sin_port);

    Protocol<HandlerDatagram> p5 = handler.takeOutgoing();
    EXPECT_EQ(p5.bytes, "multicast");
    EXPECT_EQ(p5.peer.sin_port, peer2.sin_port);

    EXPECT_FALSE(handler.hasOutgoing());
}

TEST(Datagram, SendDirectAndHasPending)
{
    UdpPair pair;
    ASSERT_TRUE(pair.ok());

    RecordingHandler handler;
    Datagram<RecordingHandler> session;
    session.bind(handler);

    EXPECT_FALSE(session.hasPending());

    // 使用 sendDirect 直发报文
    const char msg[] = "direct-udp-packet";
    ssize_t ret = session.sendDirect(pair.tx, pair.rxAddr, msg, sizeof(msg) - 1);
    EXPECT_EQ(ret, static_cast<ssize_t>(sizeof(msg) - 1));
    EXPECT_EQ(session.sentDatagrams(), 1u);

    char recvBuf[64] = {};
    ssize_t rn = ::recv(pair.rx, recvBuf, sizeof(recvBuf), 0);
    ASSERT_EQ(rn, static_cast<ssize_t>(sizeof(msg) - 1));
    EXPECT_EQ(std::string(recvBuf, static_cast<size_t>(rn)), msg);

    // 加入队列后 hasPending 为 true
    handler.sendTo(pair.rxAddr, "queued", 6);
    EXPECT_TRUE(session.hasPending());
    EXPECT_EQ(session.flushTo(pair.tx), 1u);
    EXPECT_FALSE(session.hasPending());
}

TEST(Datagram, HandleReadAndWriteApis)
{
    UdpPair pair;
    ASSERT_TRUE(pair.ok());

    // 设置接收端为非阻塞，使 handleRead 内的 recvfrom 循环在读空时正常退出
    int flags = ::fcntl(pair.rx, F_GETFL, 0);
    ASSERT_GE(flags, 0);
    ASSERT_EQ(::fcntl(pair.rx, F_SETFL, flags | O_NONBLOCK), 0);

    RecordingHandler handler;
    Datagram<RecordingHandler> session;
    session.bind(handler);

    // 1. 发送测试报文到 rx
    const char msg[] = "handle-read-datagram-test";
    ssize_t sent = ::sendto(pair.tx, msg, sizeof(msg) - 1, 0, reinterpret_cast<const sockaddr *>(&pair.rxAddr),
                            sizeof(pair.rxAddr));
    ASSERT_EQ(sent, static_cast<ssize_t>(sizeof(msg) - 1));

    // 2. 调用 handleRead 驱动事件循环读取（传入套接字 fd）
    EXPECT_EQ(session.handleRead(pair.rx), IO_STATUS::KEEP);
    EXPECT_EQ(handler.calls, 1u);
    EXPECT_EQ(handler.lastPayload, msg);

    // 3. 测试 handleWrite 排空
    handler.sendTo(pair.rxAddr, "response-datagram", 17);
    EXPECT_TRUE(session.hasPending());
    EXPECT_EQ(session.handleWrite(pair.tx), IO_STATUS::KEEP);
    EXPECT_FALSE(session.hasPending());

    // 4. 重置会话与处理器
    session.reset();
    EXPECT_FALSE(session.hasPending());
    handler.reset();
    EXPECT_FALSE(handler.hasOutgoing());
}

TEST(Datagram, BatchIoRecvmmsgAndSendmmsg)
{
    UdpPair pair;
    ASSERT_TRUE(pair.ok());

    int flags = ::fcntl(pair.rx, F_GETFL, 0);
    ASSERT_GE(flags, 0);
    ASSERT_EQ(::fcntl(pair.rx, F_SETFL, flags | O_NONBLOCK), 0);

    RecordingHandler handler;
    Datagram<RecordingHandler> session;
    session.bind(handler);
    EXPECT_TRUE(session.isBatchIoEnabled());

    // 1. 发送 16 个 UDP 报文到 rx 端测试 recvmmsg 批处理
    constexpr size_t kBatchCount = 16;
    for (size_t i = 0; i < kBatchCount; ++i)
    {
        std::string payload = "batch-packet-" + std::to_string(i);
        ssize_t s = ::sendto(pair.tx, payload.data(), payload.size(), 0,
                             reinterpret_cast<const sockaddr *>(&pair.rxAddr),
                             sizeof(pair.rxAddr));
        ASSERT_EQ(s, static_cast<ssize_t>(payload.size()));
    }

    // 单次/循环调用 handleRead 批处理读入
    EXPECT_EQ(session.handleRead(pair.rx), IO_STATUS::KEEP);
    EXPECT_EQ(handler.calls, kBatchCount);
    EXPECT_EQ(handler.lastPayload, "batch-packet-15");

    // 2. 向 handler 灌入 16 条外发数据报测试 sendmmsg 批处理
    for (size_t i = 0; i < kBatchCount; ++i)
    {
        std::string reply = "batch-reply-" + std::to_string(i);
        handler.sendTo(pair.rxAddr, std::move(reply));
    }
    EXPECT_EQ(handler.outgoingCount(), kBatchCount);

    size_t flushed = session.flushTo(pair.tx);
    EXPECT_EQ(flushed, kBatchCount);
    EXPECT_EQ(session.sentDatagrams(), kBatchCount);
    EXPECT_FALSE(session.hasPending());

    // 验证接收端确实完整收到了 16 条报文
    for (size_t i = 0; i < kBatchCount; ++i)
    {
        char buf[64] = {};
        ssize_t rn = ::recv(pair.rx, buf, sizeof(buf), 0);
        ASSERT_GT(rn, 0);
        EXPECT_EQ(std::string(buf, static_cast<size_t>(rn)), "batch-reply-" + std::to_string(i));
    }
}

TEST(Datagram, UdpGsoAndGroHelper)
{
    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(fd, 0);

    // GSO Segment 配置
    bool gsoSupported = UdpGsoHelper::setGsoSegment(fd, 1400);
    if (gsoSupported)
    {
        EXPECT_EQ(UdpGsoHelper::getGsoSegment(fd), 1400);
    }

    // GRO 配置
    [[maybe_unused]] bool groSupported = UdpGsoHelper::setGro(fd, true);

    // 非法参数防御
    EXPECT_FALSE(UdpGsoHelper::setGsoSegment(-1, 1400));
    EXPECT_FALSE(UdpGsoHelper::setGsoSegment(fd, -1));
    EXPECT_EQ(UdpGsoHelper::getGsoSegment(-1), -1);
    EXPECT_FALSE(UdpGsoHelper::setGro(-1, true));

    ::close(fd);
}

TEST(Datagram, UdpWriteBatchAggregator)
{
    UdpPair pair;
    UdpWriteBatchAggregator aggregator(8);
    EXPECT_EQ(aggregator.capacity(), 8u);
    EXPECT_TRUE(aggregator.empty());
    EXPECT_EQ(aggregator.size(), 0u);
    EXPECT_EQ(aggregator.pendingBytes(), 0u);

    // 追加 8 条数据报
    for (int i = 0; i < 8; ++i)
    {
        std::string pkt = "agg-pkt-" + std::to_string(i);
        EXPECT_TRUE(aggregator.append(pair.rxAddr, pkt));
    }
    EXPECT_EQ(aggregator.size(), 8u);
    EXPECT_FALSE(aggregator.empty());
    EXPECT_GT(aggregator.pendingBytes(), 0u);

    // 达到上限时再追加应返回 false
    EXPECT_FALSE(aggregator.append(pair.rxAddr, "overflow"));

    // flush 冲刷发送
    size_t sent = aggregator.flush(pair.tx);
    EXPECT_EQ(sent, 8u);
    EXPECT_TRUE(aggregator.empty());
    EXPECT_EQ(aggregator.pendingBytes(), 0u);

    // 验证接收端收齐
    for (int i = 0; i < 8; ++i)
    {
        char buf[64] = {};
        ssize_t rn = ::recv(pair.rx, buf, sizeof(buf), 0);
        ASSERT_GT(rn, 0);
        EXPECT_EQ(std::string(buf, static_cast<size_t>(rn)), "agg-pkt-" + std::to_string(i));
    }
}

// =============================================================================
// 25. UDP 端点状态锁固与平滑迁移测试 (借鉴 dae udp_endpoint pin #1137)
// =============================================================================

TEST(Datagram, UdpEndpointRebuildPin)
{
    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    peer.sin_addr.s_addr = htonl(0x0a000001);
    peer.sin_port = htons(8080);
    uint64_t flowKey = 0x1234567890ABCDEF;

    int dummyFd = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    ASSERT_GE(dummyFd, 0);

    {
        UdpEndpointRebuildPin pin(peer, flowKey, dummyFd);
        EXPECT_TRUE(pin.isPinned());
        EXPECT_EQ(pin.flowKey(), flowKey);
        EXPECT_EQ(pin.socketFd(), dummyFd);

        // 模拟端点平滑转交给新会话
        sockaddr_in newPeer{};
        uint64_t newFlowKey = 0;
        int newFd = -1;
        pin.transferTo(newPeer, newFlowKey, newFd);

        EXPECT_FALSE(pin.isPinned());
        EXPECT_EQ(newFlowKey, flowKey);
        EXPECT_EQ(newFd, dummyFd);
        EXPECT_EQ(newPeer.sin_port, htons(8080));

        // 最终由接收方关闭
        ::close(newFd);
    }
}

// =============================================================================
// 26. 透明 UDP 套接字复用池与 200ms 空闲节流测试 (借鉴 dae AnyfromSocketPool)
// =============================================================================

TEST(Datagram, AnyfromSocketPool)
{
    AnyfromSocketPool pool(std::chrono::milliseconds(50));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0; // 自动分配端口

    // 获取并绑定
    int fd1 = pool.acquire(addr, false);
    ASSERT_GE(fd1, 0);

    // 查询实际绑定的端口
    socklen_t len = sizeof(addr);
    ASSERT_EQ(::getsockname(fd1, reinterpret_cast<sockaddr *>(&addr), &len), 0);
    EXPECT_GT(ntohs(addr.sin_port), 0);

    // 以相同地址再次请求，应当从复用池命中同一个 fd
    int fd2 = pool.acquire(addr, false);
    EXPECT_EQ(fd1, fd2);
    EXPECT_EQ(pool.size(), 1u);

    // 空闲超时后执行清理
    auto futureTime = std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
    size_t swept = pool.sweepIdle(futureTime);
    EXPECT_EQ(swept, 1u);
    EXPECT_EQ(pool.size(), 0u);
}

// =============================================================================
// 27. 原始套接字 UDP 直连校验和计算测试 (借鉴 dae RawUdpDirectSender)
// =============================================================================

TEST(Datagram, RawUdpDirectSenderChecksum)
{
    uint32_t saddr = htonl(0x0a000001); // 10.0.0.1
    uint32_t daddr = htonl(0x08080808); // 8.8.8.8
    uint16_t sport = 12345;
    uint16_t dport = 53;

    std::vector<uint8_t> payload = {'h', 'e', 'l', 'l', 'o'};
    uint16_t csum = RawUdpDirectSender::computeUdpChecksum(saddr, daddr, sport, dport, payload);

    EXPECT_NE(csum, 0); // 检验和不能为 0

    // 单独验证通用校验和计算工具
    const char testStr[] = "test-packet";
    uint16_t genCsum = RawUdpDirectSender::computeChecksum(testStr, sizeof(testStr) - 1);
    EXPECT_NE(genCsum, 0);
}

// =============================================================================
// 28. 五元组串行保序 UDP 任务池与防溢出测试 (借鉴 dae UdpTaskPool)
// =============================================================================

TEST(Datagram, UdpTaskPoolSerializationAndThrottle)
{
    UdpTaskPool taskPool;
    uint64_t flowKey = 0xCAFEBABE;

    // 顺序入队 10 个数据包
    for (int i = 0; i < 10; ++i)
    {
        std::string s = "flow-pkt-" + std::to_string(i);
        EXPECT_TRUE(taskPool.enqueue(flowKey, std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(s.data()), s.size())));
    }
    EXPECT_EQ(taskPool.queueDepth(flowKey), 10u);
    EXPECT_EQ(taskPool.flowCount(), 1u);

    // 验证出队严格保序
    for (int i = 0; i < 10; ++i)
    {
        auto pkt = taskPool.dequeue(flowKey);
        ASSERT_TRUE(pkt.has_value());
        std::string s(reinterpret_cast<const char *>(pkt->data()), pkt->size());
        EXPECT_EQ(s, "flow-pkt-" + std::to_string(i));
    }
    EXPECT_EQ(taskPool.queueDepth(flowKey), 0u);
    EXPECT_EQ(taskPool.flowCount(), 0u);

    // 溢出防护测试：填满 128 个报文后触发尾丢弃
    for (size_t i = 0; i < UdpTaskPool::kMaxQueuePerFlow; ++i)
    {
        uint8_t b = static_cast<uint8_t>(i);
        EXPECT_TRUE(taskPool.enqueue(flowKey, std::span<const uint8_t>(&b, 1)));
    }
    EXPECT_EQ(taskPool.queueDepth(flowKey), UdpTaskPool::kMaxQueuePerFlow);

    // 第 129 个报文入队应当被丢弃
    uint8_t overflowByte = 0xFF;
    EXPECT_FALSE(taskPool.enqueue(flowKey, std::span<const uint8_t>(&overflowByte, 1)));
    EXPECT_EQ(taskPool.totalDrops(), 1u);
}

// =============================================================================
// 29. FullCone NAT 4 槽位环形热点对端缓存测试 (借鉴 dae FullConeRespCache)
// =============================================================================

TEST(Datagram, FullConeRespCache)
{
    FullConeRespCache cache;

    // 初始查询均未命中 (-1)
    EXPECT_EQ(cache.lookup(0x01020304, 80), -1);

    // 填充 4 个热点槽位
    cache.update(0x01020304, 80, 10);
    cache.update(0x01020305, 81, 11);
    cache.update(0x01020306, 82, 12);
    cache.update(0x01020307, 83, 13);

    EXPECT_EQ(cache.lookup(0x01020304, 80), 10);
    EXPECT_EQ(cache.lookup(0x01020305, 81), 11);
    EXPECT_EQ(cache.lookup(0x01020306, 82), 12);
    EXPECT_EQ(cache.lookup(0x01020307, 83), 13);

    // 更新已有对端 fd
    cache.update(0x01020304, 80, 99);
    EXPECT_EQ(cache.lookup(0x01020304, 80), 99);

    // 写入第 5 个新对端，触发环形覆盖
    cache.update(0x01020308, 84, 14);
    EXPECT_EQ(cache.lookup(0x01020308, 84), 14);

    // 失效注销
    cache.invalidate(14);
    EXPECT_EQ(cache.lookup(0x01020308, 84), -1);
}
