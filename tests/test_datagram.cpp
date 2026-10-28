// Datagram<H>：UDP 路径的传输层会话（Connection<H> 的对等物）。
//
// 覆盖三件事：编译期槽位选择、接收窗口的定容与超界截断、回复排空。
// 收发一律走真实 UDP 套接字，避免用桩件验证桩件。
#include "connection.hpp"
#include "datagram.hpp"
#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <limits>
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
        void process() {}
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

    handler.pushReply(pair.rxAddr, "pong", 4);
    ASSERT_TRUE(handler.hasReply());

    EXPECT_EQ(session.flushTo(pair.tx), size_t{1});
    EXPECT_FALSE(handler.hasReply());
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

    handler.pushReply(loopbackPeer(9), "x", 1);
    // 无效描述符：发送必然失败，回复仍会被取出（丢弃语义与改造前一致）
    EXPECT_EQ(session.flushTo(-1), size_t{0});
    EXPECT_EQ(session.sendFailures(), uint64_t{1});
    EXPECT_FALSE(handler.hasReply());
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
        handler.pushReply(pair.rxAddr, "r", 1);
    }
    ASSERT_EQ(handler.replyCount(), size_t{5});

    EXPECT_EQ(session.flushTo(pair.tx), size_t{5});
    EXPECT_EQ(session.sentDatagrams(), uint64_t{5});
    EXPECT_FALSE(handler.hasReply());

    for (int i = 0; i < 5; ++i)
    {
        char buf[8] = {};
        EXPECT_EQ(::recv(pair.rx, buf, sizeof(buf), 0), ssize_t{1}) << "reply " << i << " missing";
    }
}
