// HandlerConnection 与 HandlerHttp：协议前端对驱动它的连接所承担的契约——
// 读取数据的请求缓冲区、消费输出的响应队列，以及介于两者之间的背压信用额度。
#include "connection.hpp"
#include "datagram.hpp"
#include "http/v1/handler.hpp"
#include <fcntl.h>
#include <gtest/gtest.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

using namespace mynet;

namespace
{
    void feed(HandlerConnection &handler, const std::string &bytes)
    {
        [[maybe_unused]] auto _ = handler.appendRequest(bytes.data(), static_cast<ssize_t>(bytes.size()));
    }

    /**
     * @brief 测试夹具：开启 splice 内核零拷贝的流式回显处理器
     *
     * splice 路由由具体处理器类型选择：Connection::isSpliceEnabled() 要求
     * HandlerType::kEnableSplice 为真且运行期 spliceEnabled() 为真。
     * 回显逻辑本身来自 HandlerConnection::process()，无需重写。
     */
    class SpliceEchoHandler : public HandlerConnection
    {
    public:
        static constexpr bool kEnableSplice = true;

        void onConnect(int fd) noexcept override { setSpliceTarget(fd); }

        void reset() noexcept override { HandlerConnection::reset(); }
    };

    /**
     * @brief 测试夹具：同时组合流式与报文两种基类的回显处理器
     *
     * 两个处理器基类并列独立（无共同祖先、无虚继承），各自提供 reset /
     * onMessageComplete / onParseError。多重继承时这三个同名钩子必须由派生类
     * 显式覆盖，否则调用点二义、HandlerConstraint 不成立——本夹具即正确范式：
     * 覆盖并逐层转发，再叠加自己的数据报回显。
     * 纯报文处理器无需如此（引擎已支持只派生 HandlerDatagram）。
     */
    class CombinedEchoHandler : public HandlerConnection, public HandlerDatagram
    {
    public:
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

        void onDatagram(const sockaddr_in &peer, const char *data, size_t n) noexcept override
        {
            sendTo(peer, data, n);
        }
    };

    // 双基类夹具必须真正满足生命周期契约（钩子无二义），否则它既进不了事件槽位，
    // 也会被后来者当成可复制的错误范式。
    static_assert(HandlerConstraint<CombinedEchoHandler>);
    static_assert(MandatoryMethodConnection<CombinedEchoHandler>);
    static_assert(MandatoryMethodDatagram<CombinedEchoHandler>);
} // namespace

TEST(HandlerConnection, EchoEchoesWhateverWasAppended)
{
    HandlerConnection handler;
    feed(handler, "hello");
    EXPECT_FALSE(handler.hasResponse());
    handler.echo();
    ASSERT_TRUE(handler.hasResponse());
    EXPECT_EQ(handler.takeResponse(), "hello");
    EXPECT_EQ(handler.requestBytes(), size_t{0}); // 回显操作已完整消费请求
}

TEST(HandlerConnection, EchoOnAnEmptyBufferProducesNothing)
{
    HandlerConnection handler;
    handler.echo();
    EXPECT_FALSE(handler.hasResponse());
}

TEST(HandlerConnection, ResponseQueueIsFifo)
{
    HandlerConnection handler;
    [[maybe_unused]] auto _1 = handler.pushResponse("first");
    [[maybe_unused]] auto _2 = handler.pushResponse(std::string("second"));
    EXPECT_EQ(handler.responseCount(), size_t{2});
    EXPECT_EQ(handler.takeResponse(), "first");
    EXPECT_EQ(handler.takeResponse(), "second");
    EXPECT_TRUE(handler.takeResponse().empty()); // 消费空队列不属于错误
    EXPECT_FALSE(handler.hasResponse());
}

TEST(HandlerConnection, PushResponseFromABufferCopiesTheBytes)
{
    HandlerConnection handler;
    const std::string bytes = "abcdef";
    [[maybe_unused]] auto _ = handler.pushResponse(std::string_view(bytes.data(), 3));
    EXPECT_EQ(handler.takeResponse(), "abc");
}

TEST(HandlerConnection, RequestLimitDrivesReadCredit)
{
    HandlerConnection handler;
    handler.setMaxRequestBytes(8);
    EXPECT_EQ(handler.readCredit(), size_t{8});
    feed(handler, "abc");
    EXPECT_FALSE(handler.requestOverLimit());
    EXPECT_EQ(handler.readCredit(), size_t{5});
    feed(handler, "defghi");
    EXPECT_EQ(handler.requestBytes(), size_t{9});
    EXPECT_TRUE(handler.requestOverLimit());
    EXPECT_EQ(handler.readCredit(), size_t{0}); // 超出上限时不发放信用，永不下溢
}

TEST(HandlerConnection, DirectWritableZeroCopyIngress)
{
    HandlerConnection handler;
    auto prepRes = handler.prepareRequestWritable(128);
    ASSERT_TRUE(prepRes.has_value());
    char *target = *prepRes;
    ASSERT_NE(target, nullptr);
    EXPECT_GE(handler.requestWritableBytes(), 128u);

    std::memcpy(target, "direct-zero-copy", 16);
    handler.commitRequest(16);

    EXPECT_EQ(handler.requestBytes(), 16u);
    handler.echo();
    ASSERT_TRUE(handler.hasResponse());
    EXPECT_EQ(handler.takeResponse(), "direct-zero-copy");
    EXPECT_EQ(handler.requestBytes(), 0u);
}

TEST(HandlerConnection, RequestConsumeAndClearMoveTheCursor)
{
    HandlerConnection handler;
    feed(handler, "abcdef");
    handler.requestConsume(2);
    EXPECT_EQ(handler.requestBytes(), size_t{4});
    EXPECT_EQ(std::string(handler.requestBegin(), handler.requestBytes()), "cdef");
    handler.requestClear();
    EXPECT_EQ(handler.requestBytes(), size_t{0});
}

TEST(HandlerConnection, CloseAfterResponseDefaultsOffAndIsSettable)
{
    HandlerConnection handler;
    EXPECT_FALSE(handler.closeAfterResponse());
    handler.setCloseAfterResponse(true);
    EXPECT_TRUE(handler.closeAfterResponse());
}

TEST(HandlerConnection, ResetClearsRequestsResponsesAndTheCloseFlag)
{
    HandlerConnection handler;
    feed(handler, "request");
    [[maybe_unused]] auto _ = handler.pushResponse("response");
    handler.setCloseAfterResponse(true);
    handler.reset();
    EXPECT_EQ(handler.requestBytes(), size_t{0});
    EXPECT_FALSE(handler.hasResponse());
    EXPECT_FALSE(handler.closeAfterResponse());
}

// ---- HandlerHttp 单元测试 ----

TEST(HandlerHttp, ParsesRequestLineHeadersAndBody)
{
    HandlerHttp<HTTP_MODE::REQUEST> handler;
    feed(handler, "POST /submit?x=1 HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello");
    handler.process();

    EXPECT_EQ(handler.url(), "/submit?x=1");
    EXPECT_EQ(handler.body(), "hello");
    EXPECT_EQ(handler.headerValue("Host"), "example.com");
    EXPECT_EQ(handler.headerValue("host"), "example.com"); // 首部查找忽略大小写
    EXPECT_EQ(handler.headerValue("Missing"), "");
    EXPECT_EQ(std::string(handler.methodName()), "POST");
    EXPECT_EQ(handler.httpMajor(), 1);
    EXPECT_EQ(handler.httpMinor(), 1);
    EXPECT_TRUE(handler.keepAlive());
    EXPECT_FALSE(handler.closeAfterResponse());
}

TEST(HandlerHttp, AnswersWithAMinimalKeepAliveEcho)
{
    HandlerHttp<HTTP_MODE::REQUEST> handler;
    feed(handler, "POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\nhi");
    handler.process();
    ASSERT_TRUE(handler.hasResponse());
    const std::string response = handler.takeResponse();
    EXPECT_EQ(response.rfind("HTTP/1.1 200 OK\r\n", 0), size_t{0});
    EXPECT_NE(response.find("Content-Length: 2\r\n"), std::string::npos);
    EXPECT_NE(response.find("Connection: keep-alive\r\n"), std::string::npos);
    EXPECT_EQ(response.substr(response.size() - 2), "hi");
}

TEST(HandlerHttp, Http10WithoutConnectionKeepAliveIsNotKeepAlive)
{
    HandlerHttp<HTTP_MODE::REQUEST> handler;
    feed(handler, "GET / HTTP/1.0\r\n\r\n");
    handler.process();
    EXPECT_FALSE(handler.keepAlive());
    // 回写字节级断言：HTTP/1.0 无 Connection 头时响应必须带 Connection: close，
    // 防止 onMessageComplete 动态回写逻辑回归为恒 keep-alive
    ASSERT_TRUE(handler.hasResponse());
    const std::string response = handler.takeResponse();
    EXPECT_NE(response.find("Connection: close\r\n"), std::string::npos);
    EXPECT_EQ(response.find("Connection: keep-alive"), std::string::npos);
    EXPECT_TRUE(handler.closeAfterResponse());
}

TEST(HandlerHttp, Http11WithConnectionCloseSetsCloseAfterResponse)
{
    HandlerHttp<HTTP_MODE::REQUEST> handler;
    feed(handler, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n");
    handler.process();
    EXPECT_FALSE(handler.keepAlive());
    EXPECT_TRUE(handler.closeAfterResponse());
    ASSERT_TRUE(handler.hasResponse());
    const std::string response = handler.takeResponse();
    EXPECT_NE(response.find("Connection: close\r\n"), std::string::npos);
}

TEST(HandlerHttp, ARequestSplitAcrossTwoAppendsStillParses)
{
    HandlerHttp<HTTP_MODE::REQUEST> handler;
    feed(handler, "GET /split HTTP/1.1\r\nHost: ex");
    handler.process();
    // llhttp 支持增量解析，因此在首次追加结束时请求行已被解析完成：
    // 当首部段仍处于打开状态时 URL 已可读，且首部值尚非最终完整值。
    // 本测试验证第二次追加会无缝续接同一条消息，而非被当作全新消息处理。
    EXPECT_EQ(handler.url(), "/split");
    EXPECT_NE(handler.headerValue("Host"), "example.com");
    feed(handler, "ample.com\r\n\r\n");
    handler.process();
    EXPECT_EQ(handler.url(), "/split");
    EXPECT_EQ(handler.headerValue("Host"), "example.com");
}

TEST(HandlerHttp, ParseErrorAnswers400AndCloses)
{
    HandlerHttp<HTTP_MODE::REQUEST> handler;
    feed(handler, "\x01\x02 not a request \x03\r\n\r\n");
    handler.process();
    ASSERT_TRUE(handler.hasResponse());
    const std::string response = handler.takeResponse();
    EXPECT_NE(response.find("400 Bad Request"), std::string::npos);
    EXPECT_TRUE(handler.closeAfterResponse());
}

TEST(HandlerHttp, NullHeaderNameDoesNotCrash)
{
    HandlerHttp<HTTP_MODE::REQUEST> handler;
    EXPECT_TRUE(handler.headerValue(nullptr).empty());
}

TEST(HandlerConnection, NullPushResponseDoesNotCrash)
{
    HandlerConnection handler;
    [[maybe_unused]] auto _1 = handler.pushResponse(std::string_view{});
    [[maybe_unused]] auto _2 = handler.pushResponse(std::string_view(nullptr, 0));
    EXPECT_FALSE(handler.hasResponse());
}

TEST(HandlerHttp, EmptyHeaderValueIsPreserved)
{
    HandlerHttp<HTTP_MODE::REQUEST> handler;
    feed(handler, "GET / HTTP/1.1\r\nHost: localhost\r\nX-Empty:\r\n\r\n");
    handler.process();
    EXPECT_EQ(handler.headerValue("Host"), "localhost");
    EXPECT_EQ(handler.headerValue("X-Empty"), "");
    // 验证 X-Empty 确实存在于首部列表中
    bool found = false;
    for (const auto &h : handler.headers())
    {
        if (h.first == "X-Empty")
        {
            found = true;
            EXPECT_EQ(h.second, "");
        }
    }
    EXPECT_TRUE(found);
}

TEST(HandlerHttp, EmptyHeaderFollowedByAnotherHeaderDoesNotMerge)
{
    HandlerHttp<HTTP_MODE::REQUEST> handler;
    feed(handler, "GET / HTTP/1.1\r\nHost: localhost\r\nX-Empty:\r\nX-Next: foo\r\n\r\n");
    handler.process();
    EXPECT_EQ(handler.headerValue("Host"), "localhost");
    EXPECT_EQ(handler.headerValue("X-Empty"), "");
    EXPECT_EQ(handler.headerValue("X-Next"), "foo");
    EXPECT_EQ(handler.headerValue("X-EmptyX-Next"), "");
    ASSERT_EQ(handler.headers().size(), 3u);
    EXPECT_EQ(handler.headers()[0].first, "Host");
    EXPECT_EQ(handler.headers()[1].first, "X-Empty");
    EXPECT_EQ(handler.headers()[1].second, "");
    EXPECT_EQ(handler.headers()[2].first, "X-Next");
    EXPECT_EQ(handler.headers()[2].second, "foo");
}

TEST(HandlerHttp, UrlTooLongReturns400)
{
    HandlerHttp<HTTP_MODE::REQUEST> handler;
    std::string longUrl = "GET /" + std::string(9000, 'a') + " HTTP/1.1\r\nHost: localhost\r\n\r\n";
    feed(handler, longUrl);
    handler.process();
    ASSERT_TRUE(handler.hasResponse());
    EXPECT_NE(handler.takeResponse().find("400 Bad Request"), std::string::npos);
    EXPECT_TRUE(handler.closeAfterResponse());
}

TEST(HandlerHttp, TooManyHeadersReturns400)
{
    HandlerHttp<HTTP_MODE::REQUEST> handler;
    std::string req = "GET / HTTP/1.1\r\nHost: localhost\r\n";
    for (int i = 0; i < 110; ++i)
    {
        req += "X-H-" + std::to_string(i) + ": val\r\n";
    }
    req += "\r\n";
    feed(handler, req);
    handler.process();
    ASSERT_TRUE(handler.hasResponse());
    EXPECT_NE(handler.takeResponse().find("400 Bad Request"), std::string::npos);
    EXPECT_TRUE(handler.closeAfterResponse());
}

TEST(HandlerHttp, TotalHeadersTooLongReturns400)
{
    HandlerHttp<HTTP_MODE::REQUEST> handler;
    std::string req = "GET / HTTP/1.1\r\nHost: localhost\r\n";
    for (int i = 0; i < 10; ++i)
    {
        req += "X-Large-" + std::to_string(i) + ": " + std::string(8000, 'v') + "\r\n";
    }
    req += "\r\n";
    feed(handler, req);
    handler.process();
    ASSERT_TRUE(handler.hasResponse());
    EXPECT_NE(handler.takeResponse().find("400 Bad Request"), std::string::npos);
    EXPECT_TRUE(handler.closeAfterResponse());
}

TEST(HandlerDatagram, StandsAloneWithoutTheStreamFacilities)
{
    // 偏报文特化可独立实例化：无请求缓冲与响应队列，
    // 拥有对端标签化的外发队列。引擎的 UDP 入口正是以这种纯报文形态使用它。
    HandlerDatagram handler;
    static_assert(DerivedFromHandlerDatagram<HandlerDatagram>);
    static_assert(HandlerConstraint<HandlerDatagram>);
    static_assert(!MandatoryMethodConnection<HandlerDatagram>); // 纯报文：未派生 HandlerConnection

    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    peer.sin_port = htons(5353);
    inet_pton(AF_INET, "192.0.2.7", &peer.sin_addr);

    // 基类 onDatagram 默认空操作，不自动回显（回显属于协议级业务处理）
    handler.onDatagram(peer, "dgram", 5);
    EXPECT_FALSE(handler.hasOutgoing());
    EXPECT_EQ(handler.outgoingCount(), size_t{0});

    // 显式直接调用 sendTo 接口（协议级外发能力）
    handler.sendTo(peer, "direct_echo", 11);
    ASSERT_EQ(handler.outgoingCount(), size_t{1});
    EXPECT_EQ(handler.takeOutgoing().bytes, "direct_echo");

    // 队列上界由 setMaxPendingOutgoing 控制，溢出只丢弃并计数，不抛异常
    handler.setMaxPendingOutgoing(1);
    handler.sendTo(peer, "a", 1);
    handler.sendTo(peer, "b", 1);
    EXPECT_EQ(handler.outgoingCount(), size_t{1});
    EXPECT_EQ(handler.droppedOutgoing(), size_t{1});

    handler.reset();
    EXPECT_FALSE(handler.hasOutgoing());
    EXPECT_EQ(handler.droppedOutgoing(), size_t{0});
}

TEST(HandlerDatagram, CombinedHandlerResetsBothSides)
{
    CombinedEchoHandler handler;
    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    peer.sin_port = htons(12345);
    inet_pton(AF_INET, "127.0.0.1", &peer.sin_addr);

    EXPECT_FALSE(handler.hasOutgoing());
    handler.onDatagram(peer, "ping_datagram", 13);
    EXPECT_TRUE(handler.hasOutgoing());
    EXPECT_EQ(handler.outgoingCount(), 1u);

    auto reply = handler.takeOutgoing();
    EXPECT_EQ(reply.bytes, "ping_datagram");
    EXPECT_EQ(reply.peer.sin_port, htons(12345));
    EXPECT_FALSE(handler.hasOutgoing());

    // 验证 reset 正常清理流式与数据报状态
    feed(handler, "stream_data");
    handler.onDatagram(peer, "after_reset", 11);
    EXPECT_TRUE(handler.hasOutgoing());
    EXPECT_GT(handler.requestBytes(), 0u);
    handler.reset();
    EXPECT_FALSE(handler.hasOutgoing());
    EXPECT_EQ(handler.requestBytes(), 0u);
}

TEST(Connection, SpliceZeroCopyEcho)
{
    int sp[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sp), 0);

    Connection<SpliceEchoHandler> conn;
    conn.setFd(sp[1]);
    EXPECT_TRUE(conn.isSpliceEnabled());

    const std::string msg = "kernel_splice_zero_copy_payload";
    ssize_t wn = ::write(sp[0], msg.data(), msg.size());
    ASSERT_EQ(wn, static_cast<ssize_t>(msg.size()));

    // 执行 handleRead：通过 splice 内核通道直接环回
    IO_STATUS status = conn.handleRead();
    EXPECT_EQ(status, IO_STATUS::KEEP);

    // 零拷贝核心断言：数据未进入用户态请求缓冲区
    EXPECT_EQ(conn.handler().requestBytes(), 0u);
    EXPECT_FALSE(conn.handler().hasResponse());

    // 从对端套接字读出回显数据
    char buf[128] = {};
    ssize_t rn = ::read(sp[0], buf, sizeof(buf));
    ASSERT_EQ(rn, static_cast<ssize_t>(msg.size()));
    EXPECT_EQ(std::string(buf, static_cast<size_t>(rn)), msg);

    // 验证 EOF 场景
    ::close(sp[0]);
    status = conn.handleRead();
    EXPECT_EQ(status, IO_STATUS::CLOSE);
}

TEST(Connection, SpliceDisabledFallback)
{
    int sp[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sp), 0);

    Connection<SpliceEchoHandler> conn;
    conn.setFd(sp[1]);
    conn.handler().disableSplice();
    EXPECT_FALSE(conn.isSpliceEnabled());

    const std::string msg = "user_space_fallback_payload";
    ssize_t wn = ::write(sp[0], msg.data(), msg.size());
    ASSERT_EQ(wn, static_cast<ssize_t>(msg.size()));

    // 执行 handleRead：降级进入用户态直写并 process()
    IO_STATUS status = conn.handleRead();
    EXPECT_EQ(status, IO_STATUS::KEEP);
    EXPECT_TRUE(conn.hasPendingWrite());

    // 发送回写
    status = conn.handleWrite();
    EXPECT_EQ(status, IO_STATUS::KEEP);

    char buf[128] = {};
    ssize_t rn = ::read(sp[0], buf, sizeof(buf));
    ASSERT_EQ(rn, static_cast<ssize_t>(msg.size()));
    EXPECT_EQ(std::string(buf, static_cast<size_t>(rn)), msg);

    ::close(sp[0]);
}

TEST(Connection, WriteBacklogHardCapTriggersCloseAfterWrite)
{
    // 慢读放大回归：对端不读（套接字缓冲满）时反复收割大响应，
    // pendingBytes_ 超过 2×高水位必须停止搬运并标记发完即关。
    int sp[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sp), 0);

    Connection<HandlerConnection> conn;
    conn.setFd(sp[1]);
    conn.handler().disableSplice();

    // 把发送端塞满，模拟对端零窗口。socketpair 保持非阻塞，
    // 写到 EAGAIN/EWOULDBLOCK 即说明内核缓冲已满，绝不能阻塞。
    std::string filler(65536, 'x');
    while (true)
    {
        ssize_t wn = ::write(sp[1], filler.data(), filler.size());
        if (wn < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        {
            break;
        }
        ASSERT_GE(wn, 0);
    }

    // pump = collectResponses；每次注入一条 1MiB echo 响应
    const std::string bigRequest(1 << 20, 'a');
    for (int i = 0; i < 64; ++i)
    {
        ASSERT_TRUE(conn.handler().pushResponse(bigRequest));
        conn.pump();
        if (conn.closeAfterWrite())
        {
            break;
        }
    }

    // 1MiB × 8 = 8MiB = 2×高水位(4MiB)，第 9 条起必须被硬顶拒绝
    EXPECT_TRUE(conn.closeAfterWrite());

    // 队列中至多 8MiB（硬顶前已入队的部分），全部消费后队列为空。
    // 注意：硬顶 break 发生在 takeResponse 之前，handler 里残留一条未取走的
    // 响应，hasPendingWrite() 因此恒真 —— 只能按 pendingSize() 逐条排水。
    size_t sent = 0;
    while (conn.hasPendingWrite())
    {
        const size_t n = conn.pendingSize();
        if (n == 0)
        {
            break; // 写队列已空，剩余的是 handler 内不再取出的残留响应
        }
        sent += n;
        [[maybe_unused]] bool drained = conn.commitSent(n);
    }
    EXPECT_GE(sent, 4u << 20);
    EXPECT_LE(sent, 2 * (4u << 20));

    ::close(sp[0]);
    ::close(sp[1]);
}

TEST(Connection, CommitSentRestoresReadPause)
{
    // Proactor 纯 io_uring 路径回归：onSendDone 仅经 commitSent 递减积压，
    // 积压落回高水位以内且存在读信用时必须恢复 readPaused_（原先永不恢复）。
    int sp[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sp), 0);

    Connection<HandlerConnection> conn;
    conn.setFd(sp[1]);
    conn.handler().disableSplice();

    const std::string bigRequest(3u << 20, 'a');
    ASSERT_TRUE(conn.handler().pushResponse(bigRequest));
    ASSERT_TRUE(conn.handler().pushResponse(bigRequest));
    conn.pump();
    // 高水位 4MiB < 积压 6MiB：collectResponses 尾部应触发读暂停
    EXPECT_FALSE(conn.wantRead());

    // 全部发送完毕：积压清零，commitSent 必须恢复读背压
    // （Proactor onSendDone 只经此路径递减积压）
    EXPECT_TRUE(conn.commitSent(2 * (3u << 20)));
    EXPECT_TRUE(conn.wantRead());

    ::close(sp[0]);
    ::close(sp[1]);
}

TEST(ResponseQueue, InitCapacityOverflowReturnsError)
{
    ResponseQueue queue;
    auto res = queue.init(std::numeric_limits<size_t>::max());
    EXPECT_FALSE(res.has_value());
    EXPECT_EQ(res.error(), ERR::POOL_ALLOC_FAILED);
}

TEST(ResponseQueue, ResetClearsElementsAndPreservesCapacity)
{
    ResponseQueue queue;
    ASSERT_TRUE(queue.init(4));
    EXPECT_TRUE(queue.push(std::string("first")));
    EXPECT_TRUE(queue.push(std::string("second")));
    EXPECT_EQ(queue.size(), 2u);
    EXPECT_FALSE(queue.empty());

    queue.reset();
    EXPECT_EQ(queue.size(), 0u);
    EXPECT_TRUE(queue.empty());
    EXPECT_EQ(queue.capacity(), 4u);

    // 验证 reset 后可正常重新推入元素
    EXPECT_TRUE(queue.push(std::string("third")));
    EXPECT_EQ(queue.size(), 1u);
    EXPECT_EQ(queue.front(), "third");
}

TEST(Connection, SpliceDecoupledProxyForward)
{
    // 验证解耦改造：splice 不再写死 echo（自己发回自己），可作为内核零拷贝反向代理
    int clientSp[2];
    int proxySp[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, clientSp), 0);
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, proxySp), 0);

    Connection<SpliceEchoHandler> conn;
    conn.setFd(clientSp[1]);
    // 将零拷贝目标重定向至上游代理套接字
    conn.handler().setSpliceTarget(proxySp[1]);
    EXPECT_TRUE(conn.isSpliceEnabled());
    EXPECT_EQ(conn.handler().spliceTarget(), proxySp[1]);

    const std::string proxyPayload = "splice_proxy_upstream_payload";
    ssize_t wn = ::write(clientSp[0], proxyPayload.data(), proxyPayload.size());
    ASSERT_EQ(wn, static_cast<ssize_t>(proxyPayload.size()));

    // 执行 handleRead：数据应从 client 套接字经内核管道直接泵入 proxySp[1]
    IO_STATUS status = conn.handleRead();
    EXPECT_EQ(status, IO_STATUS::KEEP);

    // 零拷贝断言：无用户态内存堆积
    EXPECT_EQ(conn.handler().requestBytes(), 0u);
    EXPECT_FALSE(conn.handler().hasResponse());

    // 验证 clientSp[0] 没有收到 echo 回显（不是 echo）
    char echoBuf[32] = {};
    ssize_t echoRn = ::recv(clientSp[0], echoBuf, sizeof(echoBuf), MSG_DONTWAIT);
    EXPECT_TRUE(echoRn < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));

    // 验证代理对端 proxySp[0] 成功收到零拷贝转交的报文
    char proxyBuf[128] = {};
    ssize_t proxyRn = ::read(proxySp[0], proxyBuf, sizeof(proxyBuf));
    ASSERT_EQ(proxyRn, static_cast<ssize_t>(proxyPayload.size()));
    EXPECT_EQ(std::string(proxyBuf, static_cast<size_t>(proxyRn)), proxyPayload);

    ::close(clientSp[0]);
    ::close(proxySp[0]);
    ::close(proxySp[1]);
}

TEST(Connection, SpliceToAndSpliceFromApis)
{
    int sp[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sp), 0);

    Connection<SpliceEchoHandler> conn;
    conn.setFd(sp[1]);

    int pipe1[2];
    ASSERT_EQ(::pipe2(pipe1, O_NONBLOCK | O_CLOEXEC), 0);

    // 1. 测试 spliceTo：将 socket 输入零拷贝搬移到目标管道
    const std::string msgTo = "hello_splice_to_pipe";
    ssize_t wn = ::write(sp[0], msgTo.data(), msgTo.size());
    ASSERT_EQ(wn, static_cast<ssize_t>(msgTo.size()));

    auto resTo = conn.spliceTo(pipe1[1], msgTo.size());
    ASSERT_TRUE(resTo.has_value());
    EXPECT_EQ(resTo.value(), msgTo.size());

    char bufTo[64] = {};
    ssize_t rnTo = ::read(pipe1[0], bufTo, sizeof(bufTo));
    ASSERT_EQ(rnTo, static_cast<ssize_t>(msgTo.size()));
    EXPECT_EQ(std::string(bufTo, static_cast<size_t>(rnTo)), msgTo);

    // 2. 测试 spliceFrom：从源管道零拷贝搬移到当前 socket 并由对端读取
    int pipe2[2];
    ASSERT_EQ(::pipe2(pipe2, O_NONBLOCK | O_CLOEXEC), 0);

    const std::string msgFrom = "hello_splice_from_pipe";
    wn = ::write(pipe2[1], msgFrom.data(), msgFrom.size());
    ASSERT_EQ(wn, static_cast<ssize_t>(msgFrom.size()));

    auto resFrom = conn.spliceFrom(pipe2[0], msgFrom.size());
    ASSERT_TRUE(resFrom.has_value());
    EXPECT_EQ(resFrom.value(), msgFrom.size());

    char bufFrom[64] = {};
    ssize_t rnFrom = ::read(sp[0], bufFrom, sizeof(bufFrom));
    ASSERT_EQ(rnFrom, static_cast<ssize_t>(msgFrom.size()));
    EXPECT_EQ(std::string(bufFrom, static_cast<size_t>(rnFrom)), msgFrom);

    ::close(pipe1[0]);
    ::close(pipe1[1]);
    ::close(pipe2[0]);
    ::close(pipe2[1]);
    ::close(sp[0]);
}

TEST(HandlerConnection, SpliceTargetApis)
{
    HandlerConnection handler;
    EXPECT_FALSE(handler.isSpliceActive());
    EXPECT_EQ(handler.spliceControl(), SPLICE_CONTROL::DISABLED);
    EXPECT_EQ(handler.spliceTarget(), -1);

    handler.setSpliceTarget(42);
    EXPECT_TRUE(handler.isSpliceActive());
    EXPECT_EQ(handler.spliceTarget(), 42);
    EXPECT_EQ(handler.spliceControl(), SPLICE_CONTROL::ACTIVE);

    // 暂停挂起
    handler.pauseSplice();
    EXPECT_FALSE(handler.isSpliceActive());
    EXPECT_EQ(handler.spliceControl(), SPLICE_CONTROL::PAUSED);
    EXPECT_EQ(handler.spliceTarget(), 42);

    // 恢复活跃
    handler.resumeSplice();
    EXPECT_TRUE(handler.isSpliceActive());
    EXPECT_EQ(handler.spliceControl(), SPLICE_CONTROL::ACTIVE);

    // 管道排空
    handler.drainSplice();
    EXPECT_FALSE(handler.isSpliceActive());
    EXPECT_EQ(handler.spliceControl(), SPLICE_CONTROL::DRAINING);
    EXPECT_EQ(handler.spliceTarget(), 42);

    // 禁用重置
    handler.disableSplice();
    EXPECT_FALSE(handler.isSpliceActive());
    EXPECT_EQ(handler.spliceControl(), SPLICE_CONTROL::DISABLED);
    EXPECT_EQ(handler.spliceTarget(), -1);

    // 控制状态枚举设置与闭合
    handler.setSpliceControl(SPLICE_CONTROL::CLOSED);
    EXPECT_EQ(handler.spliceControl(), SPLICE_CONTROL::CLOSED);
    EXPECT_EQ(handler.spliceTarget(), -1);
}

TEST(HandlerHttp, LifecycleAndFd)
{
    http::v1::HandlerHttp<HTTP_MODE::REQUEST> handler;
    EXPECT_EQ(handler.fd(), -1);

    handler.onConnect(42);
    EXPECT_EQ(handler.fd(), 42);

    handler.reset();
    EXPECT_EQ(handler.fd(), -1);
}

TEST(HandlerHttp, SendResponseAndEcho)
{
    http::v1::HandlerHttp<HTTP_MODE::REQUEST> handler;

    // 1. sendResponse 直接推入格式化的 HTTP/1.1 报文
    auto res = handler.sendResponse(200, "OK", {{"X-App", "mynet"}}, "hello world");
    ASSERT_TRUE(res.has_value());
    ASSERT_TRUE(handler.hasResponse());
    std::string resp = handler.takeResponse();
    EXPECT_NE(resp.find("HTTP/1.1 200 OK\r\n"), std::string::npos);
    EXPECT_NE(resp.find("Content-Length: 11\r\n"), std::string::npos);
    EXPECT_NE(resp.find("X-App: mynet\r\n"), std::string::npos);
    EXPECT_NE(resp.find("\r\n\r\nhello world"), std::string::npos);

    // 2. 模拟请求解析完成后的 echo() 回显行为
    std::string rawReq = "POST /echo HTTP/1.1\r\nContent-Length: 5\r\n\r\n12345";
    feed(handler, rawReq);
    handler.process();
    // 触发 HTTP 级回显
    handler.echo();
    ASSERT_TRUE(handler.hasResponse());
    std::string echoResp = handler.takeResponse();
    EXPECT_NE(echoResp.find("HTTP/1.1 200 OK\r\n"), std::string::npos);
    EXPECT_NE(echoResp.find("Content-Length: 5\r\n"), std::string::npos);
    EXPECT_NE(echoResp.find("\r\n\r\n12345"), std::string::npos);
}

TEST(HandlerHttp, SpliceTunnelApis)
{
    http::v1::HandlerHttp<HTTP_MODE::REQUEST> handler;
    EXPECT_FALSE(handler.isSpliceTunnelActive());
    EXPECT_EQ(handler.spliceControl(), SPLICE_CONTROL::DISABLED);
    EXPECT_EQ(handler.spliceTarget(), -1);

    handler.enableSpliceTunnel(100);
    EXPECT_TRUE(handler.isSpliceTunnelActive());
    EXPECT_EQ(handler.spliceTarget(), 100);
    EXPECT_EQ(handler.spliceControl(), SPLICE_CONTROL::ACTIVE);

    handler.disableSpliceTunnel();
    EXPECT_FALSE(handler.isSpliceTunnelActive());
    EXPECT_EQ(handler.spliceControl(), SPLICE_CONTROL::DISABLED);
    EXPECT_EQ(handler.spliceTarget(), -1);
}
