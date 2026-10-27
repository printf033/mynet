// HandlerBase 与 HandlerHttp：协议前端对驱动它的连接所承担的契约——
// 读取数据的请求缓冲区、消费输出的响应队列，以及介于两者之间的背压信用额度。
#include "connection.hpp"
#include "datagram.hpp"
#include "handler.hpp"
#include "http/v1/handler.hpp"
#include <gtest/gtest.h>
#include <string>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace mynet;

namespace
{
    void feed(HandlerBase &handler, const std::string &bytes)
    {
        [[maybe_unused]] auto _ = handler.appendRequest(bytes.data(), static_cast<ssize_t>(bytes.size()));
    }
} // namespace

TEST(HandlerBase, ProcessEchoesWhateverWasAppended)
{
    HandlerBase handler;
    feed(handler, "hello");
    EXPECT_FALSE(handler.hasResponse());
    handler.process();
    ASSERT_TRUE(handler.hasResponse());
    EXPECT_EQ(handler.takeResponse(), "hello");
    EXPECT_EQ(handler.requestBytes(), size_t{0}); // 回显操作已完整消费请求
}

TEST(HandlerBase, ProcessOnAnEmptyBufferProducesNothing)
{
    HandlerBase handler;
    handler.process();
    EXPECT_FALSE(handler.hasResponse());
}

TEST(HandlerBase, ResponseQueueIsFifo)
{
    HandlerBase handler;
    [[maybe_unused]] auto _1 = handler.pushResponse("first");
    [[maybe_unused]] auto _2 = handler.pushResponse(std::string("second"));
    EXPECT_EQ(handler.responseCount(), size_t{2});
    EXPECT_EQ(handler.takeResponse(), "first");
    EXPECT_EQ(handler.takeResponse(), "second");
    EXPECT_TRUE(handler.takeResponse().empty()); // 消费空队列不属于错误
    EXPECT_FALSE(handler.hasResponse());
}

TEST(HandlerBase, PushResponseFromABufferCopiesTheBytes)
{
    HandlerBase handler;
    const std::string bytes = "abcdef";
    [[maybe_unused]] auto _ = handler.pushResponse(std::string_view(bytes.data(), 3));
    EXPECT_EQ(handler.takeResponse(), "abc");
}

TEST(HandlerBase, RequestLimitDrivesReadCredit)
{
    HandlerBase handler;
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

TEST(HandlerBase, DirectWritableZeroCopyIngress)
{
    HandlerBase handler;
    auto prepRes = handler.prepareRequestWritable(128);
    ASSERT_TRUE(prepRes.has_value());
    char *target = *prepRes;
    ASSERT_NE(target, nullptr);
    EXPECT_GE(handler.requestWritableBytes(), 128u);

    std::memcpy(target, "direct-zero-copy", 16);
    handler.commitRequest(16);

    EXPECT_EQ(handler.requestBytes(), 16u);
    handler.process();
    ASSERT_TRUE(handler.hasResponse());
    EXPECT_EQ(handler.takeResponse(), "direct-zero-copy");
    EXPECT_EQ(handler.requestBytes(), 0u);
}

TEST(HandlerBase, RequestConsumeAndClearMoveTheCursor)
{
    HandlerBase handler;
    feed(handler, "abcdef");
    handler.requestConsume(2);
    EXPECT_EQ(handler.requestBytes(), size_t{4});
    EXPECT_EQ(std::string(handler.requestBegin(), handler.requestBytes()), "cdef");
    handler.requestClear();
    EXPECT_EQ(handler.requestBytes(), size_t{0});
}

TEST(HandlerBase, CloseAfterResponseDefaultsOffAndIsSettable)
{
    HandlerBase handler;
    EXPECT_FALSE(handler.closeAfterResponse());
    handler.setCloseAfterResponse(true);
    EXPECT_TRUE(handler.closeAfterResponse());
}

TEST(HandlerBase, ResetClearsRequestsResponsesAndTheCloseFlag)
{
    HandlerBase handler;
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

TEST(HandlerBase, NullPushResponseDoesNotCrash)
{
    HandlerBase handler;
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

TEST(HandlerEcho, EchoesStreamToResponseQueue)
{
    HandlerEcho handler;
    feed(handler, "stream_ping");
    EXPECT_FALSE(handler.hasResponse());
    handler.process();
    ASSERT_TRUE(handler.hasResponse());
    EXPECT_EQ(handler.takeResponse(), "stream_ping");
    EXPECT_EQ(handler.requestBytes(), size_t{0});
}

TEST(HandlerEcho, EchoesDatagramToPeer)
{
    HandlerEcho handler;
    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    peer.sin_port = htons(12345);
    inet_pton(AF_INET, "127.0.0.1", &peer.sin_addr);

    EXPECT_FALSE(handler.hasReply());
    handler.onDatagram(peer, "ping_datagram", 13);
    EXPECT_TRUE(handler.hasReply());
    EXPECT_EQ(handler.replyCount(), 1u);

    auto reply = handler.takeReply();
    EXPECT_EQ(reply.bytes, "ping_datagram");
    EXPECT_EQ(reply.peer.sin_port, htons(12345));
    EXPECT_FALSE(handler.hasReply());

    // 验证 reset 正常清理流式与数据报状态
    feed(handler, "stream_data");
    handler.onDatagram(peer, "after_reset", 11);
    EXPECT_TRUE(handler.hasReply());
    EXPECT_GT(handler.requestBytes(), 0u);
    handler.reset();
    EXPECT_FALSE(handler.hasReply());
    EXPECT_EQ(handler.requestBytes(), 0u);
}

TEST(Connection, SpliceZeroCopyEcho)
{
    int sp[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sp), 0);

    Connection<HandlerEcho> conn;
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

    Connection<HandlerEcho> conn;
    conn.setFd(sp[1]);
    conn.handler().setSpliceEnabled(false);
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

    Connection<HandlerEcho> conn;
    conn.setFd(sp[1]);
    conn.handler().setSpliceEnabled(false);

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

    Connection<HandlerEcho> conn;
    conn.setFd(sp[1]);
    conn.handler().setSpliceEnabled(false);

    const std::string bigRequest(3u << 20, 'a');
    ASSERT_TRUE(conn.handler().pushResponse(bigRequest));
    ASSERT_TRUE(conn.handler().pushResponse(bigRequest));
    conn.pump();
    // 高水位 4MiB < 积压 6MiB：collectResponses 尾部应触发读暂停
    EXPECT_FALSE(conn.wantRead());

    // 全部发送完毕：积压清零，commitSent 必须恢复读背压
    //（Proactor onSendDone 只经此路径递减积压）
    EXPECT_TRUE(conn.commitSent(2 * (3u << 20)));
    EXPECT_TRUE(conn.wantRead());

    ::close(sp[0]);
    ::close(sp[1]);
}

TEST(RingQueue, InitCapacityOverflowReturnsError)
{
    RingQueue queue;
    auto res = queue.init(std::numeric_limits<size_t>::max());
    EXPECT_FALSE(res.has_value());
    EXPECT_EQ(res.error(), ERR::POOL_ALLOC_FAILED);
}
