// HandlerConnection 与 HandlerHttp：协议前端对驱动它的连接所承担的契约——
// 读取数据的请求缓冲区、消费输出的响应队列，以及介于两者之间的背压信用额度。
#include "connection.hpp"
#include "http/v1/handler.hpp"
#include <fcntl.h>
#include <gtest/gtest.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>

using namespace mynet;
using namespace mynet::http::v1;

namespace
{
    void feed(HandlerConnection &handler, const std::string &bytes)
    {
        [[maybe_unused]] auto _ = handler.appendRequest(bytes.data(), static_cast<ssize_t>(bytes.size()));
    }

    /**
     * @brief 测试夹具：同时组合流式与报文两种基类的回显处理器
     *
     * 两个处理器基类并列独立（无共同祖先、无虚继承），各自提供 reset /
     * onMessageComplete / onParseError。多重继承时这三个同名钩子必须由派生类
     * 显式覆盖，否则调用点二义、HandlerConstraint 不成立——本夹具即正确范式：
     * 覆盖并逐层转发，再叠加自己的数据报回显。
     * 纯报文处理器无需如此（引擎已支持只派生 HandlerDatagram）。
     */
    class CombinedEchoHandler : public HandlerBase
    {
    public:
        void reset() noexcept override { HandlerBase::reset(); }

        void onMessageComplete() noexcept override { HandlerBase::onMessageComplete(); }

        void onParseError(const char *reason) noexcept override { HandlerBase::onParseError(reason); }

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

TEST(HandlerConnection, DefaultProcessDoesNotHandleRequests)
{
    HandlerConnection handler;
    feed(handler, "hello");
    handler.handle();
    EXPECT_FALSE(handler.hasResponse());
    EXPECT_EQ(handler.requestBytes(), size_t{5});
    EXPECT_EQ(std::string(handler.requestBegin(), handler.requestBytes()), "hello");
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
    handler.handle();
    EXPECT_FALSE(handler.hasResponse());
    EXPECT_EQ(handler.requestBytes(), 16u);
    EXPECT_EQ(std::string(handler.requestBegin(), handler.requestBytes()), "direct-zero-copy");
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
    handler.handle();

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
    handler.handle();
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
    handler.handle();
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
    handler.handle();
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
    handler.handle();
    // llhttp 支持增量解析，因此在首次追加结束时请求行已被解析完成：
    // 当首部段仍处于打开状态时 URL 已可读，且首部值尚非最终完整值。
    // 本测试验证第二次追加会无缝续接同一条消息，而非被当作全新消息处理。
    EXPECT_EQ(handler.url(), "/split");
    EXPECT_NE(handler.headerValue("Host"), "example.com");
    feed(handler, "ample.com\r\n\r\n");
    handler.handle();
    EXPECT_EQ(handler.url(), "/split");
    EXPECT_EQ(handler.headerValue("Host"), "example.com");
}

TEST(HandlerHttp, ParseErrorAnswers400AndCloses)
{
    HandlerHttp<HTTP_MODE::REQUEST> handler;
    feed(handler, "\x01\x02 not a request \x03\r\n\r\n");
    handler.handle();
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
    handler.handle();
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
    handler.handle();
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
    handler.handle();
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
    handler.handle();
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
    handler.handle();
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
    static_assert(MandatoryMethodConnection<HandlerDatagram>);

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

TEST(Connection, WriteBacklogHardCapTriggersCloseAfterWrite)
{
    // 慢读放大回归：对端不读（套接字缓冲满）时反复收割大响应，
    // pendingBytes_ 超过 2×高水位必须停止搬运并标记发完即关。
    int sp[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sp), 0);

    ConnectionBase conn;
    HandlerBase handler;
    conn.setHandler(&handler);
    conn.setFd(sp[1]);

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
        ASSERT_TRUE(handler.pushResponse(bigRequest));
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
    // 响应，hasPendingWrite() 因此恒真 —— 只能按 pendingBytes() 逐条排水。
    size_t sent = 0;
    while (conn.hasPendingWrite())
    {
        const size_t n = conn.pendingBytes();
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

    ConnectionBase conn;
    HandlerBase handler;
    conn.setHandler(&handler);
    conn.setFd(sp[1]);

    const std::string bigRequest(3u << 20, 'a');
    ASSERT_TRUE(handler.pushResponse(bigRequest));
    ASSERT_TRUE(handler.pushResponse(bigRequest));
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

TEST(DatagramQueue, FixedCapacityAndPeerPreservation)
{
    DatagramQueue queue;
    ASSERT_TRUE(queue.init(2));
    EXPECT_EQ(queue.capacity(), 2u);
    EXPECT_TRUE(queue.empty());

    sockaddr_in peer1{};
    peer1.sin_family = AF_INET;
    peer1.sin_port = htons(8080);
    inet_pton(AF_INET, "127.0.0.1", &peer1.sin_addr);

    sockaddr_in peer2{};
    peer2.sin_family = AF_INET;
    peer2.sin_port = htons(9090);
    inet_pton(AF_INET, "10.0.0.1", &peer2.sin_addr);

    EXPECT_TRUE(queue.emplace(peer1, "packet_one", 10));
    EXPECT_TRUE(queue.emplace(peer2, std::string("packet_two")));
    EXPECT_EQ(queue.size(), 2u);

    // 满队拒绝
    auto overflow = queue.emplace(peer1, "overflow", 8);
    EXPECT_FALSE(overflow.has_value());
    EXPECT_EQ(overflow.error(), ERR::QUEUE_FULL);

    // 队首检验与弹出
    const auto &front1 = queue.front();
    EXPECT_EQ(front1.bytes, "packet_one");
    EXPECT_EQ(front1.peer.sin_port, htons(8080));
    queue.pop();
    EXPECT_EQ(queue.size(), 1u);

    const auto &front2 = queue.front();
    EXPECT_EQ(front2.bytes, "packet_two");
    EXPECT_EQ(front2.peer.sin_port, htons(9090));
    queue.pop();
    EXPECT_TRUE(queue.empty());

    // 再次入队验证槽位 string 内存复用与正确性
    EXPECT_TRUE(queue.emplace(peer1, "packet_three", 12));
    EXPECT_EQ(queue.size(), 1u);
    EXPECT_EQ(queue.front().bytes, "packet_three");
}

TEST(DatagramQueue, ResetClearsElementsAndPreservesCapacity)
{
    DatagramQueue queue;
    ASSERT_TRUE(queue.init(4));

    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    peer.sin_port = htons(5353);

    EXPECT_TRUE(queue.emplace(peer, "dns_query_1", 11));
    EXPECT_TRUE(queue.emplace(peer, "dns_query_2", 11));
    EXPECT_EQ(queue.size(), 2u);

    queue.reset();
    EXPECT_EQ(queue.size(), 0u);
    EXPECT_TRUE(queue.empty());
    EXPECT_EQ(queue.capacity(), 4u);

    EXPECT_TRUE(queue.emplace(peer, "dns_query_3", 11));
    EXPECT_EQ(queue.size(), 1u);
    EXPECT_EQ(queue.front().bytes, "dns_query_3");
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

TEST(HandlerHttp, SendResponseAndProcess)
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

    // 2. 模拟请求解析完成后的 handle() 业务响应行为
    std::string rawReq = "POST /echo HTTP/1.1\r\nContent-Length: 5\r\n\r\n12345";
    feed(handler, rawReq);
    handler.handle();
    ASSERT_TRUE(handler.hasResponse());
    std::string echoResp = handler.takeResponse();
    EXPECT_NE(echoResp.find("HTTP/1.1 200 OK\r\n"), std::string::npos);
    EXPECT_NE(echoResp.find("Content-Length: 5\r\n"), std::string::npos);
    EXPECT_NE(echoResp.find("\r\n\r\n12345"), std::string::npos);
}

class StreamTestHttpHandler : public http::v1::HandlerHttp<HTTP_MODE::REQUEST>
{
public:
    std::vector<std::string> chunks;
    void onBodyChunk(std::string_view chunk) noexcept override { chunks.emplace_back(chunk); }
};

TEST(HandlerHttp, StreamingBodyPassThroughZeroCopy)
{
    StreamTestHttpHandler handler;
    handler.enableStreamingBody(true);
    EXPECT_TRUE(handler.isStreamingBody());

    std::string req1 = "POST /upload HTTP/1.1\r\nContent-Length: 10\r\n\r\n12345";
    feed(handler, req1);
    handler.handle();

    EXPECT_EQ(handler.chunks.size(), 1u);
    EXPECT_EQ(handler.chunks[0], "12345");
    // 关键验证：开启 streaming 后，body_ 保持为空，杜绝堆累积硬拷贝
    EXPECT_TRUE(handler.body().empty());

    // 第二段数据到达
    std::string req2 = "67890";
    feed(handler, req2);
    handler.handle();

    EXPECT_EQ(handler.chunks.size(), 2u);
    EXPECT_EQ(handler.chunks[1], "67890");
    EXPECT_TRUE(handler.body().empty());
}

namespace
{
    class TrackedOwnedHandler final : public Handler
    {
    public:
        explicit TrackedOwnedHandler(int *destroyCount) noexcept : destroyCount_(destroyCount) {}
        ~TrackedOwnedHandler() noexcept override
        {
            if (destroyCount_ != nullptr)
            {
                ++(*destroyCount_);
            }
        }

    private:
        int *destroyCount_{nullptr};
    };
} // namespace

TEST(Connection, SetOwnedHandlerDeletesOwnedAndPreservesBorrowed)
{
    int destroyed = 0;
    {
        Connection conn;
        conn.setOwnedHandler(std::make_unique<TrackedOwnedHandler>(&destroyed));
        EXPECT_NE(conn.handler(), nullptr);
        conn.reset();
        EXPECT_EQ(destroyed, 1);
        EXPECT_EQ(conn.handler(), nullptr);
    }

    TrackedOwnedHandler stackHandler(&destroyed);
    {
        Connection conn;
        conn.setHandler(&stackHandler);
        EXPECT_EQ(conn.handler(), &stackHandler);
        conn.reset();
        EXPECT_EQ(destroyed, 1);
    }
    EXPECT_EQ(destroyed, 1);
}

TEST(Handler, LazyDatagramQueueAllocation)
{
    Handler h;
    EXPECT_EQ(std::as_const(h).outgoing().capacity(), 0u);
    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    peer.sin_port = htons(5353);
    h.sendTo(peer, "hello", 5);
    EXPECT_GT(h.outgoing().capacity(), 0u);
    EXPECT_EQ(h.outgoingCount(), 1u);
    auto pkt = h.takeOutgoing();
    EXPECT_EQ(pkt.bytes, "hello");
}

TEST(Handler, MuxInboundHandlerVariantDispatchAndReset)
{
    class TestMux final : public MuxInboundHandler<HandlerConnection, HandlerHttp<HTTP_MODE::REQUEST>>
    {
    public:
        void handle() override
        {
            if (activeChild() == nullptr && requestBytes() > 0)
            {
                emplaceChild<HandlerConnection>();
            }
            if (auto *c = activeChild(); c != nullptr)
            {
                (void)driveChild(*c);
            }
        }
    };

    TestMux mux;
    EXPECT_TRUE(mux.appendRequest("ping", 4).has_value());
    mux.drive();
    EXPECT_TRUE(mux.canSplice());
    mux.reset();
}

namespace
{
    class DummyNonPassthroughTransport final : public transport::ITransport
    {
    public:
        [[nodiscard]] transport::TransportType type() const noexcept override { return transport::TransportType::WEBSOCKET; }
        [[nodiscard]] transport::TransportState state() const noexcept override { return transport::TransportState::STREAMING; }
        [[nodiscard]] bool isReady() const noexcept override { return true; }
        void reset() noexcept override {}
    };
} // namespace

TEST(Handler, ColdWireAndDatagramStateLazyDefaultsAndRemotePeer)
{
    Handler h;
    EXPECT_TRUE(h.isPassthrough());
    EXPECT_TRUE(h.canSplice());
    EXPECT_TRUE(std::as_const(h).transportPipeline().empty());
    EXPECT_FALSE(h.hasOutgoing());
    EXPECT_EQ(h.outgoingCount(), 0u);
    EXPECT_EQ(h.droppedOutgoing(), 0u);
    EXPECT_EQ(h.remotePeer().sin_port, 0);

    Connection conn;
    conn.setHandler(&h);
    EXPECT_EQ(conn.ssl(), nullptr);
    EXPECT_FALSE(conn.ktlsRxActive());
    EXPECT_FALSE(conn.ktlsTxActive());
    EXPECT_TRUE(h.isPassthrough());
    EXPECT_TRUE(std::as_const(h).transportPipeline().empty());

    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    peer.sin_port = htons(8443);
    peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    h.setRemotePeer(peer);
    EXPECT_EQ(h.remotePeer().sin_port, htons(8443));
    EXPECT_EQ(h.remotePeer().sin_addr.s_addr, htonl(INADDR_LOOPBACK));

    h.addTransportLayer(std::make_unique<DummyNonPassthroughTransport>());
    EXPECT_FALSE(std::as_const(h).transportPipeline().empty());
    EXPECT_FALSE(h.isPassthrough());
    EXPECT_FALSE(h.canSplice());
    h.reset();
}
