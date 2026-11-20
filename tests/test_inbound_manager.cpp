#include "inboundManager.hpp"
#include "reactor.hpp"
#if defined(MYNET_ENABLE_URING)
#include "proactor.hpp"
#endif
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace mynet;
using namespace mynet::handler;

// =============================================================================
// 1. 入站节点注册表与基础属性测试
// =============================================================================

TEST(InboundManagerTest, RegistryAndTypes)
{
    InboundManager mgr;
    EXPECT_EQ(mgr.size(), 0u);

    auto mixed = std::make_shared<InboundMixed>("mixed-in", "127.0.0.1", 1080);
    EXPECT_EQ(mixed->tag(), "mixed-in");
    EXPECT_EQ(mixed->type(), "mixed");
    EXPECT_EQ(mixed->host(), "127.0.0.1");
    EXPECT_EQ(mixed->port(), 1080);
    EXPECT_TRUE(mixed->isSniffingEnabled());

    auto socks = std::make_shared<InboundSocks5>("socks-in", "127.0.0.1", 1081, "admin", "pass123");
    EXPECT_EQ(socks->tag(), "socks-in");
    EXPECT_EQ(socks->type(), "socks5");

    auto http = std::make_shared<InboundHttp>("http-in", "127.0.0.1", 8080);
    EXPECT_EQ(http->type(), "http");

    auto trojan = std::make_shared<InboundTrojan>("trojan-in", "0.0.0.0", 443, "trojan_secret");
    EXPECT_EQ(trojan->type(), "trojan");

    auto direct = std::make_shared<InboundDirect>("direct-in", "127.0.0.1", 9000);
    EXPECT_EQ(direct->type(), "direct");

    mgr.registerInbound(mixed);
    mgr.registerInbound(socks);
    mgr.registerInbound(http);
    mgr.registerInbound(trojan);
    mgr.registerInbound(direct);

    EXPECT_EQ(mgr.size(), 5u);
    EXPECT_TRUE(mgr.has("mixed-in"));
    EXPECT_TRUE(mgr.has("socks-in"));
    EXPECT_TRUE(mgr.has("http-in"));
    EXPECT_TRUE(mgr.has("trojan-in"));
    EXPECT_TRUE(mgr.has("direct-in"));

    auto tags = mgr.listTags();
    EXPECT_EQ(tags.size(), 5u);

    mgr.remove("direct-in");
    EXPECT_FALSE(mgr.has("direct-in"));
    EXPECT_EQ(mgr.size(), 4u);
}

// =============================================================================
// 2. 状态机工厂产出正确性测试
// =============================================================================

TEST(InboundManagerTest, HandlerFactoryProduction)
{
    InboundSocks5 socks("s5", "127.0.0.1", 1080, "admin", "secret");
    auto hSocks = socks.createHandler();
    ASSERT_NE(hSocks, nullptr);
    EXPECT_EQ(hSocks->stage(), InboundStage::HANDSHAKE);

    InboundMixed mixed("mixed", "127.0.0.1", 1080);
    auto hMixed = mixed.createHandler();
    ASSERT_NE(hMixed, nullptr);

    InboundHttp http("http", "127.0.0.1", 8080);
    auto hHttp = http.createHandler();
    ASSERT_NE(hHttp, nullptr);

    InboundTrojan trojan("trojan", "127.0.0.1", 443, "pwd");
    auto hTrojan = trojan.createHandler();
    ASSERT_NE(hTrojan, nullptr);

    InboundDirect direct("direct", "127.0.0.1", 9000);
    auto hDirect = direct.createHandler();
    ASSERT_NE(hDirect, nullptr);
    EXPECT_EQ(hDirect->stage(), InboundStage::STREAMING);
}

// =============================================================================
// 3. 监听生命周期与客户端连接接入测试 (Listen & Accept)
// =============================================================================

TEST(InboundManagerTest, ListenAndAcceptOne)
{
    // 监听在 127.0.0.1 端口 0 (动态空闲端口)
    InboundSocks5 inbound("socks-ephemeral", "127.0.0.1", 0);
    EXPECT_FALSE(inbound.isRunning());
    EXPECT_EQ(inbound.listenFd(), -1);

    auto res = inbound.listen();
    ASSERT_TRUE(res.has_value());
    EXPECT_TRUE(inbound.isRunning());
    EXPECT_GE(inbound.listenFd(), 0);
    EXPECT_EQ(inbound.acceptor().fd, inbound.listenFd());
    EXPECT_GT(inbound.port(), 0);

    const uint16_t dynamicPort = inbound.port();

    // 客户端发起非阻塞 TCP 连接
    int clientFd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    ASSERT_GE(clientFd, 0);

    sockaddr_in srvAddr{};
    srvAddr.sin_family = AF_INET;
    srvAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    srvAddr.sin_port = htons(dynamicPort);

    int connRc = ::connect(clientFd, reinterpret_cast<sockaddr *>(&srvAddr), sizeof(srvAddr));
    if (connRc < 0)
    {
        ASSERT_EQ(errno, EINPROGRESS);
    }

    // Inbound 端进行非阻塞 acceptOne
    auto acceptRes = inbound.acceptOne();
    // 如果握手还在路上，稍作重试
    if (!acceptRes)
    {
        usleep(5000);
        acceptRes = inbound.acceptOne();
    }

    ASSERT_TRUE(acceptRes.has_value());
    EXPECT_GE(acceptRes->first, 0);

    ::close(acceptRes->first);
    ::close(clientFd);
    inbound.close();
    EXPECT_FALSE(inbound.isRunning());
    EXPECT_EQ(inbound.listenFd(), -1);
}

// =============================================================================
// 4. InboundManager 批量并发启停测试 (Batch StartAll / StopAll)
// =============================================================================

TEST(InboundManagerTest, BatchStartAllAndStopAll)
{
    InboundManager mgr;

    auto in1 = std::make_shared<InboundSocks5>("in-1", "127.0.0.1", 0);
    auto in2 = std::make_shared<InboundMixed>("in-2", "127.0.0.1", 0);

    mgr.registerInbound(in1);
    mgr.registerInbound(in2);

    auto res = mgr.startAll();
    ASSERT_TRUE(res.has_value());

    EXPECT_TRUE(in1->isRunning());
    EXPECT_TRUE(in2->isRunning());
    EXPECT_GE(in1->listenFd(), 0);
    EXPECT_GE(in2->listenFd(), 0);
    EXPECT_GT(in1->port(), 0);
    EXPECT_GT(in2->port(), 0);

    mgr.stopAll();

    EXPECT_FALSE(in1->isRunning());
    EXPECT_FALSE(in2->isRunning());
    EXPECT_EQ(in1->listenFd(), -1);
    EXPECT_EQ(in2->listenFd(), -1);
}

// =============================================================================
// 5. Reactor 多接收器 (Multi-Acceptor) 统一驱动 Inbound 接入测试
// =============================================================================

TEST(InboundManagerTest, ReactorDrivesInboundAcceptor)
{
    // 1. 业务入站节点启动监听 (动态空闲端口)
    auto inbound = std::make_shared<InboundSocks5>("s5-dyn", "127.0.0.1", 0);
    ASSERT_TRUE(inbound->listen().has_value());
    const uint16_t port = inbound->port();
    ASSERT_GT(port, 0);

    // 2. Reactor 反应器引擎纳管该 Inbound 的套接字
    using Server = Reactor<AcceptorBase<HandlerConnection>>;
    Server reactor;

    std::atomic<bool> accepted{false};
    auto regRes = reactor.addListener(inbound->listenFd(),
                                      [&accepted](int clientFd, const sockaddr_in &)
                                      {
                                          accepted.store(true, std::memory_order_release);
                                          ::close(clientFd);
                                      });
    ASSERT_TRUE(regRes.has_value());
    EXPECT_GE(reactor.listenerCount(), 1u);

    // 3. 在后台线程运行 Reactor 事件循环
    std::thread serverThread(
        [&reactor]()
        {
            ServerConfig scfg;
            scfg.host = "127.0.0.1";
            scfg.port = 0;
            ReactorConfig rcfg;
            [[maybe_unused]] auto _ = reactor.runTcp("127.0.0.1", 0, scfg, rcfg);
        });

    // 4. 等待 reactor 启动后由客户端发起建连
    usleep(10000);
    int clientFd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    ASSERT_GE(clientFd, 0);

    sockaddr_in srvAddr{};
    srvAddr.sin_family = AF_INET;
    srvAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    srvAddr.sin_port = htons(port);
    ::connect(clientFd, reinterpret_cast<sockaddr *>(&srvAddr), sizeof(srvAddr));

    // 等待 Reactor 事件解复用驱动接收
    for (int i = 0; i < 50 && !accepted.load(std::memory_order_acquire); ++i)
    {
        usleep(5000);
    }

    EXPECT_TRUE(accepted.load(std::memory_order_acquire));

    ::close(clientFd);
    reactor.stop();
    if (serverThread.joinable())
    {
        serverThread.join();
    }
    inbound->close();
}

#if defined(MYNET_ENABLE_URING)
// =============================================================================
// 6. Proactor 多接收器 (Multi-Acceptor) 统一驱动 Inbound 接入测试 (io_uring)
// =============================================================================

TEST(InboundManagerTest, ProactorDrivesInboundAcceptor)
{
    // 1. 业务入站节点启动监听 (动态空闲端口)
    auto inbound = std::make_shared<InboundSocks5>("s5-uring-dyn", "127.0.0.1", 0);
    ASSERT_TRUE(inbound->listen().has_value());
    const uint16_t port = inbound->port();
    ASSERT_GT(port, 0);

    // 2. Proactor 前摄器引擎纳管该 Inbound 的套接字
    using Server = Proactor<AcceptorBase<HandlerConnection>>;
    Server proactor;

    std::atomic<bool> accepted{false};
    auto regRes = proactor.addListener(inbound->listenFd(),
                                       [&accepted](int clientFd, const sockaddr_in &)
                                       {
                                           accepted.store(true, std::memory_order_release);
                                           ::close(clientFd);
                                       });
    ASSERT_TRUE(regRes.has_value());
    EXPECT_GE(proactor.listenerCount(), 1u);

    // 检查当前内核环境是否支持并放行 io_uring 系统调用 (容器/seccomp 隔离环境下若未放行则跳过运行时循环)
    io_uring testRing{};
    int ringInitRc = io_uring_queue_init(8, &testRing, 0);
    if (ringInitRc < 0)
    {
        inbound->close();
        GTEST_SKIP() << "Kernel/Container environment does not permit io_uring (" << errnoText(-ringInitRc)
                     << "); skipping runtime event loop";
    }
    io_uring_queue_exit(&testRing);

    // 3. 在后台线程运行 Proactor 完成事件循环
    std::thread serverThread(
        [&proactor]()
        {
            ServerConfig scfg;
            scfg.host = "127.0.0.1";
            scfg.port = 0;
            ProactorConfig pcfg;
            [[maybe_unused]] auto _ = proactor.runTcp("127.0.0.1", 0, scfg, pcfg);
        });

    // 4. 等待 proactor 启动后由客户端发起建连
    usleep(10000);
    int clientFd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    ASSERT_GE(clientFd, 0);

    sockaddr_in srvAddr{};
    srvAddr.sin_family = AF_INET;
    srvAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    srvAddr.sin_port = htons(port);
    ::connect(clientFd, reinterpret_cast<sockaddr *>(&srvAddr), sizeof(srvAddr));

    // 等待 Proactor io_uring 异步完成队列驱动接收
    for (int i = 0; i < 50 && !accepted.load(std::memory_order_acquire); ++i)
    {
        usleep(5000);
    }

    EXPECT_TRUE(accepted.load(std::memory_order_acquire));

    ::close(clientFd);
    proactor.stop();
    if (serverThread.joinable())
    {
        serverThread.join();
    }
    inbound->close();
}
#endif
