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

    auto vless = std::make_shared<InboundVless>("vless-in", "127.0.0.1", 1080, "de04add9-5c1a-4b08-8e65-244e45cf5483");
    EXPECT_EQ(vless->tag(), "vless-in");
    EXPECT_EQ(vless->type(), "vless");
    EXPECT_EQ(vless->host(), "127.0.0.1");
    EXPECT_EQ(vless->port(), 1080);
    EXPECT_TRUE(vless->isSniffingEnabled());

    auto socks = std::make_shared<InboundSocks5>("socks-in", "127.0.0.1", 1081, "admin", "pass123");
    EXPECT_EQ(socks->tag(), "socks-in");
    EXPECT_EQ(socks->type(), "socks5");

    auto http = std::make_shared<InboundHttp>("http-in", "127.0.0.1", 8080);
    EXPECT_EQ(http->type(), "http");

    auto trojan = std::make_shared<InboundTrojan>("trojan-in", "0.0.0.0", 443, "trojan_secret");
    EXPECT_EQ(trojan->type(), "trojan");

    auto direct = std::make_shared<InboundDirect>("direct-in", "127.0.0.1", 9000);
    EXPECT_EQ(direct->type(), "direct");

    auto ss = std::make_shared<InboundShadowsocks>("ss-in", "127.0.0.1", 8388, "aes-128-gcm", "password");
    EXPECT_EQ(ss->tag(), "ss-in");
    EXPECT_EQ(ss->type(), "shadowsocks");

    mgr.registerInbound(vless);
    mgr.registerInbound(socks);
    mgr.registerInbound(http);
    mgr.registerInbound(trojan);
    mgr.registerInbound(direct);
    mgr.registerInbound(ss);

    EXPECT_EQ(mgr.size(), 6u);
    EXPECT_TRUE(mgr.has("vless-in"));
    EXPECT_TRUE(mgr.has("socks-in"));
    EXPECT_TRUE(mgr.has("http-in"));
    EXPECT_TRUE(mgr.has("trojan-in"));
    EXPECT_TRUE(mgr.has("direct-in"));
    EXPECT_TRUE(mgr.has("ss-in"));

    auto tags = mgr.listTags();
    EXPECT_EQ(tags.size(), 6u);

    mgr.remove("direct-in");
    EXPECT_FALSE(mgr.has("direct-in"));
    EXPECT_EQ(mgr.size(), 5u);
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

    InboundVless vless("vless", "127.0.0.1", 1080, "de04add9-5c1a-4b08-8e65-244e45cf5483");
    auto hVless = vless.createHandler();
    ASSERT_NE(hVless, nullptr);

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

    InboundShadowsocks ssIn("ss", "127.0.0.1", 8388, "aes-128-gcm", "pass");
    auto hSs = ssIn.createHandler();
    ASSERT_NE(hSs, nullptr);
    EXPECT_EQ(hSs->stage(), InboundStage::HANDSHAKE);
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
    auto in2 = std::make_shared<InboundHttp>("in-2", "127.0.0.1", 0);

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
// 5. Reactor 多协议与单接收器统一驱动接入测试
// =============================================================================

TEST(InboundManagerTest, ReactorDrivesAcceptor)
{
    using Server = Reactor<Acceptor<HandlerConnection>>;
    Server reactor;

    auto listenRes = reactor.listenTcp("127.0.0.1", 0);
    ASSERT_TRUE(listenRes.has_value());
    EXPECT_GE(reactor.tcpFd(), 0);
    EXPECT_EQ(reactor.listenerCount(), 1u);

    sockaddr_in boundAddr{};
    socklen_t len = sizeof(boundAddr);
    ::getsockname(reactor.tcpFd(), reinterpret_cast<sockaddr *>(&boundAddr), &len);
    const uint16_t port = ntohs(boundAddr.sin_port);
    ASSERT_GT(port, 0);

    // 在后台线程运行 Reactor 事件循环
    std::thread serverThread(
        [&reactor]()
        {
            ServerConfig scfg;
            ReactorConfig rcfg;
            [[maybe_unused]] auto _ = reactor.serve(scfg, rcfg);
        });

    usleep(10000);
    int clientFd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    ASSERT_GE(clientFd, 0);

    sockaddr_in srvAddr{};
    srvAddr.sin_family = AF_INET;
    srvAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    srvAddr.sin_port = htons(port);
    ::connect(clientFd, reinterpret_cast<sockaddr *>(&srvAddr), sizeof(srvAddr));

    for (int i = 0; i < 50 && reactor.connections() == 0; ++i)
    {
        usleep(5000);
    }
    EXPECT_GE(reactor.connections(), 1u);

    ::close(clientFd);
    reactor.stop();
    if (serverThread.joinable())
    {
        serverThread.join();
    }
}

#if defined(MYNET_ENABLE_URING)
// =============================================================================
// 6. Proactor 统一监听与连接接入测试 (io_uring)
// =============================================================================

TEST(InboundManagerTest, ProactorDrivesAcceptor)
{
    using Server = Proactor<Acceptor<HandlerConnection>>;
    Server proactor;

    auto listenRes = proactor.listenTcp("127.0.0.1", 0);
    ASSERT_TRUE(listenRes.has_value());
    EXPECT_GE(proactor.tcpFd(), 0);
    EXPECT_EQ(proactor.listenerCount(), 1u);

    proactor.reset();
    EXPECT_EQ(proactor.tcpFd(), -1);
    EXPECT_EQ(proactor.listenerCount(), 0u);
}
#endif
