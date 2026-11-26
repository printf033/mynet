#include "address.hpp"
#include "config/singbox.hpp"
#include "core.hpp"
#include "direct/direct.hpp"
#if defined(MYNET_ENABLE_URING)
#include "proactor.hpp"
#endif
#include "reactor.hpp"
#include <atomic>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

using namespace mynet;
using namespace mynet::handler;
using namespace mynet::handler::sniffing;

// =============================================================================
// 1. Core 内核初始化与基础配置测试
// =============================================================================

TEST(CoreTest, InitializationAndLifecycle)
{
    Core core;
    EXPECT_FALSE(core.isRunning());
    EXPECT_EQ(core.activeSessions(), 0u);
    EXPECT_EQ(core.totalBytes(), 0u);

    ASSERT_TRUE(core.start().has_value());
    EXPECT_TRUE(core.isRunning());

    // 预置的 direct 和 block 出站应存在
    EXPECT_TRUE(core.dialers().has("direct"));
    EXPECT_TRUE(core.dialers().has("block"));

    // 入站接收器管理器注册与查询
    core.acceptors().registerAcceptor(std::make_shared<InboundSocks5>("my-socks-in", "127.0.0.1", 1080));
    EXPECT_TRUE(core.acceptors().has("my-socks-in"));
    EXPECT_EQ(core.acceptors().size(), 1u);

    // 入站配置声明管理
    InboundConfig inCfg;
    inCfg.tag = "cfg-socks-in";
    inCfg.protocol = "socks5";
    inCfg.port = 1080;
    core.addInboundConfig(inCfg);

    auto inboundConfigs = core.inboundConfigs();
    ASSERT_EQ(inboundConfigs.size(), 1u);
    EXPECT_EQ(inboundConfigs[0].tag, "cfg-socks-in");
    EXPECT_EQ(inboundConfigs[0].port, 1080);

    // 出站配置声明管理
    OutboundConfig outCfg;
    outCfg.tag = "cfg-socks-out";
    outCfg.type = "socks5";
    outCfg.host = "127.0.0.1";
    outCfg.port = 1081;
    core.addOutboundConfig(outCfg);

    auto outboundConfigs = core.outboundConfigs();
    ASSERT_EQ(outboundConfigs.size(), 1u);
    EXPECT_EQ(outboundConfigs[0].tag, "cfg-socks-out");
    EXPECT_EQ(outboundConfigs[0].port, 1081);

    core.stop();
    EXPECT_FALSE(core.isRunning());
}

// =============================================================================
// 2. 端到端分发：阻断规则匹配测试 (Block Route Rule)
// =============================================================================

TEST(CoreTest, DispatchBlockRule)
{
    Core core;
    ASSERT_TRUE(core.start().has_value());

    // 添加拦截广告分流规则
    core.router().addRule(RouteRule::to("block").domainKeyword("adserver"));

    auto target = ProxyAddress::fromDomain("tracker.adserver.analytics.com", 80);
    HandlerInboundDirect inbound(target);

    auto res = core.dispatch(inbound, -1, "test-in");
    EXPECT_EQ(res.status, CoreDispatchStatus::BLOCKED);
    EXPECT_EQ(res.outboundTag, "block");
    EXPECT_TRUE(inbound.closeAfterResponse());
}

// =============================================================================
// 3. 端到端分发：深度嗅探协同分流测试 (Sniffing-Assisted Route Dispatch)
// =============================================================================

TEST(CoreTest, DispatchSniffingAssistedRoute)
{
    Core core;
    ASSERT_TRUE(core.start().has_value());

    // 规则：针对 netflix.com 流量分流至 block (便于无真实节点下的闭环断言)
    core.router().addRule(RouteRule::to("block").domainSuffix("netflix.com"));

    // 模拟透明代理：入站只拿到了目的 IP，但客户端首包携带 TLS ClientHello (SNI="www.netflix.com")
    in_addr remoteIp{};
    ::inet_pton(AF_INET, "198.51.100.1", &remoteIp);
    auto target = ProxyAddress::fromIPv4(remoteIp.s_addr, 443);
    HandlerInboundDirect inbound(target);

    // 构造一个合法的 TLS ClientHello (带 SNI="www.netflix.com")
    std::string sniHost = "www.netflix.com";
    std::string clientHello;
    clientHello.push_back(0x16); // Handshake
    clientHello.push_back(0x03);
    clientHello.push_back(0x01); // TLS 1.0
    // 预留 2 字节长度
    clientHello.push_back(0x00);
    clientHello.push_back(0x00);
    // Handshake Type: ClientHello (1)
    clientHello.push_back(0x01);
    // 预留 3 字节 Handshake 长度
    clientHello.push_back(0x00);
    clientHello.push_back(0x00);
    clientHello.push_back(0x00);
    // Client Version: TLS 1.2
    clientHello.push_back(0x03);
    clientHello.push_back(0x03);
    // 32 字节随机数
    clientHello.append(32, '\x01');
    // Session ID length: 0
    clientHello.push_back(0x00);
    // Cipher Suites Length: 2, Suite: 0x1301
    clientHello.push_back(0x00);
    clientHello.push_back(0x02);
    clientHello.push_back(0x13);
    clientHello.push_back(0x01);
    // Compression methods: 1, 0x00
    clientHello.push_back(0x01);
    clientHello.push_back(0x00);

    // Extensions Length (2B)
    std::string ext;
    // SNI 扩展: Type 0x0000
    ext.push_back(0x00);
    ext.push_back(0x00);
    // SNI 扩展数据长度
    uint16_t sniExtLen = static_cast<uint16_t>(2 + 1 + 2 + sniHost.size());
    ext.push_back(static_cast<char>(sniExtLen >> 8));
    ext.push_back(static_cast<char>(sniExtLen & 0xFF));
    // Server Name List Length
    uint16_t listLen = static_cast<uint16_t>(1 + 2 + sniHost.size());
    ext.push_back(static_cast<char>(listLen >> 8));
    ext.push_back(static_cast<char>(listLen & 0xFF));
    // Host Name Type: 0 (host_name)
    ext.push_back(0x00);
    // Host Name Length
    ext.push_back(static_cast<char>(sniHost.size() >> 8));
    ext.push_back(static_cast<char>(sniHost.size() & 0xFF));
    ext.append(sniHost);

    // 回填 Extensions
    clientHello.push_back(static_cast<char>(ext.size() >> 8));
    clientHello.push_back(static_cast<char>(ext.size() & 0xFF));
    clientHello.append(ext);

    // 回填长度
    uint16_t recLen = static_cast<uint16_t>(clientHello.size() - 5);
    clientHello[3] = static_cast<char>(recLen >> 8);
    clientHello[4] = static_cast<char>(recLen & 0xFF);
    uint32_t hsLen = static_cast<uint32_t>(clientHello.size() - 9);
    clientHello[6] = static_cast<char>((hsLen >> 16) & 0xFF);
    clientHello[7] = static_cast<char>((hsLen >> 8) & 0xFF);
    clientHello[8] = static_cast<char>(hsLen & 0xFF);

    [[maybe_unused]] auto _ = inbound.appendRequest(clientHello);

    auto res = core.dispatch(inbound, -1, "tproxy-in", true);
    EXPECT_EQ(res.status, CoreDispatchStatus::BLOCKED);
    EXPECT_EQ(res.outboundTag, "block");
    EXPECT_EQ(res.sniffedProtocol, ProtocolType::TLS);
    EXPECT_EQ(res.sniffedDomain, "www.netflix.com");
}

// =============================================================================
// 4. 端到端分发：直连桥接与数据泵送测试 (Direct Dial & Forwarder Session)
// =============================================================================

TEST(CoreTest, EndToEndDirectDispatchAndPump)
{
    // 本地启动测试服务
    int listenFd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    ASSERT_GE(listenFd, 0);

    sockaddr_in listenAddr{};
    listenAddr.sin_family = AF_INET;
    listenAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    listenAddr.sin_port = 0;

    int opt = 1;
    ::setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    ASSERT_EQ(::bind(listenFd, reinterpret_cast<sockaddr *>(&listenAddr), sizeof(listenAddr)), 0);
    ASSERT_EQ(::listen(listenFd, 5), 0);

    socklen_t slen = sizeof(listenAddr);
    ASSERT_EQ(::getsockname(listenFd, reinterpret_cast<sockaddr *>(&listenAddr), &slen), 0);
    uint16_t port = ntohs(listenAddr.sin_port);

    Core core;
    ASSERT_TRUE(core.start().has_value());

    auto target = ProxyAddress::fromIPv4(htonl(INADDR_LOOPBACK), port);
    HandlerInboundDirect inbound(target);

    // 客户端发送 HTTP 请求
    const std::string httpReq = "GET /status HTTP/1.1\r\nHost: localhost\r\n\r\n";
    [[maybe_unused]] auto _ = inbound.appendRequest(httpReq);

    auto res = core.dispatch(inbound, -1, "mixed-in");
    ASSERT_EQ(res.status, CoreDispatchStatus::SUCCESS);
    EXPECT_EQ(res.outboundTag, "direct");
    ASSERT_NE(res.session, nullptr);
    EXPECT_EQ(core.activeSessions(), 1u);

    // 接受出站连接
    sockaddr_in peer{};
    socklen_t plen = sizeof(peer);
    int acceptedFd = ::accept4(listenFd, reinterpret_cast<sockaddr *>(&peer), &plen, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (acceptedFd >= 0)
    {
        ::close(acceptedFd);
    }

    if (res.session->outboundFd() >= 0)
    {
        ::close(res.session->outboundFd());
    }
    ::close(listenFd);

    core.stop();
    EXPECT_EQ(core.activeSessions(), 0u);
}

// =============================================================================
// 5. 拓扑闭包校验与出入站双向生命周期联动
// =============================================================================

TEST(CoreTest, StartFailsOnDanglingRouteRuleOutbound)
{
    Core core;
    // 添加一条指向不存在节点的悬空规则
    core.router().addRule(RouteRule::to("phantom-proxy").domainSuffix("bad.com"));

    // start() 应当执行 Fail-Fast 拓扑校验，拒绝启动
    auto res = core.start();
    EXPECT_FALSE(res.has_value());
    EXPECT_FALSE(core.isRunning());
}

TEST(CoreTest, StartAndStopManagesBothInboundsAndOutbounds)
{
    Core core;
    auto in = std::make_shared<InboundSocks5>("test-in", "127.0.0.1", 0);
    auto out = std::make_shared<OutboundDirect>("custom-direct");
    core.acceptors().registerAcceptor(in);
    core.dialers().registerDialer(out);

    EXPECT_FALSE(in->isRunning());
    EXPECT_FALSE(out->isRunning());

    ASSERT_TRUE(core.start().has_value());
    EXPECT_TRUE(core.isRunning());
    EXPECT_TRUE(in->isRunning());
    EXPECT_TRUE(out->isRunning());
    EXPECT_TRUE(core.dialers().isRunning());

    core.stop();
    EXPECT_FALSE(core.isRunning());
    EXPECT_FALSE(in->isRunning());
    EXPECT_FALSE(out->isRunning());
    EXPECT_FALSE(core.dialers().isRunning());
}

// =============================================================================
// 6. Core 数据面直接桥接与会话管理测试 (Direct Bridge & Session Lifecycle)
// =============================================================================

TEST(CoreTest, DirectBridgeAndSessionManagement)
{
    Core core;
    ASSERT_TRUE(core.start().has_value());

    HandlerInboundDirect inbound;
    HandlerOutboundDirect outbound;

    auto session = core.bridge(inbound, outbound);
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(core.activeSessions(), 1u);

    const std::string payload = "CORE_FACADE_BRIDGE_PAYLOAD";
    [[maybe_unused]] auto _ = inbound.appendRequest(payload);
    inbound.handle();

    size_t pumped = core.tick();
    EXPECT_EQ(pumped, payload.size());
    ASSERT_TRUE(outbound.hasResponse());
    EXPECT_EQ(outbound.takeResponse(), payload);

    core.closeSession(session->id());
    EXPECT_EQ(core.activeSessions(), 0u);

    core.stop();
}

TEST(CoreTest, ApplyConfigHotReloadClearsStaleRulesAndConfiguresTransport)
{
    MynetConfig cfg1;
    InboundConfig in1;
    in1.tag = "in1";
    in1.protocol = "socks5";
    in1.host = "127.0.0.1";
    in1.port = 0;
    cfg1.inbounds.push_back(in1);

    OutboundConfig out1;
    out1.tag = "ss1";
    out1.type = "shadowsocks";
    out1.host = "127.0.0.1";
    out1.port = 18388;
    out1.method = "aes-128-gcm";
    out1.password = "pw1";
    cfg1.outbounds.push_back(out1);

    RouteRuleConfig rule1;
    rule1.domains = {"old.example.com"};
    rule1.outbound = "ss1";
    cfg1.router.rules.push_back(rule1);

    Core core(cfg1);
    EXPECT_TRUE(core.acceptors().has("in1"));
    EXPECT_TRUE(core.dialers().has("ss1"));
    RouteContext oldCtx;
    oldCtx.target = ProxyAddress::fromDomain("old.example.com", 443);
    EXPECT_EQ(core.router().match(oldCtx), "ss1");

    MynetConfig cfg2;
    InboundConfig in2;
    in2.tag = "in2";
    in2.protocol = "mixed";
    in2.host = "127.0.0.1";
    in2.port = 0;
    cfg2.inbounds.push_back(in2);

    RouteRuleConfig rule2;
    rule2.domains = {"new.example.org"};
    rule2.outbound = "direct";
    cfg2.router.rules.push_back(rule2);

    core.applyConfig(cfg2);
    EXPECT_FALSE(core.acceptors().has("in1"));
    EXPECT_TRUE(core.acceptors().has("in2"));
    EXPECT_FALSE(core.dialers().has("ss1"));
    EXPECT_TRUE(core.dialers().has("direct"));
    EXPECT_TRUE(core.dialers().has("block"));
    // 旧规则必须已被清理，不能再路由到不存在的 ss1
    EXPECT_EQ(core.router().match(oldCtx), "direct");
    RouteContext newCtx;
    newCtx.target = ProxyAddress::fromDomain("new.example.org", 443);
    EXPECT_EQ(core.router().match(newCtx), "direct");

    transport::TransportConfig wsCfg;
    wsCfg.type = transport::TransportType::WEBSOCKET;
    wsCfg.path = "/ws";
    EXPECT_TRUE(core.configureInboundTransport("in2", wsCfg).has_value());
    EXPECT_FALSE(core.configureInboundTransport("missing-in", wsCfg).has_value());
    EXPECT_TRUE(core.configureOutboundTransport("direct", wsCfg).has_value());
    EXPECT_FALSE(core.configureOutboundTransport("missing-out", wsCfg).has_value());
}

TEST(CoreTest, SingBoxDeclarativeTransportAutoWiredInCore)
{
    const std::string singboxJson = R"JSON({
        "inbounds": [
            {
                "type": "vless",
                "tag": "vless-ws-in",
                "listen": "127.0.0.1",
                "listen_port": 0,
                "users": [{"uuid": "de04add9-5c1a-4b08-8e65-244e45cf5483"}],
                "transport": {
                    "type": "ws",
                    "path": "/ws-inbound",
                    "headers": {"Host": "in.cdn.test"}
                }
            }
        ],
        "outbounds": [
            {
                "type": "vless",
                "tag": "vless-ws-out",
                "server": "127.0.0.1",
                "server_port": 443,
                "uuid": "de04add9-5c1a-4b08-8e65-244e45cf5483",
                "tls": {
                    "enabled": true,
                    "server_name": "out.sni.test",
                    "alpn": ["h2", "http/1.1"]
                },
                "transport": {
                    "type": "ws",
                    "path": "/ws-outbound",
                    "headers": {"Host": "out.cdn.test"}
                }
            }
        ]
    })JSON";

    auto parsed = mynet::config::singbox::parseSingBoxConfig(singboxJson);
    ASSERT_TRUE(parsed.has_value()) << parsed.error();
    ASSERT_EQ(parsed->inbounds.size(), 1u);
    EXPECT_EQ(parsed->inbounds[0].transport.type, transport::TransportType::WEBSOCKET);
    EXPECT_EQ(parsed->inbounds[0].transport.path, "/ws-inbound");
    EXPECT_EQ(parsed->inbounds[0].transport.host, "in.cdn.test");

    ASSERT_EQ(parsed->outbounds.size(), 1u);
    EXPECT_EQ(parsed->outbounds[0].transport.type, transport::TransportType::WEBSOCKET);
    EXPECT_EQ(parsed->outbounds[0].transport.path, "/ws-outbound");
    EXPECT_EQ(parsed->outbounds[0].transport.host, "out.cdn.test");
    EXPECT_TRUE(parsed->outbounds[0].transport.enableTls);
    EXPECT_EQ(parsed->outbounds[0].transport.sni, "out.sni.test");
    EXPECT_EQ(parsed->outbounds[0].transport.alpnProtocols, "h2,http/1.1");

    Core core(*parsed);
    auto acc = core.acceptors().get("vless-ws-in");
    ASSERT_NE(acc, nullptr);
    EXPECT_EQ(acc->transportConfig().type, transport::TransportType::WEBSOCKET);
    EXPECT_EQ(acc->transportConfig().path, "/ws-inbound");
    EXPECT_EQ(acc->transportConfig().host, "in.cdn.test");

    auto dialer = core.dialers().get("vless-ws-out");
    ASSERT_NE(dialer, nullptr);
    EXPECT_EQ(dialer->transportConfig().type, transport::TransportType::WEBSOCKET);
    EXPECT_EQ(dialer->transportConfig().path, "/ws-outbound");
    EXPECT_EQ(dialer->transportConfig().host, "out.cdn.test");
    EXPECT_TRUE(dialer->transportConfig().enableTls);
    EXPECT_EQ(dialer->transportConfig().sni, "out.sni.test");
}

TEST(CoreTest, AttachEventLoopDrivesOutboundWatchWithoutPolling)
{
    int listenFd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    ASSERT_GE(listenFd, 0);

    int opt = 1;
    ::setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in listenAddr{};
    listenAddr.sin_family = AF_INET;
    listenAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    listenAddr.sin_port = 0;
    ASSERT_EQ(::bind(listenFd, reinterpret_cast<sockaddr *>(&listenAddr), sizeof(listenAddr)), 0);
    ASSERT_EQ(::listen(listenFd, 4), 0);

    socklen_t slen = sizeof(listenAddr);
    ASSERT_EQ(::getsockname(listenFd, reinterpret_cast<sockaddr *>(&listenAddr), &slen), 0);
    const uint16_t port = ntohs(listenAddr.sin_port);

    Core core;
    ASSERT_TRUE(core.start().has_value());
    Reactor<AcceptorBase<HandlerConnection>> reactor;
    core.attachEventLoop(reactor.loop());

    HandlerInboundDirect inbound(ProxyAddress::fromIPv4(htonl(INADDR_LOOPBACK), port));
    ASSERT_TRUE(inbound.appendRequest("ping-evloop").has_value());

    auto res = core.dispatch(inbound, -1, "mixed-in", false, true);
    ASSERT_EQ(res.status, CoreDispatchStatus::SUCCESS);
    ASSERT_NE(res.session, nullptr);
    EXPECT_GE(res.session->outboundFd(), 0);

    int acceptedFd = -1;
    bool sentReply = false;
    bool gotDownlink = false;
    std::string downlink;

    reactor.loop().runEvery(std::chrono::milliseconds(5),
                            [&]()
                            {
                                if (acceptedFd < 0)
                                {
                                    sockaddr_in peer{};
                                    socklen_t plen = sizeof(peer);
                                    acceptedFd = ::accept4(listenFd, reinterpret_cast<sockaddr *>(&peer), &plen,
                                                           SOCK_NONBLOCK | SOCK_CLOEXEC);
                                }
                                if (acceptedFd >= 0 && !sentReply)
                                {
                                    constexpr char kReply[] = "pong-without-tick";
                                    if (::send(acceptedFd, kReply, sizeof(kReply) - 1, MSG_NOSIGNAL) ==
                                        static_cast<ssize_t>(sizeof(kReply) - 1))
                                    {
                                        sentReply = true;
                                    }
                                }
                                if (inbound.hasResponse())
                                {
                                    downlink.append(inbound.takeResponse());
                                    if (downlink == "pong-without-tick")
                                    {
                                        gotDownlink = true;
                                        reactor.stop();
                                    }
                                }
                            });
    reactor.loop().runAfter(std::chrono::milliseconds(1500), [&]() { reactor.stop(); });

    EXPECT_TRUE(reactor.loop().run().has_value());
    EXPECT_TRUE(gotDownlink);
    EXPECT_EQ(downlink, "pong-without-tick");

    core.closeSession(res.session->id());
    EXPECT_EQ(core.activeSessions(), 0u);
    core.clearEventLoop();
    core.stop();
    if (acceptedFd >= 0)
    {
        ::close(acceptedFd);
    }
    ::close(listenFd);
}

#if defined(MYNET_ENABLE_URING)
TEST(CoreTest, ProactorLoopHooksAndDeferredConnectParity)
{
    int listenFd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    ASSERT_GE(listenFd, 0);
    sockaddr_in listenAddr{};
    listenAddr.sin_family = AF_INET;
    listenAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    listenAddr.sin_port = 0;
    ASSERT_EQ(::bind(listenFd, reinterpret_cast<sockaddr *>(&listenAddr), sizeof(listenAddr)), 0);
    ASSERT_EQ(::listen(listenFd, 4), 0);
    socklen_t slen = sizeof(listenAddr);
    ASSERT_EQ(::getsockname(listenFd, reinterpret_cast<sockaddr *>(&listenAddr), &slen), 0);
    const uint16_t port = ntohs(listenAddr.sin_port);

    Core core;
    ASSERT_TRUE(core.start().has_value());
    Proactor<AcceptorBase<HandlerConnection>> proactor;
    core.attachEventLoop(proactor.loop());

    EXPECT_TRUE(core.forwarder()->loopHooks().hasAsyncRelay());
    EXPECT_TRUE(core.forwarder()->loopHooks().deferOutboundConnect);

    // 验证定时器、watch 与跨线程任务队列接口与 Reactor::loop() 完全对等
    const uint64_t tid = proactor.loop().runEvery(std::chrono::seconds(1), [&core]() { core.sweepIdleSessions(60); });
    EXPECT_GT(tid, 0u);
    EXPECT_TRUE(proactor.loop().cancelTimer(tid).has_value());

    int sv[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sv), 0);
    EXPECT_TRUE(proactor.loop().addWatch(sv[0], EPOLLIN, [](uint32_t) {}));
    EXPECT_TRUE(proactor.loop().modWatch(sv[0], EPOLLIN | EPOLLOUT));
    proactor.loop().delWatch(sv[0]);
    ::close(sv[0]);
    ::close(sv[1]);

    HandlerInboundDirect inbound(ProxyAddress::fromIPv4(htonl(INADDR_LOOPBACK), port));
    ASSERT_TRUE(inbound.appendRequest("deferred-uring-req").has_value());
    auto res = core.dispatch(inbound, -1, "mixed-in", false, true);
    ASSERT_EQ(res.status, CoreDispatchStatus::SUCCESS);
    ASSERT_NE(res.session, nullptr);
    EXPECT_TRUE(res.session->proactorManaged());
    EXPECT_TRUE(res.session->isOutboundConnecting());
    EXPECT_TRUE(res.session->isOutboundConnectDeferred());
    EXPECT_EQ(res.session->outboundTargetAddr().sin_port, htons(port));

    core.closeSession(res.session->id());
    EXPECT_EQ(core.activeSessions(), 0u);
    core.clearEventLoop();
    proactor.reset();
    core.stop();
    ::close(listenFd);
}

TEST(CoreTest, ProactorEndToEndOutboundAsyncConnectRecvSend)
{
    int listenFd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    ASSERT_GE(listenFd, 0);
    int opt = 1;
    ::setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in listenAddr{};
    listenAddr.sin_family = AF_INET;
    listenAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    listenAddr.sin_port = 0;
    ASSERT_EQ(::bind(listenFd, reinterpret_cast<sockaddr *>(&listenAddr), sizeof(listenAddr)), 0);
    ASSERT_EQ(::listen(listenFd, 4), 0);
    socklen_t slen = sizeof(listenAddr);
    ASSERT_EQ(::getsockname(listenFd, reinterpret_cast<sockaddr *>(&listenAddr), &slen), 0);
    const uint16_t port = ntohs(listenAddr.sin_port);

    Core core;
    ASSERT_TRUE(core.start().has_value());
    Proactor<AcceptorBase<HandlerConnection>> proactor;
    ASSERT_TRUE(proactor.listenTcp("127.0.0.1", 0).has_value());
    core.attachEventLoop(proactor.loop());

    HandlerInboundDirect inbound(ProxyAddress::fromIPv4(htonl(INADDR_LOOPBACK), port));
    ASSERT_TRUE(inbound.appendRequest("ping-proactor-outbound").has_value());

    auto res = core.dispatch(inbound, -1, "mixed-in", false, true);
    ASSERT_EQ(res.status, CoreDispatchStatus::SUCCESS);
    ASSERT_NE(res.session, nullptr);

    int acceptedFd = -1;
    bool sentReply = false;
    bool gotDownlink = false;
    std::string downlink;
    std::string uplink;

    const uint64_t pollTimer = proactor.loop().runEvery(
        std::chrono::milliseconds(5),
        [&]()
        {
            if (acceptedFd < 0)
            {
                sockaddr_in peer{};
                socklen_t plen = sizeof(peer);
                acceptedFd = ::accept4(listenFd, reinterpret_cast<sockaddr *>(&peer), &plen,
                                       SOCK_NONBLOCK | SOCK_CLOEXEC);
            }
            if (acceptedFd >= 0)
            {
                char buf[128];
                ssize_t rn = ::recv(acceptedFd, buf, sizeof(buf), 0);
                if (rn > 0)
                {
                    uplink.append(buf, static_cast<size_t>(rn));
                    if (!sentReply && uplink == "ping-proactor-outbound")
                    {
                        constexpr char kReply[] = "pong-proactor-outbound";
                        [[maybe_unused]] auto _ = ::send(acceptedFd, kReply, sizeof(kReply) - 1, MSG_NOSIGNAL);
                        sentReply = true;
                    }
                }
            }
            if (inbound.hasResponse())
            {
                downlink.append(inbound.takeResponse());
                if (downlink == "pong-proactor-outbound")
                {
                    gotDownlink = true;
                    proactor.stop();
                }
            }
        });
    (void)proactor.loop().runAfter(std::chrono::milliseconds(1500), [&]() { proactor.stop(); });

    ServerConfig srv;
    srv.idleTimeoutSecs = 5;
    ProactorConfig pc;
    pc.sqEntries = 64;
    pc.cqEntries = 128;
    pc.cqeWaitMs = 20;
    auto serveRes = proactor.serve(srv, pc);
    [[maybe_unused]] auto _c = proactor.loop().cancelTimer(pollTimer);

    core.closeSession(res.session->id());
    core.clearEventLoop();
    proactor.reset();
    core.stop();
    if (acceptedFd >= 0)
    {
        ::close(acceptedFd);
    }
    ::close(listenFd);

    if (!serveRes && serveRes.error() == ERR::URING_QUEUE_FAILED)
    {
        GTEST_SKIP() << "io_uring_queue_init restricted in sandbox environment";
    }
    EXPECT_TRUE(serveRes.has_value());
    EXPECT_TRUE(gotDownlink);
    EXPECT_EQ(downlink, "pong-proactor-outbound");
}
#endif

TEST(CoreTest, ConfigDatagramInboundOutboundAndDispatchEventDriven)
{
    MynetConfig cfg;
    InboundConfig inCfg;
    inCfg.tag = "udp-in";
    inCfg.protocol = "datagram";
    inCfg.host = "127.0.0.1";
    inCfg.port = 0;
    cfg.inbounds.push_back(inCfg);

    OutboundConfig outCfg;
    outCfg.tag = "udp-out";
    outCfg.type = "datagram";
    cfg.outbounds.push_back(outCfg);

    RouteRuleConfig rule;
    rule.network = "udp";
    rule.inboundTags = {"udp-in"};
    rule.outbound = "udp-out";
    cfg.router.rules.push_back(rule);

    Core core(cfg);
    ASSERT_TRUE(core.start().has_value());
    EXPECT_TRUE(core.acceptors().has("udp-in"));
    EXPECT_TRUE(core.dialers().has("udp-out"));

    auto remoteEcho = Datagram::bind("127.0.0.1", 0);
    ASSERT_TRUE(remoteEcho.has_value());
    const uint16_t echoPort = remoteEcho->localPort();

    Reactor<AcceptorBase<HandlerConnection>> reactor;
    core.attachEventLoop(reactor.loop());

    Handler inbound;
    sockaddr_in clientPeer{};
    clientPeer.sin_family = AF_INET;
    clientPeer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    clientPeer.sin_port = htons(54321);

    auto txRes = core.dispatchDatagram(inbound, clientPeer, ProxyAddress::fromIPv4(htonl(INADDR_LOOPBACK), echoPort),
                                     "hello-core-udp", "udp-in");
    ASSERT_TRUE(txRes.has_value());
    EXPECT_EQ(*txRes, 14u);
    EXPECT_EQ(core.forwarder()->activeDatagramSessions(), 1u);

    bool echoed = false;
    std::string reply;
    reactor.loop().runEvery(std::chrono::milliseconds(5),
                            [&]()
                            {
                                (void)remoteEcho->drain(
                                    [&](const DatagramView &v)
                                    {
                                        [[maybe_unused]] auto _ = remoteEcho->sendTo(v.peer, "reply-core-udp");
                                    });
                                if (inbound.hasOutgoing())
                                {
                                    reply = inbound.takeOutgoing().bytes;
                                    echoed = true;
                                    reactor.stop();
                                }
                            });
    reactor.loop().runAfter(std::chrono::milliseconds(1500), [&]() { reactor.stop(); });

    EXPECT_TRUE(reactor.loop().run().has_value());
    EXPECT_TRUE(echoed);
    EXPECT_EQ(reply, "reply-core-udp");

    core.clearEventLoop();
    core.stop();
    EXPECT_EQ(core.forwarder()->activeDatagramSessions(), 0u);
}

TEST(CoreIntegration, EbpfFwmarkPropagatedToNonBlockOutboundsAndNonVerdictSockmap)
{
    MynetConfig cfg;
    InboundConfig inCfg;
    inCfg.tag = "udp-tproxy";
    inCfg.protocol = "datagram";
    inCfg.host = "127.0.0.1";
    inCfg.port = 0;
    cfg.inbounds.push_back(inCfg);

    OutboundConfig outCustom;
    outCustom.tag = "custom-direct";
    outCustom.type = "direct";
    cfg.outbounds.push_back(outCustom);

    cfg.ebpf.enabled = true;
    cfg.ebpf.fwmark = 0x1234;

    Core core(cfg);
    ASSERT_TRUE(core.start().has_value());

    // 默认 direct 与未显式设 mark 的 direct 出站都应自动继承 ebpf.fwmark 防止回环
    auto defDirect = core.dialers().get("direct");
    auto customDirect = core.dialers().get("custom-direct");
    auto blockDl = core.dialers().get("block");
    ASSERT_NE(defDirect, nullptr);
    ASSERT_NE(customDirect, nullptr);
    ASSERT_NE(blockDl, nullptr);
    EXPECT_EQ(defDirect->mark(), 0x1234u);
    EXPECT_EQ(customDirect->mark(), 0x1234u);
    EXPECT_EQ(blockDl->mark(), 0u);

    // 若未完整挂载 sk_skb/stream_verdict，Forwarder sockmapFd 应保持 -1（回落 ZERO_COPY_SPLICE）
    ASSERT_NE(core.ebpf(), nullptr);
    if (!core.ebpf()->isVerdictAttached())
    {
        EXPECT_EQ(core.ebpf()->sockMapFd(), -1);
        EXPECT_EQ(core.forwarder()->sockmapFd(), -1);
    }

    core.stop();
}

TEST(CoreIntegration, ReactorAdoptConnectionBridgesThreeTierForwarderEndToEnd)
{
    // 1. 建立本地 Echo TCP 上游服务
    Acceptor listenEcho("echo", "direct", "127.0.0.1", 0);
    ASSERT_TRUE(listenEcho.listen(16, true, false).has_value());
    const uint16_t echoPort = listenEcho.port();

    MynetConfig cfg;
    Core core(cfg);
    ASSERT_TRUE(core.start().has_value());

    Reactor<AcceptorBase<HandlerConnection>> reactor;
    core.attachEventLoop(reactor.loop());

    // 2. 用自定义透明重定向类模拟 TProxy 获取到原始目的端口
    class LoopbackTProxyHandler final : public handler::HandlerInboundTProxy
    {
    public:
        explicit LoopbackTProxyHandler(uint16_t targetPort) : targetPort_(targetPort) {}

    protected:
        std::optional<ProxyAddress> fetchOriginalDst() override
        {
            return ProxyAddress::fromIPv4(htonl(INADDR_LOOPBACK), targetPort_);
        }

    private:
        uint16_t targetPort_{0};
    };

    int cliFd[2] = {-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, cliFd), 0);

    auto h = std::make_unique<LoopbackTProxyHandler>(echoPort);
    h->setSniffing(false);
    auto *conn = new Connection();
    conn->setFd(cliFd[1]);
    conn->setTransport(TransportType::TCP);
    h->onConnect(cliFd[1]);

    ForwardMode dispatchedMode = ForwardMode::BUFFER_PUMP;
    std::shared_ptr<ForwarderStreamSession> dispatchedSession;
    bool dispatched = false;
    Handler *rawH = h.get();
    h->setOnRequest(
        [&](uint8_t, const ProxyAddress &)
        {
            if (dispatched)
            {
                return;
            }
            dispatched = true;
            auto res = core.dispatch(*rawH, rawH->fd(), "", false, true);
            if (res.ok() && res.session != nullptr)
            {
                dispatchedSession = res.session;
                dispatchedMode = res.session->activeMode();
            }
        });
    conn->setOwnedHandler(std::move(h));
    ASSERT_TRUE(reactor.adoptConnection(conn));
    conn->handle();

    EXPECT_TRUE(dispatched);
    ASSERT_NE(dispatchedSession, nullptr);
    // 非阻塞建连进行中先安全停留在 BUFFER_PUMP（或在立即完成时直达 ZERO_COPY_SPLICE），禁止提前挂载 Sockmap/Splice
    EXPECT_TRUE(dispatchedMode == ForwardMode::BUFFER_PUMP || dispatchedMode == ForwardMode::ZERO_COPY_SPLICE);

    // 接受 upstream 连接并在事件循环线程侧回显
    int serverConnFd = -1;
    std::string echoedBack;
    constexpr std::string_view kPing = "core-reactor-adopt-echo-payload";
    ASSERT_EQ(::send(cliFd[0], kPing.data(), kPing.size(), 0), static_cast<ssize_t>(kPing.size()));

    reactor.loop().runEvery(std::chrono::milliseconds(5),
                            [&]()
                            {
                                if (serverConnFd < 0)
                                {
                                    auto accRes = listenEcho.acceptOne();
                                    if (accRes)
                                    {
                                        serverConnFd = accRes->first;
                                    }
                                }
                                if (serverConnFd >= 0)
                                {
                                    char buf[128]{};
                                    const ssize_t n = ::recv(serverConnFd, buf, sizeof(buf), 0);
                                    if (n > 0)
                                    {
                                        [[maybe_unused]] auto _ = ::send(serverConnFd, buf, static_cast<size_t>(n), 0);
                                    }
                                }
                                char cbuf[128]{};
                                const ssize_t cn = ::recv(cliFd[0], cbuf, sizeof(cbuf), 0);
                                if (cn > 0)
                                {
                                    echoedBack.append(cbuf, static_cast<size_t>(cn));
                                    if (echoedBack.size() >= kPing.size())
                                    {
                                        reactor.stop();
                                    }
                                }
                            });
    reactor.loop().runAfter(std::chrono::milliseconds(1500), [&]() { reactor.stop(); });

    EXPECT_TRUE(reactor.loop().run().has_value());
    EXPECT_EQ(echoedBack, kPing);
    // 建连完成且无内核 Sockmap 挂载时应已自适应升阶至 ZERO_COPY_SPLICE
    EXPECT_EQ(dispatchedSession->activeMode(), ForwardMode::ZERO_COPY_SPLICE);

    if (serverConnFd >= 0)
    {
        ::close(serverConnFd);
    }
    ::close(cliFd[0]);
    core.clearEventLoop();
    core.stop();
}
