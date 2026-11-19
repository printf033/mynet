#include "core.hpp"
#include "address.hpp"
#include "direct/direct.hpp"
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <sys/socket.h>
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
    EXPECT_TRUE(core.outbounds().has("direct"));
    EXPECT_TRUE(core.outbounds().has("block"));

    // 入站管理器注册与查询
    core.inbounds().registerInbound(std::make_shared<InboundSocks5>("my-socks-in", "127.0.0.1", 1080));
    EXPECT_TRUE(core.inbounds().has("my-socks-in"));
    EXPECT_EQ(core.inbounds().size(), 1u);

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
    core.inbounds().registerInbound(in);
    core.outbounds().registerOutbound(out);

    EXPECT_FALSE(in->isRunning());
    EXPECT_FALSE(out->isRunning());

    ASSERT_TRUE(core.start().has_value());
    EXPECT_TRUE(core.isRunning());
    EXPECT_TRUE(in->isRunning());
    EXPECT_TRUE(out->isRunning());
    EXPECT_TRUE(core.outbounds().isRunning());

    core.stop();
    EXPECT_FALSE(core.isRunning());
    EXPECT_FALSE(in->isRunning());
    EXPECT_FALSE(out->isRunning());
    EXPECT_FALSE(core.outbounds().isRunning());
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

