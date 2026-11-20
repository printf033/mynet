#include "address.hpp"
#include "outboundManager.hpp"
#include "shadowsocks/outbound.hpp"
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace mynet;
using namespace mynet::handler;

// =============================================================================
// 1. 默认出站与注册表基础测试
// =============================================================================

TEST(OutboundManagerTest, DefaultOutbounds)
{
    OutboundManager mgr;
    EXPECT_GE(mgr.size(), 2u);
    EXPECT_TRUE(mgr.has("direct"));
    EXPECT_TRUE(mgr.has("block"));
    EXPECT_EQ(mgr.defaultTag(), "direct");

    auto directOb = mgr.get("direct");
    ASSERT_NE(directOb, nullptr);
    EXPECT_EQ(directOb->tag(), "direct");
    EXPECT_EQ(directOb->type(), "direct");

    auto blockOb = mgr.get("block");
    ASSERT_NE(blockOb, nullptr);
    EXPECT_EQ(blockOb->tag(), "block");
    EXPECT_EQ(blockOb->type(), "block");

    auto tags = mgr.listTags();
    EXPECT_GE(tags.size(), 2u);
}

// =============================================================================
// 2. 拦截黑洞出站测试 (Block Outbound)
// =============================================================================

TEST(OutboundManagerTest, OutboundBlockBehavior)
{
    OutboundManager mgr;
    auto target = ProxyAddress::fromDomain("evil-malware.com", 80);

    auto res = mgr.dialStream("block", target);
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res->outboundTag, "block");
    EXPECT_EQ(res->fd, -1);
    ASSERT_NE(res->handler, nullptr);

    // 状态机应标记为已关闭/错误
    EXPECT_TRUE(res->handler->closeAfterResponse());
    EXPECT_EQ(res->handler->stage(), OutboundStage::ERROR);
}

// =============================================================================
// 3. 直连出站到本机监听测试 (Direct Outbound TCP Dial)
// =============================================================================

TEST(OutboundManagerTest, OutboundDirectLocalhost)
{
    // 在本地随机端口启动一个临时监听套接字
    int listenFd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    ASSERT_GE(listenFd, 0);

    sockaddr_in listenAddr{};
    listenAddr.sin_family = AF_INET;
    listenAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    listenAddr.sin_port = 0; // 系统分配空闲端口

    int opt = 1;
    ::setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    ASSERT_EQ(::bind(listenFd, reinterpret_cast<sockaddr *>(&listenAddr), sizeof(listenAddr)), 0);
    ASSERT_EQ(::listen(listenFd, 5), 0);

    socklen_t slen = sizeof(listenAddr);
    ASSERT_EQ(::getsockname(listenFd, reinterpret_cast<sockaddr *>(&listenAddr), &slen), 0);
    uint16_t port = ntohs(listenAddr.sin_port);

    // 使用 OutboundManager 直连出站
    OutboundManager mgr;
    auto target = ProxyAddress::fromIPv4(htonl(INADDR_LOOPBACK), port);

    auto res = mgr.dialStream("direct", target);
    ASSERT_TRUE(res.has_value());
    EXPECT_GE(res->fd, 0);
    EXPECT_EQ(res->outboundTag, "direct");
    ASSERT_NE(res->handler, nullptr);
    EXPECT_EQ(res->handler->stage(), OutboundStage::STREAMING);

    // 接受并验证服务端收到连接
    sockaddr_in peer{};
    socklen_t plen = sizeof(peer);
    int acceptedFd = ::accept4(listenFd, reinterpret_cast<sockaddr *>(&peer), &plen, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (acceptedFd >= 0)
    {
        ::close(acceptedFd);
    }

    if (res->fd >= 0)
    {
        ::close(res->fd);
    }
    ::close(listenFd);
}

// =============================================================================
// 4. 节点选择器测试 (Selector Outbound)
// =============================================================================

TEST(OutboundManagerTest, OutboundSelectorSwitch)
{
    OutboundManager mgr;
    auto selector = std::make_shared<OutboundSelector>("proxy_group", std::vector<std::string>{"direct", "block"});
    mgr.registerOutbound(selector);

    EXPECT_TRUE(mgr.has("proxy_group"));
    EXPECT_EQ(selector->selected(), "direct");

    auto target = ProxyAddress::fromDomain("test.com", 80);

    // 切换到 block 节点
    EXPECT_TRUE(selector->setSelected("block"));
    EXPECT_EQ(selector->selected(), "block");

    auto res = mgr.dialStream("proxy_group", target);
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res->outboundTag, "block");
    EXPECT_TRUE(res->handler->closeAfterResponse());
}

// =============================================================================
// 5. 协议出站配置化注册与查询测试 (SOCKS5 / Trojan / Shadowsocks)
// =============================================================================

TEST(OutboundManagerTest, ProtocolOutboundRegistration)
{
    OutboundManager mgr;

    auto s5 = std::make_shared<OutboundSocks5>("my_socks5", "192.168.1.100", 1080, "user", "pass");
    EXPECT_EQ(s5->serverHost(), "192.168.1.100");
    EXPECT_EQ(s5->serverPort(), 1080);
    mgr.registerOutbound(s5);

    auto trojan = std::make_shared<OutboundTrojan>("my_trojan", "trojan.node.com", 443, "password123");
    EXPECT_EQ(trojan->serverHost(), "trojan.node.com");
    EXPECT_EQ(trojan->serverPort(), 443);
    mgr.registerOutbound(trojan);

    DialerOptions ssOpt;
    ssOpt.fwmark = 0x100;
    ssOpt.tcpFastOpen = true;
    auto ss = std::make_shared<OutboundShadowsocks>("my_ss", "ss.node.com", 8388, "aes-128-gcm", "secret_key", ssOpt);
    EXPECT_EQ(ss->serverHost(), "ss.node.com");
    EXPECT_EQ(ss->serverPort(), 8388);
    EXPECT_EQ(ss->options().fwmark, 0x100);
    EXPECT_TRUE(ss->options().tcpFastOpen);
    mgr.registerOutbound(ss);

    EXPECT_TRUE(mgr.has("my_socks5"));
    EXPECT_TRUE(mgr.has("my_trojan"));
    EXPECT_TRUE(mgr.has("my_ss"));
    EXPECT_EQ(mgr.get("my_socks5")->type(), "socks5");
    EXPECT_EQ(mgr.get("my_trojan")->type(), "trojan");
    EXPECT_EQ(mgr.get("my_ss")->type(), "shadowsocks");

    mgr.remove("my_trojan");
    EXPECT_FALSE(mgr.has("my_trojan"));
}

// =============================================================================
// 6. LatenciesN 环形无锁滑动均值与容差阻尼窗口测试 (机制 63 & 64)
// =============================================================================

TEST(OutboundManagerTest, LatenciesNRingBuffer)
{
    LatenciesN<5> lat;
    EXPECT_EQ(lat.size(), 0u);
    EXPECT_EQ(lat.average(), 9999u);
    EXPECT_EQ(lat.latest(), 9999u);

    lat.add(100);
    EXPECT_EQ(lat.size(), 1u);
    EXPECT_EQ(lat.average(), 100u);
    EXPECT_EQ(lat.latest(), 100u);

    lat.add(200);
    lat.add(300);
    EXPECT_EQ(lat.size(), 3u);
    EXPECT_EQ(lat.average(), 200u); // (100+200+300)/3 = 200
    EXPECT_EQ(lat.latest(), 300u);

    lat.add(400);
    lat.add(500);
    EXPECT_EQ(lat.size(), 5u);
    EXPECT_EQ(lat.average(), 300u); // (100+200+300+400+500)/5 = 300
    EXPECT_EQ(lat.latest(), 500u);

    // 窗口滑出旧样本 100，加入 600
    lat.add(600);
    EXPECT_EQ(lat.size(), 5u);
    EXPECT_EQ(lat.average(), 400u); // (200+300+400+500+600)/5 = 400
    EXPECT_EQ(lat.latest(), 600u);

    lat.reset();
    EXPECT_EQ(lat.size(), 0u);
    EXPECT_EQ(lat.average(), 9999u);
}

TEST(OutboundManagerTest, UrlTestToleranceWindowDamping)
{
    OutboundManager mgr;
    std::vector<std::string> candidates = {"nodeA", "nodeB"};
    // toleranceMs = 20ms
    auto urlTest = std::make_shared<OutboundUrlTest>("auto_group", candidates, &mgr,
                                                     "http://cp.cloudflare.com/generate_204", 300, 20);

    // 初始状态下 nodeA 为默认主节点
    urlTest->setRtt("nodeA", 50);
    urlTest->setRtt("nodeB", 60);
    EXPECT_EQ(urlTest->getBestTag(), "nodeA");

    // nodeB 产生微小波动改善至 45ms (改善 5ms < tolerance 20ms)，不应发生切换阻尼生效
    urlTest->setRtt("nodeB", 45);
    EXPECT_EQ(urlTest->getBestTag(), "nodeA");

    // nodeB 再次微小改善至 35ms (与 nodeA 50ms 相比，差距 15ms 仍 < tolerance 20ms)，维持 nodeA
    urlTest->setRtt("nodeB", 35);
    EXPECT_EQ(urlTest->getBestTag(), "nodeA");

    // nodeB 延迟大幅改善至 25ms (差距 25ms >= tolerance 20ms)，触发切换至 nodeB
    urlTest->setRtt("nodeB", 25);
    EXPECT_EQ(urlTest->getBestTag(), "nodeB");

    // 反向测试：nodeA 产生微小优势 (nodeB 25ms, nodeA 20ms, 优势 5ms < 20ms)，维持 nodeB
    urlTest->setRtt("nodeA", 20);
    EXPECT_EQ(urlTest->getBestTag(), "nodeB");

    // nodeA 优势达到 25ms (nodeB 25ms, nodeA 0ms)，切换回 nodeA
    urlTest->setRtt("nodeA", 0);
    EXPECT_EQ(urlTest->getBestTag(), "nodeA");
}
