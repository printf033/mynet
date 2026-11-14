#include "outboundManager.hpp"
#include "handler/address.hpp"
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

TEST(OutboundManagerTest, BlockOutboundBehavior)
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

TEST(OutboundManagerTest, DirectOutboundLocalhost)
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

TEST(OutboundManagerTest, SelectorOutboundSwitch)
{
    OutboundManager mgr;
    auto selector = std::make_shared<SelectorOutbound>("proxy_group", std::vector<std::string>{"direct", "block"});
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
// 5. 协议出站配置化注册与查询测试 (SOCKS5 / Trojan)
// =============================================================================

TEST(OutboundManagerTest, ProtocolOutboundRegistration)
{
    OutboundManager mgr;

    auto s5 = std::make_shared<Socks5Outbound>("my_socks5", "192.168.1.100", 1080, "user", "pass");
    EXPECT_EQ(s5->serverHost(), "192.168.1.100");
    EXPECT_EQ(s5->serverPort(), 1080);
    mgr.registerOutbound(s5);

    auto trojan = std::make_shared<TrojanOutbound>("my_trojan", "trojan.node.com", 443, "password123");
    EXPECT_EQ(trojan->serverHost(), "trojan.node.com");
    EXPECT_EQ(trojan->serverPort(), 443);
    mgr.registerOutbound(trojan);

    EXPECT_TRUE(mgr.has("my_socks5"));
    EXPECT_TRUE(mgr.has("my_trojan"));
    EXPECT_EQ(mgr.get("my_socks5")->type(), "socks5");
    EXPECT_EQ(mgr.get("my_trojan")->type(), "trojan");

    mgr.remove("my_trojan");
    EXPECT_FALSE(mgr.has("my_trojan"));
}
