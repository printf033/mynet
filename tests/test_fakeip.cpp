#include "address.hpp"
#include "core.hpp"
#include "direct/direct.hpp"
#include "fakeip.hpp"
#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <netinet/in.h>

using namespace mynet;

// =============================================================================
// 1. FakeIP 地址池基础分配与双向解析测试
// =============================================================================

TEST(FakeIPTest, AllocateAndBidirectionalLookup)
{
    auto &pool = FakeIPPool::instance();
    pool.reset();
    EXPECT_EQ(pool.size(), 0u);

    // 为 google.com 分配 FakeIP
    in_addr ip1 = pool.allocate("google.com");
    EXPECT_TRUE(pool.isFakeIp(ip1));
    EXPECT_EQ(pool.size(), 1u);

    // 验证反查
    auto domain1 = pool.lookup(ip1);
    ASSERT_TRUE(domain1.has_value());
    EXPECT_EQ(*domain1, "google.com");

    // 验证正查
    auto lookupIp1 = pool.lookupIp("google.com");
    ASSERT_TRUE(lookupIp1.has_value());
    EXPECT_EQ(lookupIp1->s_addr, ip1.s_addr);

    // 重复分配同一域名应幂等返回同一 IP
    in_addr ip1Repeat = pool.allocate("google.com");
    EXPECT_EQ(ip1Repeat.s_addr, ip1.s_addr);
    EXPECT_EQ(pool.size(), 1u);

    // 为不同域名分配不同 FakeIP
    in_addr ip2 = pool.allocate("github.com");
    EXPECT_TRUE(pool.isFakeIp(ip2));
    EXPECT_NE(ip2.s_addr, ip1.s_addr);
    EXPECT_EQ(pool.size(), 2u);

    auto domain2 = pool.lookup(ip2);
    ASSERT_TRUE(domain2.has_value());
    EXPECT_EQ(*domain2, "github.com");

    // 检验普通公网 IP 不属于 FakeIP
    in_addr realIp{};
    ::inet_pton(AF_INET, "8.8.8.8", &realIp);
    EXPECT_FALSE(pool.isFakeIp(realIp));
    EXPECT_FALSE(pool.lookup(realIp).has_value());

    pool.reset();
    EXPECT_EQ(pool.size(), 0u);
}

// =============================================================================
// 2. FakeIP 地址池 LRU 淘汰机制测试
// =============================================================================

TEST(FakeIPTest, LruEvictionOnCapacityOverflow)
{
    // 创建一个容量仅为 3 的微型地址池
    FakeIPPool smallPool(3);
    EXPECT_EQ(smallPool.size(), 0u);

    in_addr ipA = smallPool.allocate("a.com");
    in_addr ipB = smallPool.allocate("b.com");
    in_addr ipC = smallPool.allocate("c.com");
    EXPECT_EQ(smallPool.size(), 3u);

    // 访问 a.com，使其变为最近活跃
    in_addr ipARepeat = smallPool.allocate("a.com");
    EXPECT_EQ(ipARepeat.s_addr, ipA.s_addr);

    // 分配第 4 个域名 d.com，应淘汰最老未访问的 b.com
    in_addr ipD = smallPool.allocate("d.com");
    EXPECT_EQ(smallPool.size(), 3u);

    EXPECT_TRUE(smallPool.lookup(ipA).has_value());
    EXPECT_TRUE(smallPool.lookup(ipC).has_value());
    EXPECT_TRUE(smallPool.lookup(ipD).has_value());
    EXPECT_FALSE(smallPool.lookup(ipB).has_value());
    EXPECT_FALSE(smallPool.lookupIp("b.com").has_value());
}

// =============================================================================
// 3. Core 数据平面分发与 FakeIP 原始域名自动还原测试
// =============================================================================

TEST(FakeIPTest, CoreDispatchAutoRestoresDomainFromFakeIp)
{
    auto &pool = FakeIPPool::instance();
    pool.reset();

    // 客户端先进行了 DNS 查询，分配了 FakeIP
    in_addr fakeIp = pool.allocate("api.openai.com");

    Core core;
    // 规则：针对 openai.com 流量分流至 block
    core.router().addRule(RouteRule::to("block").domainSuffix("openai.com"));
    ASSERT_TRUE(core.start().has_value());

    // 客户端向 FakeIP:443 发起连接（入站未嗅探，仅持有目标 FakeIP）
    auto target = handler::ProxyAddress::fromIPv4(fakeIp.s_addr, 443);
    handler::HandlerInboundDirect inbound(target);

    // Core 分发：应当识别 FakeIP 并自动还原出原始域名 "api.openai.com"，从而精准命中 block 出站
    auto res = core.dispatch(inbound, -1, "tproxy-in", false);
    EXPECT_EQ(res.status, CoreDispatchStatus::BLOCKED);
    EXPECT_EQ(res.outboundTag, "block");
    EXPECT_EQ(res.target.type, handler::AddressType::DOMAIN);
    EXPECT_EQ(res.target.host, "api.openai.com");
    EXPECT_EQ(res.sniffedDomain, "api.openai.com");

    core.stop();
    pool.reset();
}
