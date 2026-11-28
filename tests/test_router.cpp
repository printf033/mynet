#include "address.hpp"
#include "router.hpp"
#include "sniffer.hpp"
#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <string_view>

using namespace mynet;
using namespace mynet::handler;
using namespace mynet::handler::sniffing;

// =============================================================================
// 1. IPv4 CIDR 子网判定测试
// =============================================================================

TEST(RouterTest, IpCidrMatching)
{
    auto cidr24 = IpCidr::parse("192.168.1.0/24");
    ASSERT_TRUE(cidr24.has_value());
    EXPECT_EQ(cidr24->prefixLen, 24);

    in_addr inSubnet{};
    ::inet_pton(AF_INET, "192.168.1.100", &inSubnet);
    EXPECT_TRUE(cidr24->matches(inSubnet));

    in_addr outSubnet{};
    ::inet_pton(AF_INET, "192.168.2.1", &outSubnet);
    EXPECT_FALSE(cidr24->matches(outSubnet));

    // 单 IP (/32)
    auto singleIp = IpCidr::parse("8.8.8.8");
    ASSERT_TRUE(singleIp.has_value());
    EXPECT_EQ(singleIp->prefixLen, 32);

    in_addr dnsIp{};
    ::inet_pton(AF_INET, "8.8.8.8", &dnsIp);
    EXPECT_TRUE(singleIp->matches(dnsIp));

    in_addr otherIp{};
    ::inet_pton(AF_INET, "8.8.4.4", &otherIp);
    EXPECT_FALSE(singleIp->matches(otherIp));

    // 全局掩码 (/0)
    auto cidr0 = IpCidr::parse("0.0.0.0/0");
    ASSERT_TRUE(cidr0.has_value());
    EXPECT_TRUE(cidr0->matches(dnsIp));
    EXPECT_TRUE(cidr0->matches(inSubnet));

    // RFC 1918 私有 IP 测试
    in_addr priv10{}, priv172{}, priv192{}, loopback{}, pubIp{};
    ::inet_pton(AF_INET, "10.1.2.3", &priv10);
    ::inet_pton(AF_INET, "172.20.1.1", &priv172);
    ::inet_pton(AF_INET, "192.168.0.1", &priv192);
    ::inet_pton(AF_INET, "127.0.0.1", &loopback);
    ::inet_pton(AF_INET, "1.1.1.1", &pubIp);

    EXPECT_TRUE(IpCidr::isPrivate(priv10));
    EXPECT_TRUE(IpCidr::isPrivate(priv172));
    EXPECT_TRUE(IpCidr::isPrivate(priv192));
    EXPECT_TRUE(IpCidr::isPrivate(loopback));
    EXPECT_FALSE(IpCidr::isPrivate(pubIp));
}

// =============================================================================
// 2. 端口与端口范围过滤测试
// =============================================================================

TEST(RouterTest, PortRangeMatching)
{
    auto p80 = PortRange::parse("80");
    ASSERT_TRUE(p80.has_value());
    EXPECT_TRUE(p80->matches(80));
    EXPECT_FALSE(p80->matches(81));

    auto range = PortRange::parse("8000-8080");
    ASSERT_TRUE(range.has_value());
    EXPECT_TRUE(range->matches(8000));
    EXPECT_TRUE(range->matches(8050));
    EXPECT_TRUE(range->matches(8080));
    EXPECT_FALSE(range->matches(7999));
    EXPECT_FALSE(range->matches(8081));

    auto dotRange = PortRange::parse("1000..2000");
    ASSERT_TRUE(dotRange.has_value());
    EXPECT_TRUE(dotRange->matches(1500));
}

// =============================================================================
// 3. 域名精确、后缀与关键字匹配测试
// =============================================================================

TEST(RouterTest, DomainRules)
{
    Router router("direct");

    // 精确域名 -> direct
    router.addRule(RouteRule::to("direct").domain("example.com"));

    // 域名后缀 -> proxy
    router.addRule(RouteRule::to("proxy").domainSuffix("google.com"));

    // 域名关键字 -> block
    router.addRule(RouteRule::to("block").domainKeyword("adservice"));

    RouteContext ctx1;
    ctx1.target = Address::fromDomain("example.com", 80);
    EXPECT_EQ(router.match(ctx1), "direct");

    // "sub.example.com" 不精确匹配 example.com，且无后缀规则，回落 default
    RouteContext ctxSub;
    ctxSub.target = Address::fromDomain("sub.example.com", 80);
    EXPECT_EQ(router.match(ctxSub), "direct");

    // "google.com" 与 "mail.google.com" 命中后缀规则 -> proxy
    RouteContext ctxGoogle;
    ctxGoogle.target = Address::fromDomain("google.com", 443);
    EXPECT_EQ(router.match(ctxGoogle), "proxy");

    RouteContext ctxMailGoogle;
    ctxMailGoogle.target = Address::fromDomain("mail.google.com", 443);
    EXPECT_EQ(router.match(ctxMailGoogle), "proxy");

    // "mygoogle.com" 不是 ".google.com" 子域，不应命中后缀规则
    RouteContext ctxMyGoogle;
    ctxMyGoogle.target = Address::fromDomain("mygoogle.com", 443);
    EXPECT_EQ(router.match(ctxMyGoogle), "direct");

    // 关键字匹配
    RouteContext ctxAd;
    ctxAd.target = Address::fromDomain("api.adservice.traffic.net", 80);
    EXPECT_EQ(router.match(ctxAd), "block");

    // 大小写不敏感测试
    RouteContext ctxCase;
    ctxCase.target = Address::fromDomain("WWW.GOOGLE.COM", 443);
    EXPECT_EQ(router.match(ctxCase), "proxy");
}

// =============================================================================
// 4. 深度嗅探协同分流测试 (Sniffing-Assisted Routing)
// =============================================================================

TEST(RouterTest, SniffingAssistedRoute)
{
    Router router("direct");

    // 针对 Netflix 走代理
    router.addRule(RouteRule::to("proxy_netflix").domainSuffix("netflix.com"));

    // 针对 BitTorrent 协议一律拦截
    router.addRule(RouteRule::to("block").protocol("bittorrent"));

    // 场景 A：透明代理只有目标 IP，但经过 Sniffer 嗅探出了 TLS SNI 为 "www.netflix.com"
    RouteContext ctxTls;
    in_addr netflixIp{};
    ::inet_pton(AF_INET, "198.51.100.2", &netflixIp);
    ctxTls.target = Address::fromIPv4(netflixIp.s_addr, 443);
    ctxTls.sniffedDomain = "www.netflix.com";
    ctxTls.sniffedProtocol = ProtocolType::TLS;

    EXPECT_EQ(router.match(ctxTls), "proxy_netflix");

    // 场景 B：客户端发起的 P2P 流量，嗅探出协议为 BitTorrent
    RouteContext ctxBt;
    in_addr btIp{};
    ::inet_pton(AF_INET, "203.0.113.5", &btIp);
    ctxBt.target = Address::fromIPv4(btIp.s_addr, 6881);
    ctxBt.sniffedProtocol = ProtocolType::BITTORRENT;

    EXPECT_EQ(router.match(ctxBt), "block");
}

// =============================================================================
// 5. 组合条件与入站标签过滤测试
// =============================================================================

TEST(RouterTest, CombinedAndInboundFilters)
{
    Router router("default_out");

    // 仅针对 "tproxy-in" 入站且端口为 53 的 DNS 查询走 dns_out
    router.addRule(RouteRule::to("dns_out").fromInbound("tproxy-in").forNetwork(NetworkType::UDP).port(53));

    // 内网 IP CIDR 直连
    router.addRule(RouteRule::to("direct").cidr("10.0.0.0/8").cidr("192.168.0.0/16"));

    // 规则 1 命中
    RouteContext ctxDns;
    ctxDns.inboundTag = "tproxy-in";
    ctxDns.network = NetworkType::UDP;
    ctxDns.target.port = 53;
    EXPECT_EQ(router.match(ctxDns), "dns_out");

    // 规则 1 未命中 (来自 socks-in)
    RouteContext ctxSocksDns;
    ctxSocksDns.inboundTag = "socks-in";
    ctxSocksDns.network = NetworkType::UDP;
    ctxSocksDns.target.port = 53;
    EXPECT_EQ(router.match(ctxSocksDns), "default_out");

    // 规则 2 命中 (私有 IP 直连)
    RouteContext ctxLan;
    in_addr lanIp{};
    ::inet_pton(AF_INET, "192.168.1.10", &lanIp);
    ctxLan.target = Address::fromIPv4(lanIp.s_addr, 80);
    EXPECT_EQ(router.match(ctxLan), "direct");
}

// =============================================================================
// 6. 命中计数统计与规则优先级测试
// =============================================================================

TEST(RouterTest, HitCounterAndPriority)
{
    Router router("fallback");

    // 先添加的规则具有更高优先级
    router.addRule(RouteRule::to("first_rule").domainSuffix("example.com"));
    router.addRule(RouteRule::to("second_rule").domainSuffix("example.com"));

    EXPECT_EQ(router.ruleCount(), 2u);

    RouteContext ctx;
    ctx.target = Address::fromDomain("test.example.com", 80);

    for (int i = 0; i < 5; ++i)
    {
        EXPECT_EQ(router.match(ctx), "first_rule");
    }

    auto rules = router.rulesSnapshot();
    ASSERT_EQ(rules.size(), 2u);
    EXPECT_EQ(rules[0].hitCount(), 5u);
    EXPECT_EQ(rules[1].hitCount(), 0u);
}

// =============================================================================
// 7. 智能嗅探绕转与嗅探必要性判定测试 (借鉴 dae InferSniffPunt)
// =============================================================================

TEST(RouterTest, ShouldSniffInference)
{
    Router router("direct");

    // 1. 无规则时，无需嗅探
    EXPECT_FALSE(router.shouldSniff());

    // 2. 只有 L3/L4 规则 (CIDR / Port) 时，无需嗅探，直接直连旁路
    router.addRule(RouteRule::to("direct").cidr("192.168.0.0/16").port(80));
    EXPECT_FALSE(router.shouldSniff());

    // 3. 追加域名或协议规则时，自动唤醒嗅探
    router.addRule(RouteRule::to("proxy").domainSuffix("google.com"));
    EXPECT_TRUE(router.shouldSniff());
}

// =============================================================================
// 8. must 规则强制决策锁定测试 (借鉴 dae must rule locking)
// =============================================================================

TEST(RouterTest, MustRuleLocking)
{
    Router router("direct");

    // 规则 1: 针对 DNS 服务器 223.5.5.5:53 强制锁定为 direct (must = true)
    router.addRule(RouteRule::to("direct").cidr("223.5.5.5/32").port(53).setMust(true));

    // 规则 2: 后续通用代理规则
    router.addRule(RouteRule::to("proxy").port(53));

    RouteContext ctx;
    in_addr dnsIp{};
    ::inet_pton(AF_INET, "223.5.5.5", &dnsIp);
    ctx.target = Address::fromIPv4(dnsIp.s_addr, 53);

    auto dec = router.matchWithDecision(ctx);
    EXPECT_EQ(dec.outboundTag, "direct");
    EXPECT_TRUE(dec.locked); // must 生效，决断锁定

    // 针对普通 8.8.8.8:53，未命中 must 规则，命中规则 2，不锁定
    in_addr googleDns{};
    ::inet_pton(AF_INET, "8.8.8.8", &googleDns);
    ctx.target = Address::fromIPv4(googleDns.s_addr, 53);

    auto dec2 = router.matchWithDecision(ctx);
    EXPECT_EQ(dec2.outboundTag, "proxy");
    EXPECT_FALSE(dec2.locked);
}
