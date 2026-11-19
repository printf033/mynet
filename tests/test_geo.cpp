#include "geo.hpp"
#include "router.hpp"
#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <netinet/in.h>

using namespace mynet;

// =============================================================================
// 1. GeoIP 国家与私网判定测试
// =============================================================================

TEST(GeoTest, GeoIpPrivateAndCountryMatching)
{
    auto &matcher = GeoIpMatcher::instance();

    // 1. 私有网段测试
    in_addr priv1{}, priv2{}, priv3{}, loopback{}, cgnat{}, pubIp{};
    ::inet_pton(AF_INET, "10.0.1.20", &priv1);
    ::inet_pton(AF_INET, "172.20.5.1", &priv2);
    ::inet_pton(AF_INET, "192.168.1.1", &priv3);
    ::inet_pton(AF_INET, "127.0.0.1", &loopback);
    ::inet_pton(AF_INET, "100.64.0.1", &cgnat);
    ::inet_pton(AF_INET, "8.8.8.8", &pubIp);

    EXPECT_TRUE(matcher.isPrivate(priv1));
    EXPECT_TRUE(matcher.isPrivate(priv2));
    EXPECT_TRUE(matcher.isPrivate(priv3));
    EXPECT_TRUE(matcher.isPrivate(loopback));
    EXPECT_TRUE(matcher.isPrivate(cgnat));
    EXPECT_FALSE(matcher.isPrivate(pubIp));

    EXPECT_TRUE(matcher.matches(priv1, "private"));
    EXPECT_FALSE(matcher.matches(pubIp, "private"));

    // 2. 内置 CN IP 匹配测试
    in_addr cnIp1{}, cnIp2{};
    ::inet_pton(AF_INET, "114.114.114.114", &cnIp1); // 114.0.0.0/8
    ::inet_pton(AF_INET, "223.5.5.5", &cnIp2);       // 223.0.0.0/8
    EXPECT_TRUE(matcher.matches(cnIp1, "cn"));
    EXPECT_TRUE(matcher.matches(cnIp2, "cn"));
    EXPECT_FALSE(matcher.matches(pubIp, "cn"));      // 8.8.8.8 是 US

    // 3. 动态扩展 CIDR 测试
    matcher.addCidr("us", "8.8.8.0/24");
    EXPECT_TRUE(matcher.matches(pubIp, "us"));
}

// =============================================================================
// 2. GeoSite 域名资产分类匹配测试
// =============================================================================

TEST(GeoTest, GeoSiteCategorization)
{
    auto &matcher = GeoSiteMatcher::instance();

    // 1. cn 分类：.cn 顶级域名与国内主流服务
    EXPECT_TRUE(matcher.matches("test.gov.cn", "cn"));
    EXPECT_TRUE(matcher.matches("api.bilibili.com", "cn"));
    EXPECT_TRUE(matcher.matches("www.baidu.com", "cn"));
    EXPECT_TRUE(matcher.matches("taobao.com", "cn"));
    EXPECT_FALSE(matcher.matches("google.com", "cn"));

    // 2. category-ads-all 分类
    EXPECT_TRUE(matcher.matches("pagead2.googlesyndication.com", "category-ads-all") ||
                matcher.matches("adservice.google.com", "category-ads-all"));
    EXPECT_TRUE(matcher.matches("stats.doubleclick.net", "category-ads-all"));

    // 3. google, github, telegram, netflix 分类
    EXPECT_TRUE(matcher.matches("www.google.com", "google"));
    EXPECT_TRUE(matcher.matches("github.com", "github"));
    EXPECT_TRUE(matcher.matches("avatars.githubusercontent.com", "github"));
    EXPECT_TRUE(matcher.matches("t.me", "telegram"));
    EXPECT_TRUE(matcher.matches("www.netflix.com", "netflix"));
    EXPECT_FALSE(matcher.matches("baidu.com", "google"));
}

// =============================================================================
// 3. Router 策略路由规则与 GeoIP / GeoSite 联动分流测试
// =============================================================================

TEST(GeoTest, RouterIntegrationWithGeoRules)
{
    Router router("proxy"); // 默认出站走 proxy

    // 规则 1：私网 IP 与国内 IP 走直连 (direct)
    router.addRule(RouteRule::to("direct").geoIp("private").geoIp("cn"));

    // 规则 2：国内域名走直连 (direct)
    router.addRule(RouteRule::to("direct").geoSite("cn"));

    // 规则 3：广告域名阻断 (block)
    router.addRule(RouteRule::to("block").geoSite("category-ads-all"));

    // 规则 4：来自 curl 进程的流量特定分流
    router.addRule(RouteRule::to("direct").forProcess("curl"));

    // Case 1: 私有局域网 IP 直连
    RouteContext ctx1;
    in_addr localIp{};
    ::inet_pton(AF_INET, "192.168.1.100", &localIp);
    ctx1.target = handler::ProxyAddress::fromIPv4(localIp.s_addr, 80);
    EXPECT_EQ(router.match(ctx1), "direct");

    // Case 2: 百度域名命中 geosite:cn 直连
    RouteContext ctx2;
    ctx2.target = handler::ProxyAddress::fromDomain("www.baidu.com", 443);
    EXPECT_EQ(router.match(ctx2), "direct");

    // Case 3: 广告域名命中 block
    RouteContext ctx3;
    ctx3.target = handler::ProxyAddress::fromDomain("adservice.google.com", 443);
    EXPECT_EQ(router.match(ctx3), "block");

    // Case 4: Google 域名未命中上述白名单/黑名单，回退到默认出站 proxy
    RouteContext ctx4;
    ctx4.target = handler::ProxyAddress::fromDomain("www.google.com", 443);
    EXPECT_EQ(router.match(ctx4), "proxy");

    // Case 5: 进程名匹配
    RouteContext ctx5;
    ctx5.processName = "curl";
    ctx5.target = handler::ProxyAddress::fromDomain("anywhere.org", 80);
    EXPECT_EQ(router.match(ctx5), "direct");
}
