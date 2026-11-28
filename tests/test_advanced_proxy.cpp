#include "core.hpp"
#include "acceptorManager.hpp"
#include "dialerManager.hpp"
#include <fcntl.h>
#include <gtest/gtest.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>

using namespace mynet;

// =============================================================================
// 1. OutboundUrlTest 自动测速优选出站测试
// =============================================================================

TEST(AdvancedProxyTest, UrlTestSelectsLowestLatencyNode)
{
    DialerManager mgr;
    mgr.registerDialer(std::make_shared<DialerDirect>("hk-node"));
    mgr.registerDialer(std::make_shared<DialerDirect>("jp-node"));
    mgr.registerDialer(std::make_shared<DialerDirect>("us-node"));

    auto urltest = std::make_shared<DialerUrlTest>("auto-fastest",
                                                   std::vector<std::string>{"hk-node", "jp-node", "us-node"}, &mgr);
    mgr.registerDialer(urltest);

    // 默认初始选择第一个节点
    EXPECT_EQ(urltest->getBestTag(), "hk-node");

    // 模拟测速 RTT 更新：jp 节点延迟最低 (35ms)
    urltest->setRtt("hk-node", 80);
    urltest->setRtt("jp-node", 35);
    urltest->setRtt("us-node", 160);

    EXPECT_EQ(urltest->getRtt("jp-node"), 35u);
    EXPECT_EQ(urltest->getBestTag(), "jp-node");

    // 若 hk 节点线路优化，延迟降至 20ms
    urltest->setRtt("hk-node", 20);
    EXPECT_EQ(urltest->getBestTag(), "hk-node");
}

// =============================================================================
// 2. OutboundFallback 故障递退切换测试
// =============================================================================

TEST(AdvancedProxyTest, OutboundFallbackSequence)
{
    DialerManager mgr;
    // 假定主节点指向无效地址，备用节点为 direct
    mgr.registerDialer(std::make_shared<DialerBlock>("faulty-primary"));
    mgr.registerDialer(std::make_shared<DialerDirect>("backup-node"));

    auto fallback = std::make_shared<DialerFallback>("auto-fallback",
                                                       std::vector<std::string>{"faulty-primary", "backup-node"}, &mgr);
    mgr.registerDialer(fallback);

    ASSERT_EQ(fallback->candidates().size(), 2u);
    EXPECT_EQ(fallback->candidates()[0], "faulty-primary");
    EXPECT_EQ(fallback->candidates()[1], "backup-node");
}

// =============================================================================
// 3. VLESS / Hysteria 2 / Shadowsocks / TUN 入出站节点实例化与生命周期
// =============================================================================

TEST(AdvancedProxyTest, AdvancedInboundAndOutboundProtocols)
{
    // 1. Inbounds
    auto vlessIn =
        std::make_shared<AcceptorVless>("vless-in", "127.0.0.1", 4430, "a1b2c3d4-e5f6-7890-1234-567890abcdef");
    EXPECT_EQ(vlessIn->type(), "vless");
    EXPECT_EQ(vlessIn->uuid(), "a1b2c3d4-e5f6-7890-1234-567890abcdef");
    auto vlessHandler = vlessIn->createHandler();
    ASSERT_NE(vlessHandler, nullptr);

    auto hy2In = std::make_shared<AcceptorHysteria2>("hy2-in", "127.0.0.1", 4431, "secretpass");
    EXPECT_EQ(hy2In->type(), "hysteria2");
    EXPECT_EQ(hy2In->password(), "secretpass");
    auto hy2Handler = hy2In->createHandler();
    ASSERT_NE(hy2Handler, nullptr);

    auto ssIn = std::make_shared<AcceptorShadowsocks>("ss-in", "127.0.0.1", 8388, "aes-256-gcm", "sspassword");
    EXPECT_EQ(ssIn->type(), "shadowsocks");
    EXPECT_EQ(ssIn->method(), "aes-256-gcm");
    auto ssHandler = ssIn->createHandler();
    ASSERT_NE(ssHandler, nullptr);

    auto tunIn = std::make_shared<AcceptorTun>("tun-in", "tun88", "172.19.0.1", "255.255.255.0", 1500);
    EXPECT_EQ(tunIn->type(), "tun");
    EXPECT_EQ(tunIn->ifName(), "tun88");
    EXPECT_EQ(tunIn->inetIp(), "172.19.0.1");
    EXPECT_EQ(tunIn->mtu(), 1500u);
    auto tunHandler = tunIn->createHandler();
    ASSERT_NE(tunHandler, nullptr);

    // 2. Outbounds
    auto vlessOut =
        std::make_shared<DialerVless>("vless-out", "127.0.0.1", 4430, "a1b2c3d4-e5f6-7890-1234-567890abcdef");
    EXPECT_EQ(vlessOut->type(), "vless");
    EXPECT_EQ(vlessOut->serverHost(), "127.0.0.1");
    EXPECT_EQ(vlessOut->serverPort(), 4430);

    auto hy2Out = std::make_shared<DialerHysteria2>("hy2-out", "127.0.0.1", 4431, "secretpass");
    EXPECT_EQ(hy2Out->type(), "hysteria2");
    EXPECT_EQ(hy2Out->serverHost(), "127.0.0.1");
    EXPECT_EQ(hy2Out->serverPort(), 4431);
}

// =============================================================================
// 4. Core 配置加载全链路装配 (MynetConfig Pipeline)
// =============================================================================

TEST(AdvancedProxyTest, CoreApplyConfigWithAdvancedProtocolsAndGeoRules)
{
    MynetConfig cfg;

    // 入站配置装配
    InboundConfig inVless;
    inVless.tag = "vless-in";
    inVless.protocol = "vless";
    inVless.host = "127.0.0.1";
    inVless.port = 0;
    inVless.uuid = "12345678-1234-1234-1234-1234567890ab";
    cfg.inbounds.push_back(inVless);

    InboundConfig inTun;
    inTun.tag = "tun-in";
    inTun.protocol = "tun";
    inTun.ifName = "tun99";
    cfg.inbounds.push_back(inTun);

    // 出站配置装配
    OutboundConfig outVless;
    outVless.tag = "vless-out";
    outVless.type = "vless";
    outVless.host = "127.0.0.1";
    outVless.port = 8443;
    outVless.uuid = "12345678-1234-1234-1234-1234567890ab";
    cfg.outbounds.push_back(outVless);

    OutboundConfig outUrlTest;
    outUrlTest.tag = "auto-fast";
    outUrlTest.type = "urltest";
    outUrlTest.outbounds = {"direct", "vless-out"};
    cfg.outbounds.push_back(outUrlTest);

    // 路由分流规则 (含 GeoIP 与 GeoSite)
    cfg.router.defaultOutbound = "auto-fast";

    RouteRuleConfig ruleGeo;
    ruleGeo.outbound = "direct";
    ruleGeo.geoIps = {"cn", "private"};
    ruleGeo.geoSites = {"cn"};
    cfg.router.rules.push_back(ruleGeo);

    RouteRuleConfig ruleAd;
    ruleAd.outbound = "block";
    ruleAd.geoSites = {"category-ads-all"};
    cfg.router.rules.push_back(ruleAd);

    Core core(cfg);
    EXPECT_TRUE(core.acceptors().has("vless-in"));
    EXPECT_TRUE(core.acceptors().has("tun-in"));
    EXPECT_TRUE(core.dialers().has("vless-out"));
    EXPECT_TRUE(core.dialers().has("auto-fast"));
    EXPECT_EQ(core.router().rules().size(), 2u);
    EXPECT_EQ(core.router().defaultOutbound(), "auto-fast");

    // 探测当前运行环境（容器/无 CAP_NET_ADMIN 权限）是否允许创建 TUN 设备
    int probeFd = ::open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (probeFd >= 0)
    {
        struct ifreq ifr{};
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        std::strncpy(ifr.ifr_name, "tun_cap_probe", IFNAMSIZ - 1);
        if (::ioctl(probeFd, TUNSETIFF, &ifr) < 0 && (errno == EPERM || errno == EACCES))
        {
            ::close(probeFd);
            GTEST_SKIP() << "Skipping core.start() with TUN inbound in unprivileged container (no CAP_NET_ADMIN)";
        }
        ::close(probeFd);
    }
    else
    {
        GTEST_SKIP() << "Skipping core.start() because /dev/net/tun is unavailable";
    }

    ASSERT_TRUE(core.start().has_value());
    EXPECT_TRUE(core.isRunning());
    core.stop();
    EXPECT_FALSE(core.isRunning());
}
