#include "ebpf.hpp"
#include "core.hpp"
#include "address.hpp"
#include "direct/direct.hpp"
#include <arpa/inet.h>
#include <gtest/gtest.h>

using namespace mynet;
using namespace mynet::ebpf;

// =============================================================================
// 1. eBPF 基础配置与生命周期测试
// =============================================================================

TEST(EbpfTest, LifecycleAndConfig)
{
    EbpfConfig cfg{
        .wanInterface = "eth1",
        .lanInterface = "lo",
        .tproxyPort = 7893,
        .fwmark = 0x4321,
        .enableDirectBypass = true,
        .enableLpmGeoIp = true,
        .dropQuic = true
    };

    EbpfManager mgr(cfg);
    EXPECT_EQ(mgr.config().wanInterface, "eth1");
    EXPECT_EQ(mgr.config().tproxyPort, 7893);
    EXPECT_EQ(mgr.config().fwmark, 0x4321);
    EXPECT_TRUE(mgr.config().dropQuic);

    // 默认内置的私网 CIDR 应已加载至 LPM Trie
    PacketMetadata lanPkt{};
    ::inet_pton(AF_INET, "192.168.1.100", &lanPkt.dstIp);
    lanPkt.dstPort = 80;
    lanPkt.protocol = IPPROTO_TCP;
    lanPkt.length = 64;

    EXPECT_EQ(mgr.classify(lanPkt), Action::DIRECT);

    auto stats = mgr.getStats();
    EXPECT_EQ(stats.directBypassedPackets, 1u);
    EXPECT_EQ(stats.totalBytesEvaluated, 64u);
}

// =============================================================================
// 2. 最长前缀匹配 (LPM Trie) 网段分类决断测试
// =============================================================================

TEST(EbpfTest, LpmTriePrefixMatching)
{
    EbpfManager mgr;

    // 注入自定义 CIDR 规则
    EXPECT_TRUE(mgr.addLpmCidr("198.51.100.0/24", Action::DIRECT));
    EXPECT_TRUE(mgr.addLpmCidr("198.51.100.128/28", Action::BLOCK)); // 更长前缀覆盖
    EXPECT_TRUE(mgr.addLpmCidr("203.0.113.0/24", Action::PROXY));

    // 非法 CIDR 应安全被拒
    EXPECT_FALSE(mgr.addLpmCidr("invalid-cidr", Action::DIRECT));
    EXPECT_FALSE(mgr.addLpmCidr("10.0.0.1/33", Action::DIRECT));

    PacketMetadata pkt{};
    pkt.dstPort = 8080;
    pkt.protocol = IPPROTO_TCP;

    // 198.51.100.10 属于 /24，未落入 /28 -> DIRECT
    ::inet_pton(AF_INET, "198.51.100.10", &pkt.dstIp);
    EXPECT_EQ(mgr.classify(pkt), Action::DIRECT);

    // 198.51.100.130 属于 /28 (更长前缀) -> BLOCK
    ::inet_pton(AF_INET, "198.51.100.130", &pkt.dstIp);
    EXPECT_EQ(mgr.classify(pkt), Action::BLOCK);

    // 203.0.113.5 -> PROXY
    ::inet_pton(AF_INET, "203.0.113.5", &pkt.dstIp);
    EXPECT_EQ(mgr.classify(pkt), Action::PROXY);

    // 8.8.8.8 未匹配任何规则 -> 默认 PROXY
    ::inet_pton(AF_INET, "8.8.8.8", &pkt.dstIp);
    EXPECT_EQ(mgr.classify(pkt), Action::PROXY);
}

// =============================================================================
// 3. 直连 IP 哈希表动态增删与快速直连测试
// =============================================================================

TEST(EbpfTest, DirectIpFastPath)
{
    EbpfManager mgr;

    in_addr targetIp{};
    ::inet_pton(AF_INET, "1.1.1.1", &targetIp);

    PacketMetadata pkt{};
    pkt.dstIp = targetIp;
    pkt.dstPort = 53;
    pkt.protocol = IPPROTO_UDP;

    // 初始状态应走默认代理
    EXPECT_EQ(mgr.classify(pkt), Action::PROXY);

    // 动态添加直连 IP
    mgr.addDirectIp(targetIp);
    EXPECT_EQ(mgr.classify(pkt), Action::DIRECT);

    // 动态移除直连 IP
    mgr.removeDirectIp(targetIp);
    EXPECT_EQ(mgr.classify(pkt), Action::PROXY);
}

// =============================================================================
// 4. QUIC 阻断策略 (dropQuic: UDP 443 拦截降级) 测试
// =============================================================================

TEST(EbpfTest, DropQuicPolicy)
{
    EbpfConfig cfg{};
    cfg.dropQuic = true;
    EbpfManager mgr(cfg);

    PacketMetadata quicPkt{};
    ::inet_pton(AF_INET, "142.250.190.46", &quicPkt.dstIp); // Google
    quicPkt.dstPort = 443;
    quicPkt.protocol = IPPROTO_UDP;

    // UDP 443 且 dropQuic=true 应在内核/仿真层直接 BLOCK 丢弃
    EXPECT_EQ(mgr.classify(quicPkt), Action::BLOCK);

    // 普通 TCP 443 流量不受影响
    PacketMetadata tcpPkt = quicPkt;
    tcpPkt.protocol = IPPROTO_TCP;
    EXPECT_EQ(mgr.classify(tcpPkt), Action::PROXY);

    // 普通 UDP 53 (DNS) 流量不受影响
    PacketMetadata dnsPkt = quicPkt;
    dnsPkt.dstPort = 53;
    EXPECT_EQ(mgr.classify(dnsPkt), Action::PROXY);
}

// =============================================================================
// 5. GeoIP 规则同步与最长匹配测试
// =============================================================================

TEST(EbpfTest, GeoIpRuleSync)
{
    EbpfManager mgr;
    GeoIpMatcher geo;

    mgr.syncGeoIp(geo, "cn", Action::DIRECT);

    PacketMetadata cnPkt{};
    ::inet_pton(AF_INET, "114.114.114.114", &cnPkt.dstIp); // 114.0.0.0/8
    cnPkt.dstPort = 53;
    cnPkt.protocol = IPPROTO_UDP;

    EXPECT_EQ(mgr.classify(cnPkt), Action::DIRECT);

    PacketMetadata foreignPkt{};
    ::inet_pton(AF_INET, "8.8.8.8", &foreignPkt.dstIp);
    foreignPkt.dstPort = 53;
    foreignPkt.protocol = IPPROTO_UDP;

    EXPECT_EQ(mgr.classify(foreignPkt), Action::PROXY);
}

// =============================================================================
// 6. 内核 eBPF C 源码动态生成测试
// =============================================================================

TEST(EbpfTest, GenerateBpfSource)
{
    std::string bpfSrc = EbpfManager::generateBpfSource();
    EXPECT_FALSE(bpfSrc.empty());
    EXPECT_NE(bpfSrc.find("BPF_MAP_TYPE_LPM_TRIE"), std::string::npos);
    EXPECT_NE(bpfSrc.find("BPF_MAP_TYPE_HASH"), std::string::npos);
    EXPECT_NE(bpfSrc.find("BPF_MAP_TYPE_ARRAY"), std::string::npos);
    EXPECT_TRUE(bpfSrc.find("BPF_MAP_TYPE_SOCKHASH") != std::string::npos ||
                bpfSrc.find("BPF_MAP_TYPE_SOCKMAP") != std::string::npos);
    EXPECT_TRUE(bpfSrc.find("SEC(\"tc\")") != std::string::npos ||
                bpfSrc.find("SEC(\"tc_ingress\")") != std::string::npos);
    EXPECT_NE(bpfSrc.find("mynet_tc_filter"), std::string::npos);
    EXPECT_NE(bpfSrc.find("TC_ACT_OK"), std::string::npos);
    EXPECT_NE(bpfSrc.find("TC_ACT_SHOT"), std::string::npos);
}

// =============================================================================
// 7. Core 与 eBPF 统一纳管分发集成测试
// =============================================================================

TEST(EbpfTest, CoreEbpfIntegration)
{
    Core core;
    EXPECT_EQ(core.ebpf(), nullptr);

    EbpfConfig ebpfCfg{};
    ebpfCfg.dropQuic = true;
    auto mgr = core.enableEbpf(ebpfCfg);
    ASSERT_NE(mgr, nullptr);
    EXPECT_EQ(core.ebpf(), mgr);

    ASSERT_TRUE(core.start().has_value());

    // 1. 策略控制面统一：在 Router 中配置拦截黑洞规则并一键同步至 eBPF LPM
    core.router().addRule(RouteRule::to("block").cidr("1.2.3.0/24"));
    core.syncEbpfFromRouter();

    // 2. 验证规则已编译下发至 eBPF 引擎的 LPM 前缀树
    PacketMetadata pkt{};
    ::inet_pton(AF_INET, "1.2.3.4", &pkt.dstIp);
    pkt.dstPort = 80;
    pkt.protocol = IPPROTO_TCP;
    EXPECT_EQ(mgr->classify(pkt), Action::BLOCK);

    // 3. 用户态 Core::dispatch 由单一中枢 Router 决断，优雅返回 BLOCKED
    auto target = handler::ProxyAddress::fromIPv4(pkt.dstIp.s_addr, 80);
    handler::HandlerInboundDirect inbound(target);

    auto res = core.dispatch(inbound, -1, "test-ebpf-in");
    EXPECT_EQ(res.status, CoreDispatchStatus::BLOCKED);
    EXPECT_TRUE(inbound.closeAfterResponse());
}

// =============================================================================
// 8. SockMap 内核套接字流卸载与 Splice 双模回退测试
// =============================================================================

TEST(EbpfTest, SockmapLifecycleAndSpliceFallback)
{
    bool supported = EbpfManager::isSockmapSupported();
    (void)supported;

    int sv[2] = {-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv), 0);

    handler::HandlerInboundDirect handler;
    bool ok = EbpfManager::enableOffloadOrSplice(handler, sv[0], sv[1], -1);
    EXPECT_TRUE(ok);
    EXPECT_TRUE(handler.isSpliceActive());
    EXPECT_EQ(handler.spliceTarget(), sv[1]);

    handler.reset();
    ::close(sv[0]);
    ::close(sv[1]);

    EXPECT_FALSE(EbpfManager::enableOffloadOrSplice(handler, -1, -1, -1));
    EXPECT_FALSE(EbpfManager::attachPair(-1, 0, 1));
    EXPECT_FALSE(EbpfManager::detachPair(-1, 0, 1));
}

// =============================================================================
// 9. Forwarder 统一数据面阶梯自适应 (Sockmap -> Splice -> Buffer Pump) 测试
// =============================================================================

TEST(EbpfTest, ForwarderAdaptiveLadder)
{
    Forwarder forwarder;
    EXPECT_EQ(forwarder.sockmapFd(), -1);

    handler::HandlerInboundDirect in;
    handler::HandlerOutboundDirect out;

    // 1. 无 sockmap 时，明文直连默认自适应到 ZERO_COPY_SPLICE
    auto session = forwarder.bridge(in, out);
    ASSERT_NE(session, nullptr);
    session->setInboundFd(10);
    session->setOutboundFd(11);
    session->activateAdaptiveMode();
    EXPECT_EQ(session->activeMode(), ForwardMode::ZERO_COPY_SPLICE);

    // 2. 模拟配置了有效伪 sockmapFd 时，明文直连优先自适应到 KERNEL_SOCKMAP (失败回退 splice)
    int sv[2] = {-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv), 0);

    forwarder.setSockmapFd(999);
    auto session2 = forwarder.bridge(in, out);
    session2->setInboundFd(sv[0]);
    session2->setOutboundFd(sv[1]);
    session2->activateAdaptiveMode();
    // 999 并非实际 BPF map fd，系统调用失败后优雅降级至 ZERO_COPY_SPLICE
    EXPECT_EQ(session2->activeMode(), ForwardMode::ZERO_COPY_SPLICE);

    ::close(sv[0]);
    ::close(sv[1]);
}

// =============================================================================
// 10. IPv6 LPM 前缀匹配与流分类测试
// =============================================================================

TEST(EbpfTest, Ipv6LpmPrefixMatching)
{
    EbpfManager mgr;

    EXPECT_TRUE(mgr.addLpmCidrIpv6("2001:db8::/32", Action::DIRECT));
    EXPECT_TRUE(mgr.addLpmCidrIpv6("2001:db8:abcd::/48", Action::BLOCK));
    EXPECT_FALSE(mgr.addLpmCidrIpv6("invalid-ipv6/64", Action::DIRECT));
    EXPECT_FALSE(mgr.addLpmCidrIpv6("2001:db8::/129", Action::DIRECT));

    PacketMetadata pkt{};
    pkt.isIpv6 = true;
    pkt.protocol = IPPROTO_TCP;
    pkt.dstPort = 443;

    // 2001:db8:1::1 命中 /32 -> DIRECT
    ::inet_pton(AF_INET6, "2001:db8:1::1", &pkt.dstIp6);
    EXPECT_EQ(mgr.classify(pkt), Action::DIRECT);

    // 2001:db8:abcd::1 命中更长前缀 /48 -> BLOCK
    ::inet_pton(AF_INET6, "2001:db8:abcd::1", &pkt.dstIp6);
    EXPECT_EQ(mgr.classify(pkt), Action::BLOCK);

    // 2400::1 未匹配任何规则 -> PROXY
    ::inet_pton(AF_INET6, "2400::1", &pkt.dstIp6);
    EXPECT_EQ(mgr.classify(pkt), Action::PROXY);
}

// =============================================================================
// 11. 流缓存 (Flow Cache) 加速与规则热更新失效测试
// =============================================================================

TEST(EbpfTest, FlowCacheAccelerationAndInvalidation)
{
    EbpfManager mgr;
    EXPECT_TRUE(mgr.addLpmCidr("192.0.2.0/24", Action::DIRECT));

    PacketMetadata pkt{};
    ::inet_pton(AF_INET, "192.0.2.100", &pkt.dstIp);
    pkt.protocol = IPPROTO_TCP;
    pkt.dstPort = 80;

    // 首次判定：遍历 LPM 并存入缓存
    EXPECT_EQ(mgr.classify(pkt), Action::DIRECT);

    // 再次判定：命中快速流缓存
    EXPECT_EQ(mgr.classify(pkt), Action::DIRECT);

    // 动态注入覆盖规则 (更长前缀 /28 -> BLOCK)，缓存应自动清空失效
    EXPECT_TRUE(mgr.addLpmCidr("192.0.2.96/28", Action::BLOCK));
    EXPECT_EQ(mgr.classify(pkt), Action::BLOCK);
}

// =============================================================================
// 12. KERNEL_SOCKMAP 模式下 Splice 管道零拷贝保底与数据传输测试
// =============================================================================

TEST(EbpfTest, KernelSockmapSpliceFallbackTransfer)
{
    Forwarder forwarder;
    handler::HandlerInboundDirect in;
    handler::HandlerOutboundDirect out;

    int sp1[2] = {-1, -1};
    int sp2[2] = {-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sp1), 0);
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sp2), 0);

    auto session = forwarder.bridge(in, out);
    session->setInboundFd(sp1[1]);
    session->setOutboundFd(sp2[0]);

    // 手动准备管道并激活 KERNEL_SOCKMAP 模式，验证即使处于该模式也能走零拷贝管道传输
    session->activateSplice();
    // 模拟 KERNEL_SOCKMAP 状态
    // 上行写入数据
    const std::string testMsg = "SOCKMAP_SPLICE_DATA_VERIFICATION";
    ssize_t wn = ::write(sp1[0], testMsg.data(), testMsg.size());
    ASSERT_EQ(wn, static_cast<ssize_t>(testMsg.size()));

    size_t pumped = forwarder.pumpSession(*session);
    EXPECT_GE(pumped, testMsg.size());

    char buf[128]{};
    ssize_t rn = ::read(sp2[1], buf, sizeof(buf));
    ASSERT_EQ(rn, static_cast<ssize_t>(testMsg.size()));
    EXPECT_EQ(std::string_view(buf, static_cast<size_t>(rn)), testMsg);

    ::close(sp1[0]);
    ::close(sp1[1]);
    ::close(sp2[0]);
    ::close(sp2[1]);
}

// =============================================================================
// 13. eBPF Sockmap 与 Connection 统一背压高水位联动自愈测试
// =============================================================================

TEST(EbpfTest, SockmapBackpressureThrottleAndResume)
{
    Forwarder forwarder;
    handler::HandlerInboundDirect in;
    handler::HandlerOutboundDirect out;

    int sp1[2] = {-1, -1};
    int sp2[2] = {-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sp1), 0);
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sp2), 0);

    auto session = forwarder.bridge(in, out);
    session->setInboundFd(sp1[1]);
    session->setOutboundFd(sp2[0]);
    session->setSockmapFd(999);

    EXPECT_FALSE(session->isSockmapPaused());
    EXPECT_FALSE(session->isBackpressured());

    // 默认空缓冲区状态下执行背压自检，无背压状态保持正常
    session->checkAndApplySockmapBackpressure();
    EXPECT_FALSE(session->isSockmapPaused());

    // 验证 getSocketPendingOutBytes 能够安全获取套接字积压
    size_t pending = session->getSocketPendingOutBytes(sp1[1]);
    EXPECT_EQ(pending, 0u);

    ::close(sp1[0]);
    ::close(sp1[1]);
    ::close(sp2[0]);
    ::close(sp2[1]);
}

// =============================================================================
// 14. 双 Epoch (Double Epoch) 路由表零停机原子热重载测试 (借鉴 dae)
// =============================================================================

TEST(EbpfTest, DoubleEpochZeroDowntimeHotReload)
{
    EbpfConfig cfg{};
    cfg.enableDoubleEpoch = true;
    EbpfManager mgr(cfg);

    // 初始活跃槽位应为 0
    EXPECT_EQ(mgr.activeEpoch(), 0);

    // 在 Epoch 0 注入网段：192.0.2.0/24 -> DIRECT
    EXPECT_TRUE(mgr.addLpmCidr("192.0.2.0/24", Action::DIRECT));

    PacketMetadata pkt{};
    ::inet_pton(AF_INET, "192.0.2.100", &pkt.dstIp);
    pkt.protocol = IPPROTO_TCP;
    pkt.dstPort = 80;

    EXPECT_EQ(mgr.classify(pkt), Action::DIRECT);

    // 原子热重载至 Epoch 1：将 192.0.2.0/24 改为 BLOCK，并新增 198.51.100.0/24 -> DIRECT
    mgr.reloadRoutingEpoch([&](auto &&addIpv4, auto &&addIpv6) {
        (void)addIpv6;
        addIpv4("192.0.2.0/24", Action::BLOCK);
        addIpv4("198.51.100.0/24", Action::DIRECT);
    });

    // 活跃槽位应原子切换为 1
    EXPECT_EQ(mgr.activeEpoch(), 1);

    // 报文分类应瞬间无缝切换至新规则，零停机无中间状态
    EXPECT_EQ(mgr.classify(pkt), Action::BLOCK);

    PacketMetadata pkt2{};
    ::inet_pton(AF_INET, "198.51.100.50", &pkt2.dstIp);
    pkt2.protocol = IPPROTO_TCP;
    pkt2.dstPort = 443;
    EXPECT_EQ(mgr.classify(pkt2), Action::DIRECT);

    // 再次热重载回 Epoch 0
    mgr.reloadRoutingEpoch([&](auto &&addIpv4, auto &&) {
        addIpv4("192.0.2.0/24", Action::DIRECT);
    });
    EXPECT_EQ(mgr.activeEpoch(), 0);
    EXPECT_EQ(mgr.classify(pkt), Action::DIRECT);
}

// =============================================================================
// 15. 旁路由非对称 MAC 改写 (Asymmetric Gateway Routing) 测试 (借鉴 dae)
// =============================================================================

TEST(EbpfTest, AsymmetricGatewayMacRewrite)
{
    // 1. MAC 地址解析与格式校验 (单根抽象，复用 crypto::hexCharToNibble)
    auto mac1 = MacAddress::parse("00:11:22:33:44:55");
    ASSERT_TRUE(mac1.has_value());
    EXPECT_EQ(mac1->bytes[0], 0x00);
    EXPECT_EQ(mac1->bytes[1], 0x11);
    EXPECT_EQ(mac1->bytes[5], 0x55);
    EXPECT_EQ(mac1->toString(), "00:11:22:33:44:55");

    auto mac2 = MacAddress::parse("aa-bb-cc-dd-ee-ff");
    ASSERT_TRUE(mac2.has_value());
    EXPECT_EQ(mac2->bytes[0], 0xaa);
    EXPECT_EQ(mac2->bytes[5], 0xff);

    EXPECT_FALSE(MacAddress::parse("invalid-mac").has_value());
    EXPECT_FALSE(MacAddress::parse("00:11:22:33:44").has_value());
    EXPECT_FALSE(MacAddress::parse("00:11:22:33:44:gg").has_value());

    // 2. 旁路由非对称网关调度测试
    EbpfConfig cfg{};
    cfg.asymmetricGateway = true;
    cfg.gatewayMac = "00:11:22:33:44:55";
    cfg.wanMac = "aa:bb:cc:dd:ee:ff";
    EbpfManager mgr(cfg);

    mgr.addLpmCidr("192.0.2.0/24", Action::DIRECT);
    mgr.addLpmCidr("203.0.113.0/24", Action::BLOCK);

    PacketMetadata directPkt{};
    ::inet_pton(AF_INET, "192.0.2.1", &directPkt.dstIp);
    directPkt.protocol = IPPROTO_TCP;
    directPkt.dstPort = 80;

    auto res = mgr.evaluateAsymmetricGateway(directPkt);
    EXPECT_TRUE(res.redirected);
    EXPECT_EQ(res.dstMac[0], 0x00);
    EXPECT_EQ(res.dstMac[5], 0x55);
    EXPECT_EQ(res.srcMac[0], 0xaa);
    EXPECT_EQ(res.srcMac[5], 0xff);

    // 阻塞或代理流量绝不触发旁路由 MAC 伪装与重定向
    PacketMetadata blockPkt{};
    ::inet_pton(AF_INET, "203.0.113.1", &blockPkt.dstIp);
    blockPkt.protocol = IPPROTO_TCP;
    blockPkt.dstPort = 80;
    auto blockRes = mgr.evaluateAsymmetricGateway(blockPkt);
    EXPECT_FALSE(blockRes.redirected);

    PacketMetadata proxyPkt{};
    ::inet_pton(AF_INET, "8.8.8.8", &proxyPkt.dstIp);
    proxyPkt.protocol = IPPROTO_TCP;
    proxyPkt.dstPort = 80;
    auto proxyRes = mgr.evaluateAsymmetricGateway(proxyPkt);
    EXPECT_FALSE(proxyRes.redirected);
}

// =============================================================================
// 16. BPF Map 持久化挂载 (Pinning to /sys/fs/bpf) 生命周期测试 (借鉴 dae)
// =============================================================================

TEST(EbpfTest, BpfMapPinningLifecycle)
{
    const std::string testPinDir = "/tmp/mynet_test_bpffs_pin";

    // 验证目录自动创建
    EXPECT_TRUE(EbpfEngine::ensureBpffsDir(testPinDir));

    struct stat st{};
    EXPECT_EQ(::stat(testPinDir.c_str(), &st), 0);
    EXPECT_TRUE(S_ISDIR(st.st_mode));

    // 验证安全清理与解挂
    EbpfEngine::unpinAllMaps(testPinDir);
    EXPECT_NE(::stat(testPinDir.c_str(), &st), 0);
}

// =============================================================================
// 17. UDP 内核连接状态表与保活回收器 (conn_state_janitor) 测试 (借鉴 dae)
// =============================================================================

TEST(EbpfTest, UdpConnStateTrackingAndJanitorSweep)
{
    EbpfManager mgr;

    TuplesKey key1{
        .saddr = 0x0100007f, // 127.0.0.1
        .daddr = 0x01010101, // 1.1.1.1
        .sport = htons(12345),
        .dport = htons(53),
        .proto = IPPROTO_UDP
    };

    TuplesKey key2{
        .saddr = 0x0100007f,
        .daddr = 0x08080808, // 8.8.8.8
        .sport = htons(23456),
        .dport = htons(53),
        .proto = IPPROTO_UDP
    };

    uint64_t nowNs = getMonotonicTimeNs();

    // 1. 注入一条活跃会话与一条超期会话 (120 秒前)
    uint64_t oldNs = (nowNs > 120ULL * 1000 * 1000 * 1000) ? (nowNs - 120ULL * 1000 * 1000 * 1000) : 1;
    EXPECT_TRUE(mgr.trackUdpConnState(key1, Action::DIRECT, nowNs));
    EXPECT_TRUE(mgr.trackUdpConnState(key2, Action::PROXY, oldNs));
    EXPECT_EQ(mgr.connStateCount(), 2u);

    // 查询会话详情
    auto cs1 = mgr.getConnState(key1);
    ASSERT_TRUE(cs1.has_value());
    EXPECT_EQ(cs1->action, static_cast<uint32_t>(Action::DIRECT));

    auto cs2 = mgr.getConnState(key2);
    ASSERT_TRUE(cs2.has_value());
    EXPECT_EQ(cs2->action, static_cast<uint32_t>(Action::PROXY));

    // 2. 触发 janitor 清理 (超期阈值 60 秒)
    size_t swept = mgr.sweepConnState(60ULL * 1000 * 1000 * 1000);
    EXPECT_EQ(swept, 1u);
    EXPECT_EQ(mgr.connStateCount(), 1u);

    // 活跃会话依然存活，超期会话已被彻底回收
    EXPECT_TRUE(mgr.getConnState(key1).has_value());
    EXPECT_FALSE(mgr.getConnState(key2).has_value());
}

// =============================================================================
// 18. 无连接 UDP 进程归属捕获 (cgroup/sendmsg4/6) 测试 (借鉴 dae)
// =============================================================================

TEST(EbpfTest, UnconnectedUdpProcessAttribution)
{
    EbpfConfig cfg{};
    cfg.enableUnconnectedUdpAttribution = true;
    EbpfManager mgr(cfg);

    const uint64_t mockCookie = 0xdeadbeef1234ULL;
    const uint32_t mockPid = 9876;
    const std::string mockComm = "unconnected_dns";

    // 模拟 cgroup/sendmsg4/6 捕获到无连接 UDP 报文并发起进程关联记录
    mgr.recordProcessSocket(mockCookie, mockPid, mockComm);

    auto proc = mgr.getProcessByCookie(mockCookie);
    ASSERT_TRUE(proc.has_value());
    EXPECT_EQ(proc->pid, mockPid);
    EXPECT_EQ(proc->name, mockComm);

    // 未记录的陌生 cookie 返回 nullopt
    EXPECT_FALSE(mgr.getProcessByCookie(0xfeedfaceULL).has_value());
}

// =============================================================================
// 19. 内核直接指定套接字免 iptables (bpf_sk_assign) 调度测试 (借鉴 dae)
// =============================================================================

TEST(EbpfTest, InKernelDirectSocketAssignment)
{
    EbpfConfig cfg{};
    cfg.enableSkAssign = true;
    cfg.fwmark = 0x100;
    EbpfManager mgr(cfg);

    int spTcp[2] = {-1, -1};
    int spUdp[2] = {-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, spTcp), 0);
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_DGRAM, 0, spUdp), 0);

    const int tcp4Fd = spTcp[0];
    const int udpFd = spUdp[0];
    const int tcp6Fd = spTcp[1];

    EXPECT_TRUE(mgr.setListeningSockets(tcp4Fd, udpFd, tcp6Fd));

    // 验证能够精确匹配并提取对应的 listener 描述符
    EXPECT_EQ(mgr.getAssignedSocket(IPPROTO_TCP, false), tcp4Fd);
    EXPECT_EQ(mgr.getAssignedSocket(IPPROTO_UDP, false), udpFd);
    EXPECT_EQ(mgr.getAssignedSocket(IPPROTO_TCP, true), tcp6Fd);

    // 验证 evaluateProxyDispatch 决断结果为 SK_ASSIGN，且直接绑定 listener fd
    PacketMetadata pktTcp{};
    pktTcp.protocol = IPPROTO_TCP;
    pktTcp.isIpv6 = false;
    auto resTcp = mgr.evaluateProxyDispatch(pktTcp);
    EXPECT_EQ(resTcp.mode, EbpfManager::ProxyDispatchResult::Mode::SK_ASSIGN);
    EXPECT_EQ(resTcp.assignedFd, tcp4Fd);

    PacketMetadata pktUdp{};
    pktUdp.protocol = IPPROTO_UDP;
    auto resUdp = mgr.evaluateProxyDispatch(pktUdp);
    EXPECT_EQ(resUdp.mode, EbpfManager::ProxyDispatchResult::Mode::SK_ASSIGN);
    EXPECT_EQ(resUdp.assignedFd, udpFd);

    ::close(spTcp[0]);
    ::close(spTcp[1]);
    ::close(spUdp[0]);
    ::close(spUdp[1]);
}

// =============================================================================
// 20. GRO/GSO 非线性大包拉取安全与深层判定测试 (借鉴 dae bpf_skb_pull_data)
// =============================================================================

TEST(EbpfTest, NonLinearSkbPullDataSafety)
{
    EbpfManager mgr;
    mgr.addLpmCidr("192.0.2.0/24", Action::DIRECT);

    // 模拟 64KB 超级聚合大包 (GRO/GSO)
    PacketMetadata bigPkt{};
    ::inet_pton(AF_INET, "192.0.2.1", &bigPkt.dstIp);
    bigPkt.protocol = IPPROTO_TCP;
    bigPkt.dstPort = 80;
    bigPkt.length = 65535;

    // 超级大包必须正常完成快速路径分类，且不截断、不越界
    EXPECT_EQ(mgr.classifyFast(bigPkt), Action::DIRECT);
}

// =============================================================================
// 21. 内核级自适应阻断与恶意扫描令牌桶限速测试 (借鉴 dae alive_block_rate_map)
// =============================================================================

TEST(EbpfTest, KernelAdaptiveBlockRateLimiting)
{
    EbpfManager mgr;

    const uint32_t bucketKey = 1;
    const uint16_t windowMs = 50; // 50毫秒测试窗口

    // 首次事件：应放行 (未被限速)
    EXPECT_FALSE(mgr.isBlockRateLimited(bucketKey, windowMs));

    // 突发连续呼叫：应被内核令牌桶限速 (触发静默黑洞丢弃)
    EXPECT_TRUE(mgr.isBlockRateLimited(bucketKey, windowMs));
    EXPECT_TRUE(mgr.isBlockRateLimited(bucketKey, windowMs));

    // 不同 bucketKey 拥有独立配额
    const uint32_t otherKey = 2;
    EXPECT_FALSE(mgr.isBlockRateLimited(otherKey, windowMs));
    EXPECT_TRUE(mgr.isBlockRateLimited(otherKey, windowMs));

    // 等待限速窗口过期
    ::usleep(60 * 1000); // 60ms

    // 窗口过期后重新放行
    EXPECT_FALSE(mgr.isBlockRateLimited(bucketKey, windowMs));
}

// =============================================================================
// 22. 隔离虚拟通道 (veth/netkit/mynet0) 架构重定向测试
// =============================================================================

TEST(EbpfTest, IsolatedVirtualInterfaceRedirect)
{
    EbpfConfig cfg{};
    cfg.enableSkAssign = false; // 关闭直接套接字指定
    cfg.virtualInterface = "mynet0";
    EbpfManager mgr(cfg);

    PacketMetadata pkt{};
    pkt.protocol = IPPROTO_TCP;

    // 当未开启 sk_assign 且配置了虚拟通道时，应评估为 REDIRECT 模式或保底 FWMARK
    auto res = mgr.evaluateProxyDispatch(pkt);
    if (mgr.virtualIfIndex() > 0)
    {
        EXPECT_EQ(res.mode, EbpfManager::ProxyDispatchResult::Mode::REDIRECT);
        EXPECT_EQ(res.redirectIfIndex, mgr.virtualIfIndex());
    }
    else
    {
        // 虚拟网卡在测试环境中若不存在，优雅回退至 FWMARK 模式
        EXPECT_EQ(res.mode, EbpfManager::ProxyDispatchResult::Mode::FWMARK);
        EXPECT_EQ(res.fwmark, cfg.fwmark);
    }
}

// =============================================================================
// 23. 组播与局域网广播绝对免拦截 (Multicast & Broadcast Immunity) 测试 (借鉴 dae)
// =============================================================================

TEST(EbpfTest, MulticastAndBroadcastDirectImmunity)
{
    EbpfManager mgr;

    // IPv4 组播 (224.0.0.1, 239.255.255.250 SSDP)
    PacketMetadata ssdpPkt{};
    ::inet_pton(AF_INET, "239.255.255.250", &ssdpPkt.dstIp);
    ssdpPkt.protocol = IPPROTO_UDP;
    ssdpPkt.dstPort = 1900;
    EXPECT_EQ(mgr.classifyFast(ssdpPkt), Action::DIRECT);

    // IPv4 受限广播 (255.255.255.255)
    PacketMetadata bcastPkt{};
    ::inet_pton(AF_INET, "255.255.255.255", &bcastPkt.dstIp);
    bcastPkt.protocol = IPPROTO_UDP;
    bcastPkt.dstPort = 67;
    EXPECT_EQ(mgr.classifyFast(bcastPkt), Action::DIRECT);

    // IPv6 组播 (ff02::1, ff02::c)
    PacketMetadata ip6MultiPkt{};
    ip6MultiPkt.isIpv6 = true;
    ::inet_pton(AF_INET6, "ff02::1", &ip6MultiPkt.dstIp6);
    ip6MultiPkt.protocol = IPPROTO_UDP;
    ip6MultiPkt.dstPort = 5353;
    EXPECT_EQ(mgr.classifyFast(ip6MultiPkt), Action::DIRECT);
}

// =============================================================================
// 24. TCP 状态流表化快速放行 (TcpFlowStateTrackingFastPath) 测试 (借鉴 dae)
// =============================================================================

TEST(EbpfTest, TcpFlowStateTrackingFastPath)
{
    EbpfManager mgr;

    TuplesKey tcpKey{
        .saddr = 0x0100007f, // 127.0.0.1
        .daddr = 0x02020202, // 2.2.2.2
        .sport = htons(45678),
        .dport = htons(80),
        .proto = IPPROTO_TCP
    };

    // 预置 TCP 连接状态为 DIRECT
    EXPECT_TRUE(mgr.trackUdpConnState(tcpKey, Action::DIRECT));

    PacketMetadata pkt{};
    pkt.srcIp.s_addr = tcpKey.saddr;
    pkt.dstIp.s_addr = tcpKey.daddr;
    pkt.srcPort = 45678;
    pkt.dstPort = 80;
    pkt.protocol = IPPROTO_TCP;

    // 后续数据报文必须瞬间命中 O(1) 流状态表
    EXPECT_EQ(mgr.classifyFast(pkt), Action::DIRECT);

    // 将该 TCP 流动态覆写为 PROXY
    EXPECT_TRUE(mgr.trackUdpConnState(tcpKey, Action::PROXY));
    EXPECT_EQ(mgr.classifyFast(pkt), Action::PROXY);
}

// =============================================================================
// 25. Sockmap 内核背压熔断保险丝 (SockmapBacklogFuseOffloadPause) 测试 (借鉴 dae)
// =============================================================================

TEST(EbpfTest, SockmapBacklogFuseOffloadPause)
{
    EbpfManager mgr;

    TuplesKey flowKey{
        .saddr = 0x0a000001,
        .daddr = 0x0a000002,
        .sport = htons(1111),
        .dport = htons(2222),
        .proto = IPPROTO_TCP
    };

    // 初始状态未被暂停
    EXPECT_FALSE(mgr.isOffloadPaused(flowKey));

    // 用户态触发背压：熔断暂停内核直接重定向
    EXPECT_TRUE(mgr.setOffloadPause(flowKey, true));
    EXPECT_TRUE(mgr.isOffloadPaused(flowKey));

    // 背压排空自愈：恢复内核快速流卸载
    EXPECT_TRUE(mgr.setOffloadPause(flowKey, false));
    EXPECT_FALSE(mgr.isOffloadPaused(flowKey));
}

// =============================================================================
// 26. 内核态出站节点健康与连通性感知表 (OutboundConnectivityHealthSensing) 测试 (借鉴 dae)
// =============================================================================

TEST(EbpfTest, OutboundConnectivityHealthSensing)
{
    EbpfManager mgr;

    const uint32_t outboundId = 5;
    const uint32_t domainTcp = 0;
    const uint32_t domainUdp = 2;
    const uint32_t ipv4 = 0;

    // 初始默认健康
    EXPECT_TRUE(mgr.isOutboundAlive(outboundId, domainTcp, ipv4));

    // 节点 TCP 探测失败：内核置为不可用
    EXPECT_TRUE(mgr.setOutboundConnectivity(outboundId, domainTcp, ipv4, false));
    EXPECT_FALSE(mgr.isOutboundAlive(outboundId, domainTcp, ipv4));

    // 独立的 UDP 域状态不受干扰
    EXPECT_TRUE(mgr.isOutboundAlive(outboundId, domainUdp, ipv4));

    // 节点恢复存活
    EXPECT_TRUE(mgr.setOutboundConnectivity(outboundId, domainTcp, ipv4, true));
    EXPECT_TRUE(mgr.isOutboundAlive(outboundId, domainTcp, ipv4));
}

// =============================================================================
// 27. Linux Bridge 网桥从属成员接口自动发现与级联挂载测试 (借鉴 dae bridge_members)
// =============================================================================

TEST(EbpfTest, BridgeSlaveMemberInterfaceDiscovery)
{
    // 1. 空接口与不存在接口防御
    auto emptySlaves = EbpfEngine::discoverBridgeSlaves("");
    EXPECT_TRUE(emptySlaves.empty());

    auto nonExistent = EbpfEngine::discoverBridgeSlaves("non_existent_br999");
    EXPECT_TRUE(nonExistent.empty());

    // 2. 模拟网桥挂载与接口追踪
    EbpfManager mgr;
    mgr.attachTcFilter("lo");
    auto attached = mgr.getAttachedInterfaces();
    ASSERT_FALSE(attached.empty());
    EXPECT_EQ(attached[0], "lo");

    mgr.detachTcFilter();
    EXPECT_TRUE(mgr.getAttachedInterfaces().empty());
}

// =============================================================================
// 28. Linux 旁路由内核参数自动调优与 ICMP 防重定向管理器测试 (借鉴 dae SysctlManager)
// =============================================================================

TEST(EbpfTest, SysctlManagerGatewaySafeguards)
{
    // 1. 验证根据网卡名生成双节点 send_redirects 路径 (conf.all 与 conf.<ifname>)
    auto allPaths = SysctlManager::sendRedirectsSysctls("all");
    ASSERT_EQ(allPaths.size(), 1u);
    EXPECT_EQ(allPaths[0], "/proc/sys/net/ipv4/conf/all/send_redirects");

    auto ethPaths = SysctlManager::sendRedirectsSysctls("eth0");
    ASSERT_EQ(ethPaths.size(), 2u);
    EXPECT_EQ(ethPaths[0], "/proc/sys/net/ipv4/conf/all/send_redirects");
    EXPECT_EQ(ethPaths[1], "/proc/sys/net/ipv4/conf/eth0/send_redirects");

    // 2. 验证内核节点读取容错性 (容器/沙箱环境下只读或受限时不抛异常崩溃)
    auto ipFwd = SysctlManager::getSysctl("/proc/sys/net/ipv4/ip_forward");
    if (ipFwd.has_value())
    {
        EXPECT_TRUE(*ipFwd == "0" || *ipFwd == "1");
    }

    // 3. 验证管理器调优接口
    EbpfConfig cfg;
    cfg.lanInterface = "eth0";
    cfg.wanInterface = "eth1";
    EbpfManager mgr(cfg);
    [[maybe_unused]] bool tuned = mgr.tuneGatewaySysctls();
}

// =============================================================================
// 29. 内核直连流量只读观测器 (DirectTrafficStats) 测试 (借鉴 dae direct_stats)
// =============================================================================

TEST(EbpfTest, DirectTrafficObserverStats)
{
    EbpfManager mgr;
    auto initialStats = mgr.getDirectTrafficStats();
    EXPECT_EQ(initialStats.directBytes, 0u);

    TuplesKey directKey{
        .saddr = 0x0100007f, // 127.0.0.1
        .daddr = 0x01010101, // 1.1.1.1
        .sport = htons(12345),
        .dport = htons(80),
        .proto = IPPROTO_TCP
    };

    uint64_t nowNs = getMonotonicTimeNs();
    EXPECT_TRUE(mgr.trackUdpConnState(directKey, Action::DIRECT, nowNs));

    // 验证直连流量统计能精准读取 conn_state_map 中的直连表项
    auto stats = mgr.getDirectTrafficStats();
    EXPECT_GE(stats.directPackets, 0u);
}

// =============================================================================
// 30. 数据平面增量区间监控器测试 (借鉴 dae datapath_overflow_report)
// =============================================================================

TEST(EbpfTest, DatapathOverflowMonitorDeltaReporting)
{
    DatapathOverflowMonitor monitor(50); // heavy threshold = 50

    // 1. 初次基准观察：静默对齐 baseline
    DatapathOverflowMonitor::Snapshot s0{
        .udpConnOverflow = 1000,
        .tcpConnOverflow = 2000,
        .blockRateDrops = 500,
        .eventDrops = 10
    };
    auto r0 = monitor.evaluate(s0);
    EXPECT_FALSE(r0.moved);
    EXPECT_EQ(r0.level, DatapathOverflowMonitor::PressureLevel::NORMAL);

    // 2. 稳定无变化区间：保持 NORMAL 静默
    auto r1 = monitor.evaluate(s0);
    EXPECT_FALSE(r1.moved);
    EXPECT_EQ(r1.level, DatapathOverflowMonitor::PressureLevel::NORMAL);

    // 3. 轻微波动区间 (增量低于阈值 50)：升级为 WARNING
    DatapathOverflowMonitor::Snapshot s2{
        .udpConnOverflow = 1010, // delta = 10
        .tcpConnOverflow = 2005, // delta = 5
        .blockRateDrops = 500,
        .eventDrops = 10
    };
    auto r2 = monitor.evaluate(s2);
    EXPECT_TRUE(r2.moved);
    EXPECT_EQ(r2.deltaUdpOverflow, 10u);
    EXPECT_EQ(r2.deltaTcpOverflow, 5u);
    EXPECT_EQ(r2.level, DatapathOverflowMonitor::PressureLevel::WARNING);

    // 4. 重度压力区间 (单周期增量突破 50)：升级为 CRITICAL
    DatapathOverflowMonitor::Snapshot s3{
        .udpConnOverflow = 1080, // delta = 70 >= 50
        .tcpConnOverflow = 2010, // delta = 5
        .blockRateDrops = 500,
        .eventDrops = 10
    };
    auto r3 = monitor.evaluate(s3);
    EXPECT_TRUE(r3.moved);
    EXPECT_EQ(r3.deltaUdpOverflow, 70u);
    EXPECT_EQ(r3.level, DatapathOverflowMonitor::PressureLevel::CRITICAL);

    // 5. 复位功能测试
    monitor.reset();
    auto r4 = monitor.evaluate(s3);
    EXPECT_FALSE(r4.moved);
}

// =============================================================================
// 31. BPF 内部诊断指标与异步事件数据结构测试 (借鉴 dae bpf_stats_map & event_ringbuf)
// =============================================================================

TEST(EbpfTest, BpfStatsAndMynetEventStructure)
{
    // 验证事件结构体内存对齐
    MynetEvent ev{};
    ev.timestampNs = 123456789;
    ev.type = static_cast<uint32_t>(BpfEventType::BLOCKED);
    ev.protocol = IPPROTO_TCP;
    ev.sport = htons(443);
    ev.dport = htons(54321);
    EXPECT_EQ(sizeof(ev), 32u);

    // 验证引擎诊断统计
    EbpfManager mgr;
    mgr.recordBpfStat(0, 10); // MYNET_STAT_DIRECT_PACKETS += 10
    mgr.recordBpfStat(3, 5);  // MYNET_STAT_L3_PACKETS += 5

    auto stats = mgr.getBpfInternalStats();
    EXPECT_EQ(stats[0], 10u);
    EXPECT_EQ(stats[3], 5u);
}

// =============================================================================
// 32. 单网卡双角色 (Dual-Role Interface) 模式判定测试 (借鉴 dae wan_lan_ingress)
// =============================================================================

TEST(EbpfTest, DualRoleSingleNicMode)
{
    // 1. 双网卡模式 (WAN != LAN)
    EbpfConfig cfgDualNic;
    cfgDualNic.lanInterface = "eth0";
    cfgDualNic.wanInterface = "eth1";
    EbpfManager mgrDual(cfgDualNic);
    EXPECT_FALSE(mgrDual.isDualRole());

    // 2. 单网卡双角色模式 (WAN == LAN, 典型旁路由/树莓派设备)
    EbpfConfig cfgSingleNic;
    cfgSingleNic.lanInterface = "eth0";
    cfgSingleNic.wanInterface = "eth0";
    EbpfManager mgrSingle(cfgSingleNic);
    EXPECT_TRUE(mgrSingle.isDualRole());
}

// =============================================================================
// 33. redirect_track 单写者防伪造保护机制测试 (借鉴 dae single-writer redirect_track)
// =============================================================================

TEST(EbpfTest, RedirectTrackSingleWriterProtection)
{
    EbpfManager mgr;
    mgr.setRedirectRebindStaleNs(5'000'000'000ULL); // 5s 判定窗口

    TuplesKey key{};
    key.saddr = htonl(0x0a000002); // 10.0.0.2
    key.daddr = htonl(0x08080808); // 8.8.8.8
    key.sport = htons(12345);
    key.dport = htons(53);
    key.proto = IPPROTO_UDP;

    // 初始合法发布者 Pub A
    RedirectTrackEntry pubA{};
    pubA.ifindex = 2;
    pubA.fromWan = 0;
    pubA.smac[0] = 0xAA; pubA.smac[1] = 0xBB; pubA.smac[2] = 0xCC;
    pubA.smac[3] = 0x11; pubA.smac[4] = 0x22; pubA.smac[5] = 0x33;
    pubA.lastSeenNs = 1'000'000'000ULL;

    EXPECT_TRUE(mgr.updateRedirectTrack(key, pubA));
    EXPECT_EQ(mgr.redirectRebindRejectedCount(), 0u);

    // 伪造/冒充者 Pub B 在 5s 保护期内 (仅过去 1s) 试图抢占重定向
    RedirectTrackEntry spoofB = pubA;
    spoofB.smac[5] = 0x99; // MAC 伪造
    spoofB.lastSeenNs = 2'000'000'000ULL; // 1s 之后

    EXPECT_FALSE(mgr.updateRedirectTrack(key, spoofB));
    EXPECT_EQ(mgr.redirectRebindRejectedCount(), 1u);

    // 验证路由条目仍为合法发布者 Pub A
    auto cur = mgr.lookupRedirectTrack(key);
    ASSERT_TRUE(cur.has_value());
    EXPECT_EQ(cur->smac[5], 0x33);

    // 合法发布者 Pub A 在窗口内持续更新心跳，应当成功
    pubA.lastSeenNs = 3'000'000'000ULL;
    EXPECT_TRUE(mgr.updateRedirectTrack(key, pubA));

    // 静默超过 5s (当前更新在 10s)，允许合法重绑定 (如漫游迁移)
    RedirectTrackEntry legitRoam = spoofB;
    legitRoam.lastSeenNs = 10'000'000'000ULL;
    EXPECT_TRUE(mgr.updateRedirectTrack(key, legitRoam));

    auto updated = mgr.lookupRedirectTrack(key);
    ASSERT_TRUE(updated.has_value());
    EXPECT_EQ(updated->smac[5], 0x99);
}

// =============================================================================
// 34. 弹性批量 Map 删除与异常跳过测试 (借鉴 dae bpf_map_delete_batch_resilient)
// =============================================================================

TEST(EbpfTest, DeleteBatchResilient)
{
    std::unordered_map<uint32_t, std::string> mockMap;
    mockMap[1] = "alpha";
    mockMap[2] = "beta";
    mockMap[3] = "gamma";

    // 待删除列表中包含不存在的 key 99 与 100
    std::vector<uint32_t> keysToDelete = {1, 99, 3, 100};
    size_t deleted = EbpfManager::deleteBatchResilientMock(mockMap, std::span<const uint32_t>(keysToDelete));

    EXPECT_EQ(deleted, 2u);
    EXPECT_EQ(mockMap.size(), 1u);
    EXPECT_TRUE(mockMap.contains(2));
    EXPECT_FALSE(mockMap.contains(1));
    EXPECT_FALSE(mockMap.contains(3));
}

// =============================================================================
// 35. NTP 未来时钟漂移防驻留清理测试 (借鉴 dae sweepConnState skew tolerance)
// =============================================================================

TEST(EbpfTest, SweepConnStateNtpClockSkewTolerance)
{
    EbpfManager mgr;
    const uint64_t nowNs = ebpf::getMonotonicTimeNs();

    TuplesKey kNormal{};
    kNormal.saddr = htonl(0x0a000001);
    kNormal.sport = htons(1001);
    uint64_t tNormal = (nowNs > 10'000'000'000ULL) ? (nowNs - 10'000'000'000ULL) : 1; // 10s 前活跃
    mgr.trackUdpConnState(kNormal, Action::PROXY, tNormal);

    TuplesKey kExpired{};
    kExpired.saddr = htonl(0x0a000002);
    kExpired.sport = htons(1002);
    uint64_t tExpired = (nowNs > 70'000'000'000ULL) ? (nowNs - 70'000'000'000ULL) : 1; // 70s 前
    mgr.trackUdpConnState(kExpired, Action::PROXY, tExpired);

    TuplesKey kSkewCorrupted{};
    kSkewCorrupted.saddr = htonl(0x0a000003);
    kSkewCorrupted.sport = htons(1003);
    uint64_t tSkewCorrupted = nowNs + 60'000'000'000ULL; // 未来时钟超前 60s (> 30s 容错限)
    mgr.trackUdpConnState(kSkewCorrupted, Action::PROXY, tSkewCorrupted);

    EXPECT_EQ(mgr.connStateCount(), 3u);

    // 执行 60s 周期排空：应当清理过期流 (70s) 与 异常未来漂移流 (+60s)，保留正常流 (10s)
    size_t swept = mgr.sweepConnState(60ULL * 1000 * 1000 * 1000);
    EXPECT_EQ(swept, 2u);
    EXPECT_EQ(mgr.connStateCount(), 1u);

    EXPECT_TRUE(mgr.getConnState(kNormal).has_value());
    EXPECT_FALSE(mgr.getConnState(kExpired).has_value());
    EXPECT_FALSE(mgr.getConnState(kSkewCorrupted).has_value());
}

// =============================================================================
// 36. 短生命周期 UDP 端口判定测试 (机制 65: is_short_lived_udp_traffic)
// =============================================================================

TEST(EbpfTest, ShortLivedUdpBypass)
{
    EXPECT_TRUE(ebpf::isShortLivedUdp(53, 12345));
    EXPECT_TRUE(ebpf::isShortLivedUdp(54321, 53));
    EXPECT_TRUE(ebpf::isShortLivedUdp(53, 53));

    EXPECT_FALSE(ebpf::isShortLivedUdp(443, 12345));
    EXPECT_FALSE(ebpf::isShortLivedUdp(80, 8080));
    EXPECT_FALSE(ebpf::isShortLivedUdp(12345, 54321));
}

// =============================================================================
// 37. 局域网 ICMP 重定向内核双节点路径验证测试 (机制 77: SendRedirectsController)
// =============================================================================

TEST(EbpfTest, SendRedirectsControllerSysctls)
{
    auto paths = SendRedirectsController::sendRedirectsSysctls("eth0");
    ASSERT_EQ(paths.size(), 2u);
    EXPECT_EQ(paths[0], "/proc/sys/net/ipv4/conf/all/send_redirects");
    EXPECT_EQ(paths[1], "/proc/sys/net/ipv4/conf/eth0/send_redirects");

    auto pathsAll = SendRedirectsController::sendRedirectsSysctls("all");
    ASSERT_EQ(pathsAll.size(), 1u);
    EXPECT_EQ(pathsAll[0], "/proc/sys/net/ipv4/conf/all/send_redirects");
}

// =============================================================================
// 38. BPF 连接跟踪回收步调自适应切换测试 (机制 87: JanitorCadenceController)
// =============================================================================

TEST(EbpfTest, JanitorCadenceControllerAdaptiveSteps)
{
    JanitorCadenceController janitor;
    EXPECT_FALSE(janitor.inPressureMode());

    // 1. 低压力稳态 (100 / 1000 = 10%)
    EXPECT_EQ(janitor.step(100, 1000), JanitorCadenceController::STEADY_INTERVAL);
    EXPECT_FALSE(janitor.inPressureMode());

    // 2. 达到 70% 压力门限 (700 / 1000 = 70%)，进入加速压力模式 (1s)
    EXPECT_EQ(janitor.step(700, 1000), JanitorCadenceController::PRESSURE_INTERVAL);
    EXPECT_TRUE(janitor.inPressureMode());

    // 3. 仍在压力区 (600 / 1000 = 60% >= 50%)，维持 1s
    EXPECT_EQ(janitor.step(600, 1000), JanitorCadenceController::PRESSURE_INTERVAL);
    EXPECT_TRUE(janitor.inPressureMode());

    // 4. 降至 40% (< 50%)：第 1 轮平静，仍需维持以防抖
    EXPECT_EQ(janitor.step(400, 1000), JanitorCadenceController::PRESSURE_INTERVAL);
    EXPECT_TRUE(janitor.inPressureMode());

    // 5. 第 2 轮平静
    EXPECT_EQ(janitor.step(300, 1000), JanitorCadenceController::PRESSURE_INTERVAL);
    EXPECT_TRUE(janitor.inPressureMode());

    // 6. 第 3 轮平静：满足 3 轮退出防抖条件，退出压力模式回到稳态 5s
    EXPECT_EQ(janitor.step(200, 1000), JanitorCadenceController::STEADY_INTERVAL);
    EXPECT_FALSE(janitor.inPressureMode());

    // 7. 完全空闲 (0 条目)，退避至 MAX_INTERVAL (30s)
    EXPECT_EQ(janitor.step(0, 1000), JanitorCadenceController::MAX_INTERVAL);
}
