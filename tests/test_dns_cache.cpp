#include "dns/cache.hpp"
#include "dns/dns.hpp"
#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <thread>
#include <vector>

using namespace mynet;
using namespace mynet::dns;

TEST(DnsReverseCacheTest, InsertAndLookupIpv4)
{
    auto &cache = DnsReverseCache::instance();
    cache.clear();

    in_addr ip{};
    ASSERT_EQ(::inet_pton(AF_INET, "1.1.1.1", &ip), 1);

    cache.insert(ip, "one.one.one.one", 300);
    auto hit = cache.lookup(ip);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(*hit, "one.one.one.one");

    in_addr unknownIp{};
    ASSERT_EQ(::inet_pton(AF_INET, "8.8.8.8", &unknownIp), 1);
    EXPECT_FALSE(cache.lookup(unknownIp).has_value());
}

TEST(DnsReverseCacheTest, InsertAndLookupIpv6)
{
    auto &cache = DnsReverseCache::instance();
    cache.clear();

    in6_addr ip6{};
    ASSERT_EQ(::inet_pton(AF_INET6, "2606:4700:4700::1111", &ip6), 1);

    cache.insert(ip6, "cloudflare-dns.com", 600);
    auto hit = cache.lookup(ip6);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(*hit, "cloudflare-dns.com");
}

TEST(DnsReverseCacheTest, LookupProxyAddress)
{
    auto &cache = DnsReverseCache::instance();
    cache.clear();

    in_addr ip{};
    ASSERT_EQ(::inet_pton(AF_INET, "104.16.132.229", &ip), 1);
    cache.insert(ip, "cloudflare.com", 300);

    auto proxyAddr = Address::fromIPv4(ip.s_addr, 443);
    auto upgraded = cache.lookup(proxyAddr);
    ASSERT_TRUE(upgraded.has_value());
    EXPECT_EQ(upgraded->type, AddressType::DOMAIN);
    EXPECT_EQ(upgraded->host, "cloudflare.com");
    EXPECT_EQ(upgraded->port, 443);
}

TEST(DnsReverseCacheTest, InsertFromDnsMessage)
{
    auto &cache = DnsReverseCache::instance();
    cache.clear();

    DnsMessage msg;
    msg.header.setResponse(true);
    msg.header.ancount = 2;

    in_addr v4{};
    ASSERT_EQ(::inet_pton(AF_INET, "93.184.216.34", &v4), 1);
    msg.answers.push_back(DnsRecord::createA("example.com", v4, 120));

    in6_addr v6{};
    ASSERT_EQ(::inet_pton(AF_INET6, "2606:2800:220:1:248:1893:25c8:1946", &v6), 1);
    msg.answers.push_back(DnsRecord::createAAAA("example.com", v6, 120));

    cache.insertFromDnsMessage(msg);

    auto hitV4 = cache.lookup(v4);
    ASSERT_TRUE(hitV4.has_value());
    EXPECT_EQ(*hitV4, "example.com");

    auto hitV6 = cache.lookup(v6);
    ASSERT_TRUE(hitV6.has_value());
    EXPECT_EQ(*hitV6, "example.com");
}

TEST(DnsReverseCacheTest, ConcurrentAccess)
{
    auto &cache = DnsReverseCache::instance();
    cache.clear();

    std::vector<std::thread> workers;
    workers.reserve(8);

    for (int t = 0; t < 8; ++t)
    {
        workers.emplace_back(
            [t, &cache]()
            {
                for (int i = 0; i < 200; ++i)
                {
                    in_addr ip{};
                    ip.s_addr = htonl((10 << 24) | (t << 16) | (i & 0xFFFF));
                    std::string dom = "worker-" + std::to_string(t) + ".test";
                    cache.insert(ip, dom, 60);

                    auto res = cache.lookup(ip);
                    if (res.has_value())
                    {
                        EXPECT_EQ(*res, dom);
                    }
                }
            });
    }

    for (auto &w : workers)
    {
        w.join();
    }

    EXPECT_GT(cache.size(), 0u);
}

TEST(DnsReverseCacheTest, Rfc8767OptimisticServeStale)
{
    auto &cache = DnsReverseCache::instance();
    cache.clear();
    cache.setStaleGracePeriod(std::chrono::seconds(60));

    in_addr ip{};
    ASSERT_EQ(::inet_pton(AF_INET, "198.51.100.1", &ip), 1);

    // 插入一条已经过期的记录（当前时间前 5 秒）
    const auto now = std::chrono::steady_clock::now();
    cache.insertExplicit(ip, "stale.example.com", now - std::chrono::seconds(5));

    // 普通严格 lookup 应返回 nullopt（已过期）
    EXPECT_FALSE(cache.lookup(ip).has_value());

    // RFC 8767 弹性乐观 lookupOptimistic 应命中陈旧记录并标记 needsRefresh
    bool isStale = false;
    bool needsRefresh = false;
    auto staleHit = cache.lookupOptimistic(ip, &isStale, &needsRefresh);
    ASSERT_TRUE(staleHit.has_value());
    EXPECT_EQ(*staleHit, "stale.example.com");
    EXPECT_TRUE(isStale);
    EXPECT_TRUE(needsRefresh);

    // 第二次并发/后续访问：虽然仍处于 stale 状态，但 refreshing 标志位已置位，不再重复触发刷新（防击穿）
    bool isStale2 = false;
    bool needsRefresh2 = false;
    auto staleHit2 = cache.lookupOptimistic(ip, &isStale2, &needsRefresh2);
    ASSERT_TRUE(staleHit2.has_value());
    EXPECT_TRUE(isStale2);
    EXPECT_FALSE(needsRefresh2);

    // 模拟后台异步刷新完成
    cache.markRefreshed(ip);

    // 再次访问时应再次允许触发刷新
    bool isStale3 = false;
    bool needsRefresh3 = false;
    auto staleHit3 = cache.lookupOptimistic(ip, &isStale3, &needsRefresh3);
    ASSERT_TRUE(staleHit3.has_value());
    EXPECT_TRUE(needsRefresh3);

    // 测试超过 staleGracePeriod 的记录（当前时间前 120 秒，容忍期 60 秒）
    in_addr expiredFarIp{};
    ASSERT_EQ(::inet_pton(AF_INET, "198.51.100.2", &expiredFarIp), 1);
    cache.insertExplicit(expiredFarIp, "dead.example.com", now - std::chrono::seconds(120));

    bool isStaleDead = false;
    bool needsRefreshDead = false;
    auto deadHit = cache.lookupOptimistic(expiredFarIp, &isStaleDead, &needsRefreshDead);
    EXPECT_FALSE(deadHit.has_value());
}

// =============================================================================
// 7. DNS UDP 截断与 TCP 降级管理器测试 (借鉴 dae DnsTruncationManager)
// =============================================================================

TEST(DnsReverseCacheTest, DnsTruncationManager)
{
    DnsTruncationManager mgr;

    // 构造标准正常响应报文 (TC = 0)
    uint8_t normalWire[32] = {0x12, 0x34, 0x81, 0x80}; // flags: 0x8180 (TC=0)
    EXPECT_FALSE(DnsTruncationManager::isTruncated(std::span<const uint8_t>(normalWire, sizeof(normalWire))));
    EXPECT_FALSE(mgr.shouldFallbackToTcp(std::span<const uint8_t>(normalWire, sizeof(normalWire))));

    // 构造携带截断标志位的报文 (TC = 1, byte 2 bit 1 = 0x02)
    uint8_t truncatedWire[32] = {0x12, 0x34, 0x83, 0x80}; // flags: 0x8380 (TC=1)
    EXPECT_TRUE(DnsTruncationManager::isTruncated(std::span<const uint8_t>(truncatedWire, sizeof(truncatedWire))));
    EXPECT_TRUE(mgr.shouldFallbackToTcp(std::span<const uint8_t>(truncatedWire, sizeof(truncatedWire))));
    EXPECT_EQ(mgr.tcCount(), 1u);

    // 记录 TCP 回退统计
    mgr.recordTcpFallbackResult(true);
    mgr.recordTcpFallbackResult(false);
    EXPECT_EQ(mgr.tcpFallbackSuccessCount(), 1u);
    EXPECT_EQ(mgr.tcpFallbackFailureCount(), 1u);
}

// =============================================================================
// 8. DNS 线缆格式原生响应缓存与 ID 重写测试 (借鉴 dae DnsPackedResponseCache)
// =============================================================================

TEST(DnsReverseCacheTest, DnsPackedResponseCache)
{
    DnsPackedResponseCache packedCache;

    // 构造一个简单的原生 DNS 响应线缆字节流 (ID = 0x1122)
    std::vector<uint8_t> mockWire = {
        0x11, 0x22, // ID
        0x81, 0x80, // Flags: Standard query response, No error
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x01, // ANCOUNT = 1
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x00, // ARCOUNT = 0
        0x07, 'e',  'x',  'a',  'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, // example.com
        0x00, 0x01, 0x00, 0x01,                                                // QTYPE=A, QCLASS=IN
        0xc0, 0x0c,                                                            // Pointer to example.com
        0x00, 0x01, 0x00, 0x01,                                                // TYPE=A, CLASS=IN
        0x00, 0x00, 0x00, 0x3c,                                                // TTL = 60s
        0x00, 0x04,                                                            // RDLENGTH = 4
        0x5d, 0xd0, 0x01, 0x01                                                 // 93.208.1.1
    };

    packedCache.put("example.com", 1, std::span<const uint8_t>(mockWire), 60);
    EXPECT_EQ(packedCache.size(), 1u);

    // 客户端使用新的事务 ID 0xABCD 查询缓存
    auto hit = packedCache.get("example.com", 1, 0xABCD);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->size(), mockWire.size());

    // 验证返回的报文 ID 被动态重写为 0xABCD (大端 0xAB, 0xCD)
    EXPECT_EQ((*hit)[0], 0xAB);
    EXPECT_EQ((*hit)[1], 0xCD);

    // 验证其余载荷与应答一致
    EXPECT_EQ((*hit)[2], mockWire[2]);
    EXPECT_EQ((*hit)[3], mockWire[3]);
    EXPECT_EQ((*hit)[hit->size() - 1], mockWire.back());

    // 未命中测试
    auto miss = packedCache.get("notfound.com", 1, 0x1234);
    EXPECT_FALSE(miss.has_value());
}

// =============================================================================
// 9. DNS 并发查询单飞去重器测试 (借鉴 dae DnsSingleflight)
// =============================================================================

TEST(DnsReverseCacheTest, DnsSingleflight)
{
    DnsSingleflight flight;

    bool isLeader1 = false;
    auto call1 = flight.enter("api.github.com", 1, isLeader1);
    EXPECT_TRUE(isLeader1);
    ASSERT_NE(call1, nullptr);
    EXPECT_FALSE(call1->ready);

    // 第二个并发请求到达，应当加入现有队列，且不为 Leader
    bool isLeader2 = true;
    auto call2 = flight.enter("api.github.com", 1, isLeader2);
    EXPECT_FALSE(isLeader2);
    ASSERT_EQ(call1, call2); // 共享同一对象
    EXPECT_EQ(flight.inFlightCount(), 1u);

    // Leader 完成网络查询并广播结果
    std::vector<uint8_t> dummyResult = {0x01, 0x02, 0x03, 0x04};
    flight.complete("api.github.com", 1, std::span<const uint8_t>(dummyResult), true);

    EXPECT_EQ(flight.inFlightCount(), 0u);
    EXPECT_TRUE(call1->ready);
    EXPECT_TRUE(call1->success);
    EXPECT_EQ(call1->payload, dummyResult);

    EXPECT_TRUE(call2->ready);
    EXPECT_TRUE(call2->success);
    EXPECT_EQ(call2->payload, dummyResult);
}

// =============================================================================
// 10. 65536 位 DNS ID 原子位图分配器测试 (借鉴 dae DnsIdBitmap)
// =============================================================================

TEST(DnsReverseCacheTest, DnsIdBitmapAllocation)
{
    DnsIdBitmap bitmap;

    // 分配第一个 ID
    auto id1 = bitmap.allocateId(100);
    ASSERT_TRUE(id1.has_value());
    EXPECT_EQ(*id1, 100);
    EXPECT_TRUE(bitmap.isAllocated(100));

    // 再次以相同的 hint 100 分配，应当自动步长探针分配不同 ID，无碰撞冲突
    auto id2 = bitmap.allocateId(100);
    ASSERT_TRUE(id2.has_value());
    EXPECT_NE(*id2, 100);
    EXPECT_TRUE(bitmap.isAllocated(*id2));

    // 释放 id1
    bitmap.releaseId(100);
    EXPECT_FALSE(bitmap.isAllocated(100));

    // 再次分配 hint 100，应当成功复用
    auto id3 = bitmap.allocateId(100);
    ASSERT_TRUE(id3.has_value());
    EXPECT_EQ(*id3, 100);
    EXPECT_TRUE(bitmap.isAllocated(100));
}

// =============================================================================
// 11. RFC 5452 问题段严格回显匹配与迟到投递测试 (借鉴 dae RFC 5452 verification)
// =============================================================================

TEST(DnsReverseCacheTest, Rfc5452SecurityValidation)
{
    // 构造请求报文 queryWire (QNAME = example.com, QTYPE = A, QCLASS = IN)
    std::vector<uint8_t> queryWire = {
        0x12, 0x34, // ID
        0x01, 0x00, // Flags: Standard query
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 'e',  'x',  'a',  'm', 'p',
        'l',  'e',  0x03, 'c',  'o',  'm',  0x00, 0x00, 0x01, 0x00, 0x01 // QTYPE=1, QCLASS=1
    };

    // 构造完全匹配的响应报文 respWire
    std::vector<uint8_t> respWire = {
        0x12, 0x34, // ID
        0x81, 0x80, // Flags: Response
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',  0x03, 'c',
        'o',  'm',  0x00, 0x00, 0x01, 0x00, 0x01, // QTYPE=1, QCLASS=1
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04};

    EXPECT_TRUE(DnsSecurityValidator::questionEchoMatches(queryWire, respWire));

    // 构造 QTYPE 不匹配的欺骗响应 (QTYPE=AAAA: 0x001C)
    std::vector<uint8_t> spoofedWire = respWire;
    spoofedWire[25] = 0x1C; // 修改 QTYPE
    EXPECT_FALSE(DnsSecurityValidator::questionEchoMatches(queryWire, spoofedWire));

    // 测试迟到投递检测
    DnsIdBitmap bitmap;
    auto allocated500 = bitmap.allocateId(500);
    EXPECT_TRUE(allocated500.has_value());
    EXPECT_FALSE(DnsSecurityValidator::isLateDelivery(500, bitmap)); // 在途，未迟到
    EXPECT_TRUE(DnsSecurityValidator::isLateDelivery(600, bitmap));  // 未知/已超时释放，为迟到包
}

// =============================================================================
// 12. EDNS0 缓冲区容量超限自动截断测试 (借鉴 dae truncateDnsResponse)
// =============================================================================

TEST(DnsReverseCacheTest, TruncateDnsResponse)
{
    // 构造超长响应报文 (大于 32 字节)
    std::vector<uint8_t> longResp = {0x12, 0x34, 0x81, 0x80, // TC = 0
                                     0x00, 0x01,             // QDCOUNT = 1
                                     0x00, 0x02,             // ANCOUNT = 2
                                     0x00, 0x00, 0x00, 0x00, 0x04, 't', 'e', 's', 't', 0x00, 0x00, 0x01, 0x00, 0x01,
                                     // 伪造 30 字节额外应答数据
                                     0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
                                     8, 9};

    // 限制缓冲区上限为 25 字节，强制触发截断
    auto truncated = truncateDnsResponse(longResp, 25);
    EXPECT_LE(truncated.size(), 25u);

    // 验证 TC=1 标志位置位 (byte 2 bit 1 = 0x02)
    EXPECT_TRUE((truncated[2] & 0x02) != 0);

    // 验证 ANCOUNT, NSCOUNT, ARCOUNT 被清空为 0
    EXPECT_EQ(truncated[6], 0);
    EXPECT_EQ(truncated[7], 0);
    EXPECT_EQ(truncated[8], 0);
    EXPECT_EQ(truncated[9], 0);
    EXPECT_EQ(truncated[10], 0);
    EXPECT_EQ(truncated[11], 0);

    // 验证 Question 段完整保留
    EXPECT_EQ(truncated[4], 0);
    EXPECT_EQ(truncated[5], 1); // QDCOUNT = 1
}

// =============================================================================
// 13. Happy Eyeballs v2 双栈仲裁等待注册器测试 (借鉴 dae PreferenceWaitRegistry)
// =============================================================================

TEST(DnsReverseCacheTest, PreferenceWaitRegistry)
{
    DnsPreferencePacer waitReg;
    waitReg.setPreferredQtype(28); // 偏好 IPv6 (AAAA)

    EXPECT_TRUE(waitReg.startWait("dual.example.com", 1, std::chrono::milliseconds(50)));
    EXPECT_FALSE(waitReg.isReadyOrExpired("dual.example.com"));

    // 优选响应到达
    EXPECT_TRUE(waitReg.notifyPreferred("dual.example.com", true));
    EXPECT_TRUE(waitReg.isReadyOrExpired("dual.example.com"));

    waitReg.completeWait("dual.example.com");
    EXPECT_TRUE(waitReg.isReadyOrExpired("dual.example.com"));
}
