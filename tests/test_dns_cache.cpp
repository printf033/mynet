#include "handler/dns/cache.hpp"
#include "handler/dns/dns.hpp"
#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <thread>
#include <vector>

using namespace mynet::handler;
using namespace mynet::handler::dns;

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

    auto proxyAddr = ProxyAddress::fromIPv4(ip.s_addr, 443);
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
        workers.emplace_back([t, &cache]() {
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
