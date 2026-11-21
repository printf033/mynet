#include "address.hpp"
#include "router.hpp"
#include "ruleset.hpp"
#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <memory>
#include <vector>

using namespace mynet;
using namespace mynet::handler;
using namespace mynet::ruleset;

TEST(SrsTest, InvalidMagicAndTruncated)
{
    // Empty data
    auto res1 = RuleSetSrs::parse({});
    EXPECT_FALSE(res1.has_value());
    EXPECT_EQ(res1.error(), SrsError::MALFORMED_DATA);

    // Bad magic
    std::vector<uint8_t> badMagic = {'F', 'O', 'O', 1, 0, 0};
    auto res2 = RuleSetSrs::parse(badMagic);
    EXPECT_FALSE(res2.has_value());
    EXPECT_EQ(res2.error(), SrsError::INVALID_MAGIC);

    // Unsupported version (> 5)
    std::vector<uint8_t> badVer = {'S', 'R', 'S', 99, 0, 0};
    auto res3 = RuleSetSrs::parse(badVer);
    EXPECT_FALSE(res3.has_value());
    EXPECT_EQ(res3.error(), SrsError::UNSUPPORTED_VERSION);
}

TEST(SrsTest, BuildSerializeAndParseRoundtrip)
{
    RuleSetSrs srs;

    SrsRule rule;
    rule.isLogical = false;
    rule.domainKeywords.push_back("google");
    rule.domainKeywords.push_back("youtube");
    rule.ports.push_back(443);
    rule.ports.push_back(8443);
    rule.portRanges.push_back({8000, 8080});

    // 192.168.1.0 ~ 192.168.1.255
    uint32_t ipFrom = (192 << 24) | (168 << 16) | (1 << 8) | 0;
    uint32_t ipTo = (192 << 24) | (168 << 16) | (1 << 8) | 255;
    rule.ipRanges4.push_back({ipFrom, ipTo});

    srs.addRule(std::move(rule));
    EXPECT_EQ(srs.rules().size(), 1u);

    // Serialize
    auto bin = srs.serialize(1);
    ASSERT_FALSE(bin.empty());
    EXPECT_EQ(bin[0], 'S');
    EXPECT_EQ(bin[1], 'R');
    EXPECT_EQ(bin[2], 'S');
    EXPECT_EQ(bin[3], 1);

    // Parse back
    auto parsed = RuleSetSrs::parse(bin);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->rules().size(), 1u);

    const auto &r = parsed->rules()[0];
    EXPECT_FALSE(r.isLogical);
    EXPECT_EQ(r.domainKeywords.size(), 2u);
    EXPECT_EQ(r.domainKeywords[0], "google");
    EXPECT_EQ(r.domainKeywords[1], "youtube");
    EXPECT_EQ(r.ports.size(), 2u);
    EXPECT_EQ(r.ports[0], 443);
    EXPECT_EQ(r.ports[1], 8443);
    ASSERT_EQ(r.portRanges.size(), 1u);
    EXPECT_EQ(r.portRanges[0].from, 8000);
    EXPECT_EQ(r.portRanges[0].to, 8080);
    ASSERT_EQ(r.ipRanges4.size(), 1u);
    EXPECT_EQ(r.ipRanges4[0].from, ipFrom);
    EXPECT_EQ(r.ipRanges4[0].to, ipTo);
}

TEST(SrsTest, MatcherEvaluation)
{
    RuleSetSrs srs;

    // Rule 1: domain keyword "github"
    SrsRule rDomain;
    rDomain.isLogical = false;
    rDomain.domainKeywords.push_back("github");
    srs.addRule(std::move(rDomain));

    // Rule 2: port 443
    SrsRule rPort;
    rPort.isLogical = false;
    rPort.ports.push_back(443);
    srs.addRule(std::move(rPort));

    // Rule 3: IP range 10.0.0.0/8
    SrsRule rIp;
    rIp.isLogical = false;
    uint32_t ip10From = (10 << 24);
    uint32_t ip10To = (10 << 24) | 0xFFFFFF;
    rIp.ipRanges4.push_back({ip10From, ip10To});
    srs.addRule(std::move(rIp));

    sockaddr_in inSubnet{};
    inSubnet.sin_family = AF_INET;
    ::inet_pton(AF_INET, "10.1.2.3", &inSubnet.sin_addr);

    sockaddr_in outSubnet{};
    outSubnet.sin_family = AF_INET;
    ::inet_pton(AF_INET, "8.8.8.8", &outSubnet.sin_addr);

    // Domain match
    EXPECT_TRUE(srs.match("api.github.com", nullptr, 80, "tcp"));
    EXPECT_FALSE(srs.match("gitlab.com", nullptr, 80, "tcp"));

    // Port match
    EXPECT_TRUE(srs.match("", nullptr, 443, "tcp"));
    EXPECT_FALSE(srs.match("", nullptr, 8080, "tcp"));

    // IP match
    EXPECT_TRUE(srs.match("", &inSubnet, 8080, "tcp"));
    EXPECT_FALSE(srs.match("", &outSubnet, 8080, "tcp"));
}

TEST(SrsTest, RouterRuleSetIntegration)
{
    Router router("direct");

    RuleSetSrs blockRules;
    SrsRule r;
    r.isLogical = false;
    r.domainKeywords.push_back("doubleclick");
    r.domainKeywords.push_back("adservice");
    blockRules.addRule(std::move(r));

    router.addRuleSet("adblock", std::make_shared<RuleSetSrs>(std::move(blockRules)));

    // Route matching adblock -> "block"
    router.addRule(RouteRule::to("block").ruleSet("adblock"));
    // Route matching cn-sites -> "proxy"
    router.addRule(RouteRule::to("proxy").domainSuffix("google.com"));

    RouteContext ctxAd;
    ctxAd.target = ProxyAddress::fromDomain("pagead2.doubleclick.net", 443);
    EXPECT_EQ(router.match(ctxAd), "block");

    RouteContext ctxGoogle;
    ctxGoogle.target = ProxyAddress::fromDomain("www.google.com", 443);
    EXPECT_EQ(router.match(ctxGoogle), "proxy");

    RouteContext ctxOther;
    ctxOther.target = ProxyAddress::fromDomain("kernel.org", 443);
    EXPECT_EQ(router.match(ctxOther), "direct");
}
