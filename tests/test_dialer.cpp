#include "dialer.hpp"
#include "handler/handler.hpp"
#include "../examples/common/resolver.hpp"
#include <gtest/gtest.h>
#include <string>
#include <vector>

using namespace mynet;
using namespace mynet::handler;
using namespace mynet::handler::dns;

// =============================================================================
// 1. DnsResolver 单元测试
// =============================================================================

TEST(DnsResolverTest, EncodeQueryRfc1035)
{
    auto query = dns::encodeQuery("example.com", dns::kTypeA, 0xABCD);
    ASSERT_GE(query.size(), 12 + 13 + 4);

    // 事务 ID
    EXPECT_EQ(query[0], 0xAB);
    EXPECT_EQ(query[1], 0xCD);

    // Flags (RD=1)
    EXPECT_EQ(query[2], 0x01);
    EXPECT_EQ(query[3], 0x00);

    // QDCOUNT = 1
    EXPECT_EQ(query[4], 0x00);
    EXPECT_EQ(query[5], 0x01);

    // QNAME: 7example3com0
    EXPECT_EQ(query[12], 7);
    std::string label1(reinterpret_cast<char *>(&query[13]), 7);
    EXPECT_EQ(label1, "example");
    EXPECT_EQ(query[20], 3);
    std::string label2(reinterpret_cast<char *>(&query[21]), 3);
    EXPECT_EQ(label2, "com");
    EXPECT_EQ(query[24], 0);

    // QTYPE = 1 (A), QCLASS = 1 (IN)
    EXPECT_EQ(query[25], 0x00);
    EXPECT_EQ(query[26], 0x01);
    EXPECT_EQ(query[27], 0x00);
    EXPECT_EQ(query[28], 0x01);
}

TEST(DnsResolverTest, DecodeResponseAndCache)
{
    // 构造一个合法的 DNS 响应包: 事务 ID=0x1234, Flags=0x8180 (标准响应, No error)
    // QDCOUNT=1, ANCOUNT=1, A 记录: 93.184.216.34, TTL=300
    std::vector<uint8_t> resp = {
        0x12, 0x34,             // ID
        0x81, 0x80,             // Flags: Response, Recursion Desired & Available
        0x00, 0x01,             // QDCOUNT = 1
        0x00, 0x01,             // ANCOUNT = 1
        0x00, 0x00,             // NSCOUNT = 0
        0x00, 0x00,             // ARCOUNT = 0
        // Question: 7example3com0 | Type A | Class IN
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01,
        // Answer: 指针压缩 0xC00C, TYPE=1, CLASS=1, TTL=300 (0x0000012C), RDLENGTH=4, IP=93.184.216.34
        0xC0, 0x0C,
        0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x01, 0x2C,
        0x00, 0x04,
        93, 184, 216, 34
    };

    std::vector<in_addr> v4;
    std::vector<in6_addr> v6;
    uint32_t ttl = 0;
    bool ok = dns::decodeResponse(resp, v4, v6, ttl);
    ASSERT_TRUE(ok);
    ASSERT_EQ(v4.size(), 1u);
    EXPECT_EQ(ttl, 300u);

    char ipBuf[INET_ADDRSTRLEN]{};
    ::inet_ntop(AF_INET, &v4[0], ipBuf, sizeof(ipBuf));
    EXPECT_STREQ(ipBuf, "93.184.216.34");

    // 测试 DnsResolver 缓存与 resolveFast
    DnsResolver resolver;
    resolver.putCache("example.com", v4, v6, ttl);

    auto resolved = resolver.resolveFast("example.com", 80);
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved->host, "93.184.216.34");
    EXPECT_EQ(resolved->port, 80);

    // IP 字面量直接快速解析，无需 DNS 查询
    auto directIp = resolver.resolveFast("1.1.1.1", 443);
    ASSERT_TRUE(directIp.has_value());
    EXPECT_EQ(directIp->host, "1.1.1.1");
    EXPECT_EQ(directIp->port, 443);
}

// =============================================================================
// 2. DialerBase 单元测试
// =============================================================================

TEST(DialerBaseTest, LifecycleAndReset)
{
    DialerBase<HandlerConnection> dialer;
    EXPECT_EQ(dialer.fd, -1);

    // 拨号非法 IP 格式失败
    auto res = dialer.dialTcp("not_an_ip", 80);
    EXPECT_FALSE(res.has_value());
    EXPECT_EQ(res.error(), ERR::ADDR_INVALID);

    // 拨号非阻塞，向本地不存在的服务建连应返回 false (EINPROGRESS) 或失败
    auto res2 = dialer.dialTcp("127.0.0.1", 65534);
    if (res2.has_value())
    {
        // 若为 false，说明处于 EINPROGRESS 异步连接中
        EXPECT_GE(dialer.fd, 0);
    }
    dialer.reset();
    EXPECT_EQ(dialer.fd, -1);
}

// =============================================================================
// 3. HandlerOutboundConnection 出站协议族测试
// =============================================================================

TEST(HandlerOutboundTest, DirectOutbound)
{
    auto target = ProxyAddress::fromDomain("example.com", 443);
    HandlerOutboundDirect direct(target);

    EXPECT_TRUE(direct.isEstablished());
    EXPECT_EQ(direct.stage(), OutboundStage::STREAMING);
    EXPECT_EQ(direct.target().toString(), "example.com:443");
}

TEST(HandlerOutboundTest, TrojanOutbound)
{
    auto target = ProxyAddress::fromDomain("example.com", 443);
    HandlerOutboundTrojan trojan("password123", target);

    EXPECT_FALSE(trojan.isEstablished());
    EXPECT_EQ(trojan.stage(), OutboundStage::INITIAL);

    // 驱动 process() 发送出站头部
    trojan.process();
    EXPECT_TRUE(trojan.isEstablished());
    EXPECT_EQ(trojan.stage(), OutboundStage::STREAMING);
    ASSERT_TRUE(trojan.hasResponse());

    std::string sent = trojan.takeResponse();
    // Trojan 头部：56B 密钥 + CRLF + CMD + Address + CRLF
    std::string expectedKey = crypto::sha224Hex("password123");
    EXPECT_TRUE(sent.starts_with(expectedKey + "\r\n\x01"));
    EXPECT_TRUE(sent.ends_with("\r\n"));
}

TEST(HandlerOutboundTest, VlessOutbound)
{
    auto target = ProxyAddress::fromDomain("vless.test", 8443);
    std::array<uint8_t, 16> uuid = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    HandlerOutboundVless vless(uuid, target);

    EXPECT_FALSE(vless.isEstablished());
    vless.process(); // 发送首包，进入 CONNECTING
    EXPECT_EQ(vless.stage(), OutboundStage::CONNECTING);
    ASSERT_TRUE(vless.hasResponse());

    std::string sent = vless.takeResponse();
    // VLESS 首字节 Version 0x00, 紧跟 16B UUID
    EXPECT_EQ(static_cast<uint8_t>(sent[0]), 0x00);
    EXPECT_EQ(std::memcmp(sent.data() + 1, uuid.data(), 16), 0);

    // 服务端回送 2 字节握手响应 [0x00, 0x00]
    std::string serverResp("\x00\x00", 2);
    [[maybe_unused]] auto _ = vless.appendRequest(serverResp);
    vless.process();

    EXPECT_TRUE(vless.isEstablished());
    EXPECT_EQ(vless.stage(), OutboundStage::STREAMING);
}

TEST(HandlerOutboundTest, Socks5Outbound)
{
    auto target = ProxyAddress::fromDomain("target.org", 80);
    HandlerOutboundSocks5 s5(target);

    // Step 1: 发送 greeting [0x05, 0x01, 0x00]
    s5.process();
    EXPECT_EQ(s5.stage(), OutboundStage::CONNECTING);
    ASSERT_TRUE(s5.hasResponse());
    std::string greeting = s5.takeResponse();
    EXPECT_EQ(greeting, std::string("\x05\x01\x00", 3));

    // Step 2: 服务端回复 [0x05, 0x00] (免密)
    std::string srvGreeting("\x05\x00", 2);
    [[maybe_unused]] auto _1 = s5.appendRequest(srvGreeting);
    s5.process();

    // 应该已推送 CONNECT 请求包
    ASSERT_TRUE(s5.hasResponse());
    std::string connectReq = s5.takeResponse();
    EXPECT_EQ(connectReq.substr(0, 3), std::string("\x05\x01\x00", 3));

    // Step 3: 服务端回复 CONNECT 成功响应 [0x05, 0x00, 0x00, 0x01, IP(4), PORT(2)]
    std::string srvConnectOk = std::string("\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00", 10);
    [[maybe_unused]] auto _2 = s5.appendRequest(srvConnectOk);
    s5.process();

    EXPECT_TRUE(s5.isEstablished());
    EXPECT_EQ(s5.stage(), OutboundStage::STREAMING);
}

TEST(HandlerOutboundTest, BlockOutbound)
{
    HandlerOutboundBlock block;
    EXPECT_FALSE(block.isEstablished());
    EXPECT_EQ(block.stage(), OutboundStage::ERROR);
    EXPECT_TRUE(block.closeAfterResponse());
}

TEST(HandlerOutboundTest, Hysteria2Outbound)
{
    auto target = ProxyAddress::fromDomain("hysteria.test", 443);
    HandlerOutboundHysteria2 hy2("mypassword", target);

    EXPECT_FALSE(hy2.isEstablished());
    EXPECT_EQ(hy2.stage(), OutboundStage::INITIAL);

    hy2.process(); // 发送认证首包，进入 CONNECTING
    EXPECT_EQ(hy2.stage(), OutboundStage::CONNECTING);
    ASSERT_TRUE(hy2.hasResponse());

    std::string sent = hy2.takeResponse();
    ASSERT_GE(sent.size(), 12u);
    EXPECT_EQ(static_cast<uint8_t>(sent[0]), 10u);
    EXPECT_EQ(sent.substr(1, 10), "mypassword");
    EXPECT_EQ(static_cast<uint8_t>(sent[11]), hysteria2::kCmdTcp);

    // 服务端回送 1 字节握手成功 [0x00]
    std::string serverResp("\x00", 1);
    [[maybe_unused]] auto _ = hy2.appendRequest(serverResp);
    hy2.process();

    EXPECT_TRUE(hy2.isEstablished());
    EXPECT_EQ(hy2.stage(), OutboundStage::STREAMING);
}

// =============================================================================
// 4. DNS 协议处理器族测试 (HandlerInboundConnectionDns / HandlerInboundDatagramDns / HandlerOutboundConnectionDns / HandlerOutboundDatagramDns)
// =============================================================================

TEST(HandlerDnsTest, TcpDnsServerAndClient)
{
    HandlerInboundConnectionDns server;
    server.setResponder([](const dns::DnsMessage &query) -> std::optional<dns::DnsMessage> {
        auto resp = query.makeResponse();
        in_addr ip{};
        ::inet_pton(AF_INET, "10.0.0.1", &ip);
        resp.answers.push_back(dns::DnsRecord::createA("api.test.com", ip, 120));
        return resp;
    });

    // 客户端构造查询
    auto queryBytes = dns::encodeQuery("api.test.com", dns::kTypeA, 0x1234);
    std::string tcpReq;
    tcpReq.push_back(static_cast<char>(queryBytes.size() >> 8));
    tcpReq.push_back(static_cast<char>(queryBytes.size() & 0xFF));
    tcpReq.append(reinterpret_cast<const char *>(queryBytes.data()), queryBytes.size());

    // 服务端消费请求并应答
    [[maybe_unused]] auto _ = server.appendRequest(tcpReq);
    server.process();

    ASSERT_TRUE(server.lastQuery().has_value());
    EXPECT_EQ(server.lastQuery()->header.id, 0x1234);
    ASSERT_TRUE(server.hasResponse());

    std::string srvResp = server.takeResponse();

    // 客户端接收响应
    HandlerInboundConnectionDns client;
    [[maybe_unused]] auto _2 = client.appendRequest(srvResp);
    client.process();

    ASSERT_TRUE(client.lastResponse().has_value());
    EXPECT_EQ(client.lastResponse()->header.id, 0x1234);
    ASSERT_EQ(client.lastResponse()->answers.size(), 1u);
    EXPECT_EQ(client.lastResponse()->answers[0].ipString(), "10.0.0.1");
    EXPECT_EQ(client.lastResponse()->answers[0].ttl, 120u);
}

TEST(HandlerDnsTest, UdpDatagramDnsServer)
{
    HandlerInboundDatagramDns udpServer;
    udpServer.setResponder([](const dns::DnsMessage &query) -> std::optional<dns::DnsMessage> {
        auto resp = query.makeResponse();
        in_addr ip{};
        ::inet_pton(AF_INET, "192.168.1.1", &ip);
        resp.answers.push_back(dns::DnsRecord::createA("udp.test.com", ip, 60));
        return resp;
    });

    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    peer.sin_port = htons(12345);
    ::inet_pton(AF_INET, "127.0.0.1", &peer.sin_addr);

    auto queryBytes = dns::encodeQuery("udp.test.com", dns::kTypeA, 0x7788);
    udpServer.onDatagram(peer, reinterpret_cast<const char *>(queryBytes.data()), queryBytes.size());

    ASSERT_TRUE(udpServer.hasOutgoing());
    auto outPkt = udpServer.takeOutgoing();
    std::span<const uint8_t> payload(reinterpret_cast<const uint8_t *>(outPkt.bytes.data()), outPkt.bytes.size());

    auto decoded = dns::DnsMessage::decode(payload);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->header.id, 0x7788);
    ASSERT_EQ(decoded->answers.size(), 1u);
    EXPECT_EQ(decoded->answers[0].ipString(), "192.168.1.1");
}

TEST(HandlerDnsTest, OutboundDnsClient)
{
    HandlerOutboundConnectionDns client("query.test", dns::kTypeA, 0x9999);
    EXPECT_EQ(client.stage(), OutboundStage::INITIAL);

    // 驱动 process() 发出 TCP 查询包
    client.process();
    EXPECT_EQ(client.stage(), OutboundStage::CONNECTING);
    ASSERT_TRUE(client.hasResponse());

    std::string sent = client.takeResponse();
    ASSERT_GE(sent.size(), 2u);

    // 构造上游响应回包
    dns::DnsMessage resp;
    resp.header.id = 0x9999;
    resp.header.setResponse(true);
    in_addr ip{};
    ::inet_pton(AF_INET, "8.8.4.4", &ip);
    resp.answers.push_back(dns::DnsRecord::createA("query.test", ip, 300));
    auto respRaw = resp.encode();

    std::string tcpResp;
    tcpResp.push_back(static_cast<char>(respRaw.size() >> 8));
    tcpResp.push_back(static_cast<char>(respRaw.size() & 0xFF));
    tcpResp.append(reinterpret_cast<const char *>(respRaw.data()), respRaw.size());

    [[maybe_unused]] auto _ = client.appendRequest(tcpResp);
    client.process();

    EXPECT_TRUE(client.isEstablished());
    EXPECT_EQ(client.stage(), OutboundStage::STREAMING);
    ASSERT_TRUE(client.response().has_value());
    EXPECT_EQ(client.response()->header.id, 0x9999);
    ASSERT_EQ(client.response()->answers.size(), 1u);
    EXPECT_EQ(client.response()->answers[0].ipString(), "8.8.4.4");
}

TEST(HandlerDnsTest, OutboundDatagramDnsClient)
{
    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port = htons(53);
    ::inet_pton(AF_INET, "8.8.8.8", &server.sin_addr);

    HandlerOutboundDatagramDns client(server, "udpquery.test", dns::kTypeA, 0x4321);
    client.sendQuery();
    ASSERT_TRUE(client.hasOutgoing());

    auto out = client.takeOutgoing();
    std::span<const uint8_t> payload(reinterpret_cast<const uint8_t *>(out.bytes.data()), out.bytes.size());
    auto decoded = dns::DnsMessage::decode(payload);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->header.id, 0x4321);

    // 服务端响应
    dns::DnsMessage resp;
    resp.header.id = 0x4321;
    resp.header.setResponse(true);
    in_addr ip{};
    ::inet_pton(AF_INET, "1.1.1.1", &ip);
    resp.answers.push_back(dns::DnsRecord::createA("udpquery.test", ip, 60));
    auto respBytes = resp.encode();

    client.onDatagram(server, reinterpret_cast<const char *>(respBytes.data()), respBytes.size());
    ASSERT_TRUE(client.response().has_value());
    EXPECT_EQ(client.response()->header.id, 0x4321);
    ASSERT_EQ(client.response()->answers.size(), 1u);
    EXPECT_EQ(client.response()->answers[0].ipString(), "1.1.1.1");
}

TEST(DialerBaseTest, StrategyRoutingOptionsFwmarkAndTransparent)
{
    struct DummyHandler : HandlerConnection
    {
        void process() {}
    };

    DialerBase<DummyHandler> dialer;
    EXPECT_EQ(dialer.mark(), 0u);
    EXPECT_FALSE(dialer.isTransparent());

    dialer.setMark(0x1F2E);
    EXPECT_EQ(dialer.mark(), 0x1F2Eu);

    dialer.setTransparent(true);
    EXPECT_TRUE(dialer.isTransparent());

    dialer.reset();
    // reset clears fd and targetAddr
    EXPECT_EQ(dialer.fd, -1);
}
