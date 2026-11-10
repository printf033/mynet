#include "handler/address.hpp"
#include "handler/socks/socks5.hpp"
#include <gtest/gtest.h>
#include <string>
#include <vector>

using namespace mynet;
using namespace mynet::handler;

static_assert(HandlerConstraint<HandlerInboundSocks5>, "HandlerInboundSocks5 must satisfy HandlerConstraint");
static_assert(MandatoryMethodConnection<HandlerInboundSocks5>, "HandlerInboundSocks5 must satisfy MandatoryMethodConnection");

namespace
{
    void feed(HandlerConnection &h, const std::vector<uint8_t> &bytes)
    {
        [[maybe_unused]] auto _ =
            h.appendRequest(reinterpret_cast<const char *>(bytes.data()), static_cast<ssize_t>(bytes.size()));
    }
} // namespace

// ---- ProxyAddress 测试 ----

TEST(ProxyAddressTest, IPv4Codec)
{
    // 127.0.0.1:8080 (0x7F000001, 8080 = 0x1F90)
    uint32_t ipBe = htonl(0x7F000001);
    ProxyAddress addr = ProxyAddress::fromIPv4(ipBe, 8080);
    EXPECT_EQ(addr.type, AddressType::IPV4);
    EXPECT_EQ(addr.host, "127.0.0.1");
    EXPECT_EQ(addr.port, 8080);
    EXPECT_EQ(addr.toString(), "127.0.0.1:8080");

    std::vector<uint8_t> encoded;
    addr.encodeSocks5(encoded);
    // [0x01][127,0,0,1][0x1F, 0x90]
    ASSERT_EQ(encoded.size(), 7);
    EXPECT_EQ(encoded[0], 0x01);
    EXPECT_EQ(encoded[1], 127);
    EXPECT_EQ(encoded[2], 0);
    EXPECT_EQ(encoded[3], 0);
    EXPECT_EQ(encoded[4], 1);
    EXPECT_EQ(encoded[5], 0x1F);
    EXPECT_EQ(encoded[6], 0x90);

    size_t consumed = 0;
    auto decoded = ProxyAddress::decodeSocks5(encoded, consumed);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(consumed, 7);
    EXPECT_EQ(decoded->type, AddressType::IPV4);
    EXPECT_EQ(decoded->host, "127.0.0.1");
    EXPECT_EQ(decoded->port, 8080);
}

TEST(ProxyAddressTest, DomainCodec)
{
    std::string domain = "example.com";
    ProxyAddress addr = ProxyAddress::fromDomain(domain, 443);
    EXPECT_EQ(addr.type, AddressType::DOMAIN);
    EXPECT_EQ(addr.host, "example.com");
    EXPECT_EQ(addr.port, 443);
    EXPECT_EQ(addr.toString(), "example.com:443");

    std::vector<uint8_t> encoded;
    addr.encodeSocks5(encoded);
    // [0x03][len=11]["example.com"][0x01, 0xBB]
    ASSERT_EQ(encoded.size(), 1 + 1 + 11 + 2);
    EXPECT_EQ(encoded[0], 0x03);
    EXPECT_EQ(encoded[1], 11);
    EXPECT_EQ(encoded[13], 0x01);
    EXPECT_EQ(encoded[14], 0xBB);

    size_t consumed = 0;
    auto decoded = ProxyAddress::decodeSocks5(encoded, consumed);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(consumed, encoded.size());
    EXPECT_EQ(decoded->type, AddressType::DOMAIN);
    EXPECT_EQ(decoded->host, "example.com");
    EXPECT_EQ(decoded->port, 443);
}

TEST(ProxyAddressTest, IPv6Codec)
{
    uint8_t ip6[16] = {0};
    ip6[15] = 1; // ::1
    ProxyAddress addr = ProxyAddress::fromIPv6(ip6, 1080);
    EXPECT_EQ(addr.type, AddressType::IPV6);
    EXPECT_EQ(addr.host, "::1");
    EXPECT_EQ(addr.port, 1080);
    EXPECT_EQ(addr.toString(), "[::1]:1080");

    std::vector<uint8_t> encoded;
    addr.encodeSocks5(encoded);
    ASSERT_EQ(encoded.size(), 19);

    size_t consumed = 0;
    auto decoded = ProxyAddress::decodeSocks5(encoded, consumed);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(consumed, 19);
    EXPECT_EQ(decoded->type, AddressType::IPV6);
    EXPECT_EQ(decoded->host, "::1");
    EXPECT_EQ(decoded->port, 1080);
}

// ---- HandlerInboundSocks5 测试 ----

TEST(HandlerSocks5Test, ProxyConfigConstruction)
{
    ProxyConfig cfg;
    cfg.autoReplyConnectSuccess = false;
    HandlerInboundSocks5 handler(cfg);

    // 握手
    feed(handler, std::vector<uint8_t>{0x05, 0x01, 0x00});
    handler.process();
    EXPECT_EQ(handler.stage(), Socks5Stage::REQUEST);
    [[maybe_unused]] auto _ = handler.takeResponse();

    // CONNECT 请求
    std::vector<uint8_t> req = {0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x00, 80};
    feed(handler, req);
    handler.process();

    EXPECT_EQ(handler.stage(), Socks5Stage::STREAMING);
    // 因为设置了 autoReplyConnectSuccess = false，此时不应自动向客户端回送响应
    EXPECT_FALSE(handler.hasResponse());

    // 重新应用配置
    cfg.autoReplyConnectSuccess = true;
    handler.configure(cfg);
}

TEST(HandlerSocks5Test, NoAuthConnectIPv4Success)
{
    HandlerInboundSocks5 handler;
    bool requestCalled = false;
    handler.setOnRequest(
        [&](uint8_t cmd, const ProxyAddress &target)
        {
            requestCalled = true;
            EXPECT_EQ(cmd, socks5::kCmdConnect);
            EXPECT_EQ(target.host, "1.2.3.4");
            EXPECT_EQ(target.port, 80);
        });

    // 1. 发送握手请求：支持 NO_AUTH (0x00)
    std::vector<uint8_t> hello = {0x05, 0x01, 0x00};
    feed(handler, hello);
    handler.process();

    EXPECT_EQ(handler.stage(), Socks5Stage::REQUEST);
    ASSERT_TRUE(handler.hasResponse());
    std::string resp1 = handler.takeResponse();
    ASSERT_EQ(resp1.size(), 2);
    EXPECT_EQ(static_cast<uint8_t>(resp1[0]), 0x05);
    EXPECT_EQ(static_cast<uint8_t>(resp1[1]), 0x00); // 选中 NO_AUTH

    // 2. 发送 CONNECT 请求至 1.2.3.4:80
    // [0x05][0x01 CMD][0x00 RSV][0x01 IPV4][1, 2, 3, 4][0x00, 0x50]
    std::vector<uint8_t> req = {0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50};
    feed(handler, req);
    handler.process();

    EXPECT_TRUE(requestCalled);
    EXPECT_EQ(handler.stage(), Socks5Stage::STREAMING);
    EXPECT_TRUE(handler.isEstablished());

    ASSERT_TRUE(handler.hasResponse());
    std::string resp2 = handler.takeResponse();
    // 响应：0x05, 0x00(Success), 0x00(RSV), 0x01, 0,0,0,0, 0,0
    ASSERT_GE(resp2.size(), 10);
    EXPECT_EQ(static_cast<uint8_t>(resp2[0]), 0x05);
    EXPECT_EQ(static_cast<uint8_t>(resp2[1]), 0x00); // REP_SUCCESS
}

TEST(HandlerSocks5Test, NoAuthConnectDomainSuccess)
{
    HandlerInboundSocks5 handler;
    std::string targetHost;
    uint16_t targetPort = 0;
    handler.setOnRequest(
        [&](uint8_t, const ProxyAddress &target)
        {
            targetHost = target.host;
            targetPort = target.port;
        });

    // 一并喂入握手包和域名请求包（流水线/粘包测试）
    std::vector<uint8_t> stream;
    // 握手
    stream.push_back(0x05);
    stream.push_back(0x01);
    stream.push_back(0x00);
    // 域名 CONNECT: "github.com":443
    std::string domain = "github.com";
    stream.push_back(0x05);
    stream.push_back(0x01);
    stream.push_back(0x00);
    stream.push_back(0x03); // DOMAIN
    stream.push_back(static_cast<uint8_t>(domain.size()));
    stream.insert(stream.end(), domain.begin(), domain.end());
    stream.push_back(0x01);
    stream.push_back(0xBB);

    feed(handler, stream);
    handler.process();

    EXPECT_EQ(targetHost, "github.com");
    EXPECT_EQ(targetPort, 443);
    EXPECT_TRUE(handler.isEstablished());

    // 应该累积了两条响应（握手确认 + CONNECT 成功）
    EXPECT_TRUE(handler.hasResponse());
    std::string resp1 = handler.takeResponse();
    EXPECT_EQ(resp1.size(), 2);
    EXPECT_TRUE(handler.hasResponse());
    std::string resp2 = handler.takeResponse();
    EXPECT_EQ(static_cast<uint8_t>(resp2[1]), socks5::kRepSuccess);
}

TEST(HandlerSocks5Test, UsernamePasswordAuthSuccess)
{
    HandlerInboundSocks5 handler;
    handler.setAuthenticator([](std::string_view user, std::string_view pass)
                             { return user == "admin" && pass == "secret123"; });

    // 1. 客户端发送支持 USER_PASS (0x02) 与 NO_AUTH (0x00)
    std::vector<uint8_t> hello = {0x05, 0x02, 0x00, 0x02};
    feed(handler, hello);
    handler.process();

    EXPECT_EQ(handler.stage(), Socks5Stage::AUTH);
    std::string resp1 = handler.takeResponse();
    ASSERT_EQ(resp1.size(), 2);
    EXPECT_EQ(static_cast<uint8_t>(resp1[1]), 0x02); // 选中 USER_PASS

    // 2. 客户端发送认证凭证：admin / secret123
    std::vector<uint8_t> auth;
    auth.push_back(0x01); // Subnegotiation ver
    auth.push_back(5);    // user len
    auth.insert(auth.end(), {'a', 'd', 'm', 'i', 'n'});
    auth.push_back(9); // pass len
    auth.insert(auth.end(), {'s', 'e', 'c', 'r', 'e', 't', '1', '2', '3'});
    feed(handler, auth);
    handler.process();

    EXPECT_EQ(handler.stage(), Socks5Stage::REQUEST);
    std::string resp2 = handler.takeResponse();
    ASSERT_EQ(resp2.size(), 2);
    EXPECT_EQ(static_cast<uint8_t>(resp2[0]), 0x01);
    EXPECT_EQ(static_cast<uint8_t>(resp2[1]), 0x00); // 认证成功
}

TEST(HandlerSocks5Test, UsernamePasswordAuthFailure)
{
    HandlerInboundSocks5 handler;
    handler.setAuthenticator([](std::string_view user, std::string_view pass)
                             { return user == "admin" && pass == "correct"; });

    // 握手
    feed(handler, std::vector<uint8_t>{0x05, 0x01, 0x02});
    handler.process();
    EXPECT_EQ(handler.stage(), Socks5Stage::AUTH);
    [[maybe_unused]] auto _ = handler.takeResponse();

    // 错误密码
    std::vector<uint8_t> auth = {0x01, 5, 'a', 'd', 'm', 'i', 'n', 5, 'w', 'r', 'o', 'n', 'g'};
    feed(handler, auth);
    handler.process();

    EXPECT_EQ(handler.stage(), Socks5Stage::ERROR);
    std::string resp = handler.takeResponse();
    ASSERT_EQ(resp.size(), 2);
    EXPECT_EQ(static_cast<uint8_t>(resp[1]), 0xFF); // 认证失败
}

TEST(HandlerSocks5Test, UnsupportedMethodRejected)
{
    HandlerInboundSocks5 handler;
    handler.setAuthenticator([](std::string_view, std::string_view) { return true; });

    // 客户端只声明支持 GSSAPI (0x01)，不支持 0x02
    feed(handler, std::vector<uint8_t>{0x05, 0x01, 0x01});
    handler.process();

    EXPECT_EQ(handler.stage(), Socks5Stage::ERROR);
    std::string resp = handler.takeResponse();
    ASSERT_EQ(resp.size(), 2);
    EXPECT_EQ(static_cast<uint8_t>(resp[1]), 0xFF); // NO ACCEPTABLE METHODS
}

TEST(HandlerSocks5Test, UnsupportedCommandRejected)
{
    HandlerInboundSocks5 handler;
    feed(handler, std::vector<uint8_t>{0x05, 0x01, 0x00});
    handler.process();
    [[maybe_unused]] auto _ = handler.takeResponse();

    // 发送 BIND (CMD = 0x02) 命令
    std::vector<uint8_t> req = {0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0x00, 80};
    feed(handler, req);
    handler.process();

    EXPECT_EQ(handler.stage(), Socks5Stage::ERROR);
    std::string resp = handler.takeResponse();
    ASSERT_GE(resp.size(), 4);
    EXPECT_EQ(static_cast<uint8_t>(resp[1]), socks5::kRepCommandNotSupported);
}

TEST(HandlerSocks5Test, ByteByByteFeedRobustness)
{
    HandlerInboundSocks5 handler;

    std::vector<uint8_t> allBytes = {
        0x05, 0x01, 0x00,                  // 握手
        0x05, 0x01, 0x00, 0x01,            // CONNECT IPv4
        10,   0,    0,    1,    0x04, 0xD2 // 10.0.0.1:1234
    };

    // 逐字节喂入并调用 process()
    for (uint8_t b : allBytes)
    {
        feed(handler, std::vector<uint8_t>{b});
        handler.process();
    }

    EXPECT_TRUE(handler.isEstablished());
    ASSERT_TRUE(handler.targetAddress().has_value());
    EXPECT_EQ(handler.targetAddress()->host, "10.0.0.1");
    EXPECT_EQ(handler.targetAddress()->port, 1234);
}

TEST(HandlerSocks5Test, ResetAndReuse)
{
    HandlerInboundSocks5 handler;
    feed(handler, std::vector<uint8_t>{0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01, 8, 8, 8, 8, 0x00, 53});
    handler.process();
    EXPECT_TRUE(handler.isEstablished());

    // 重置
    handler.reset();
    EXPECT_EQ(handler.stage(), Socks5Stage::METHOD_SELECT);
    EXPECT_FALSE(handler.isEstablished());
    EXPECT_FALSE(handler.targetAddress().has_value());

    // 再次喂入能够重新握手
    feed(handler, std::vector<uint8_t>{0x05, 0x01, 0x00});
    handler.process();
    EXPECT_EQ(handler.stage(), Socks5Stage::REQUEST);
}

TEST(HandlerSocks5Test, SpliceForwardApis)
{
    HandlerInboundSocks5 handler;
    static_assert(HandlerInboundSocks5::kEnableSplice, "HandlerInboundSocks5 must declare kEnableSplice = true");

    EXPECT_FALSE(handler.isSpliceForwardActive());
    EXPECT_EQ(handler.spliceControl(), SPLICE_CONTROL::DISABLED);
    EXPECT_EQ(handler.spliceTarget(), -1);

    handler.enableSpliceForward(200);
    EXPECT_TRUE(handler.isSpliceForwardActive());
    EXPECT_EQ(handler.spliceTarget(), 200);
    EXPECT_EQ(handler.spliceControl(), SPLICE_CONTROL::ACTIVE);

    handler.disableSpliceForward();
    EXPECT_FALSE(handler.isSpliceForwardActive());
    EXPECT_EQ(handler.spliceControl(), SPLICE_CONTROL::DISABLED);
    EXPECT_EQ(handler.spliceTarget(), -1);

    handler.enableSpliceForward(201);
    EXPECT_TRUE(handler.isSpliceForwardActive());
    handler.reset();
    EXPECT_FALSE(handler.isSpliceForwardActive());
    EXPECT_EQ(handler.spliceControl(), SPLICE_CONTROL::DISABLED);
    EXPECT_EQ(handler.spliceTarget(), -1);
}
