#include "handler/handler.hpp"
#include <gtest/gtest.h>
#include <string>
#include <vector>

using namespace mynet;
using namespace mynet::handler;

// 静态概念约束检验：全部代理协议处理器均必须严格满足 HandlerConstraint 与 MandatoryMethodConnection
static_assert(HandlerConstraint<HandlerSocks4>, "HandlerSocks4 must satisfy HandlerConstraint");
static_assert(MandatoryMethodConnection<HandlerSocks4>, "HandlerSocks4 must satisfy MandatoryMethodConnection");

static_assert(HandlerConstraint<HandlerSocks>, "HandlerSocks must satisfy HandlerConstraint");
static_assert(MandatoryMethodConnection<HandlerSocks>, "HandlerSocks must satisfy MandatoryMethodConnection");

static_assert(HandlerConstraint<HandlerHttpProxy>, "HandlerHttpProxy must satisfy HandlerConstraint");
static_assert(MandatoryMethodConnection<HandlerHttpProxy>, "HandlerHttpProxy must satisfy MandatoryMethodConnection");

static_assert(HandlerConstraint<HandlerMixed>, "HandlerMixed must satisfy HandlerConstraint");
static_assert(MandatoryMethodConnection<HandlerMixed>, "HandlerMixed must satisfy MandatoryMethodConnection");

static_assert(HandlerConstraint<HandlerTrojan>, "HandlerTrojan must satisfy HandlerConstraint");
static_assert(MandatoryMethodConnection<HandlerTrojan>, "HandlerTrojan must satisfy MandatoryMethodConnection");

static_assert(HandlerConstraint<HandlerVless>, "HandlerVless must satisfy HandlerConstraint");
static_assert(MandatoryMethodConnection<HandlerVless>, "HandlerVless must satisfy MandatoryMethodConnection");

static_assert(HandlerConstraint<HandlerVmess>, "HandlerVmess must satisfy HandlerConstraint");
static_assert(MandatoryMethodConnection<HandlerVmess>, "HandlerVmess must satisfy MandatoryMethodConnection");

static_assert(HandlerConstraint<HandlerShadowsocks>, "HandlerShadowsocks must satisfy HandlerConstraint");
static_assert(MandatoryMethodConnection<HandlerShadowsocks>,
              "HandlerShadowsocks must satisfy MandatoryMethodConnection");

static_assert(HandlerConstraint<HandlerShadowTls>, "HandlerShadowTls must satisfy HandlerConstraint");
static_assert(MandatoryMethodConnection<HandlerShadowTls>, "HandlerShadowTls must satisfy MandatoryMethodConnection");

static_assert(HandlerConstraint<HandlerSnell>, "HandlerSnell must satisfy HandlerConstraint");
static_assert(MandatoryMethodConnection<HandlerSnell>, "HandlerSnell must satisfy MandatoryMethodConnection");

static_assert(HandlerConstraint<HandlerHysteria2>, "HandlerHysteria2 must satisfy HandlerConstraint");
static_assert(MandatoryMethodConnection<HandlerHysteria2>, "HandlerHysteria2 must satisfy MandatoryMethodConnection");

static_assert(HandlerConstraint<HandlerTuic>, "HandlerTuic must satisfy HandlerConstraint");
static_assert(MandatoryMethodConnection<HandlerTuic>, "HandlerTuic must satisfy MandatoryMethodConnection");

static_assert(HandlerConstraint<HandlerRedirect>, "HandlerRedirect must satisfy HandlerConstraint");
static_assert(MandatoryMethodConnection<HandlerRedirect>, "HandlerRedirect must satisfy MandatoryMethodConnection");

static_assert(HandlerConstraint<HandlerDirect>, "HandlerDirect must satisfy HandlerConstraint");
static_assert(MandatoryMethodConnection<HandlerDirect>, "HandlerDirect must satisfy MandatoryMethodConnection");

static_assert(HandlerConstraint<HandlerBlock>, "HandlerBlock must satisfy HandlerConstraint");
static_assert(MandatoryMethodConnection<HandlerBlock>, "HandlerBlock must satisfy MandatoryMethodConnection");

namespace
{
    void feed(HandlerConnection &h, const std::vector<uint8_t> &bytes)
    {
        [[maybe_unused]] auto _ =
            h.appendRequest(reinterpret_cast<const char *>(bytes.data()), static_cast<ssize_t>(bytes.size()));
    }

    void feed(HandlerConnection &h, std::string_view str)
    {
        [[maybe_unused]] auto _ = h.appendRequest(str.data(), static_cast<ssize_t>(str.size()));
    }
} // namespace

// =============================================================================
// 1. SOCKS4 & SOCKS4a 测试
// =============================================================================

TEST(HandlerSocks4Test, IPv4ConnectSuccess)
{
    HandlerSocks4 handler;
    bool requestCalled = false;
    handler.setOnRequest(
        [&](uint8_t cmd, const ProxyAddress &target)
        {
            requestCalled = true;
            EXPECT_EQ(cmd, socks4::kCmdConnect);
            EXPECT_EQ(target.host, "1.2.3.4");
            EXPECT_EQ(target.port, 80);
        });

    // SOCKS4 CONNECT 请求: VN(0x04) | CMD(0x01) | Port(80: 0x0050) | IP(1.2.3.4: 0x01020304) | USERID("alice\0")
    std::vector<uint8_t> req = {0x04, 0x01, 0x00, 80, 1, 2, 3, 4, 'a', 'l', 'i', 'c', 'e', 0x00};
    feed(handler, req);
    handler.process();

    EXPECT_TRUE(requestCalled);
    EXPECT_EQ(handler.stage(), Socks4Stage::STREAMING);
    EXPECT_TRUE(handler.isEstablished());
    EXPECT_EQ(handler.userId(), "alice");
    ASSERT_TRUE(handler.targetAddress().has_value());
    EXPECT_EQ(handler.targetAddress()->toString(), "1.2.3.4:80");

    // 检查服务端 0x5A 成功响应: [0x00, 0x5A, Port(2), IP(4)]
    ASSERT_TRUE(handler.hasResponse());
    std::string resp = handler.takeResponse();
    ASSERT_EQ(resp.size(), 8u);
    EXPECT_EQ(static_cast<uint8_t>(resp[0]), 0x00);
    EXPECT_EQ(static_cast<uint8_t>(resp[1]), socks4::kRepSuccess);
}

TEST(HandlerSocks4Test, Socks4aDomainConnect)
{
    HandlerSocks4 handler;
    handler.setOnRequest(
        [](uint8_t cmd, const ProxyAddress &target)
        {
            EXPECT_EQ(cmd, socks4::kCmdConnect);
            EXPECT_EQ(target.type, AddressType::DOMAIN);
            EXPECT_EQ(target.host, "example.com");
            EXPECT_EQ(target.port, 443);
        });

    // SOCKS4a: IP 设为 0.0.0.1，在 USERID\0 之后跟 HOSTNAME\0
    std::vector<uint8_t> req = {
        0x04, 0x01, 0x01, 0xBB,                                         // Port 443
        0,    0,    0,    1,                                            // 0.0.0.1
        'b',  'o',  'b',  0x00,                                         // User "bob"
        'e',  'x',  'a',  'm',  'p', 'l', 'e', '.', 'c', 'o', 'm', 0x00 // Domain
    };
    feed(handler, req);
    handler.process();

    EXPECT_TRUE(handler.isEstablished());
    EXPECT_EQ(handler.userId(), "bob");
    ASSERT_TRUE(handler.targetAddress().has_value());
    EXPECT_EQ(handler.targetAddress()->toString(), "example.com:443");
}

TEST(HandlerSocks4Test, AuthFailureRejected)
{
    HandlerSocks4 handler;
    handler.setAuthenticator([](std::string_view uid) { return uid == "admin"; });

    std::vector<uint8_t> req = {0x04, 0x01, 0x00, 80, 10, 0, 0, 1, 'h', 'a', 'c', 'k', 'e', 'r', 0x00};
    feed(handler, req);
    handler.process();

    EXPECT_EQ(handler.stage(), Socks4Stage::ERROR);
    ASSERT_TRUE(handler.hasResponse());
    std::string resp = handler.takeResponse();
    ASSERT_EQ(resp.size(), 8u);
    EXPECT_EQ(static_cast<uint8_t>(resp[1]), socks4::kRepRejected);
}

// =============================================================================
// 2. 统一 SOCKS 处理器 (HandlerSocks) 嗅探自适应测试
// =============================================================================

TEST(HandlerSocksTest, AutoDetectSocks4AndSocks5)
{
    // 测试 SOCKS4 路径
    {
        HandlerSocks handler;
        std::vector<uint8_t> req4 = {0x04, 0x01, 0x00, 80, 1, 1, 1, 1, 0x00};
        feed(handler, req4);
        handler.process();
        EXPECT_EQ(handler.version(), SocksProtocolVersion::SOCKS4);
        EXPECT_TRUE(handler.isEstablished());
        ASSERT_TRUE(handler.targetAddress().has_value());
        EXPECT_EQ(handler.targetAddress()->host, "1.1.1.1");
    }

    // 测试 SOCKS5 路径
    {
        HandlerSocks handler;
        // 1. SOCKS5 初始握手
        feed(handler, std::vector<uint8_t>{0x05, 0x01, 0x00});
        handler.process();
        EXPECT_EQ(handler.version(), SocksProtocolVersion::SOCKS5);
        [[maybe_unused]] auto _ = handler.takeResponse();

        // 2. SOCKS5 CONNECT
        std::vector<uint8_t> req5 = {0x05, 0x01, 0x00, 0x01, 8, 8, 8, 8, 0x00, 53};
        feed(handler, req5);
        handler.process();
        EXPECT_TRUE(handler.isEstablished());
        ASSERT_TRUE(handler.targetAddress().has_value());
        EXPECT_EQ(handler.targetAddress()->toString(), "8.8.8.8:53");
    }
}

// =============================================================================
// 3. HTTP 代理 (HandlerHttpProxy) 测试
// =============================================================================

TEST(HandlerHttpProxyTest, ConnectTunneling)
{
    HandlerHttpProxy handler;
    bool requestCalled = false;
    handler.setOnRequest(
        [&](uint8_t cmd, const ProxyAddress &target)
        {
            requestCalled = true;
            EXPECT_EQ(cmd, http_proxy::kCmdConnect);
            EXPECT_EQ(target.host, "example.com");
            EXPECT_EQ(target.port, 443);
        });

    std::string req = "CONNECT example.com:443 HTTP/1.1\r\n"
                      "Host: example.com:443\r\n"
                      "User-Agent: curl/8.0\r\n\r\n";
    feed(handler, req);
    handler.process();

    EXPECT_TRUE(requestCalled);
    EXPECT_TRUE(handler.isEstablished());
    EXPECT_TRUE(handler.isConnectMethod());
    ASSERT_TRUE(handler.hasResponse());
    std::string resp = handler.takeResponse();
    EXPECT_TRUE(resp.starts_with("HTTP/1.1 200 Connection Established\r\n\r\n"));
}

TEST(HandlerHttpProxyTest, PlainHttpForwardProxy)
{
    HandlerHttpProxy handler;
    handler.setOnRequest(
        [](uint8_t cmd, const ProxyAddress &target)
        {
            EXPECT_EQ(cmd, http_proxy::kCmdPlain);
            EXPECT_EQ(target.host, "example.org");
            EXPECT_EQ(target.port, 8080);
        });

    std::string req = "GET http://example.org:8080/index.html HTTP/1.1\r\n"
                      "Host: example.org:8080\r\n\r\n";
    feed(handler, req);
    handler.process();

    EXPECT_TRUE(handler.isEstablished());
    EXPECT_FALSE(handler.isConnectMethod());
    ASSERT_TRUE(handler.targetAddress().has_value());
    EXPECT_EQ(handler.targetAddress()->toString(), "example.org:8080");
}

TEST(HandlerHttpProxyTest, BasicAuthCheck)
{
    HandlerHttpProxy handler;
    handler.setAuthenticator([](std::string_view user, std::string_view pass)
                             { return user == "admin" && pass == "secret"; });

    // 1. 无认证 -> 返回 407
    std::string reqNoAuth = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
    feed(handler, reqNoAuth);
    handler.process();
    EXPECT_EQ(handler.stage(), HttpProxyStage::ERROR);
    ASSERT_TRUE(handler.hasResponse());
    std::string resp407 = handler.takeResponse();
    EXPECT_TRUE(resp407.starts_with("HTTP/1.1 407 Proxy Authentication Required"));

    // 2. 带正确 Basic 认证 (admin:secret -> YWRtaW46c2VjcmV0)
    handler.reset();
    std::string reqAuth = "CONNECT example.com:443 HTTP/1.1\r\n"
                          "Host: example.com:443\r\n"
                          "Proxy-Authorization: Basic YWRtaW46c2VjcmV0\r\n\r\n";
    feed(handler, reqAuth);
    handler.process();
    EXPECT_TRUE(handler.isEstablished());
    ASSERT_TRUE(handler.hasResponse());
    std::string resp200 = handler.takeResponse();
    EXPECT_TRUE(resp200.starts_with("HTTP/1.1 200 Connection Established"));
}

// =============================================================================
// 4. Mixed 混合共端口代理 (HandlerMixed) 测试
// =============================================================================

TEST(HandlerMixedTest, MultiplexSocksAndHttp)
{
    // 1. SOCKS5 客户端接入
    {
        HandlerMixed handler;
        feed(handler, std::vector<uint8_t>{0x05, 0x01, 0x00});
        handler.process();
        EXPECT_EQ(handler.protocol(), MixedProtocolType::SOCKS5);
    }

    // 2. SOCKS4 客户端接入
    {
        HandlerMixed handler;
        feed(handler, std::vector<uint8_t>{0x04, 0x01, 0x00, 80, 1, 2, 3, 4, 0x00});
        handler.process();
        EXPECT_EQ(handler.protocol(), MixedProtocolType::SOCKS4);
    }

    // 3. HTTP 客户端接入
    {
        HandlerMixed handler;
        std::string httpReq = "CONNECT 127.0.0.1:8443 HTTP/1.1\r\nHost: 127.0.0.1:8443\r\n\r\n";
        feed(handler, httpReq);
        handler.process();
        EXPECT_EQ(handler.protocol(), MixedProtocolType::HTTP);
        EXPECT_TRUE(handler.isEstablished());
        ASSERT_TRUE(handler.targetAddress().has_value());
        EXPECT_EQ(handler.targetAddress()->toString(), "127.0.0.1:8443");
    }
}

// =============================================================================
// 5. Trojan 代理协议 (HandlerTrojan) 测试
// =============================================================================

TEST(HandlerTrojanTest, Sha224KeyHandshake)
{
    std::string pass = "trojan-password";
    std::string hexKey = crypto::sha224Hex(pass);
    ASSERT_EQ(hexKey.size(), 56u);

    HandlerTrojan handler(pass);
    bool reqCalled = false;
    handler.setOnRequest(
        [&](uint8_t cmd, const ProxyAddress &target)
        {
            reqCalled = true;
            EXPECT_EQ(cmd, trojan::kCmdConnect);
            EXPECT_EQ(target.host, "1.1.1.1");
            EXPECT_EQ(target.port, 853);
        });

    // 构造 Trojan 请求报文：
    // [Key (56B)][\r\n][CMD(1=0x01)][SOCKS5 Addr (1.1.1.1:853)][\r\n][Payload...]
    std::vector<uint8_t> req;
    req.insert(req.end(), hexKey.begin(), hexKey.end());
    req.push_back('\r');
    req.push_back('\n');
    req.push_back(trojan::kCmdConnect);

    // 1.1.1.1:853 -> ATYP(0x01), 1,1,1,1, Port(0x03, 0x55)
    ProxyAddress target = ProxyAddress::fromIPv4(htonl(0x01010101), 853);
    target.encodeSocks5(req);

    req.push_back('\r');
    req.push_back('\n');

    // 附加载荷
    std::string payload = "GET /dns-query HTTP/1.1\r\n\r\n";
    req.insert(req.end(), payload.begin(), payload.end());

    feed(handler, req);
    handler.process();

    EXPECT_TRUE(reqCalled);
    EXPECT_TRUE(handler.isEstablished());
    EXPECT_EQ(handler.stage(), TrojanStage::STREAMING);
    ASSERT_TRUE(handler.targetAddress().has_value());
    EXPECT_EQ(handler.targetAddress()->toString(), "1.1.1.1:853");

    // 握手后残留的载荷数据应保留在 RequestBuffer 中，供直接透传
    EXPECT_EQ(handler.requestBytes(), payload.size());
}

TEST(HandlerTrojanTest, WrongPasswordRejected)
{
    HandlerTrojan handler("correct-password");
    std::string wrongKey = crypto::sha224Hex("wrong-password");

    std::vector<uint8_t> req;
    req.insert(req.end(), wrongKey.begin(), wrongKey.end());
    req.push_back('\r');
    req.push_back('\n');
    req.push_back(trojan::kCmdConnect);
    ProxyAddress::fromIPv4(htonl(0x7F000001), 80).encodeSocks5(req);
    req.push_back('\r');
    req.push_back('\n');

    feed(handler, req);
    handler.process();

    EXPECT_EQ(handler.stage(), TrojanStage::ERROR);
    EXPECT_FALSE(handler.isEstablished());
}

// =============================================================================
// 6. VLESS (v0) 代理协议 (HandlerVless) 测试
// =============================================================================

TEST(HandlerVlessTest, UuidConnectHandshake)
{
    std::string uuidStr = "a1b2c3d4-e5f6-7890-abcd-ef0123456789";
    auto parsedUuid = crypto::parseUuid(uuidStr);
    ASSERT_TRUE(parsedUuid.has_value());

    HandlerVless handler(uuidStr);
    bool reqCalled = false;
    handler.setOnRequest(
        [&](uint8_t cmd, const ProxyAddress &target)
        {
            reqCalled = true;
            EXPECT_EQ(cmd, vless::kCmdTcp);
            EXPECT_EQ(target.host, "github.com");
            EXPECT_EQ(target.port, 443);
        });

    // 构造 VLESS 请求包：
    // [Ver 0x00][UUID 16B][AddonLen 0x00][CMD 0x01][Port 443: 0x01BB][ATYP 0x02][Len 10]["github.com"][Payload...]
    std::vector<uint8_t> req;
    req.push_back(vless::kVersion);
    req.insert(req.end(), parsedUuid->begin(), parsedUuid->end());
    req.push_back(0x00); // addon len = 0
    req.push_back(vless::kCmdTcp);
    req.push_back(0x01); // Port 443 MSB
    req.push_back(0xBB); // Port 443 LSB
    req.push_back(0x02); // ATYP: Domain
    std::string domain = "github.com";
    req.push_back(static_cast<uint8_t>(domain.size()));
    req.insert(req.end(), domain.begin(), domain.end());

    std::string payload = "TLSClientHelloSimulation...";
    req.insert(req.end(), payload.begin(), payload.end());

    feed(handler, req);
    handler.process();

    EXPECT_TRUE(reqCalled);
    EXPECT_TRUE(handler.isEstablished());
    EXPECT_EQ(handler.stage(), VlessStage::STREAMING);
    ASSERT_TRUE(handler.targetAddress().has_value());
    EXPECT_EQ(handler.targetAddress()->toString(), "github.com:443");

    // 检查服务端 2 字节响应头 [0x00, 0x00]
    ASSERT_TRUE(handler.hasResponse());
    std::string resp = handler.takeResponse();
    ASSERT_EQ(resp.size(), 2u);
    EXPECT_EQ(static_cast<uint8_t>(resp[0]), 0x00);
    EXPECT_EQ(static_cast<uint8_t>(resp[1]), 0x00);

    // 载荷数据保留在 RequestBuffer
    EXPECT_EQ(handler.requestBytes(), payload.size());
}

// =============================================================================
// 7. VMess 代理协议 (HandlerVmess) 测试
// =============================================================================

TEST(HandlerVmessTest, AuthAndHeaderDecode)
{
    std::string uuidStr = "de04add9-5c1a-4b08-8e65-244e45cf5483";
    HandlerVmess handler(uuidStr);

    bool reqCalled = false;
    handler.setOnRequest(
        [&](uint8_t cmd, const ProxyAddress &target)
        {
            reqCalled = true;
            EXPECT_EQ(cmd, vmess::kCmdTcp);
            EXPECT_EQ(target.host, "10.0.0.1");
            EXPECT_EQ(target.port, 80);
        });

    // 16 字节 AuthID
    std::vector<uint8_t> req(16, 0xAA);

    // Header 模拟
    req.push_back(vmess::kVersion);
    std::vector<uint8_t> ivKey(32, 0x01); // IV(16) + Key(16)
    req.insert(req.end(), ivKey.begin(), ivKey.end());
    req.push_back(0x55); // RespAuth
    req.push_back(0x00); // Option
    req.push_back(0x03); // Sec
    req.push_back(0x00); // Reserved
    req.push_back(vmess::kCmdTcp);
    req.push_back(0x00); // Port 80
    req.push_back(80);

    // SOCKS5 目标地址
    ProxyAddress::fromIPv4(htonl(0x0A000001), 80).encodeSocks5(req);

    feed(handler, req);
    handler.process();

    EXPECT_TRUE(reqCalled);
    EXPECT_TRUE(handler.isEstablished());
}

// =============================================================================
// 8. Shadowsocks AEAD (HandlerShadowsocks) 测试
// =============================================================================

TEST(HandlerShadowsocksTest, NoneCipherDirectCodec)
{
    HandlerShadowsocks handler("none", "");
    bool reqCalled = false;
    handler.setOnRequest(
        [&](uint8_t, const ProxyAddress &target)
        {
            reqCalled = true;
            EXPECT_EQ(target.host, "127.0.0.1");
            EXPECT_EQ(target.port, 9000);
        });

    std::vector<uint8_t> req;
    ProxyAddress::fromIPv4(htonl(0x7F000001), 9000).encodeSocks5(req);
    feed(handler, req);
    handler.process();

    EXPECT_TRUE(reqCalled);
    EXPECT_TRUE(handler.isEstablished());
}

TEST(HandlerShadowsocksTest, Aes128GcmHandshakeAndDecryption)
{
    std::string pass = "test-password";
    HandlerShadowsocks handler("aes-128-gcm", pass);

    bool reqCalled = false;
    handler.setOnRequest(
        [&](uint8_t, const ProxyAddress &target)
        {
            reqCalled = true;
            EXPECT_EQ(target.host, "1.1.1.1");
            EXPECT_EQ(target.port, 53);
        });

    // 客户端加密仿真：
    // 1. 派生主密钥
    std::vector<uint8_t> masterKey(16);
    EVP_BytesToKey(EVP_aes_128_gcm(), EVP_md5(), nullptr, reinterpret_cast<const unsigned char *>(pass.data()),
                   pass.size(), 1, masterKey.data(), nullptr);

    // 2. 生成 16 字节随机 Salt
    std::vector<uint8_t> salt(16, 0x42);

    // 3. 派生子密钥 subkey = HKDF-SHA1
    static constexpr uint8_t kInfo[] = {'s', 's', '-', 's', 'u', 'b', 'k', 'e', 'y'};
    std::vector<uint8_t> subkey(16);
    ASSERT_TRUE(crypto::hkdfSha1(masterKey, salt, kInfo, subkey));

    // 4. 目标地址载荷
    std::vector<uint8_t> plainPayload;
    ProxyAddress::fromIPv4(htonl(0x01010101), 53).encodeSocks5(plainPayload);

    // 5. 加密 2 字节长度块 (len = plainPayload.size())
    std::array<uint8_t, 12> nonce{};
    std::array<uint8_t, 2> lenBytes = {static_cast<uint8_t>((plainPayload.size() >> 8) & 0xFF),
                                       static_cast<uint8_t>(plainPayload.size() & 0xFF)};
    std::vector<uint8_t> cipherLen;
    std::array<uint8_t, 16> lenTag{};
    ASSERT_TRUE(crypto::aeadEncrypt(EVP_aes_128_gcm(), subkey, nonce, lenBytes, cipherLen, lenTag));

    // 自增 nonce
    nonce[0]++;

    // 6. 加密载荷块
    std::vector<uint8_t> cipherPayload;
    std::array<uint8_t, 16> payloadTag{};
    ASSERT_TRUE(crypto::aeadEncrypt(EVP_aes_128_gcm(), subkey, nonce, plainPayload, cipherPayload, payloadTag));

    // 7. 组装发往服务端的全量字节流：[Salt(16)][CipherLen(2)][LenTag(16)][CipherPayload(N)][PayloadTag(16)]
    std::vector<uint8_t> packet;
    packet.insert(packet.end(), salt.begin(), salt.end());
    packet.insert(packet.end(), cipherLen.begin(), cipherLen.end());
    packet.insert(packet.end(), lenTag.begin(), lenTag.end());
    packet.insert(packet.end(), cipherPayload.begin(), cipherPayload.end());
    packet.insert(packet.end(), payloadTag.begin(), payloadTag.end());

    feed(handler, packet);
    handler.process();

    EXPECT_TRUE(reqCalled);
    EXPECT_TRUE(handler.isEstablished());
    ASSERT_TRUE(handler.targetAddress().has_value());
    EXPECT_EQ(handler.targetAddress()->toString(), "1.1.1.1:53");
}

// =============================================================================
// 9. ShadowTLS (HandlerShadowTls) 测试
// =============================================================================

TEST(HandlerShadowTlsTest, ClientHelloSniFallbackAndAuth)
{
    ProxyAddress detour = ProxyAddress::fromHostPort("127.0.0.1", 8388);
    ProxyAddress fallback = ProxyAddress::fromHostPort("cloudflare.com", 443);
    std::string pass = "shadowtls-secret";

    // 辅助函数：构造带有指定 SessionID 和 SNI 的合法 ClientHello 报文
    auto buildClientHello = [](const std::vector<uint8_t> &randomBytes, const std::vector<uint8_t> &sessionId,
                               std::string_view sni) -> std::vector<uint8_t>
    {
        // 1. Extensions
        std::vector<uint8_t> extensions;
        if (!sni.empty())
        {
            // Extension SNI: [Type 0x0000 (2B)][Len (2B)][ServerNameListLen (2B)][NameType 0x00 (1B)][NameLen
            // (2B)][Name]
            std::vector<uint8_t> sniExt;
            const uint16_t nameLen = static_cast<uint16_t>(sni.size());
            const uint16_t listLen = 1 + 2 + nameLen;
            sniExt.push_back(static_cast<uint8_t>((listLen >> 8) & 0xFF));
            sniExt.push_back(static_cast<uint8_t>(listLen & 0xFF));
            sniExt.push_back(0x00); // host_name
            sniExt.push_back(static_cast<uint8_t>((nameLen >> 8) & 0xFF));
            sniExt.push_back(static_cast<uint8_t>(nameLen & 0xFF));
            sniExt.insert(sniExt.end(), sni.begin(), sni.end());

            extensions.push_back(0x00); // Ext Type 0x0000 MSB
            extensions.push_back(0x00); // LSB
            extensions.push_back(static_cast<uint8_t>((sniExt.size() >> 8) & 0xFF));
            extensions.push_back(static_cast<uint8_t>(sniExt.size() & 0xFF));
            extensions.insert(extensions.end(), sniExt.begin(), sniExt.end());
        }

        // 2. Handshake Body
        std::vector<uint8_t> handshake;
        handshake.push_back(0x03); // TLS 1.2 version
        handshake.push_back(0x03);
        handshake.insert(handshake.end(), randomBytes.begin(), randomBytes.end()); // Random (32B)
        handshake.push_back(static_cast<uint8_t>(sessionId.size()));               // SessionID Len
        handshake.insert(handshake.end(), sessionId.begin(), sessionId.end());     // SessionID
        handshake.push_back(0x00);                                                 // Cipher Suites Len (2B) = 2
        handshake.push_back(0x02);
        handshake.push_back(0x13); // TLS_AES_128_GCM_SHA256
        handshake.push_back(0x01);
        handshake.push_back(0x01); // Compression Methods Len = 1
        handshake.push_back(0x00); // null compression

        // Extensions block
        handshake.push_back(static_cast<uint8_t>((extensions.size() >> 8) & 0xFF));
        handshake.push_back(static_cast<uint8_t>(extensions.size() & 0xFF));
        handshake.insert(handshake.end(), extensions.begin(), extensions.end());

        // 3. Handshake Header: [Type 0x01 (1B)][Len 3B]
        std::vector<uint8_t> fullHandshake;
        fullHandshake.push_back(0x01); // ClientHello
        const size_t hsLen = handshake.size();
        fullHandshake.push_back(static_cast<uint8_t>((hsLen >> 16) & 0xFF));
        fullHandshake.push_back(static_cast<uint8_t>((hsLen >> 8) & 0xFF));
        fullHandshake.push_back(static_cast<uint8_t>(hsLen & 0xFF));
        fullHandshake.insert(fullHandshake.end(), handshake.begin(), handshake.end());

        // 4. Record Header: [0x16][0x03, 0x01][Len 2B]
        std::vector<uint8_t> record;
        record.push_back(0x16); // Handshake
        record.push_back(0x03); // TLS 1.0
        record.push_back(0x01);
        const size_t recLen = fullHandshake.size();
        record.push_back(static_cast<uint8_t>((recLen >> 8) & 0xFF));
        record.push_back(static_cast<uint8_t>(recLen & 0xFF));
        record.insert(record.end(), fullHandshake.begin(), fullHandshake.end());

        return record;
    };

    // 场景 A: 普通浏览器 ClientHello (带 SNI "cloudflare.com"，但未包含合法 ShadowTLS 认证令牌)
    {
        HandlerShadowTls handler(ShadowTlsVersion::V3, pass, detour, fallback);
        bool callbackCalled = false;
        handler.setOnRequest(
            [&](bool authed, const ProxyAddress &target)
            {
                callbackCalled = true;
                EXPECT_FALSE(authed); // 未通过认证
                EXPECT_EQ(target.host, "cloudflare.com");
                EXPECT_EQ(target.port, 443);
            });

        std::vector<uint8_t> random(32, 0x11);
        std::vector<uint8_t> dummySid(32, 0x22);
        std::vector<uint8_t> packet = buildClientHello(random, dummySid, "cloudflare.com");

        feed(handler, packet);
        handler.process();

        EXPECT_TRUE(callbackCalled);
        EXPECT_TRUE(handler.isEstablished());
        EXPECT_FALSE(handler.isClientAuthenticated());
        EXPECT_EQ(handler.sni(), "cloudflare.com");
        ASSERT_TRUE(handler.targetAddress().has_value());
        EXPECT_EQ(handler.targetAddress()->toString(), "cloudflare.com:443");
    }

    // 场景 B: 合法 ShadowTLS v3 客户端 (SessionID 包含对 Random 的 HMAC-SHA256 签名)
    {
        HandlerShadowTls handler(ShadowTlsVersion::V3, pass, detour, fallback);
        bool callbackCalled = false;
        handler.setOnRequest(
            [&](bool authed, const ProxyAddress &target)
            {
                callbackCalled = true;
                EXPECT_TRUE(authed); // 认证通过
                EXPECT_EQ(target.toString(), detour.toString());
            });

        std::vector<uint8_t> random(32, 0x33);
        std::vector<uint8_t> hmacKey(pass.begin(), pass.end());
        auto hmacRes = crypto::hmacSha256(hmacKey, random);
        ASSERT_TRUE(hmacRes.has_value());

        std::vector<uint8_t> validSid(hmacRes->begin(), hmacRes->end());
        std::vector<uint8_t> packet = buildClientHello(random, validSid, "shadowtls.internal");

        feed(handler, packet);
        handler.process();

        EXPECT_TRUE(callbackCalled);
        EXPECT_TRUE(handler.isEstablished());
        EXPECT_TRUE(handler.isClientAuthenticated());
        ASSERT_TRUE(handler.targetAddress().has_value());
        EXPECT_EQ(handler.targetAddress()->toString(), detour.toString());
    }

    // 场景 C: 非 TLS 明文流量 (直接回落到 fallback)
    {
        HandlerShadowTls handler(ShadowTlsVersion::V3, pass, detour, fallback);
        handler.setOnRequest(
            [&](bool authed, const ProxyAddress &target)
            {
                EXPECT_FALSE(authed);
                EXPECT_EQ(target.toString(), fallback.toString());
            });

        feed(handler, std::string_view("GET / HTTP/1.1\r\n\r\n"));
        handler.process();
        EXPECT_TRUE(handler.isEstablished());
        EXPECT_FALSE(handler.isClientAuthenticated());
    }
}

// =============================================================================
// 10. Snell (HandlerSnell) 测试
// =============================================================================

TEST(HandlerSnellTest, ConnectHandshake)
{
    HandlerSnell handler(2, "psk123");
    bool reqCalled = false;
    handler.setOnRequest(
        [&](uint8_t cmd, const ProxyAddress &target)
        {
            reqCalled = true;
            EXPECT_EQ(cmd, snell::kCmdConnect);
            EXPECT_EQ(target.host, "1.2.3.4");
            EXPECT_EQ(target.port, 80);
        });

    std::vector<uint8_t> req = {2, snell::kCmdConnect};
    ProxyAddress::fromIPv4(htonl(0x01020304), 80).encodeSocks5(req);

    feed(handler, req);
    handler.process();

    EXPECT_TRUE(reqCalled);
    EXPECT_TRUE(handler.isEstablished());
}

// =============================================================================
// 11. Hysteria 2 (HandlerHysteria2) 测试
// =============================================================================

TEST(HandlerHysteria2Test, AuthAndConnectSuccess)
{
    HandlerHysteria2 handler("mypassword");
    bool reqCalled = false;
    handler.setOnRequest(
        [&](uint8_t cmd, const ProxyAddress &target)
        {
            reqCalled = true;
            EXPECT_EQ(cmd, hysteria2::kCmdTcp);
            EXPECT_EQ(target.host, "example.com");
            EXPECT_EQ(target.port, 80);
        });

    // [AuthLen 1B][AuthStr "mypassword"][CMD 1B][SOCKS5 Addr]
    std::vector<uint8_t> req;
    std::string pass = "mypassword";
    req.push_back(static_cast<uint8_t>(pass.size()));
    req.insert(req.end(), pass.begin(), pass.end());
    req.push_back(hysteria2::kCmdTcp);
    ProxyAddress::fromDomain("example.com", 80).encodeSocks5(req);

    feed(handler, req);
    handler.process();

    EXPECT_TRUE(reqCalled);
    EXPECT_TRUE(handler.isEstablished());
    ASSERT_TRUE(handler.hasResponse());
    std::string resp = handler.takeResponse();
    ASSERT_EQ(resp.size(), 1u);
    EXPECT_EQ(static_cast<uint8_t>(resp[0]), hysteria2::kStatusOk);
}

// =============================================================================
// 12. TUIC (HandlerTuic) 测试
// =============================================================================

TEST(HandlerTuicTest, ConnectSuccess)
{
    std::string uuidStr = "12345678-1234-1234-1234-123456789abc";
    auto uuid = crypto::parseUuid(uuidStr);
    ASSERT_TRUE(uuid.has_value());

    HandlerTuic handler(uuidStr);
    bool reqCalled = false;
    handler.setOnRequest(
        [&](uint8_t cmd, const ProxyAddress &target)
        {
            reqCalled = true;
            EXPECT_EQ(cmd, tuic::kCmdConnect);
            EXPECT_EQ(target.host, "10.0.0.1");
            EXPECT_EQ(target.port, 443);
        });

    std::vector<uint8_t> req;
    req.push_back(tuic::kCmdConnect);
    req.insert(req.end(), uuid->begin(), uuid->end());
    ProxyAddress::fromIPv4(htonl(0x0A000001), 443).encodeSocks5(req);

    feed(handler, req);
    handler.process();

    EXPECT_TRUE(reqCalled);
    EXPECT_TRUE(handler.isEstablished());
    ASSERT_TRUE(handler.hasResponse());
    std::string resp = handler.takeResponse();
    ASSERT_EQ(resp.size(), 1u);
    EXPECT_EQ(static_cast<uint8_t>(resp[0]), tuic::kRepSuccess);
}

// =============================================================================
// 13. Direct & Block 路由处理器测试
// =============================================================================

TEST(HandlerDirectBlockTest, DirectPassThrough)
{
    ProxyAddress target = ProxyAddress::fromHostPort("8.8.8.8", 53);
    HandlerDirect direct(target);
    EXPECT_TRUE(direct.isEstablished());
    EXPECT_EQ(direct.targetAddress().toString(), "8.8.8.8:53");

    bool called = false;
    direct.setOnRequest(
        [&](const ProxyAddress &addr)
        {
            called = true;
            EXPECT_EQ(addr.toString(), "8.8.8.8:53");
        });
    direct.process();
    EXPECT_TRUE(called);
}

TEST(HandlerBlockTest, BlockRejects)
{
    HandlerBlock block;
    EXPECT_FALSE(block.isEstablished());
    feed(block, std::string_view("GET / HTTP/1.1\r\n\r\n"));
    block.process();
    EXPECT_TRUE(block.closeAfterResponse());
}
