#include "vless/reality.hpp"
#include "vless/vision.hpp"
#include <gtest/gtest.h>
#include <openssl/rand.h>
#include <string>
#include <vector>

using namespace mynet::handler::vless;

namespace
{
    // 构造一个合法的 TLS 1.3 ClientHello 测试报文
    std::vector<uint8_t> makeTlsClientHello(std::string_view sni, std::span<const uint8_t, 32> clientPubKey)
    {
        std::vector<uint8_t> body;

        // 1. Client Version (TLS 1.2 compatibility)
        body.push_back(0x03);
        body.push_back(0x03);

        // 2. Client Random (32B)
        for (int i = 0; i < 32; ++i)
        {
            body.push_back(static_cast<uint8_t>(i + 1));
        }

        // 3. Session ID (1B len = 32, 32B zero)
        body.push_back(32);
        for (int i = 0; i < 32; ++i)
        {
            body.push_back(0x00);
        }

        // 4. Cipher Suites: 1 suite (0x1301 TLS_AES_128_GCM_SHA256)
        body.push_back(0x00);
        body.push_back(0x02);
        body.push_back(0x13);
        body.push_back(0x01);

        // 5. Compression: 1 byte 0x00
        body.push_back(0x01);
        body.push_back(0x00);

        // 6. Extensions
        std::vector<uint8_t> exts;

        // 6.1 SNI Extension (0x0000)
        if (!sni.empty())
        {
            exts.push_back(0x00);
            exts.push_back(0x00);
            uint16_t sniExtLen = static_cast<uint16_t>(5 + sni.size());
            exts.push_back(static_cast<uint8_t>((sniExtLen >> 8) & 0xFF));
            exts.push_back(static_cast<uint8_t>(sniExtLen & 0xFF));

            uint16_t listLen = static_cast<uint16_t>(3 + sni.size());
            exts.push_back(static_cast<uint8_t>((listLen >> 8) & 0xFF));
            exts.push_back(static_cast<uint8_t>(listLen & 0xFF));
            exts.push_back(0x00); // host_name
            exts.push_back(static_cast<uint8_t>((sni.size() >> 8) & 0xFF));
            exts.push_back(static_cast<uint8_t>(sni.size() & 0xFF));
            exts.insert(exts.end(), sni.begin(), sni.end());
        }

        // 6.2 key_share Extension (0x0033)
        {
            exts.push_back(0x00);
            exts.push_back(0x33);
            uint16_t ksExtLen = 2 + 2 + 2 + 32;
            exts.push_back(static_cast<uint8_t>((ksExtLen >> 8) & 0xFF));
            exts.push_back(static_cast<uint8_t>(ksExtLen & 0xFF));

            uint16_t clientSharesLen = 2 + 2 + 32;
            exts.push_back(static_cast<uint8_t>((clientSharesLen >> 8) & 0xFF));
            exts.push_back(static_cast<uint8_t>(clientSharesLen & 0xFF));

            // Group: X25519 (0x001d)
            exts.push_back(0x00);
            exts.push_back(0x1d);
            // Key Exchange length: 32
            exts.push_back(0x00);
            exts.push_back(0x20);
            exts.insert(exts.end(), clientPubKey.begin(), clientPubKey.end());
        }

        // Write extensions length + extensions
        uint16_t extsLen = static_cast<uint16_t>(exts.size());
        body.push_back(static_cast<uint8_t>((extsLen >> 8) & 0xFF));
        body.push_back(static_cast<uint8_t>(extsLen & 0xFF));
        body.insert(body.end(), exts.begin(), exts.end());

        // 7. Assemble Handshake & Record
        std::vector<uint8_t> record;
        // Record Header: Type 0x16, Ver 0x0301, Length
        record.push_back(0x16);
        record.push_back(0x03);
        record.push_back(0x01);
        uint16_t recordLen = static_cast<uint16_t>(4 + body.size());
        record.push_back(static_cast<uint8_t>((recordLen >> 8) & 0xFF));
        record.push_back(static_cast<uint8_t>(recordLen & 0xFF));

        // Handshake Header: Type 0x01 (ClientHello), Length 3B
        record.push_back(0x01);
        record.push_back(0x00);
        record.push_back(static_cast<uint8_t>((body.size() >> 8) & 0xFF));
        record.push_back(static_cast<uint8_t>(body.size() & 0xFF));
        record.insert(record.end(), body.begin(), body.end());

        return record;
    }
} // namespace

TEST(RealityTest, X25519AndBase64RawUrl)
{
    auto kpAlice = mynet::x25519::generateKeyPair();
    ASSERT_TRUE(kpAlice.has_value());

    auto kpBob = mynet::x25519::generateKeyPair();
    ASSERT_TRUE(kpBob.has_value());

    // Alice ECDH with Bob's public key
    auto secretA = mynet::x25519::computeSharedSecret(kpAlice->privKey, kpBob->pubKey);
    ASSERT_TRUE(secretA.has_value());

    // Bob ECDH with Alice's public key
    auto secretB = mynet::x25519::computeSharedSecret(kpBob->privKey, kpAlice->pubKey);
    ASSERT_TRUE(secretB.has_value());

    // Secrets must match identically
    EXPECT_EQ(*secretA, *secretB);

    // Test Base64 RawURL roundtrip
    std::string b64 = reality::encodeBase64RawUrl(kpAlice->pubKey);
    EXPECT_FALSE(b64.contains('+'));
    EXPECT_FALSE(b64.contains('/'));
    EXPECT_FALSE(b64.contains('='));

    auto decoded = reality::decodeBase64RawUrl(b64);
    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded->size(), 32u);
    EXPECT_EQ(std::memcmp(decoded->data(), kpAlice->pubKey.data(), 32), 0);
}

TEST(RealityTest, HandshakeAuthenticationSuccess)
{
    // Generate Server KeyPair
    auto serverKp = mynet::x25519::generateKeyPair();
    ASSERT_TRUE(serverKp.has_value());

    // Generate Client Ephemeral KeyPair
    auto clientEcdhe = mynet::x25519::generateKeyPair();
    ASSERT_TRUE(clientEcdhe.has_value());

    reality::ServerConfig serverCfg;
    serverCfg.serverName = "www.apple.com";
    serverCfg.destHost = "www.apple.com";
    serverCfg.destPort = 443;
    serverCfg.privateKey = serverKp->privKey;

    auto shortId = reality::parseShortId("0123456789abcdef");
    ASSERT_TRUE(shortId.has_value());
    serverCfg.shortIds.push_back(*shortId);

    reality::ClientConfig clientCfg;
    clientCfg.serverName = "www.apple.com";
    clientCfg.publicKey = serverKp->pubKey;
    clientCfg.shortId = *shortId;

    // Client creates TLS ClientHello with client public key
    auto ch = makeTlsClientHello("www.apple.com", clientEcdhe->pubKey);
    ASSERT_FALSE(ch.empty());

    // Client seals ClientHello
    bool sealed = reality::sealClientHello(ch, clientCfg, clientEcdhe->privKey);
    EXPECT_TRUE(sealed);

    // Server verifies ClientHello
    auto authRes = reality::verifyClientHello(ch, serverCfg);
    EXPECT_EQ(authRes.status, reality::AuthStatus::AUTHENTICATED);
    EXPECT_EQ(authRes.sni, "www.apple.com");
    EXPECT_EQ(authRes.shortId, *shortId);

    // Expected shared secret
    auto expectedSecret = mynet::x25519::computeSharedSecret(serverKp->privKey, clientEcdhe->pubKey);
    ASSERT_TRUE(expectedSecret.has_value());
    EXPECT_EQ(authRes.authKey, *expectedSecret);
}

TEST(RealityTest, HandshakeFallbackOnProbe)
{
    auto serverKp = mynet::x25519::generateKeyPair();
    ASSERT_TRUE(serverKp.has_value());

    auto clientEcdhe = mynet::x25519::generateKeyPair();
    ASSERT_TRUE(clientEcdhe.has_value());

    reality::ServerConfig serverCfg;
    serverCfg.serverName = "www.apple.com";
    serverCfg.privateKey = serverKp->privKey;
    serverCfg.shortIds.push_back(*reality::parseShortId("0123456789abcdef"));

    // Case 1: Active probe sending normal unsealed TLS ClientHello
    auto normalCh = makeTlsClientHello("www.apple.com", clientEcdhe->pubKey);
    auto resProbe = reality::verifyClientHello(normalCh, serverCfg);
    EXPECT_EQ(resProbe.status, reality::AuthStatus::FALLBACK_DEST);

    // Case 2: Wrong SNI (e.g. unknown host)
    auto wrongSniCh = makeTlsClientHello("unknown.probe.com", clientEcdhe->pubKey);
    reality::ClientConfig clientCfg;
    clientCfg.serverName = "unknown.probe.com";
    clientCfg.publicKey = serverKp->pubKey;
    clientCfg.shortId = *reality::parseShortId("0123456789abcdef");
    reality::sealClientHello(wrongSniCh, clientCfg, clientEcdhe->privKey);

    auto resWrongSni = reality::verifyClientHello(wrongSniCh, serverCfg);
    EXPECT_EQ(resWrongSni.status, reality::AuthStatus::FALLBACK_DEST);

    // Case 3: Wrong shortID
    auto wrongShortIdCh = makeTlsClientHello("www.apple.com", clientEcdhe->pubKey);
    clientCfg.serverName = "www.apple.com";
    clientCfg.shortId = *reality::parseShortId("9999999999999999");
    reality::sealClientHello(wrongShortIdCh, clientCfg, clientEcdhe->privKey);

    auto resWrongId = reality::verifyClientHello(wrongShortIdCh, serverCfg);
    EXPECT_EQ(resWrongId.status, reality::AuthStatus::FALLBACK_DEST);
}

TEST(VisionTest, PaddingAndUnpaddingRoundtrip)
{
    std::array<uint8_t, 16> testUuid = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    vision::VisionContext sender(testUuid);
    vision::VisionContext receiver(testUuid);

    // 1. First packet (contains UUID and padding header)
    std::string payload1 = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    auto padded1 =
        sender.pad(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(payload1.data()), payload1.size()));
    EXPECT_GE(padded1.size(), 16 + 5 + payload1.size());

    std::vector<uint8_t> unpacked1;
    size_t consumed1 = receiver.unpad(padded1, unpacked1);
    EXPECT_EQ(consumed1, padded1.size());
    EXPECT_EQ(std::string(reinterpret_cast<const char *>(unpacked1.data()), unpacked1.size()), payload1);

    // 2. Second packet (no UUID, only padding header)
    std::string payload2 = "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!";
    auto padded2 =
        sender.pad(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(payload2.data()), payload2.size()));
    // Second packet should NOT have UUID prefix
    EXPECT_LT(padded2.size(), 16 + 5 + payload2.size() + 256);

    std::vector<uint8_t> unpacked2;
    size_t consumed2 = receiver.unpad(padded2, unpacked2);
    EXPECT_EQ(consumed2, padded2.size());
    EXPECT_EQ(std::string(reinterpret_cast<const char *>(unpacked2.data()), unpacked2.size()), payload2);
}

TEST(VisionTest, DirectSpliceSignaling)
{
    std::array<uint8_t, 16> testUuid = {0xAA, 0xBB, 0xCC, 0xDD, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    vision::VisionContext sender(testUuid);
    vision::VisionContext receiver(testUuid);

    std::string sample = "Data switching to direct splice!";
    auto padded = sender.pad(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(sample.data()), sample.size()),
                             vision::kCommandPaddingDirect);

    std::vector<uint8_t> unpacked;
    receiver.unpad(padded, unpacked);
    EXPECT_EQ(std::string(reinterpret_cast<const char *>(unpacked.data()), unpacked.size()), sample);
    EXPECT_TRUE(receiver.isDirectSpliceEnabled());
}
