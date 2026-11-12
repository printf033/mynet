#include "handler/sniffing.hpp"
#include <gtest/gtest.h>
#include <string>
#include <vector>

using namespace mynet::handler::sniffing;

namespace
{

    std::vector<uint8_t> createTlsRecordClientHello(std::string_view serverName)
    {
        std::vector<uint8_t> extSni;
        extSni.push_back(0x00);
        extSni.push_back(0x00); // Extension Type: Server Name (0)
        const uint16_t sniExtLen = static_cast<uint16_t>(5 + serverName.size());
        extSni.push_back(static_cast<uint8_t>(sniExtLen >> 8));
        extSni.push_back(static_cast<uint8_t>(sniExtLen & 0xFF));

        const uint16_t sniListLen = static_cast<uint16_t>(3 + serverName.size());
        extSni.push_back(static_cast<uint8_t>(sniListLen >> 8));
        extSni.push_back(static_cast<uint8_t>(sniListLen & 0xFF));
        extSni.push_back(0x00); // HostName type
        const uint16_t nameLen = static_cast<uint16_t>(serverName.size());
        extSni.push_back(static_cast<uint8_t>(nameLen >> 8));
        extSni.push_back(static_cast<uint8_t>(nameLen & 0xFF));
        extSni.insert(extSni.end(), serverName.begin(), serverName.end());

        std::vector<uint8_t> hs;
        hs.push_back(0x01); // Handshake Type: ClientHello
        // Handshake length (3B) placeholder
        hs.push_back(0x00);
        hs.push_back(0x00);
        hs.push_back(0x00);

        hs.push_back(0x03);
        hs.push_back(0x03); // TLS 1.2 client version

        // 32B random
        for (int i = 0; i < 32; ++i)
        {
            hs.push_back(0x11);
        }

        // Session ID (0B)
        hs.push_back(0x00);

        // Cipher suites (2B len + 2B suite)
        hs.push_back(0x00);
        hs.push_back(0x02);
        hs.push_back(0x13);
        hs.push_back(0x01);

        // Compression methods (1B len + 1B null)
        hs.push_back(0x01);
        hs.push_back(0x00);

        // Extensions (2B len + extSni)
        const uint16_t extTotalLen = static_cast<uint16_t>(extSni.size());
        hs.push_back(static_cast<uint8_t>(extTotalLen >> 8));
        hs.push_back(static_cast<uint8_t>(extTotalLen & 0xFF));
        hs.insert(hs.end(), extSni.begin(), extSni.end());

        // Fill handshake length
        const uint32_t hsLen = static_cast<uint32_t>(hs.size() - 4);
        hs[1] = static_cast<uint8_t>((hsLen >> 16) & 0xFF);
        hs[2] = static_cast<uint8_t>((hsLen >> 8) & 0xFF);
        hs[3] = static_cast<uint8_t>(hsLen & 0xFF);

        // TLS Record Header: [Type 0x16 (1B)][Version 0x03 0x01 (2B)][Length (2B)]
        std::vector<uint8_t> record;
        record.push_back(0x16);
        record.push_back(0x03);
        record.push_back(0x01);
        const uint16_t recLen = static_cast<uint16_t>(hs.size());
        record.push_back(static_cast<uint8_t>(recLen >> 8));
        record.push_back(static_cast<uint8_t>(recLen & 0xFF));
        record.insert(record.end(), hs.begin(), hs.end());

        return record;
    }

    std::vector<uint8_t> createQuicInitialPacket(std::string_view serverName)
    {
        // 1. 构造明文 Handshake ClientHello
        auto tlsRecord = createTlsRecordClientHello(serverName);
        std::span<const uint8_t> clientHello(tlsRecord.data() + 5, tlsRecord.size() - 5);

        // 2. 构造 CRYPTO 帧 (Type 0x06, Offset 0, Length, Data)
        std::vector<uint8_t> payload;
        payload.push_back(0x06); // Frame Type CRYPTO
        detail::appendUvarint(payload, 0); // Offset = 0
        detail::appendUvarint(payload, clientHello.size()); // Length
        payload.insert(payload.end(), clientHello.begin(), clientHello.end());
        // 填充至 64 字节以上以保证采样空间
        while (payload.size() < 64)
        {
            payload.push_back(0x00); // PADDING
        }

        // 3. QUIC 头部参数
        std::array<uint8_t, 8> dcid = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        uint8_t scidLen = 0;
        uint32_t packetNumber = 1;
        uint8_t pnLen = 1;

        // 4. 派生密钥 (RFC 9000 v1)
        auto initialSecret = mynet::handler::crypto::hkdfSha256Extract(detail::kQuicSaltV1, dcid);
        if (!initialSecret.has_value())
        {
            return {};
        }

        std::array<uint8_t, 32> clientInitialSecret{};
        [[maybe_unused]] bool ok = mynet::handler::crypto::hkdfExpandLabel(*initialSecret, "client in", {}, 32, clientInitialSecret);
        if (!ok)
        {
            return {};
        }

        std::array<uint8_t, 16> hpKey{};
        std::array<uint8_t, 16> key{};
        std::array<uint8_t, 12> iv{};
        ok = mynet::handler::crypto::hkdfExpandLabel(clientInitialSecret, "quic hp", {}, 16, hpKey);
        EXPECT_TRUE(ok);
        ok = mynet::handler::crypto::hkdfExpandLabel(clientInitialSecret, "quic key", {}, 16, key);
        EXPECT_TRUE(ok);
        ok = mynet::handler::crypto::hkdfExpandLabel(clientInitialSecret, "quic iv", {}, 12, iv);
        EXPECT_TRUE(ok);

        // 5. 组装未加密头部
        std::vector<uint8_t> packet;
        uint8_t firstByte = 0xC0 | (pnLen - 1); // Long Header, Initial (0x00), pnLen=1
        packet.push_back(firstByte);
        // Version 1
        packet.push_back(0x00);
        packet.push_back(0x00);
        packet.push_back(0x00);
        packet.push_back(0x01);
        // DCID
        packet.push_back(static_cast<uint8_t>(dcid.size()));
        packet.insert(packet.end(), dcid.begin(), dcid.end());
        // SCID
        packet.push_back(scidLen);
        // Token Length = 0
        detail::appendUvarint(packet, 0);

        // Length (uvarint): pnLen + payload.size() + 16(tag)
        size_t protectedLength = pnLen + payload.size() + 16;
        detail::appendUvarint(packet, protectedLength);

        const size_t hdrLen = packet.size();
        packet.push_back(static_cast<uint8_t>(packetNumber));
        const size_t extHdrLen = hdrLen + pnLen;

        // 6. AEAD 加密载荷
        std::array<uint8_t, 12> nonce = iv;
        nonce[11] ^= static_cast<uint8_t>(packetNumber);

        std::span<const uint8_t> aad(packet.data(), extHdrLen);
        std::vector<uint8_t> ciphertext;
        std::array<uint8_t, 16> tag{};
        ok = mynet::handler::crypto::aes128GcmEncryptWithAad(key, nonce, aad, payload, ciphertext, tag);
        EXPECT_TRUE(ok);

        packet.insert(packet.end(), ciphertext.begin(), ciphertext.end());
        packet.insert(packet.end(), tag.begin(), tag.end());

        // 7. 头部保护掩码
        std::array<uint8_t, 16> sample{};
        std::memcpy(sample.data(), packet.data() + hdrLen + 4, 16);
        std::array<uint8_t, 16> mask{};
        ok = mynet::handler::crypto::aes128EcbEncryptBlock(hpKey, sample, mask);
        EXPECT_TRUE(ok);

        packet[0] ^= (mask[0] & 0x0F);
        packet[hdrLen] ^= mask[1];

        return packet;
    }

} // namespace

TEST(DomainSnifferTest, TlsSniExtraction)
{
    auto data = createTlsRecordClientHello("www.google.com");
    auto res = DomainSniffer::sniffTlsSni(data);
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(*res, "www.google.com");

    auto unified = DomainSniffer::sniff(data);
    ASSERT_TRUE(unified.has_value());
    EXPECT_EQ(unified->protocol, ProtocolType::TLS);
    EXPECT_EQ(unified->host, "www.google.com");
}

TEST(DomainSnifferTest, TlsSniCaseAndTrailingDotNormalization)
{
    auto data = createTlsRecordClientHello("GitHub.COM.");
    auto unified = DomainSniffer::sniff(data);
    ASSERT_TRUE(unified.has_value());
    EXPECT_EQ(unified->protocol, ProtocolType::TLS);
    EXPECT_EQ(unified->host, "github.com");
}

TEST(DomainSnifferTest, HttpHostExtraction)
{
    std::string req = "GET /index.html HTTP/1.1\r\n"
                      "User-Agent: curl/7.88.1\r\n"
                      "Host: api.cloudflare.com\r\n"
                      "Accept: */*\r\n\r\n";
    std::span<const uint8_t> data(reinterpret_cast<const uint8_t *>(req.data()), req.size());

    auto res = DomainSniffer::sniffHttpHost(data);
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res->first, "api.cloudflare.com");
    EXPECT_EQ(res->second, 0);

    auto unified = DomainSniffer::sniff(data);
    ASSERT_TRUE(unified.has_value());
    EXPECT_EQ(unified->protocol, ProtocolType::HTTP);
    EXPECT_EQ(unified->host, "api.cloudflare.com");
    EXPECT_EQ(unified->port, 0);
}

TEST(DomainSnifferTest, HttpHostWithPortExtraction)
{
    std::string req = "POST /v1/chat HTTP/1.1\r\n"
                      "host: example.com:8443\r\n"
                      "Content-Length: 0\r\n\r\n";
    std::span<const uint8_t> data(reinterpret_cast<const uint8_t *>(req.data()), req.size());

    auto res = DomainSniffer::sniffHttpHost(data);
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res->first, "example.com");
    EXPECT_EQ(res->second, 8443);

    auto unified = DomainSniffer::sniff(data);
    ASSERT_TRUE(unified.has_value());
    EXPECT_EQ(unified->protocol, ProtocolType::HTTP);
    EXPECT_EQ(unified->host, "example.com");
    EXPECT_EQ(unified->port, 8443);
}

TEST(DomainSnifferTest, QuicInitialSniExtraction)
{
    auto quicPkt = createQuicInitialPacket("quic.nginx.org");
    auto res = DomainSniffer::sniffQuicSni(quicPkt);
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(*res, "quic.nginx.org");

    auto unified = DomainSniffer::sniff(quicPkt);
    ASSERT_TRUE(unified.has_value());
    EXPECT_EQ(unified->protocol, ProtocolType::QUIC);
    EXPECT_EQ(unified->host, "quic.nginx.org");
}

TEST(DomainSnifferTest, DnsQuestionExtraction)
{
    // 标准 DNS 查询包: Transaction ID=0x1234, Flags=0x0100 (RD), QDCOUNT=1
    // QNAME: 3www6google3com0
    std::vector<uint8_t> dnsQuery = {
        0x12, 0x34,
        0x01, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        3, 'w', 'w', 'w',
        6, 'g', 'o', 'o', 'g', 'l', 'e',
        3, 'c', 'o', 'm',
        0x00,
        0x00, 0x01, // Type A
        0x00, 0x01  // Class IN
    };

    auto res = DomainSniffer::sniffDnsQuestion(dnsQuery);
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(*res, "www.google.com");

    auto unified = DomainSniffer::sniff(dnsQuery);
    ASSERT_TRUE(unified.has_value());
    EXPECT_EQ(unified->protocol, ProtocolType::DNS);
    EXPECT_EQ(unified->host, "www.google.com");
    EXPECT_EQ(unified->port, 53);
}

TEST(DomainSnifferTest, BitTorrentHandshakeExtraction)
{
    std::string btHandshake;
    btHandshake.push_back(19);
    btHandshake.append("BitTorrent protocol");
    btHandshake.append(std::string(8, '\0'));  // reserved
    btHandshake.append(std::string(20, 'A')); // info_hash
    btHandshake.append(std::string(20, 'B')); // peer_id

    std::span<const uint8_t> data(reinterpret_cast<const uint8_t *>(btHandshake.data()), btHandshake.size());
    EXPECT_TRUE(DomainSniffer::sniffBitTorrent(data));

    auto unified = DomainSniffer::sniff(data);
    ASSERT_TRUE(unified.has_value());
    EXPECT_EQ(unified->protocol, ProtocolType::BITTORRENT);
}

TEST(DomainSnifferTest, SshBannerExtraction)
{
    std::string sshBanner = "SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3\r\n";
    std::span<const uint8_t> data(reinterpret_cast<const uint8_t *>(sshBanner.data()), sshBanner.size());

    auto res = DomainSniffer::sniffSsh(data);
    ASSERT_TRUE(res.has_value());

    auto unified = DomainSniffer::sniff(data);
    ASSERT_TRUE(unified.has_value());
    EXPECT_EQ(unified->protocol, ProtocolType::SSH);
}

TEST(DomainSnifferTest, DtlsAndStunAndNtpAndRdpExtraction)
{
    // DTLS 1.2 Handshake (0x16, 0xFE, 0xFD)
    std::vector<uint8_t> dtlsPacket(13, 0);
    dtlsPacket[0] = 0x16; // Handshake
    dtlsPacket[1] = 0xFE;
    dtlsPacket[2] = 0xFD; // DTLS 1.2
    EXPECT_TRUE(DomainSniffer::sniffDtls(dtlsPacket));
    auto unifiedDtls = DomainSniffer::sniff(dtlsPacket);
    ASSERT_TRUE(unifiedDtls.has_value());
    EXPECT_EQ(unifiedDtls->protocol, ProtocolType::DTLS);

    // STUN Binding Request (Type 0x0001, Length 0, Cookie 0x2112A442)
    std::vector<uint8_t> stunPacket(20, 0);
    stunPacket[0] = 0x00;
    stunPacket[1] = 0x01; // Binding Request
    stunPacket[2] = 0x00;
    stunPacket[3] = 0x00; // Length 0
    stunPacket[4] = 0x21;
    stunPacket[5] = 0x12;
    stunPacket[6] = 0xA4;
    stunPacket[7] = 0x42; // Magic Cookie
    EXPECT_TRUE(DomainSniffer::sniffStun(stunPacket));
    auto unifiedStun = DomainSniffer::sniff(stunPacket);
    ASSERT_TRUE(unifiedStun.has_value());
    EXPECT_EQ(unifiedStun->protocol, ProtocolType::STUN);

    // NTP Client Request (LI 0, VN 4, Mode 3 = 0x23)
    std::vector<uint8_t> ntpPacket(48, 0);
    ntpPacket[0] = 0x23; // LI 0, VN 4, Mode 3
    EXPECT_TRUE(DomainSniffer::sniffNtp(ntpPacket));
    auto unifiedNtp = DomainSniffer::sniff(ntpPacket);
    ASSERT_TRUE(unifiedNtp.has_value());
    EXPECT_EQ(unifiedNtp->protocol, ProtocolType::NTP);
    EXPECT_EQ(unifiedNtp->port, 123);

    // RDP Connection Request (TPKT len 19, COTP type 0xE0)
    std::vector<uint8_t> rdpPacket(19, 0);
    rdpPacket[0] = 0x03; // TPKT Version
    rdpPacket[1] = 0x00; // Reserved
    rdpPacket[2] = 0x00;
    rdpPacket[3] = 19;   // Length 19
    rdpPacket[4] = 14;   // COTP Length
    rdpPacket[5] = 0xE0; // COTP CR TPDU
    EXPECT_TRUE(DomainSniffer::sniffRdp(rdpPacket));
    auto unifiedRdp = DomainSniffer::sniff(rdpPacket);
    ASSERT_TRUE(unifiedRdp.has_value());
    EXPECT_EQ(unifiedRdp->protocol, ProtocolType::RDP);
    EXPECT_EQ(unifiedRdp->port, 3389);
}

TEST(DomainSnifferTest, NegativeCases)
{
    // 随机非协议二进制
    std::vector<uint8_t> randomBytes = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04};
    auto unified = DomainSniffer::sniff(randomBytes);
    EXPECT_FALSE(unified.has_value());

    // 截断的 TLS 记录
    std::vector<uint8_t> truncatedTls = {0x16, 0x03, 0x01, 0x00, 0x50, 0x01};
    EXPECT_FALSE(DomainSniffer::sniffTlsSni(truncatedTls).has_value());

    // 空数据
    EXPECT_FALSE(DomainSniffer::sniff({}).has_value());
}
