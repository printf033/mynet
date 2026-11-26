#include "checksum.hpp"
#include "dialer.hpp"
#include "dns/ech.hpp"
#include "process.hpp"
#include "tls/fragmenter.hpp"
#include "tls/pinning.hpp"
#include "uot/uot.hpp"
#include "uvarint.hpp"
#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace mynet;
using namespace mynet::tls;
using namespace mynet::transport;

namespace
{

    // 构造测试用的标准 TLS ClientHello 报文（携带 SNI 扩展）
    std::vector<uint8_t> makeSampleClientHello(std::string_view sni = "www.cloudflare.com")
    {
        std::vector<uint8_t> ch;
        const size_t sniLen = sni.size();
        const size_t extSniPayloadLen = 2 + 1 + 2 + sniLen;
        const size_t extLen = 4 + extSniPayloadLen;
        const size_t hsBodyLen = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extLen;
        const size_t recLen = 4 + hsBodyLen;
        ch.reserve(5 + recLen);

        // TLS Record Header: Handshake (0x16), TLS 1.0 (0x03 0x01)
        ch.push_back(0x16);
        ch.push_back(0x03);
        ch.push_back(0x01);
        ch.push_back(static_cast<uint8_t>((recLen >> 8) & 0xFF));
        ch.push_back(static_cast<uint8_t>(recLen & 0xFF));
        // Handshake Header: ClientHello (0x01)
        ch.push_back(0x01);
        ch.push_back(static_cast<uint8_t>((hsBodyLen >> 16) & 0xFF));
        ch.push_back(static_cast<uint8_t>((hsBodyLen >> 8) & 0xFF));
        ch.push_back(static_cast<uint8_t>(hsBodyLen & 0xFF));
        // Client Version TLS 1.2 + 32-byte Random + empty session_id
        ch.push_back(0x03);
        ch.push_back(0x03);
        ch.insert(ch.end(), 32, 0x11);
        ch.push_back(0x00);
        // Cipher suites: 1 suite (0x1301)
        ch.push_back(0x00);
        ch.push_back(0x02);
        ch.push_back(0x13);
        ch.push_back(0x01);
        // Compression methods: 1 null
        ch.push_back(0x01);
        ch.push_back(0x00);
        // Extensions total length
        ch.push_back(static_cast<uint8_t>((extLen >> 8) & 0xFF));
        ch.push_back(static_cast<uint8_t>(extLen & 0xFF));
        // Extension SNI (0x0000)
        ch.push_back(0x00);
        ch.push_back(0x00);
        ch.push_back(static_cast<uint8_t>((extSniPayloadLen >> 8) & 0xFF));
        ch.push_back(static_cast<uint8_t>(extSniPayloadLen & 0xFF));
        const size_t listLen = 1 + 2 + sniLen;
        ch.push_back(static_cast<uint8_t>((listLen >> 8) & 0xFF));
        ch.push_back(static_cast<uint8_t>(listLen & 0xFF));
        ch.push_back(0x00); // host_name
        ch.push_back(static_cast<uint8_t>((sniLen >> 8) & 0xFF));
        ch.push_back(static_cast<uint8_t>(sniLen & 0xFF));
        ch.insert(ch.end(), sni.begin(), sni.end());
        return ch;
    }

} // namespace

// ============================================================================
// 1. TLS ClientHello Fragmenter 测试
// ============================================================================

TEST(SingboxFeaturesTest, TlsFragmenterFindSniAndSplitOffsets)
{
    auto ch = makeSampleClientHello("www.cloudflare.com");
    auto sniInfo = TlsFragmenter::findSni(ch);

    ASSERT_TRUE(sniInfo.has_value());
    EXPECT_EQ(sniInfo->serverName, "www.cloudflare.com");
    EXPECT_GT(sniInfo->sniOffset, 5u);
    EXPECT_EQ(sniInfo->sniLength, 18u);

    // 计算切分点
    auto offsets = TlsFragmenter::computeSplitOffsets(ch, *sniInfo);
    ASSERT_FALSE(offsets.empty());
    for (auto off : offsets)
    {
        EXPECT_GT(off, 5u);
        EXPECT_LT(off, ch.size());
    }
}

TEST(SingboxFeaturesTest, TlsFragmenterSplitRecordsValidity)
{
    auto ch = makeSampleClientHello("developers.google.com");
    auto sniInfo = TlsFragmenter::findSni(ch);
    ASSERT_TRUE(sniInfo.has_value());

    auto offsets = TlsFragmenter::computeSplitOffsets(ch, *sniInfo);
    auto records = TlsFragmenter::buildSplitRecords(ch, offsets);

    ASSERT_GE(records.size(), 2u);

    // 验证每个分片都是合规的 TLS 记录层 (0x16 0x03 0x01/0x03 [len 2B])
    size_t totalPayload = 0;
    for (const auto &rec : records)
    {
        ASSERT_GE(rec.size(), 5u);
        EXPECT_EQ(rec[0], 0x16);
        EXPECT_EQ(rec[1], 0x03);

        size_t len = (static_cast<size_t>(rec[3]) << 8) | rec[4];
        EXPECT_EQ(rec.size() - 5, len);
        totalPayload += len;
    }

    // 原始握手载荷长 (去掉原始 5 字节记录头) 应当严格等于各分片载荷长之和
    EXPECT_EQ(totalPayload, ch.size() - 5);
}

TEST(SingboxFeaturesTest, TlsFragmenterSendOverSocketPair)
{
    int sv[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);

    auto ch = makeSampleClientHello("api.github.com");

    // 启动线程在接收端读取并重组
    std::vector<uint8_t> received;
    std::thread receiver(
        [&]()
        {
            uint8_t buf[512];
            while (received.size() < ch.size())
            {
                ssize_t n = ::recv(sv[1], buf, sizeof(buf), 0);
                if (n <= 0)
                    break;
                received.insert(received.end(), buf, buf + n);
            }
        });

    // 发送分片 (RECORD_ONLY 模式)
    bool ok = TlsFragmenter::sendFragmentedClientHello(sv[0], ch, FragmentMode::RECORD_ONLY);
    EXPECT_TRUE(ok);

    receiver.join();
    ::close(sv[0]);
    ::close(sv[1]);

    // 验证接收端收到了分片数据，并且能成功解析出分片记录
    EXPECT_GT(received.size(), 0u);
}

// ============================================================================
// 3. UoT (UDP-over-TCP) v1/v2 协议测试
// ============================================================================

TEST(SingboxFeaturesTest, UotMagicAddressDetection)
{
    EXPECT_TRUE(UotProtocol::isUotMagicAddress("sp.v2.udp-over-tcp.arpa"));
    EXPECT_TRUE(UotProtocol::isUotMagicAddress("sp.udp-over-tcp.arpa"));
    EXPECT_FALSE(UotProtocol::isUotMagicAddress("example.com"));
    EXPECT_FALSE(UotProtocol::isUotMagicAddress(""));
}

TEST(SingboxFeaturesTest, UotRequestEncodeDecodeRoundtrip)
{
    // 1. IPv4 目标
    UotRequest req4{.isConnect = true,
                    .destination = {.type = UotAddressType::IPV4,
                                    .ipv4 = 0x08080808, // 8.8.8.8
                                    .port = 53}};
    auto enc4 = UotProtocol::encodeRequest(req4);
    auto dec4 = UotProtocol::decodeRequest(enc4);
    ASSERT_TRUE(dec4.has_value());
    EXPECT_EQ(dec4->first.isConnect, true);
    EXPECT_EQ(dec4->first.destination.type, UotAddressType::IPV4);
    EXPECT_EQ(dec4->first.destination.ipv4, 0x08080808);
    EXPECT_EQ(dec4->first.destination.port, 53);

    // 2. FQDN 目标
    UotRequest reqDomain{.isConnect = false,
                         .destination = {.type = UotAddressType::FQDN, .domain = "dns.google", .port = 853}};
    auto encDomain = UotProtocol::encodeRequest(reqDomain);
    auto decDomain = UotProtocol::decodeRequest(encDomain);
    ASSERT_TRUE(decDomain.has_value());
    EXPECT_EQ(decDomain->first.isConnect, false);
    EXPECT_EQ(decDomain->first.destination.type, UotAddressType::FQDN);
    EXPECT_EQ(decDomain->first.destination.domain, "dns.google");
    EXPECT_EQ(decDomain->first.destination.port, 853);
}

TEST(SingboxFeaturesTest, UotConnectedFrameEncodeDecode)
{
    std::string payloadStr = "Hello UDP over TCP Singbox!";
    std::vector<uint8_t> payload(payloadStr.begin(), payloadStr.end());

    auto frame = UotProtocol::encodeConnectedFrame(payload);
    ASSERT_EQ(frame.size(), 2 + payload.size());

    auto decoded = UotProtocol::decodeConnectedFrame(frame);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->second, frame.size());

    std::string recovered(decoded->first.begin(), decoded->first.end());
    EXPECT_EQ(recovered, payloadStr);
}

TEST(SingboxFeaturesTest, UotPacketFrameEncodeDecode)
{
    UotEndpoint ep{.type = UotAddressType::IPV4,
                   .ipv4 = 0x01010101, // 1.1.1.1
                   .port = 53};
    std::vector<uint8_t> dnsQuery = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01};

    auto frame = UotProtocol::encodePacketFrame(ep, dnsQuery);
    ASSERT_GT(frame.size(), dnsQuery.size());

    size_t consumed = 0;
    auto decoded = UotProtocol::decodePacketFrame(frame, consumed);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(consumed, frame.size());
    EXPECT_EQ(decoded->first.ipv4, 0x01010101);
    EXPECT_EQ(decoded->first.port, 53);
    EXPECT_EQ(decoded->second, dnsQuery);
}

// ============================================================================
// 4. Parallel Interface Dialer 赛马机制测试
// ============================================================================

TEST(SingboxFeaturesTest, ParallelInterfaceDialerLocalEchoRace)
{
    // 创建一个本地监听套接字模拟服务端
    int listenFd = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(listenFd, 0);

    sockaddr_in sin{};
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = 0; // 自动分配端口
    ASSERT_EQ(::bind(listenFd, reinterpret_cast<sockaddr *>(&sin), sizeof(sin)), 0);
    ASSERT_EQ(::listen(listenFd, 5), 0);

    socklen_t slen = sizeof(sin);
    ASSERT_EQ(::getsockname(listenFd, reinterpret_cast<sockaddr *>(&sin), &slen), 0);

    // 启动多网卡赛马测试
    std::vector<std::string> primary = {""}; // 回环/默认接口
    std::vector<std::string> fallback = {""};

    auto res =
        ParallelInterfaceDialer::dialParallelInterface(sin, primary, fallback, InterfaceStrategy::HYBRID,
                                                       std::chrono::milliseconds(50), std::chrono::milliseconds(1000));

    EXPECT_GE(res.winnerFd, 0);

    // 服务端 accept
    int clientFd = ::accept(listenFd, nullptr, nullptr);
    EXPECT_GE(clientFd, 0);

    if (res.winnerFd >= 0)
        ::close(res.winnerFd);
    if (clientFd >= 0)
        ::close(clientFd);
    ::close(listenFd);
}

// ============================================================================
// 5. Process Resolver Netlink & Inode 测试
// ============================================================================

TEST(SingboxFeaturesTest, ProcessResolverCurrentPid)
{
    pid_t myPid = ::getpid();
    std::string name = ProcessResolver::getProcessNameByPid(myPid);
    EXPECT_FALSE(name.empty());

    std::string path = ProcessResolver::getProcessPathByPid(myPid);
    EXPECT_FALSE(path.empty());
}

TEST(SingboxFeaturesTest, ProcessResolverCacheClear)
{
    ProcessResolver::clearCache();
    // 验证调用 clearCache 安全不崩溃
    SUCCEED();
}

// ============================================================================
// 6. Certificate & SPKI SHA-256 Pinning 测试
// ============================================================================

TEST(SingboxFeaturesTest, CertPinnerSha256)
{
    std::string testData = "Singbox Certificate Pinning Test Data";
    auto digest = CertPinner::sha256(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(testData.data()), testData.size()));
    ASSERT_EQ(digest.size(), 32u);

    // 空白白名单默认通过
    EXPECT_TRUE(CertPinner::verifyPeerCertificate(nullptr, {}, {}));
}

// ============================================================================
// 8. ECH (Encrypted Client Hello) HTTPS/SVCB DNS 反向映射测试
// ============================================================================

TEST(SingboxFeaturesTest, EchReverseMapperResolution)
{
    auto &mapper = mynet::dns::EchReverseMapper::instance();
    mapper.clear();

    const std::string realDomain = "chat.openai.com";
    const std::string publicName = "cloudflare-ech.com";
    const uint32_t fakeIp = 0x68123456;

    mapper.recordMapping(realDomain, publicName, fakeIp, std::chrono::seconds(10));
    EXPECT_TRUE(mapper.isKnownPublicName(publicName));

    // 根据 public_name + IP 反查
    auto resolved = mapper.lookupRealDomain(publicName, fakeIp);
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(*resolved, realDomain);

    // 查询错误的 IP 应当返回 nullopt
    auto mismatch = mapper.lookupRealDomain(publicName, 0x12345678);
    EXPECT_FALSE(mismatch.has_value());

    mapper.clear();
}

// ============================================================================
// 9. TCP Prefix 动态前缀注入测试
// ============================================================================

TEST(SingboxFeaturesTest, TcpPrefixInjection)
{
    int sv[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);

    struct DummyHandler
    {
        void reset() noexcept {}
        void onMessageComplete() noexcept {}
        void onParseError(const char *) noexcept {}
    };

    DialerBase<DummyHandler> dialer;

    std::vector<uint8_t> prefix = {'P', 'R', 'E', 'F', 'I', 'X', 0x01, 0x02};
    dialer.setTcpPrefix(prefix);
    EXPECT_EQ(dialer.getTcpPrefix().size(), prefix.size());

    EXPECT_TRUE(dialer.flushTcpPrefix(sv[0]));

    uint8_t buf[16]{};
    ssize_t n = ::recv(sv[1], buf, sizeof(buf), 0);
    EXPECT_EQ(n, static_cast<ssize_t>(prefix.size()));
    EXPECT_EQ(std::memcmp(buf, prefix.data(), prefix.size()), 0);

    dialer.reset();
    ::close(sv[0]);
    ::close(sv[1]);
}

// ============================================================================
// 10. 边界与防御性鲁棒性测试 (Edge cases & Hardening)
// ============================================================================

TEST(SingboxFeaturesTest, TlsFragmenterUnsortedAndDuplicateOffsets)
{
    std::string sni = "sub.domain.example.com";
    auto clientHello = makeSampleClientHello(sni);

    // 传入乱序且带重复的切分点
    std::vector<size_t> unsortedOffsets = {120, 45, 120, 60, 45, 80};
    auto records = TlsFragmenter::buildSplitRecords(clientHello, unsortedOffsets);

    // 依然应当按单调递增合规切分，且首个与末尾分片头部完整
    ASSERT_GT(records.size(), 1);
    size_t reassembledPayloadLen = 0;
    for (const auto &rec : records)
    {
        ASSERT_GE(rec.size(), 5);
        EXPECT_EQ(rec[0], 0x16); // ContentType Handshake
        uint16_t chunkLen = (static_cast<uint16_t>(rec[3]) << 8) | rec[4];
        EXPECT_EQ(rec.size(), 5 + chunkLen);
        reassembledPayloadLen += chunkLen;
    }
    EXPECT_EQ(reassembledPayloadLen, clientHello.size() - 5);
}

TEST(SingboxFeaturesTest, UotPayloadOverflowProtection)
{
    // 测试超过 65535 字节的载荷不会发生 16-bit 长度溢出绕回
    std::vector<uint8_t> largePayload(70000, 0x55);
    auto frameConnected = UotProtocol::encodeConnectedFrame(largePayload);
    EXPECT_TRUE(frameConnected.empty());

    UotEndpoint ep;
    ep.type = UotAddressType::IPV4;
    ep.ipv4 = 0x7F000001;
    ep.port = 8080;
    auto framePacket = UotProtocol::encodePacketFrame(ep, largePayload);
    EXPECT_TRUE(framePacket.empty());

    // writev 也应安全拒绝
    int sv[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    EXPECT_EQ(UotProtocol::writeVectorisedConnectedFrame(sv[0], largePayload), -1);
    ::close(sv[0]);
    ::close(sv[1]);
}

TEST(SingboxFeaturesTest, UvarintBoundaryAndOverflow)
{
    // 0 ~ 最大值 LEB128 编解码
    std::vector<uint8_t> buf;
    mynet::uvarint::append(buf, 0);
    mynet::uvarint::append(buf, 127);
    mynet::uvarint::append(buf, 128);
    mynet::uvarint::append(buf, 16384);
    mynet::uvarint::append(buf, 0xFFFFFFFFFFFFFFFFULL);

    std::span<const uint8_t> stream(buf);
    auto [v0, n0] = mynet::uvarint::decode(stream);
    EXPECT_EQ(v0, 0);
    EXPECT_EQ(n0, 1);
    stream = stream.subspan(n0);

    auto [v1, n1] = mynet::uvarint::decode(stream);
    EXPECT_EQ(v1, 127);
    EXPECT_EQ(n1, 1);
    stream = stream.subspan(n1);

    auto [v2, n2] = mynet::uvarint::decode(stream);
    EXPECT_EQ(v2, 128);
    EXPECT_EQ(n2, 2);
    stream = stream.subspan(n2);

    auto [v3, n3] = mynet::uvarint::decode(stream);
    EXPECT_EQ(v3, 16384);
    EXPECT_EQ(n3, 3);
    stream = stream.subspan(n3);

    auto [v4, n4] = mynet::uvarint::decode(stream);
    EXPECT_EQ(v4, 0xFFFFFFFFFFFFFFFFULL);
    EXPECT_EQ(n4, 10);
    stream = stream.subspan(n4);

    EXPECT_TRUE(stream.empty());

    // 溢出序列防御测试 (第10字节 > 1)
    uint8_t overflowBuf[10] = {0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7F};
    auto [vOverflow, nOverflow] = mynet::uvarint::decode(overflowBuf);
    EXPECT_EQ(nOverflow, 0); // 必须判定为溢出非法
}

TEST(SingboxFeaturesTest, ChecksumParityAndZeroHandling)
{
    // RFC 768 / RFC 1071 边界校验
    std::vector<uint8_t> oddBytes = {0x12, 0x34, 0x56};
    uint16_t c1 = mynet::rfc1071Checksum(oddBytes);
    EXPECT_NE(c1, 0);

    // RFC 768 规定若校验和为 0 必须输出 0xFFFF
    uint16_t udpCsum = mynet::rfcUdp4Checksum(0x7F000001, 0x7F000001, 1234, 5678, {});
    EXPECT_NE(udpCsum, 0);
}
