#include "../src/config/singbox.hpp"
#include "../src/core.hpp"
#include "../src/tun/inbound.hpp"
#include "../src/tun/engine.hpp"
#include "../src/tun/packet.hpp"
#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

using namespace mynet;
using namespace mynet::tun;

TEST(TunPacketTest, CidrParsing)
{
    auto [ip1, mask1] = parseCidrToIpAndMask("172.19.0.1/30");
    EXPECT_EQ(ip1, "172.19.0.1");
    EXPECT_EQ(mask1, "255.255.255.252");

    auto [ip2, mask2] = parseCidrToIpAndMask("10.0.0.1/8");
    EXPECT_EQ(ip2, "10.0.0.1");
    EXPECT_EQ(mask2, "255.0.0.0");

    auto [ip3, mask3] = parseCidrToIpAndMask("192.168.1.1/24");
    EXPECT_EQ(ip3, "192.168.1.1");
    EXPECT_EQ(mask3, "255.255.255.0");

    auto [ip4, mask4] = parseCidrToIpAndMask("1.1.1.1");
    EXPECT_EQ(ip4, "1.1.1.1");
    EXPECT_EQ(mask4, "255.255.255.0");
}

TEST(TunPacketTest, Ipv4UdpPacketBuildAndParse)
{
    uint32_t srcIp = inet_addr("192.168.1.100");
    uint32_t dstIp = inet_addr("8.8.8.8");
    uint16_t srcPort = 12345;
    uint16_t dstPort = 53;
    const std::string payload = "Hello DNS query!";

    auto pkt = buildIpv4UdpPacket(reinterpret_cast<const uint8_t *>(&srcIp),
                                  reinterpret_cast<const uint8_t *>(&dstIp), srcPort, dstPort,
                                  std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(payload.data()),
                                                          payload.size()));

    ASSERT_FALSE(pkt.empty());
    EXPECT_EQ(pkt.size(), 20 + 8 + payload.size());

    Ipv4View ip{pkt.data(), pkt.size()};
    ASSERT_TRUE(ip.valid());
    EXPECT_EQ(ip.version(), 4);
    EXPECT_EQ(ip.protocol(), 17); // UDP
    EXPECT_EQ(ip.srcIp(), srcIp);
    EXPECT_EQ(ip.dstIp(), dstIp);
    EXPECT_TRUE(ip.verifyChecksum());

    auto udpSpan = ip.payload();
    UdpView udp{udpSpan.data(), udpSpan.size()};
    ASSERT_TRUE(udp.valid());
    EXPECT_EQ(udp.srcPort(), srcPort);
    EXPECT_EQ(udp.dstPort(), dstPort);
    EXPECT_EQ(udp.length(), 8 + payload.size());

    auto udpPayload = udp.payload();
    std::string extracted(reinterpret_cast<const char *>(udpPayload.data()), udpPayload.size());
    EXPECT_EQ(extracted, payload);
}

TEST(TunPacketTest, Ipv4TcpPacketBuildAndParse)
{
    uint32_t srcIp = inet_addr("10.0.0.2");
    uint32_t dstIp = inet_addr("1.1.1.1");
    uint16_t srcPort = 54321;
    uint16_t dstPort = 443;
    uint32_t seq = 1000;
    uint32_t ackSeq = 2000;
    uint8_t flags = 0x12; // SYN | ACK

    auto pkt = buildIpv4TcpPacket(reinterpret_cast<const uint8_t *>(&srcIp),
                                  reinterpret_cast<const uint8_t *>(&dstIp), srcPort, dstPort, seq, ackSeq, flags);

    ASSERT_FALSE(pkt.empty());
    EXPECT_EQ(pkt.size(), 40u); // 20 IP + 20 TCP

    Ipv4View ip{pkt.data(), pkt.size()};
    ASSERT_TRUE(ip.valid());
    EXPECT_EQ(ip.protocol(), 6); // TCP
    EXPECT_TRUE(ip.verifyChecksum());

    auto tcpSpan = ip.payload();
    TcpView tcp{tcpSpan.data(), tcpSpan.size()};
    ASSERT_TRUE(tcp.valid());
    EXPECT_EQ(tcp.srcPort(), srcPort);
    EXPECT_EQ(tcp.dstPort(), dstPort);
    EXPECT_EQ(tcp.seq(), seq);
    EXPECT_EQ(tcp.ackSeq(), ackSeq);
    EXPECT_TRUE(tcp.syn());
    EXPECT_TRUE(tcp.ack());
    EXPECT_FALSE(tcp.fin());
    EXPECT_FALSE(tcp.rst());
}

TEST(TunPacketTest, IcmpEchoReplySynthesis)
{
    uint32_t clientIp = inet_addr("172.19.0.2");
    uint32_t tunIp = inet_addr("172.19.0.1");

    // 手工构造一个 ICMP Echo Request 数据包 (20B IP + 8B ICMP + 4B 载荷)
    std::vector<uint8_t> reqPkt(32, 0);
    // IPv4 Header
    reqPkt[0] = 0x45;
    reqPkt[2] = 0;
    reqPkt[3] = 32;
    reqPkt[8] = 64; // TTL
    reqPkt[9] = 1;  // ICMP
    std::memcpy(reqPkt.data() + 12, &clientIp, 4);
    std::memcpy(reqPkt.data() + 16, &tunIp, 4);
    uint16_t ipCsum = calculateChecksum(std::span<const uint8_t>(reqPkt.data(), 20));
    reqPkt[10] = static_cast<uint8_t>(ipCsum >> 8);
    reqPkt[11] = static_cast<uint8_t>(ipCsum & 0xFF);

    // ICMP Header (Offset 20)
    reqPkt[20] = 8; // Echo Request
    reqPkt[21] = 0; // Code
    reqPkt[24] = 0x12; // Identifier
    reqPkt[25] = 0x34;
    reqPkt[26] = 0x00; // Sequence
    reqPkt[27] = 0x01;
    // Payload: "ping"
    reqPkt[28] = 'p';
    reqPkt[29] = 'i';
    reqPkt[30] = 'n';
    reqPkt[31] = 'g';

    uint16_t icmpCsum = calculateChecksum(std::span<const uint8_t>(reqPkt.data() + 20, 12));
    reqPkt[22] = static_cast<uint8_t>(icmpCsum >> 8);
    reqPkt[23] = static_cast<uint8_t>(icmpCsum & 0xFF);

    // 调用合成函数生成 Reply
    auto reply = buildIcmpEchoReply(reqPkt);
    ASSERT_FALSE(reply.empty());
    EXPECT_EQ(reply.size(), 32u);

    Ipv4View repIp{reply.data(), reply.size()};
    ASSERT_TRUE(repIp.valid());
    EXPECT_EQ(repIp.srcIp(), tunIp);      // 交换源地址
    EXPECT_EQ(repIp.dstIp(), clientIp);   // 交换目的地址
    EXPECT_TRUE(repIp.verifyChecksum());

    auto icmpSpan = repIp.payload();
    IcmpView repIcmp{icmpSpan.data(), icmpSpan.size()};
    ASSERT_TRUE(repIcmp.valid());
    EXPECT_EQ(repIcmp.type(), 0); // 0 = Echo Reply
    EXPECT_EQ(repIcmp.code(), 0);
    EXPECT_EQ(repIcmp.id(), 0x1234);
    EXPECT_EQ(repIcmp.sequence(), 0x0001);
    EXPECT_TRUE(repIcmp.verifyChecksum());
}

TEST(TunEngineTest, MockSocketpairIcmpPingLoop)
{
    int sv[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sv), 0);

    const int engineFd = sv[0];
    const int clientPeerFd = sv[1];

    TunEngine engine(engineFd, 1500);

    // 构造 Ping 请求
    uint32_t clientIp = inet_addr("172.19.0.2");
    uint32_t targetIp = inet_addr("8.8.8.8");
    std::vector<uint8_t> pingReq(28, 0);
    pingReq[0] = 0x45;
    pingReq[3] = 28;
    pingReq[8] = 64;
    pingReq[9] = 1; // ICMP
    std::memcpy(pingReq.data() + 12, &clientIp, 4);
    std::memcpy(pingReq.data() + 16, &targetIp, 4);
    uint16_t ipCsum = calculateChecksum(std::span<const uint8_t>(pingReq.data(), 20));
    pingReq[10] = static_cast<uint8_t>(ipCsum >> 8);
    pingReq[11] = static_cast<uint8_t>(ipCsum & 0xFF);

    pingReq[20] = 8; // Echo Request
    pingReq[24] = 0xAA;
    pingReq[25] = 0xBB;
    uint16_t icmpCsum = calculateChecksum(std::span<const uint8_t>(pingReq.data() + 20, 8));
    pingReq[22] = static_cast<uint8_t>(icmpCsum >> 8);
    pingReq[23] = static_cast<uint8_t>(icmpCsum & 0xFF);

    // 模拟客户端将 Ping 报文发送入 TUN 设备
    ASSERT_EQ(::write(clientPeerFd, pingReq.data(), pingReq.size()), static_cast<ssize_t>(pingReq.size()));

    // 驱动引擎一次轮询泵送
    size_t handled = engine.pumpOnce(50);
    EXPECT_GE(handled, 1u);
    EXPECT_GE(engine.packetsIn(), 1u);
    EXPECT_GE(engine.packetsOut(), 1u);

    // 从客户端对端读取生成的 Ping 回包
    std::vector<uint8_t> replyBuf(1500, 0);
    ssize_t n = ::read(clientPeerFd, replyBuf.data(), replyBuf.size());
    ASSERT_GT(n, 0);

    Ipv4View replyIp{replyBuf.data(), static_cast<size_t>(n)};
    ASSERT_TRUE(replyIp.valid());
    EXPECT_EQ(replyIp.srcIp(), targetIp);
    EXPECT_EQ(replyIp.dstIp(), clientIp);

    auto icmpSpan = replyIp.payload();
    IcmpView replyIcmp{icmpSpan.data(), icmpSpan.size()};
    ASSERT_TRUE(replyIcmp.valid());
    EXPECT_EQ(replyIcmp.type(), 0); // Echo Reply!

    ::close(clientPeerFd);
}

TEST(AcceptorTunTest, MockModeLifecycle)
{
    auto tun = std::make_shared<AcceptorTun>("tun-test", "nekobox-tun", "172.19.0.1", "255.255.255.252", 9000);
    tun->setMockMode(true);

    auto res = tun->listen();
    ASSERT_TRUE(res.has_value());
    EXPECT_TRUE(tun->isRunning());
    EXPECT_GE(tun->tunFd(), 0);
    EXPECT_GE(tun->mockPeerFd(), 0);
    EXPECT_NE(tun->engine(), nullptr);
    EXPECT_EQ(tun->mtu(), 9000u);
    EXPECT_EQ(tun->inetIp(), "172.19.0.1");

    tun->close();
    EXPECT_FALSE(tun->isRunning());
    EXPECT_EQ(tun->tunFd(), -1);
}

TEST(SingBoxTunConfigTest, ParseAndApplyToCore)
{
    const std::string_view singBoxJson = R"({
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": "nekobox-tun",
                "address": ["172.19.0.1/30"],
                "mtu": 9000,
                "auto_route": true,
                "strict_route": false,
                "sniff": true
            },
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 2080
            }
        ],
        "outbounds": [
            {
                "type": "direct",
                "tag": "direct"
            }
        ],
        "route": {
            "final": "direct"
        }
    })";

    auto parsed = config::singbox::parseSingBoxConfig(singBoxJson);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->inbounds.size(), 2u);

    const auto &tunCfg = parsed->inbounds[0];
    EXPECT_EQ(tunCfg.protocol, "tun");
    EXPECT_EQ(tunCfg.tag, "tun-in");
    EXPECT_EQ(tunCfg.ifName, "nekobox-tun");
    EXPECT_EQ(tunCfg.inetIp, "172.19.0.1");
    EXPECT_EQ(tunCfg.inetMask, "255.255.255.252");
    EXPECT_EQ(tunCfg.mtu, 9000u);
    EXPECT_TRUE(tunCfg.enableSniffing);

    Core core;
    core.applyConfig(*parsed);

    EXPECT_TRUE(core.acceptors().has("tun-in"));
    EXPECT_TRUE(core.acceptors().has("mixed-in"));

    auto tunAcceptor = std::dynamic_pointer_cast<AcceptorTun>(core.acceptors().get("tun-in"));
    ASSERT_NE(tunAcceptor, nullptr);
    EXPECT_EQ(tunAcceptor->ifName(), "nekobox-tun");
    EXPECT_EQ(tunAcceptor->inetIp(), "172.19.0.1");
    EXPECT_EQ(tunAcceptor->netmask(), "255.255.255.252");
    EXPECT_EQ(tunAcceptor->mtu(), 9000u);
}
