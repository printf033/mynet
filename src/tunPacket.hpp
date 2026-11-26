#pragma once

/**
 * @file tunPacket.hpp
 * @brief 高性能零拷贝 Linux TUN L3/L4 报文解析器、校验和计算与数据报构建引擎。
 *
 * 遵循标准 RFC 规范：
 * 1. RFC 791 (IPv4 报文头解析与校验和)；
 * 2. RFC 2460 / RFC 8200 (IPv6 基本报文头解析)；
 * 3. RFC 792 (ICMP 协议与 Echo Request / Echo Reply 生成)；
 * 4. RFC 768 (UDP 数据报与伪首部校验和计算)；
 * 5. RFC 793 / RFC 9293 (TCP 报文与三次握手 / 状态流转报文构建)；
 * 6. 100% 内存安全、异常中立 (-fno-exceptions)，零外部第三方依赖。
 */

#include <arpa/inet.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace mynet::tun
{

    // =========================================================================
    // RFC 1071 互联网校验和算法 (Internet Checksum)
    // =========================================================================

    /**
     * @brief 计算 16-bit 反码求和校验和 (One's Complement Checksum)
     */
    [[nodiscard]] inline uint16_t calculateChecksum(std::span<const uint8_t> data, uint32_t initialSum = 0) noexcept
    {
        uint32_t sum = initialSum;
        size_t i = 0;
        while (i + 1 < data.size())
        {
            uint16_t word = (static_cast<uint16_t>(data[i]) << 8) | static_cast<uint16_t>(data[i + 1]);
            sum += word;
            i += 2;
        }
        if (i < data.size())
        {
            sum += (static_cast<uint16_t>(data[i]) << 8);
        }
        while (sum >> 16)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return static_cast<uint16_t>(~sum);
    }

    /**
     * @brief 计算 IPv4 伪首部累加和 (用于 TCP / UDP 校验和)
     */
    [[nodiscard]] inline uint32_t ipv4PseudoHeaderSum(const uint8_t *srcIpBytes, const uint8_t *dstIpBytes,
                                                     uint8_t protocol, uint16_t length) noexcept
    {
        uint32_t sum = 0;
        sum += (static_cast<uint16_t>(srcIpBytes[0]) << 8) | srcIpBytes[1];
        sum += (static_cast<uint16_t>(srcIpBytes[2]) << 8) | srcIpBytes[3];
        sum += (static_cast<uint16_t>(dstIpBytes[0]) << 8) | dstIpBytes[1];
        sum += (static_cast<uint16_t>(dstIpBytes[2]) << 8) | dstIpBytes[3];
        sum += static_cast<uint32_t>(protocol);
        sum += static_cast<uint32_t>(length);
        return sum;
    }

    /**
     * @brief 计算包含伪首部的 TCP 校验和
     */
    [[nodiscard]] inline uint16_t calculateTcpChecksum(const uint8_t *srcIpBytes, const uint8_t *dstIpBytes,
                                                       std::span<const uint8_t> tcpSegment) noexcept
    {
        uint32_t pSum = ipv4PseudoHeaderSum(srcIpBytes, dstIpBytes, 6, static_cast<uint16_t>(tcpSegment.size()));
        return calculateChecksum(tcpSegment, pSum);
    }

    /**
     * @brief 计算包含伪首部的 UDP 校验和 (RFC 768: 若结果为 0 则映射为 0xFFFF)
     */
    [[nodiscard]] inline uint16_t calculateUdpChecksum(const uint8_t *srcIpBytes, const uint8_t *dstIpBytes,
                                                       std::span<const uint8_t> udpSegment) noexcept
    {
        uint32_t pSum = ipv4PseudoHeaderSum(srcIpBytes, dstIpBytes, 17, static_cast<uint16_t>(udpSegment.size()));
        uint16_t csum = calculateChecksum(udpSegment, pSum);
        return (csum == 0) ? 0xFFFF : csum;
    }

    // =========================================================================
    // 零拷贝只读报文视图 (Views)
    // =========================================================================

    /**
     * @brief IPv4 报文只读视图 (RFC 791)
     */
    struct Ipv4View
    {
        const uint8_t *data_{nullptr};
        size_t size_{0};

        [[nodiscard]] inline bool valid() const noexcept
        {
            return data_ != nullptr && size_ >= 20 && version() == 4 && ihl() >= 5 && size_ >= totalLength() &&
                   totalLength() >= headerLength();
        }

        [[nodiscard]] inline uint8_t version() const noexcept { return data_[0] >> 4; }
        [[nodiscard]] inline uint8_t ihl() const noexcept { return data_[0] & 0x0F; }
        [[nodiscard]] inline size_t headerLength() const noexcept { return static_cast<size_t>(ihl()) * 4; }
        [[nodiscard]] inline uint8_t tos() const noexcept { return data_[1]; }
        [[nodiscard]] inline uint16_t totalLength() const noexcept
        {
            return (static_cast<uint16_t>(data_[2]) << 8) | data_[3];
        }
        [[nodiscard]] inline uint16_t id() const noexcept
        {
            return (static_cast<uint16_t>(data_[4]) << 8) | data_[5];
        }
        [[nodiscard]] inline uint16_t flagsAndFrag() const noexcept
        {
            return (static_cast<uint16_t>(data_[6]) << 8) | data_[7];
        }
        [[nodiscard]] inline uint8_t ttl() const noexcept { return data_[8]; }
        [[nodiscard]] inline uint8_t protocol() const noexcept { return data_[9]; }
        [[nodiscard]] inline uint16_t checksum() const noexcept
        {
            return (static_cast<uint16_t>(data_[10]) << 8) | data_[11];
        }

        [[nodiscard]] inline const uint8_t *srcIpBytes() const noexcept { return data_ + 12; }
        [[nodiscard]] inline const uint8_t *dstIpBytes() const noexcept { return data_ + 16; }

        [[nodiscard]] inline uint32_t srcIp() const noexcept
        {
            uint32_t val;
            std::memcpy(&val, data_ + 12, sizeof(val));
            return val;
        }

        [[nodiscard]] inline uint32_t dstIp() const noexcept
        {
            uint32_t val;
            std::memcpy(&val, data_ + 16, sizeof(val));
            return val;
        }

        [[nodiscard]] inline std::span<const uint8_t> payload() const noexcept
        {
            if (!valid())
                return {};
            const size_t hLen = headerLength();
            const size_t tLen = totalLength();
            return {data_ + hLen, tLen - hLen};
        }

        [[nodiscard]] inline bool verifyChecksum() const noexcept
        {
            if (!valid())
                return false;
            return calculateChecksum(std::span<const uint8_t>(data_, headerLength())) == 0;
        }
    };

    /**
     * @brief IPv6 报文只读视图 (RFC 8200)
     */
    struct Ipv6View
    {
        const uint8_t *data_{nullptr};
        size_t size_{0};

        [[nodiscard]] inline bool valid() const noexcept
        {
            return data_ != nullptr && size_ >= 40 && version() == 6 &&
                   size_ >= static_cast<size_t>(40 + payloadLength());
        }

        [[nodiscard]] inline uint8_t version() const noexcept { return data_[0] >> 4; }
        [[nodiscard]] inline uint16_t payloadLength() const noexcept
        {
            return (static_cast<uint16_t>(data_[4]) << 8) | data_[5];
        }
        [[nodiscard]] inline uint8_t nextHeader() const noexcept { return data_[6]; }
        [[nodiscard]] inline uint8_t hopLimit() const noexcept { return data_[7]; }

        [[nodiscard]] inline const uint8_t *srcIpBytes() const noexcept { return data_ + 8; }
        [[nodiscard]] inline const uint8_t *dstIpBytes() const noexcept { return data_ + 24; }

        [[nodiscard]] inline std::span<const uint8_t> payload() const noexcept
        {
            if (!valid())
                return {};
            return {data_ + 40, payloadLength()};
        }
    };

    /**
     * @brief ICMP 报文只读视图 (RFC 792)
     */
    struct IcmpView
    {
        const uint8_t *data_{nullptr};
        size_t size_{0};

        [[nodiscard]] inline bool valid() const noexcept { return data_ != nullptr && size_ >= 4; }
        [[nodiscard]] inline uint8_t type() const noexcept { return data_[0]; }
        [[nodiscard]] inline uint8_t code() const noexcept { return data_[1]; }
        [[nodiscard]] inline uint16_t checksum() const noexcept
        {
            return (static_cast<uint16_t>(data_[2]) << 8) | data_[3];
        }
        [[nodiscard]] inline uint16_t id() const noexcept
        {
            return size_ >= 6 ? ((static_cast<uint16_t>(data_[4]) << 8) | data_[5]) : 0;
        }
        [[nodiscard]] inline uint16_t sequence() const noexcept
        {
            return size_ >= 8 ? ((static_cast<uint16_t>(data_[6]) << 8) | data_[7]) : 0;
        }

        [[nodiscard]] inline std::span<const uint8_t> payload() const noexcept
        {
            if (size_ <= 8)
                return {};
            return {data_ + 8, size_ - 8};
        }

        [[nodiscard]] inline bool verifyChecksum() const noexcept
        {
            if (!valid())
                return false;
            return calculateChecksum(std::span<const uint8_t>(data_, size_)) == 0;
        }
    };

    /**
     * @brief UDP 数据报只读视图 (RFC 768)
     */
    struct UdpView
    {
        const uint8_t *data_{nullptr};
        size_t size_{0};

        [[nodiscard]] inline bool valid() const noexcept
        {
            return data_ != nullptr && size_ >= 8 && length() >= 8 && size_ >= length();
        }

        [[nodiscard]] inline uint16_t srcPort() const noexcept
        {
            return (static_cast<uint16_t>(data_[0]) << 8) | data_[1];
        }
        [[nodiscard]] inline uint16_t dstPort() const noexcept
        {
            return (static_cast<uint16_t>(data_[2]) << 8) | data_[3];
        }
        [[nodiscard]] inline uint16_t length() const noexcept
        {
            return (static_cast<uint16_t>(data_[4]) << 8) | data_[5];
        }
        [[nodiscard]] inline uint16_t checksum() const noexcept
        {
            return (static_cast<uint16_t>(data_[6]) << 8) | data_[7];
        }

        [[nodiscard]] inline std::span<const uint8_t> payload() const noexcept
        {
            if (!valid())
                return {};
            return {data_ + 8, static_cast<size_t>(length() - 8)};
        }
    };

    /**
     * @brief TCP 报文只读视图 (RFC 793 / RFC 9293)
     */
    struct TcpView
    {
        const uint8_t *data_{nullptr};
        size_t size_{0};

        [[nodiscard]] inline bool valid() const noexcept
        {
            return data_ != nullptr && size_ >= 20 && headerLength() >= 20 && size_ >= headerLength();
        }

        [[nodiscard]] inline uint16_t srcPort() const noexcept
        {
            return (static_cast<uint16_t>(data_[0]) << 8) | data_[1];
        }
        [[nodiscard]] inline uint16_t dstPort() const noexcept
        {
            return (static_cast<uint16_t>(data_[2]) << 8) | data_[3];
        }
        [[nodiscard]] inline uint32_t seq() const noexcept
        {
            return (static_cast<uint32_t>(data_[4]) << 24) | (static_cast<uint32_t>(data_[5]) << 16) |
                   (static_cast<uint32_t>(data_[6]) << 8) | data_[7];
        }
        [[nodiscard]] inline uint32_t ackSeq() const noexcept
        {
            return (static_cast<uint32_t>(data_[8]) << 24) | (static_cast<uint32_t>(data_[9]) << 16) |
                   (static_cast<uint32_t>(data_[10]) << 8) | data_[11];
        }
        [[nodiscard]] inline uint8_t dataOffset() const noexcept { return (data_[12] >> 4) & 0x0F; }
        [[nodiscard]] inline size_t headerLength() const noexcept { return static_cast<size_t>(dataOffset()) * 4; }
        [[nodiscard]] inline uint8_t flags() const noexcept { return data_[13]; }

        [[nodiscard]] inline bool syn() const noexcept { return (flags() & 0x02) != 0; }
        [[nodiscard]] inline bool ack() const noexcept { return (flags() & 0x10) != 0; }
        [[nodiscard]] inline bool fin() const noexcept { return (flags() & 0x01) != 0; }
        [[nodiscard]] inline bool rst() const noexcept { return (flags() & 0x04) != 0; }
        [[nodiscard]] inline bool psh() const noexcept { return (flags() & 0x08) != 0; }
        [[nodiscard]] inline bool urg() const noexcept { return (flags() & 0x20) != 0; }

        [[nodiscard]] inline uint16_t window() const noexcept
        {
            return (static_cast<uint16_t>(data_[14]) << 8) | data_[15];
        }
        [[nodiscard]] inline uint16_t checksum() const noexcept
        {
            return (static_cast<uint16_t>(data_[16]) << 8) | data_[17];
        }

        [[nodiscard]] inline std::span<const uint8_t> payload() const noexcept
        {
            if (!valid())
                return {};
            const size_t hLen = headerLength();
            return {data_ + hLen, size_ - hLen};
        }
    };

    // =========================================================================
    // 报文生成与合成工具 (Packet Builders)
    // =========================================================================

    /**
     * @brief 从接收到的 ICMP Echo Request 直接合成对应的 Echo Reply (Ping 响应)
     */
    [[nodiscard]] inline std::vector<uint8_t> buildIcmpEchoReply(std::span<const uint8_t> requestPacket)
    {
        Ipv4View ip{requestPacket.data(), requestPacket.size()};
        if (!ip.valid() || ip.protocol() != 1)
        {
            return {};
        }

        const auto icmpPayload = ip.payload();
        IcmpView icmp{icmpPayload.data(), icmpPayload.size()};
        if (!icmp.valid() || icmp.type() != 8) // 8 = Echo Request
        {
            return {};
        }

        std::vector<uint8_t> reply(requestPacket.begin(), requestPacket.begin() + ip.totalLength());

        // 1. 交换源与目标 IPv4 地址
        std::memcpy(reply.data() + 12, ip.dstIpBytes(), 4);
        std::memcpy(reply.data() + 16, ip.srcIpBytes(), 4);
        reply[8] = 64; // TTL 设置为 64

        // 清空 IPv4 校验和并重算
        reply[10] = 0;
        reply[11] = 0;
        const uint16_t ipCsum = calculateChecksum(std::span<const uint8_t>(reply.data(), ip.headerLength()));
        reply[10] = static_cast<uint8_t>(ipCsum >> 8);
        reply[11] = static_cast<uint8_t>(ipCsum & 0xFF);

        // 2. 修改 ICMP 首部：Type = 0 (Echo Reply), Code = 0
        const size_t icmpOffset = ip.headerLength();
        reply[icmpOffset] = 0;     // Type: Echo Reply
        reply[icmpOffset + 1] = 0; // Code: 0
        reply[icmpOffset + 2] = 0; // Checksum 置零
        reply[icmpOffset + 3] = 0;

        const uint16_t icmpCsum =
            calculateChecksum(std::span<const uint8_t>(reply.data() + icmpOffset, reply.size() - icmpOffset));
        reply[icmpOffset + 2] = static_cast<uint8_t>(icmpCsum >> 8);
        reply[icmpOffset + 3] = static_cast<uint8_t>(icmpCsum & 0xFF);

        return reply;
    }

    /**
     * @brief 构建标准 IPv4 UDP 数据报
     */
    [[nodiscard]] inline std::vector<uint8_t> buildIpv4UdpPacket(const uint8_t *srcIpBytes, const uint8_t *dstIpBytes,
                                                                 uint16_t srcPort, uint16_t dstPort,
                                                                 std::span<const uint8_t> payload,
                                                                 uint16_t ipId = 0)
    {
        const size_t totalLen = 20 + 8 + payload.size();
        std::vector<uint8_t> pkt(totalLen, 0);

        // 1. IPv4 首部 (20 字节)
        pkt[0] = 0x45; // Version 4, IHL 5
        pkt[1] = 0;    // TOS
        pkt[2] = static_cast<uint8_t>(totalLen >> 8);
        pkt[3] = static_cast<uint8_t>(totalLen & 0xFF);
        pkt[4] = static_cast<uint8_t>(ipId >> 8);
        pkt[5] = static_cast<uint8_t>(ipId & 0xFF);
        pkt[6] = 0x40; // Flags: DF (Don't Fragment)
        pkt[7] = 0x00;
        pkt[8] = 64; // TTL 64
        pkt[9] = 17; // Protocol: UDP
        pkt[10] = 0; // Checksum placeholder
        pkt[11] = 0;
        std::memcpy(pkt.data() + 12, srcIpBytes, 4);
        std::memcpy(pkt.data() + 16, dstIpBytes, 4);

        const uint16_t ipCsum = calculateChecksum(std::span<const uint8_t>(pkt.data(), 20));
        pkt[10] = static_cast<uint8_t>(ipCsum >> 8);
        pkt[11] = static_cast<uint8_t>(ipCsum & 0xFF);

        // 2. UDP 首部 (8 字节)
        const size_t udpOffset = 20;
        const uint16_t udpLen = static_cast<uint16_t>(8 + payload.size());
        pkt[udpOffset] = static_cast<uint8_t>(srcPort >> 8);
        pkt[udpOffset + 1] = static_cast<uint8_t>(srcPort & 0xFF);
        pkt[udpOffset + 2] = static_cast<uint8_t>(dstPort >> 8);
        pkt[udpOffset + 3] = static_cast<uint8_t>(dstPort & 0xFF);
        pkt[udpOffset + 4] = static_cast<uint8_t>(udpLen >> 8);
        pkt[udpOffset + 5] = static_cast<uint8_t>(udpLen & 0xFF);
        pkt[udpOffset + 6] = 0; // Checksum placeholder
        pkt[udpOffset + 7] = 0;

        if (!payload.empty())
        {
            std::memcpy(pkt.data() + udpOffset + 8, payload.data(), payload.size());
        }

        const uint16_t udpCsum = calculateUdpChecksum(srcIpBytes, dstIpBytes,
                                                      std::span<const uint8_t>(pkt.data() + udpOffset, udpLen));
        pkt[udpOffset + 6] = static_cast<uint8_t>(udpCsum >> 8);
        pkt[udpOffset + 7] = static_cast<uint8_t>(udpCsum & 0xFF);

        return pkt;
    }

    /**
     * @brief 构建标准 IPv4 TCP 报文 (支持 SYN, ACK, FIN, RST, PSH 等标志)
     */
    [[nodiscard]] inline std::vector<uint8_t> buildIpv4TcpPacket(const uint8_t *srcIpBytes, const uint8_t *dstIpBytes,
                                                                 uint16_t srcPort, uint16_t dstPort, uint32_t seq,
                                                                 uint32_t ackSeq, uint8_t flags, uint16_t window = 65535,
                                                                 std::span<const uint8_t> payload = {},
                                                                 uint16_t ipId = 0)
    {
        const size_t totalLen = 20 + 20 + payload.size();
        std::vector<uint8_t> pkt(totalLen, 0);

        // 1. IPv4 首部 (20 字节)
        pkt[0] = 0x45;
        pkt[1] = 0;
        pkt[2] = static_cast<uint8_t>(totalLen >> 8);
        pkt[3] = static_cast<uint8_t>(totalLen & 0xFF);
        pkt[4] = static_cast<uint8_t>(ipId >> 8);
        pkt[5] = static_cast<uint8_t>(ipId & 0xFF);
        pkt[6] = 0x40; // DF
        pkt[7] = 0x00;
        pkt[8] = 64; // TTL
        pkt[9] = 6;  // Protocol: TCP
        pkt[10] = 0;
        pkt[11] = 0;
        std::memcpy(pkt.data() + 12, srcIpBytes, 4);
        std::memcpy(pkt.data() + 16, dstIpBytes, 4);

        const uint16_t ipCsum = calculateChecksum(std::span<const uint8_t>(pkt.data(), 20));
        pkt[10] = static_cast<uint8_t>(ipCsum >> 8);
        pkt[11] = static_cast<uint8_t>(ipCsum & 0xFF);

        // 2. TCP 首部 (20 字节，Data Offset = 5)
        const size_t tcpOffset = 20;
        pkt[tcpOffset] = static_cast<uint8_t>(srcPort >> 8);
        pkt[tcpOffset + 1] = static_cast<uint8_t>(srcPort & 0xFF);
        pkt[tcpOffset + 2] = static_cast<uint8_t>(dstPort >> 8);
        pkt[tcpOffset + 3] = static_cast<uint8_t>(dstPort & 0xFF);

        pkt[tcpOffset + 4] = static_cast<uint8_t>(seq >> 24);
        pkt[tcpOffset + 5] = static_cast<uint8_t>((seq >> 16) & 0xFF);
        pkt[tcpOffset + 6] = static_cast<uint8_t>((seq >> 8) & 0xFF);
        pkt[tcpOffset + 7] = static_cast<uint8_t>(seq & 0xFF);

        pkt[tcpOffset + 8] = static_cast<uint8_t>(ackSeq >> 24);
        pkt[tcpOffset + 9] = static_cast<uint8_t>((ackSeq >> 16) & 0xFF);
        pkt[tcpOffset + 10] = static_cast<uint8_t>((ackSeq >> 8) & 0xFF);
        pkt[tcpOffset + 11] = static_cast<uint8_t>(ackSeq & 0xFF);

        pkt[tcpOffset + 12] = 0x50; // Data Offset 5 (20 bytes)
        pkt[tcpOffset + 13] = flags;
        pkt[tcpOffset + 14] = static_cast<uint8_t>(window >> 8);
        pkt[tcpOffset + 15] = static_cast<uint8_t>(window & 0xFF);
        pkt[tcpOffset + 16] = 0; // Checksum placeholder
        pkt[tcpOffset + 17] = 0;
        pkt[tcpOffset + 18] = 0; // Urgent Pointer
        pkt[tcpOffset + 19] = 0;

        if (!payload.empty())
        {
            std::memcpy(pkt.data() + tcpOffset + 20, payload.data(), payload.size());
        }

        const size_t tcpLen = 20 + payload.size();
        const uint16_t tcpCsum =
            calculateTcpChecksum(srcIpBytes, dstIpBytes, std::span<const uint8_t>(pkt.data() + tcpOffset, tcpLen));
        pkt[tcpOffset + 16] = static_cast<uint8_t>(tcpCsum >> 8);
        pkt[tcpOffset + 17] = static_cast<uint8_t>(tcpCsum & 0xFF);

        return pkt;
    }

    /**
     * @brief 解析 CIDR 格式字符串 (如 "172.19.0.1/30") 为 IP 与点分十进制子网掩码
     */
    [[nodiscard]] inline std::pair<std::string, std::string> parseCidrToIpAndMask(std::string_view cidr)
    {
        const auto slashPos = cidr.find('/');
        if (slashPos == std::string_view::npos)
        {
            return {std::string(cidr), "255.255.255.0"};
        }
        std::string ip(cidr.substr(0, slashPos));
        int prefix = 0;
        std::string_view prefixStr = cidr.substr(slashPos + 1);
        for (char c : prefixStr)
        {
            if (c >= '0' && c <= '9')
            {
                prefix = prefix * 10 + (c - '0');
            }
        }
        if (prefix <= 0 || prefix > 32)
        {
            prefix = 24;
        }
        const uint32_t mask = (prefix == 32) ? 0xFFFFFFFFU : (~0U << (32 - prefix));
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", (mask >> 24) & 0xFF, (mask >> 16) & 0xFF, (mask >> 8) & 0xFF,
                      mask & 0xFF);
        return {ip, std::string(buf)};
    }

} // namespace mynet::tun
