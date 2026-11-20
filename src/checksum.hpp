#pragma once

#include <arpa/inet.h>
#include <cstddef>
#include <cstdint>
#include <netinet/in.h>
#include <span>

namespace mynet
{

    /**
     * @brief 纯内存计算 RFC 1071 16-bit 检验和 (Single Source of Truth)
     *
     * 适用于 IP、ICMP、IGMP、TCP、UDP 校验和的 16 位反码求和算法。
     */
    [[nodiscard]] inline uint16_t rfc1071Checksum(std::span<const uint8_t> data, uint32_t initialSum = 0) noexcept
    {
        uint32_t sum = initialSum;
        const size_t nwords = data.size() / 2;

        for (size_t i = 0; i < nwords; ++i)
        {
            uint16_t word = (static_cast<uint16_t>(data[i * 2]) << 8) | data[i * 2 + 1];
            sum += word;
        }

        if (data.size() % 2 != 0)
        {
            uint16_t word = static_cast<uint16_t>(data[data.size() - 1]) << 8;
            sum += word;
        }

        while (sum >> 16)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return static_cast<uint16_t>(~sum & 0xFFFF);
    }

    /**
     * @brief 计算 IPv4 UDP 伪首部和有效载荷的 RFC 768 校验和 (Single Source of Truth)
     *
     * @param saddr 源 IPv4 地址 (网络字节序)
     * @param daddr 目的 IPv4 地址 (网络字节序)
     * @param sport 源端口 (主机字节序)
     * @param dport 目的端口 (主机字节序)
     * @param payload UDP 负载数据切片
     * @return uint16_t 16位校验和 (主机字节序；RFC 768 规定若计算结果为 0 则回绕填 0xFFFF)
     */
    [[nodiscard]] inline uint16_t rfcUdp4Checksum(uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport,
                                                  std::span<const uint8_t> payload) noexcept
    {
        const uint16_t udpLen = static_cast<uint16_t>(8 + payload.size());
        uint32_t sum = 0;

        // IPv4 伪首部: saddr(4) + daddr(4) + zero(1) + proto=17(1) + len(2)
        sum += (saddr >> 16) & 0xffff;
        sum += saddr & 0xffff;
        sum += (daddr >> 16) & 0xffff;
        sum += daddr & 0xffff;
        sum += ::htons(IPPROTO_UDP);
        sum += ::htons(udpLen);

        // UDP 首部中的 sport + dport + len
        sum += ::htons(sport);
        sum += ::htons(dport);
        sum += ::htons(udpLen);

        // 累加 payload
        const size_t nwords = payload.size() / 2;
        for (size_t i = 0; i < nwords; ++i)
        {
            uint16_t w = (static_cast<uint16_t>(payload[i * 2]) << 8) | payload[i * 2 + 1];
            sum += w;
        }
        if (payload.size() % 2 != 0)
        {
            sum += static_cast<uint16_t>(payload.back()) << 8;
        }

        while (sum >> 16)
        {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        const uint16_t csum = static_cast<uint16_t>(~sum);
        return (csum == 0) ? 0xffff : csum;
    }

} // namespace mynet
