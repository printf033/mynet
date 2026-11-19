#pragma once

#include "dns.hpp"
#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace mynet::handler::sniffing
{

    /**
     * @brief 嗅探标准 DNS 查询报文并提取 QNAME
     * (复用 mynet::dns::decodeDomainLabels 标签解析器与压缩指针支持)
     */
    [[nodiscard]] inline std::optional<std::string> sniffDnsQuestion(std::span<const uint8_t> data) noexcept
    {
        if (data.size() < 12)
        {
            return std::nullopt;
        }

        // Flags: 检查是否为标准查询 (QR bit == 0)
        const uint16_t flags = (static_cast<uint16_t>(data[2]) << 8) | data[3];
        if ((flags & 0x8000) != 0) // QR = 1 为响应包
        {
            return std::nullopt;
        }

        // QDCOUNT (查询段数量必须 >= 1)
        const uint16_t qdcount = (static_cast<uint16_t>(data[4]) << 8) | data[5];
        if (qdcount == 0)
        {
            return std::nullopt;
        }

        size_t offset = 12;
        std::string qname;
        if (!dns::decodeDomainLabels(data, offset, qname) || qname.empty())
        {
            return std::nullopt;
        }
        return qname;
    }

} // namespace mynet::handler::sniffing
