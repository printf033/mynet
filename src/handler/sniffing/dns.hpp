#pragma once

#include "common.hpp"
#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace mynet::handler::sniffing
{

    /**
     * @brief 嗅探标准 DNS 查询报文并提取 QNAME
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

        // 解析 QNAME
        size_t offset = 12;
        std::string qname;
        while (offset < data.size())
        {
            const uint8_t labelLen = data[offset++];
            if (labelLen == 0)
            {
                break; // 结束标记
            }
            if ((labelLen & 0xC0) != 0)
            {
                return std::nullopt; // 查询段通常不出现指针压缩
            }
            if (offset + labelLen > data.size() || qname.size() + labelLen + 1 > 255)
            {
                return std::nullopt;
            }
            if (!qname.empty())
            {
                qname.push_back('.');
            }
            qname.append(reinterpret_cast<const char *>(data.data() + offset), labelLen);
            offset += labelLen;
        }

        if (qname.empty())
        {
            return std::nullopt;
        }
        return qname;
    }

} // namespace mynet::handler::sniffing
