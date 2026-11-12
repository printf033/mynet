#pragma once

#include <cctype>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace mynet::handler::sniffing
{

    enum class ProtocolType : uint8_t
    {
        UNKNOWN = 0,
        TLS,
        HTTP,
        QUIC,
        DNS,
        BITTORRENT,
        SSH,
        DTLS,
        STUN,
        NTP,
        RDP
    };

    [[nodiscard]] constexpr std::string_view protocolName(ProtocolType proto) noexcept
    {
        switch (proto)
        {
        case ProtocolType::TLS:
            return "tls";
        case ProtocolType::HTTP:
            return "http";
        case ProtocolType::QUIC:
            return "quic";
        case ProtocolType::DNS:
            return "dns";
        case ProtocolType::BITTORRENT:
            return "bittorrent";
        case ProtocolType::SSH:
            return "ssh";
        case ProtocolType::DTLS:
            return "dtls";
        case ProtocolType::STUN:
            return "stun";
        case ProtocolType::NTP:
            return "ntp";
        case ProtocolType::RDP:
            return "rdp";
        default:
            return "unknown";
        }
    }

    struct SniffResult
    {
        ProtocolType protocol{ProtocolType::UNKNOWN};
        std::string host{}; ///< 提取并规整后的主机名或域名
        uint16_t port{0};   ///< 可选端口（若从 HTTP Host 提取到；0 表示使用原目的端口）
    };

    [[nodiscard]] inline std::string normalizeDomain(std::string_view raw)
    {
        while (!raw.empty() && (std::isspace(static_cast<unsigned char>(raw.front())) != 0))
        {
            raw.remove_prefix(1);
        }
        while (!raw.empty() && (std::isspace(static_cast<unsigned char>(raw.back())) != 0))
        {
            raw.remove_suffix(1);
        }

        if (raw.empty())
        {
            return {};
        }

        if (raw.front() == '[' && raw.back() == ']')
        {
            raw.remove_prefix(1);
            raw.remove_suffix(1);
        }

        if (!raw.empty() && raw.back() == '.')
        {
            raw.remove_suffix(1);
        }

        std::string result;
        result.reserve(raw.size());
        for (char c : raw)
        {
            result.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        }
        return result;
    }

} // namespace mynet::handler::sniffing
