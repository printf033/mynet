#pragma once

#include "bittorrent/sniff.hpp"
#include "dns/sniff.hpp"
#include "dtls/sniff.hpp"
#include "http/sniff.hpp"
#include "ntp/sniff.hpp"
#include "quic/sniff.hpp"
#include "rdp/sniff.hpp"
#include "ssh/sniff.hpp"
#include "stun/sniff.hpp"
#include "tls/sniff.hpp"

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

    /**
     * @brief 域名与协议嗅探器主体
     */
    class DomainSniffer
    {
    public:
        [[nodiscard]] static std::optional<std::string_view> sniffTlsSni(std::span<const uint8_t> data) noexcept
        {
            return sniffing::sniffTlsSni(data);
        }

        [[nodiscard]] static std::optional<std::pair<std::string_view, uint16_t>> sniffHttpHost(std::span<const uint8_t> data) noexcept
        {
            return sniffing::sniffHttpHost(data);
        }

        [[nodiscard]] static std::optional<std::string> sniffQuicSni(std::span<const uint8_t> data) noexcept
        {
            return sniffing::sniffQuicSni(data);
        }

        [[nodiscard]] static std::optional<std::string> sniffDnsQuestion(std::span<const uint8_t> data) noexcept
        {
            return sniffing::sniffDnsQuestion(data);
        }

        [[nodiscard]] static bool sniffBitTorrent(std::span<const uint8_t> data) noexcept
        {
            return sniffing::sniffBitTorrent(data);
        }

        [[nodiscard]] static std::optional<std::string_view> sniffSsh(std::span<const uint8_t> data) noexcept
        {
            return sniffing::sniffSsh(data);
        }

        [[nodiscard]] static bool sniffDtls(std::span<const uint8_t> data) noexcept
        {
            return sniffing::sniffDtls(data);
        }

        [[nodiscard]] static bool sniffStun(std::span<const uint8_t> data) noexcept
        {
            return sniffing::sniffStun(data);
        }

        [[nodiscard]] static bool sniffNtp(std::span<const uint8_t> data) noexcept
        {
            return sniffing::sniffNtp(data);
        }

        [[nodiscard]] static bool sniffRdp(std::span<const uint8_t> data) noexcept
        {
            return sniffing::sniffRdp(data);
        }

        /**
         * @brief 统一综合嗅探入口：依次探测 TLS -> HTTP -> QUIC -> DNS -> BitTorrent -> SSH -> DTLS -> STUN -> NTP -> RDP
         *
         * @param data 报文切片（通常为首包或前 4096 字节）
         * @return std::optional<SniffResult> 成功返回识别出的协议与目标主机名
         */
        [[nodiscard]] static std::optional<SniffResult> sniff(std::span<const uint8_t> data) noexcept
        {
            if (data.empty())
            {
                return std::nullopt;
            }

            // 1. TLS SNI
            if (auto sni = sniffTlsSni(data); sni.has_value())
            {
                return SniffResult{
                    .protocol = ProtocolType::TLS,
                    .host = normalizeDomain(*sni),
                    .port = 0};
            }

            // 2. HTTP Host
            if (auto http = sniffHttpHost(data); http.has_value())
            {
                return SniffResult{
                    .protocol = ProtocolType::HTTP,
                    .host = normalizeDomain(http->first),
                    .port = http->second};
            }

            // 3. QUIC Initial SNI
            if (auto quicSni = sniffQuicSni(data); quicSni.has_value())
            {
                return SniffResult{
                    .protocol = ProtocolType::QUIC,
                    .host = normalizeDomain(*quicSni),
                    .port = 0};
            }

            // 4. DNS Query
            if (auto dnsQname = sniffDnsQuestion(data); dnsQname.has_value())
            {
                return SniffResult{
                    .protocol = ProtocolType::DNS,
                    .host = normalizeDomain(*dnsQname),
                    .port = 53};
            }

            // 5. BitTorrent
            if (sniffBitTorrent(data))
            {
                return SniffResult{
                    .protocol = ProtocolType::BITTORRENT,
                    .host = {},
                    .port = 0};
            }

            // 6. SSH
            if (auto ssh = sniffSsh(data); ssh.has_value())
            {
                return SniffResult{
                    .protocol = ProtocolType::SSH,
                    .host = {},
                    .port = 0};
            }

            // 7. DTLS
            if (sniffDtls(data))
            {
                return SniffResult{
                    .protocol = ProtocolType::DTLS,
                    .host = {},
                    .port = 0};
            }

            // 8. STUN
            if (sniffStun(data))
            {
                return SniffResult{
                    .protocol = ProtocolType::STUN,
                    .host = {},
                    .port = 0};
            }

            // 9. NTP
            if (sniffNtp(data))
            {
                return SniffResult{
                    .protocol = ProtocolType::NTP,
                    .host = {},
                    .port = 123};
            }

            // 10. RDP
            if (sniffRdp(data))
            {
                return SniffResult{
                    .protocol = ProtocolType::RDP,
                    .host = {},
                    .port = 3389};
            }

            return std::nullopt;
        }
    };

    using Sniffer = DomainSniffer;

} // namespace mynet::handler::sniffing

namespace mynet
{
    namespace sniffing = handler::sniffing;
}
