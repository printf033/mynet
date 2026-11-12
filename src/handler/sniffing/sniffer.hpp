#pragma once

#include "common.hpp"
#include "tls.hpp"
#include "http.hpp"
#include "quic.hpp"
#include "dns.hpp"
#include "bittorrent.hpp"
#include "ssh.hpp"
#include "dtls.hpp"
#include "stun.hpp"
#include "ntp.hpp"
#include "rdp.hpp"
#include <optional>
#include <span>

namespace mynet::handler::sniffing
{

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

} // namespace mynet::handler::sniffing
