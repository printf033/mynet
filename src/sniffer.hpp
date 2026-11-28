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
#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace mynet
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

    enum class SniffTransport : uint8_t
    {
        ANY = 0,
        TCP = 1,
        UDP = 2
    };

    /**
     * @brief 嗅探负缓存（连续 N 次嗅探失败后在退避窗口内直接跳过，避免未知 UDP/私有协议重复解析）
     */
    class SniffNegativeCache
    {
    private:
        struct Key
        {
            uint32_t ipBe{0};
            uint16_t port{0};
            uint8_t transport{0};

            bool operator==(const Key &o) const noexcept
            {
                return ipBe == o.ipBe && port == o.port && transport == o.transport;
            }
        };

        struct KeyHash
        {
            size_t operator()(const Key &k) const noexcept
            {
                size_t h = k.ipBe;
                h ^= (static_cast<size_t>(k.port) << 16) | k.transport;
                return h;
            }
        };

        struct Entry
        {
            uint8_t failCount{0};
            std::chrono::steady_clock::time_point backoffUntil{};
        };

        mutable std::mutex mutex_{};
        std::unordered_map<Key, Entry, KeyHash> entries_{};
        uint8_t threshold_{3};
        std::chrono::seconds backoff_{300};

    public:
        static SniffNegativeCache &instance() noexcept
        {
            static SniffNegativeCache s_inst;
            return s_inst;
        }

        [[nodiscard]] bool isNegative(uint32_t ipBe, uint16_t port, uint8_t transport) const noexcept
        {
            if (ipBe == 0 && port == 0)
            {
                return false;
            }
            const auto now = std::chrono::steady_clock::now();
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = entries_.find(Key{ipBe, port, transport});
            return it != entries_.end() && it->second.failCount >= threshold_ && it->second.backoffUntil > now;
        }

        void recordFailure(uint32_t ipBe, uint16_t port, uint8_t transport) noexcept
        {
            if (ipBe == 0 && port == 0)
            {
                return;
            }
            const auto now = std::chrono::steady_clock::now();
            std::lock_guard<std::mutex> lock(mutex_);
            if (entries_.size() >= 4096)
            {
                for (auto it = entries_.begin(); it != entries_.end();)
                {
                    if (it->second.failCount >= threshold_ && it->second.backoffUntil <= now)
                    {
                        it = entries_.erase(it);
                    }
                    else
                    {
                        ++it;
                    }
                }
                if (entries_.size() >= 4096)
                {
                    entries_.clear();
                }
            }
            auto &e = entries_[Key{ipBe, port, transport}];
            if (e.failCount < threshold_)
            {
                ++e.failCount;
            }
            if (e.failCount >= threshold_)
            {
                e.backoffUntil = now + backoff_;
            }
        }

        void recordSuccess(uint32_t ipBe, uint16_t port, uint8_t transport) noexcept
        {
            if (ipBe == 0 && port == 0)
            {
                return;
            }
            std::lock_guard<std::mutex> lock(mutex_);
            entries_.erase(Key{ipBe, port, transport});
        }

        void clear() noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            entries_.clear();
        }
    };

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

        // 快路径：大多数 TLS SNI / DNS 域名已全小写，无需逐字符转小写
        bool needsLower = false;
        for (unsigned char c : raw)
        {
            if (c >= 'A' && c <= 'Z')
            {
                needsLower = true;
                break;
            }
        }
        if (!needsLower)
        {
            return std::string(raw);
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
            return handler::sniffing::sniffTlsSni(data);
        }

        [[nodiscard]] static std::optional<std::pair<std::string_view, uint16_t>>
        sniffHttpHost(std::span<const uint8_t> data) noexcept
        {
            return handler::sniffing::sniffHttpHost(data);
        }

        [[nodiscard]] static std::optional<std::string> sniffQuicSni(std::span<const uint8_t> data) noexcept
        {
            return handler::sniffing::sniffQuicSni(data);
        }

        [[nodiscard]] static std::optional<std::string> sniffDnsQuestion(std::span<const uint8_t> data) noexcept
        {
            return handler::sniffing::sniffDnsQuestion(data);
        }

        [[nodiscard]] static bool sniffBitTorrent(std::span<const uint8_t> data) noexcept
        {
            return handler::sniffing::sniffBitTorrent(data);
        }

        [[nodiscard]] static std::optional<std::string_view> sniffSsh(std::span<const uint8_t> data) noexcept
        {
            return handler::sniffing::sniffSsh(data);
        }

        [[nodiscard]] static bool sniffDtls(std::span<const uint8_t> data) noexcept
        {
            return handler::sniffing::sniffDtls(data);
        }

        [[nodiscard]] static bool sniffStun(std::span<const uint8_t> data) noexcept
        {
            return handler::sniffing::sniffStun(data);
        }

        [[nodiscard]] static bool sniffNtp(std::span<const uint8_t> data) noexcept { return handler::sniffing::sniffNtp(data); }

        [[nodiscard]] static bool sniffRdp(std::span<const uint8_t> data) noexcept { return handler::sniffing::sniffRdp(data); }

        [[nodiscard]] static constexpr bool couldBeTcpSniffable(uint8_t b0) noexcept
        {
            return b0 == 0x16 || b0 == 'G' || b0 == 'P' || b0 == 'H' || b0 == 'D' || b0 == 'C' || b0 == 'O' ||
                   b0 == 'T' || b0 == 19 || b0 == 'S' || b0 == 0x03;
        }

        [[nodiscard]] static constexpr bool couldBeUdpSniffable(uint8_t b0) noexcept
        {
            return (b0 & 0x80) != 0 || (b0 >= 0x14 && b0 <= 0x19) || (b0 & 0xC0) == 0;
        }

        [[nodiscard]] static constexpr bool couldBeSniffable(uint8_t b0,
                                                             SniffTransport transport = SniffTransport::ANY) noexcept
        {
            if (transport == SniffTransport::TCP)
            {
                return couldBeTcpSniffable(b0);
            }
            if (transport == SniffTransport::UDP)
            {
                return couldBeUdpSniffable(b0);
            }
            return couldBeTcpSniffable(b0) || couldBeUdpSniffable(b0);
        }

        /**
         * @brief 按传输层与首字节快速分派的统一综合嗅探入口
         *
         * @param data 报文切片（通常为首包或前 4096 字节）
         * @param transport 传输层提示（TCP / UDP / ANY），避免跨层无效探测
         * @param dstPort 可选目的端口提示
         * @return std::optional<SniffResult> 成功返回识别出的协议与目标主机名
         */
        [[nodiscard]] static std::optional<SniffResult> sniff(std::span<const uint8_t> data,
                                                              SniffTransport transport = SniffTransport::ANY,
                                                              [[maybe_unused]] uint16_t dstPort = 0) noexcept
        {
            using namespace mynet::handler::sniffing;
            if (data.empty())
            {
                return std::nullopt;
            }

            const uint8_t b0 = data[0];

            // ---- TCP 专属探测链 (或 ANY 兜底) ----
            if (transport != SniffTransport::UDP)
            {
                // 1. TLS SNI: 首字节恒为 0x16 (TLS Handshake)
                if (b0 == 0x16)
                {
                    if (auto sni = sniffTlsSni(data); sni.has_value())
                    {
                        return SniffResult{.protocol = ProtocolType::TLS, .host = normalizeDomain(*sni), .port = 0};
                    }
                }

                // 2. HTTP Host: 首字节只可能是常见 HTTP 方法首字母
                if (b0 == 'G' || b0 == 'P' || b0 == 'H' || b0 == 'D' || b0 == 'C' || b0 == 'O' || b0 == 'T')
                {
                    if (auto http = sniffHttpHost(data); http.has_value())
                    {
                        return SniffResult{
                            .protocol = ProtocolType::HTTP, .host = normalizeDomain(http->first), .port = http->second};
                    }
                }

                // 3. BitTorrent: 首字节为协议名长度 19 (0x13)
                if (b0 == 19 && sniffBitTorrent(data))
                {
                    return SniffResult{.protocol = ProtocolType::BITTORRENT, .host = {}, .port = 0};
                }

                // 4. SSH: 首字节为 'S' ("SSH-")
                if (b0 == 'S')
                {
                    if (auto ssh = sniffSsh(data); ssh.has_value())
                    {
                        return SniffResult{.protocol = ProtocolType::SSH, .host = {}, .port = 0};
                    }
                }

                // 5. RDP: 首字节为 TPKT 0x03
                if (b0 == 0x03 && sniffRdp(data))
                {
                    return SniffResult{.protocol = ProtocolType::RDP, .host = {}, .port = 3389};
                }
            }

            // ---- UDP 专属探测链 (或 ANY 兜底) ----
            if (transport != SniffTransport::TCP)
            {
                // 6. QUIC Initial SNI: Long Header 最高位为 1
                if ((b0 & 0x80) != 0)
                {
                    if (auto quicSni = sniffQuicSni(data); quicSni.has_value())
                    {
                        return SniffResult{.protocol = ProtocolType::QUIC, .host = normalizeDomain(*quicSni), .port = 0};
                    }
                }

                // 7. DNS Query: 至少 12 字节头部
                if (data.size() >= 12)
                {
                    if (auto dnsQname = sniffDnsQuestion(data); dnsQname.has_value())
                    {
                        return SniffResult{.protocol = ProtocolType::DNS, .host = normalizeDomain(*dnsQname), .port = 53};
                    }
                }

                // 8. DTLS: ContentType 为 20..25 (0x14..0x19)
                if (b0 >= 0x14 && b0 <= 0x19 && sniffDtls(data))
                {
                    return SniffResult{.protocol = ProtocolType::DTLS, .host = {}, .port = 0};
                }

                // 9. STUN: 前两位恒为 00
                if ((b0 & 0xC0) == 0 && data.size() >= 20 && sniffStun(data))
                {
                    return SniffResult{.protocol = ProtocolType::STUN, .host = {}, .port = 0};
                }

                // 10. NTP: 固定 >= 48 字节
                if (data.size() >= 48 && sniffNtp(data))
                {
                    return SniffResult{.protocol = ProtocolType::NTP, .host = {}, .port = 123};
                }
            }

            return std::nullopt;
        }
    };


} // namespace mynet
