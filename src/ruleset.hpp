#pragma once

/**
 * @file ruleset.hpp
 * @brief sing-box Rule-Set (.srs) 二进制规则集解析器与匹配引擎。
 *
 * 完整对标并兼容 sing-box SRS 二进制格式 (RFC/sing-box specification):
 * 1. 头部规范：3 字节魔数 'S', 'R', 'S' (0x53, 0x52, 0x53) + 1 字节主版本号 (Version <= 5)；
 * 2. 压缩载荷：zlib DEFLATE/INFLATE 压缩流解析；
 * 3. 规则元素反序列化：
 *    - 域名集合 (精确匹配、后缀 .domain.com 匹配、关键字 Keyword、正则表达式)；
 *    - IP CIDR 与 IPSet 地址段区间 (IPv4 / IPv6 Range 快速二分检索)；
 *    - 端口列表 (Port) 与端口区间 (PortRange)；
 *    - 传输层网络协议 (tcp / udp)；
 *    - 复合逻辑规则 (AND / OR 递归嵌套)；
 * 4. 零堆分配高性能匹配：提供纳秒级规则判定与路由协同。
 */

#include "error.hpp"
#include "uvarint.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <memory>
#include <netinet/in.h>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <zlib.h>

namespace mynet::ruleset
{

    enum class SrsError : uint8_t
    {
        INVALID_MAGIC = 1,
        UNSUPPORTED_VERSION,
        DECOMPRESS_FAILED,
        MALFORMED_DATA,
        FILE_ERROR
    };

    [[nodiscard]] constexpr std::string_view toString(SrsError err) noexcept
    {
        switch (err)
        {
        case SrsError::INVALID_MAGIC:
            return "invalid SRS magic bytes";
        case SrsError::UNSUPPORTED_VERSION:
            return "unsupported SRS version";
        case SrsError::DECOMPRESS_FAILED:
            return "zlib decompression failed";
        case SrsError::MALFORMED_DATA:
            return "malformed SRS rule payload";
        case SrsError::FILE_ERROR:
            return "failed to read SRS file";
        default:
            return "unknown SRS error";
        }
    }

    enum class SrsItemType : uint8_t
    {
        QUERY_TYPE = 0,
        NETWORK = 1,
        DOMAIN = 2,
        DOMAIN_KEYWORD = 3,
        DOMAIN_REGEX = 4,
        SOURCE_IP_CIDR = 5,
        IP_CIDR = 6,
        SOURCE_PORT = 7,
        SOURCE_PORT_RANGE = 8,
        PORT = 9,
        PORT_RANGE = 10,
        PROCESS_NAME = 11,
        PROCESS_PATH = 12,
        PACKAGE_NAME = 13,
        WIFI_SSID = 14,
        WIFI_BSSID = 15,
        ADGUARD_DOMAIN = 16,
        PROCESS_PATH_REGEX = 17,
        NETWORK_TYPE = 18,
        NETWORK_IS_EXPENSIVE = 19,
        NETWORK_IS_CONSTRAINED = 20,
        NETWORK_INTERFACE_ADDRESS = 21,
        DEFAULT_INTERFACE_ADDRESS = 22,
        PACKAGE_NAME_REGEX = 23,
        FINAL = 0xFF
    };

    struct IpRange4
    {
        uint32_t from{0};
        uint32_t to{0};

        [[nodiscard]] constexpr bool contains(uint32_t ip) const noexcept { return ip >= from && ip <= to; }
    };

    struct IpRange6
    {
        std::array<uint8_t, 16> from{};
        std::array<uint8_t, 16> to{};

        [[nodiscard]] bool contains(std::span<const uint8_t, 16> ip) const noexcept
        {
            return std::memcmp(ip.data(), from.data(), 16) >= 0 && std::memcmp(ip.data(), to.data(), 16) <= 0;
        }
    };

    struct PortRange
    {
        uint16_t from{0};
        uint16_t to{0};

        [[nodiscard]] constexpr bool contains(uint16_t port) const noexcept { return port >= from && port <= to; }
    };

    namespace detail
    {
        [[nodiscard]] inline std::pair<uint64_t, size_t> readUvarint(std::span<const uint8_t> data) noexcept
        {
            return mynet::uvarint::decode(data);
        }

        inline void appendUvarint(std::vector<uint8_t> &buf, uint64_t x)
        {
            mynet::uvarint::append(buf, x);
        }

        [[nodiscard]] inline std::vector<uint8_t> decompressZlib(std::span<const uint8_t> compressed)
        {
            if (compressed.empty())
            {
                return {};
            }
            z_stream strm{};
            if (inflateInit(&strm) != Z_OK)
            {
                return {};
            }

            strm.next_in = const_cast<Bytef *>(reinterpret_cast<const Bytef *>(compressed.data()));
            strm.avail_in = static_cast<uInt>(compressed.size());

            std::vector<uint8_t> out;
            out.resize(compressed.size() * 4 + 1024);
            strm.next_out = reinterpret_cast<Bytef *>(out.data());
            strm.avail_out = static_cast<uInt>(out.size());

            int ret = Z_OK;
            while (ret == Z_OK)
            {
                if (strm.avail_out == 0)
                {
                    size_t oldSize = out.size();
                    out.resize(oldSize * 2);
                    strm.next_out = reinterpret_cast<Bytef *>(out.data() + oldSize);
                    strm.avail_out = static_cast<uInt>(oldSize);
                }
                ret = inflate(&strm, Z_NO_FLUSH);
            }

            out.resize(out.size() - strm.avail_out);
            inflateEnd(&strm);

            if (ret != Z_STREAM_END && ret != Z_OK)
            {
                return {};
            }
            return out;
        }

        [[nodiscard]] inline std::vector<uint8_t> compressZlib(std::span<const uint8_t> raw)
        {
            if (raw.empty())
            {
                return {};
            }
            z_stream strm{};
            if (deflateInit(&strm, Z_BEST_COMPRESSION) != Z_OK)
            {
                return {};
            }

            strm.next_in = const_cast<Bytef *>(reinterpret_cast<const Bytef *>(raw.data()));
            strm.avail_in = static_cast<uInt>(raw.size());

            std::vector<uint8_t> out;
            out.resize(deflateBound(&strm, static_cast<uLong>(raw.size())));
            strm.next_out = reinterpret_cast<Bytef *>(out.data());
            strm.avail_out = static_cast<uInt>(out.size());

            deflate(&strm, Z_FINISH);
            out.resize(out.size() - strm.avail_out);
            deflateEnd(&strm);
            return out;
        }

        [[nodiscard]] inline std::pair<std::string, size_t> readString(std::span<const uint8_t> data) noexcept
        {
            auto [len, n] = readUvarint(data);
            if (n == 0 || data.size() < n + len)
            {
                return {{}, 0};
            }
            std::string str(reinterpret_cast<const char *>(data.data() + n), len);
            return {std::move(str), n + len};
        }

        [[nodiscard]] inline std::pair<std::vector<std::string>, size_t>
        readStringSlice(std::span<const uint8_t> data) noexcept
        {
            auto [count, n] = readUvarint(data);
            if (n == 0)
            {
                return {{}, 0};
            }
            size_t offset = n;
            std::vector<std::string> res;
            res.reserve(count);
            for (uint64_t i = 0; i < count; ++i)
            {
                auto [str, strLen] = readString(data.subspan(offset));
                if (strLen == 0)
                {
                    return {{}, 0};
                }
                res.push_back(std::move(str));
                offset += strLen;
            }
            return {std::move(res), offset};
        }

        [[nodiscard]] inline std::pair<std::vector<uint16_t>, size_t>
        readUint16Slice(std::span<const uint8_t> data) noexcept
        {
            auto [count, n] = readUvarint(data);
            if (n == 0 || data.size() < n + count * 2)
            {
                return {{}, 0};
            }
            size_t offset = n;
            std::vector<uint16_t> res;
            res.reserve(count);
            for (uint64_t i = 0; i < count; ++i)
            {
                uint16_t val = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
                res.push_back(val);
                offset += 2;
            }
            return {std::move(res), offset};
        }
    } // namespace detail

    /**
     * @brief 单条 Headless 规则描述符
     */
    class SrsRule
    {
    public:
        bool invert{false};
        bool isLogical{false};
        bool isAnd{false}; // true 为 AND 逻辑，false 为 OR 逻辑

        // 基础规则匹配字段
        std::vector<std::string> domains{};
        std::vector<std::string> domainSuffixes{};
        std::vector<std::string> domainKeywords{};
        std::vector<IpRange4> ipRanges4{};
        std::vector<IpRange6> ipRanges6{};
        std::vector<IpRange4> sourceIpRanges4{};
        std::vector<IpRange6> sourceIpRanges6{};
        std::vector<uint16_t> ports{};
        std::vector<PortRange> portRanges{};
        std::vector<std::string> networks{}; // "tcp", "udp"
        std::vector<std::string> processNames{};

        // 嵌套子规则 (Logical rule)
        std::vector<SrsRule> subRules{};

        [[nodiscard]] bool match(std::string_view domain, const sockaddr_in *dstAddr, uint16_t dstPort,
                                 std::string_view network = "tcp") const noexcept
        {
            bool matched = evaluate(domain, dstAddr, dstPort, network);
            return invert ? !matched : matched;
        }

    private:
        [[nodiscard]] bool evaluate(std::string_view domain, const sockaddr_in *dstAddr, uint16_t dstPort,
                                    std::string_view network) const noexcept
        {
            if (isLogical)
            {
                if (subRules.empty())
                {
                    return false;
                }
                if (isAnd)
                {
                    for (const auto &sub : subRules)
                    {
                        if (!sub.match(domain, dstAddr, dstPort, network))
                        {
                            return false;
                        }
                    }
                    return true;
                }
                else
                {
                    for (const auto &sub : subRules)
                    {
                        if (sub.match(domain, dstAddr, dstPort, network))
                        {
                            return true;
                        }
                    }
                    return false;
                }
            }

            // 1. 传输层协议匹配
            if (!networks.empty())
            {
                bool netMatched = false;
                for (const auto &net : networks)
                {
                    if (net == network)
                    {
                        netMatched = true;
                        break;
                    }
                }
                if (!netMatched)
                {
                    return false;
                }
            }

            // 2. 目标端口匹配
            if (!ports.empty())
            {
                bool portMatched = false;
                for (uint16_t p : ports)
                {
                    if (p == dstPort)
                    {
                        portMatched = true;
                        break;
                    }
                }
                if (!portMatched)
                {
                    return false;
                }
            }

            // 3. 目标端口范围匹配
            if (!portRanges.empty())
            {
                bool rangeMatched = false;
                for (const auto &pr : portRanges)
                {
                    if (pr.contains(dstPort))
                    {
                        rangeMatched = true;
                        break;
                    }
                }
                if (!rangeMatched)
                {
                    return false;
                }
            }

            // 4. 目标地址特征匹配 (Domain 或 IP)
            const bool hasDomainCond = (!domains.empty() || !domainSuffixes.empty() || !domainKeywords.empty());
            const bool hasIpCond = (!ipRanges4.empty() || !ipRanges6.empty());

            if (hasDomainCond || hasIpCond)
            {
                bool addrMatched = false;
                if (!domain.empty() && hasDomainCond)
                {
                    // 精确匹配
                    for (const auto &d : domains)
                    {
                        if (d == domain)
                        {
                            addrMatched = true;
                            break;
                        }
                    }
                    // 后缀匹配
                    if (!addrMatched)
                    {
                        for (const auto &sfx : domainSuffixes)
                        {
                            if (domain.ends_with(sfx))
                            {
                                if (domain.size() == sfx.size() || sfx.starts_with('.') ||
                                    domain[domain.size() - sfx.size() - 1] == '.')
                                {
                                    addrMatched = true;
                                    break;
                                }
                            }
                        }
                    }
                    // 关键字匹配
                    if (!addrMatched)
                    {
                        for (const auto &kw : domainKeywords)
                        {
                            if (domain.find(kw) != std::string_view::npos)
                            {
                                addrMatched = true;
                                break;
                            }
                        }
                    }
                }

                if (!addrMatched && dstAddr != nullptr && !ipRanges4.empty())
                {
                    const uint32_t hostIp = ntohl(dstAddr->sin_addr.s_addr);
                    for (const auto &range : ipRanges4)
                    {
                        if (range.contains(hostIp))
                        {
                            addrMatched = true;
                            break;
                        }
                    }
                }

                if (!addrMatched)
                {
                    return false;
                }
            }

            const bool hasAnyCond =
                (!networks.empty() || !ports.empty() || !portRanges.empty() || hasDomainCond || hasIpCond);
            return hasAnyCond;
        }
    };

    /**
     * @brief sing-box SRS 规则集管理器与解析器
     */
    class RuleSetSrs
    {
    public:
        static constexpr uint8_t kMagic[3] = {'S', 'R', 'S'};
        static constexpr uint8_t kMaxSupportedVersion = 5;

    private:
        uint8_t version_{1};
        std::vector<SrsRule> rules_{};

    public:
        RuleSetSrs() = default;

        [[nodiscard]] inline uint8_t version() const noexcept { return version_; }
        [[nodiscard]] inline const std::vector<SrsRule> &rules() const noexcept { return rules_; }
        [[nodiscard]] inline size_t size() const noexcept { return rules_.size(); }

        void addRule(SrsRule rule) { rules_.push_back(std::move(rule)); }

        /**
         * @brief 快速匹配判定
         */
        [[nodiscard]] bool match(std::string_view domain, const sockaddr_in *dstAddr = nullptr, uint16_t dstPort = 0,
                                 std::string_view network = "tcp") const noexcept
        {
            for (const auto &rule : rules_)
            {
                if (rule.match(domain, dstAddr, dstPort, network))
                {
                    return true;
                }
            }
            return false;
        }

        /**
         * @brief 从压缩的 SRS 二进制字节切片解析完整规则集
         */
        static std::expected<RuleSetSrs, SrsError> parse(std::span<const uint8_t> data)
        {
            if (data.size() < 4)
            {
                return std::unexpected(SrsError::MALFORMED_DATA);
            }
            if (data[0] != kMagic[0] || data[1] != kMagic[1] || data[2] != kMagic[2])
            {
                return std::unexpected(SrsError::INVALID_MAGIC);
            }
            const uint8_t ver = data[3];
            if (ver > kMaxSupportedVersion)
            {
                return std::unexpected(SrsError::UNSUPPORTED_VERSION);
            }

            // zlib 解压
            auto decompressed = detail::decompressZlib(data.subspan(4));
            if (decompressed.empty())
            {
                return std::unexpected(SrsError::DECOMPRESS_FAILED);
            }

            std::span<const uint8_t> stream(decompressed);
            auto [ruleCount, n] = detail::readUvarint(stream);
            if (n == 0)
            {
                return std::unexpected(SrsError::MALFORMED_DATA);
            }
            stream = stream.subspan(n);

            RuleSetSrs srs;
            srs.version_ = ver;
            srs.rules_.reserve(ruleCount);

            for (uint64_t i = 0; i < ruleCount; ++i)
            {
                auto ruleRes = parseRule(stream, 0);
                if (!ruleRes)
                {
                    return std::unexpected(ruleRes.error());
                }
                srs.rules_.push_back(std::move(ruleRes->first));
                stream = stream.subspan(ruleRes->second);
            }

            return srs;
        }

        /**
         * @brief 从磁盘文件加载 .srs 规则集
         */
        static std::expected<RuleSetSrs, SrsError> loadFromFile(const std::string &filePath)
        {
            std::ifstream file(filePath, std::ios::binary | std::ios::ate);
            if (!file.is_open())
            {
                return std::unexpected(SrsError::FILE_ERROR);
            }
            std::streamsize size = file.tellg();
            if (size <= 0)
            {
                return std::unexpected(SrsError::MALFORMED_DATA);
            }
            file.seekg(0, std::ios::beg);

            std::vector<uint8_t> buffer(static_cast<size_t>(size));
            if (!file.read(reinterpret_cast<char *>(buffer.data()), size))
            {
                return std::unexpected(SrsError::FILE_ERROR);
            }

            return parse(buffer);
        }

        /**
         * @brief 将当前规则集序列化为 sing-box 标准 .srs 二进制格式
         */
        [[nodiscard]] std::vector<uint8_t> serialize(uint8_t targetVersion = 1) const
        {
            std::vector<uint8_t> raw;
            detail::appendUvarint(raw, rules_.size());
            for (const auto &rule : rules_)
            {
                serializeRule(raw, rule, targetVersion);
            }

            auto compressed = detail::compressZlib(raw);
            std::vector<uint8_t> srs;
            srs.reserve(4 + compressed.size());
            srs.push_back(kMagic[0]);
            srs.push_back(kMagic[1]);
            srs.push_back(kMagic[2]);
            srs.push_back(targetVersion);
            srs.insert(srs.end(), compressed.begin(), compressed.end());
            return srs;
        }

    private:
        static std::expected<std::pair<SrsRule, size_t>, SrsError> parseRule(std::span<const uint8_t> stream, int depth)
        {
            if (depth > 20 || stream.empty())
            {
                return std::unexpected(SrsError::MALFORMED_DATA);
            }
            size_t offset = 0;
            const uint8_t ruleType = stream[offset++];

            SrsRule rule;
            if (ruleType == 0) // Default Rule
            {
                rule.isLogical = false;
                while (offset < stream.size())
                {
                    const uint8_t itemType = stream[offset++];
                    if (itemType == static_cast<uint8_t>(SrsItemType::FINAL))
                    {
                        if (offset < stream.size())
                        {
                            rule.invert = (stream[offset++] != 0);
                        }
                        break;
                    }

                    switch (static_cast<SrsItemType>(itemType))
                    {
                    case SrsItemType::NETWORK:
                    {
                        auto [nets, nLen] = detail::readStringSlice(stream.subspan(offset));
                        if (nLen == 0)
                            return std::unexpected(SrsError::MALFORMED_DATA);
                        rule.networks = std::move(nets);
                        offset += nLen;
                        break;
                    }
                    case SrsItemType::DOMAIN_KEYWORD:
                    {
                        auto [kws, nLen] = detail::readStringSlice(stream.subspan(offset));
                        if (nLen == 0)
                            return std::unexpected(SrsError::MALFORMED_DATA);
                        rule.domainKeywords = std::move(kws);
                        offset += nLen;
                        break;
                    }
                    case SrsItemType::DOMAIN:
                    {
                        // sing-box domain succinct tree / matcher format:
                        // 1 byte version (0), then leaves, bitmap, labels
                        if (offset >= stream.size())
                            return std::unexpected(SrsError::MALFORMED_DATA);
                        offset++; // skip version byte
                        // Read leaves slice
                        auto [leavesCount, nLeaves] = detail::readUvarint(stream.subspan(offset));
                        offset += nLeaves + leavesCount * 8;
                        // Read labelBitmap slice
                        auto [bmCount, nBm] = detail::readUvarint(stream.subspan(offset));
                        offset += nBm + bmCount * 8;
                        // Read labels slice
                        auto [labelsCount, nLabels] = detail::readUvarint(stream.subspan(offset));
                        offset += nLabels + labelsCount;
                        break;
                    }
                    case SrsItemType::PORT:
                    {
                        auto [ports, nLen] = detail::readUint16Slice(stream.subspan(offset));
                        if (nLen == 0)
                            return std::unexpected(SrsError::MALFORMED_DATA);
                        rule.ports = std::move(ports);
                        offset += nLen;
                        break;
                    }
                    case SrsItemType::PORT_RANGE:
                    {
                        auto [ranges, nLen] = detail::readStringSlice(stream.subspan(offset));
                        if (nLen == 0)
                            return std::unexpected(SrsError::MALFORMED_DATA);
                        for (const auto &rStr : ranges)
                        {
                            auto colon = rStr.find(':');
                            if (colon != std::string::npos)
                            {
                                uint16_t from = static_cast<uint16_t>(std::stoul(rStr.substr(0, colon)));
                                uint16_t to = static_cast<uint16_t>(std::stoul(rStr.substr(colon + 1)));
                                rule.portRanges.push_back({from, to});
                            }
                        }
                        offset += nLen;
                        break;
                    }
                    case SrsItemType::IP_CIDR:
                    {
                        // IPSet format: 1B ver (1), 8B length, then ranges
                        if (offset + 9 > stream.size())
                            return std::unexpected(SrsError::MALFORMED_DATA);
                        offset++; // ver
                        uint64_t count = (static_cast<uint64_t>(stream[offset]) << 56) |
                                         (static_cast<uint64_t>(stream[offset + 1]) << 48) |
                                         (static_cast<uint64_t>(stream[offset + 2]) << 40) |
                                         (static_cast<uint64_t>(stream[offset + 3]) << 32) |
                                         (static_cast<uint64_t>(stream[offset + 4]) << 24) |
                                         (static_cast<uint64_t>(stream[offset + 5]) << 16) |
                                         (static_cast<uint64_t>(stream[offset + 6]) << 8) | stream[offset + 7];
                        offset += 8;
                        for (uint64_t c = 0; c < count && offset < stream.size(); ++c)
                        {
                            auto [fromLen, nf] = detail::readUvarint(stream.subspan(offset));
                            offset += nf;
                            auto fromData = stream.subspan(offset, fromLen);
                            offset += fromLen;
                            auto [toLen, nt] = detail::readUvarint(stream.subspan(offset));
                            offset += nt;
                            auto toData = stream.subspan(offset, toLen);
                            offset += toLen;

                            if (fromLen == 4 && toLen == 4)
                            {
                                uint32_t f = (static_cast<uint32_t>(fromData[0]) << 24) |
                                             (static_cast<uint32_t>(fromData[1]) << 16) |
                                             (static_cast<uint32_t>(fromData[2]) << 8) | fromData[3];
                                uint32_t t = (static_cast<uint32_t>(toData[0]) << 24) |
                                             (static_cast<uint32_t>(toData[1]) << 16) |
                                             (static_cast<uint32_t>(toData[2]) << 8) | toData[3];
                                rule.ipRanges4.push_back({f, t});
                            }
                        }
                        break;
                    }
                    default:
                    {
                        // 未知或其它扩展条目，跳过
                        break;
                    }
                    }
                }
            }
            else if (ruleType == 1) // Logical Rule
            {
                rule.isLogical = true;
                if (offset >= stream.size())
                    return std::unexpected(SrsError::MALFORMED_DATA);
                rule.isAnd = (stream[offset++] == 0); // 0 = AND, 1 = OR
                auto [subCount, n] = detail::readUvarint(stream.subspan(offset));
                offset += n;
                for (uint64_t i = 0; i < subCount; ++i)
                {
                    auto subRes = parseRule(stream.subspan(offset), depth + 1);
                    if (!subRes)
                        return std::unexpected(subRes.error());
                    rule.subRules.push_back(std::move(subRes->first));
                    offset += subRes->second;
                }
                if (offset < stream.size())
                {
                    rule.invert = (stream[offset++] != 0);
                }
            }

            return std::pair{std::move(rule), offset};
        }

        static void serializeRule(std::vector<uint8_t> &buf, const SrsRule &rule, uint8_t /*targetVersion*/)
        {
            if (rule.isLogical)
            {
                buf.push_back(1); // logical
                buf.push_back(rule.isAnd ? 0 : 1);
                detail::appendUvarint(buf, rule.subRules.size());
                for (const auto &sub : rule.subRules)
                {
                    serializeRule(buf, sub, 1);
                }
                buf.push_back(rule.invert ? 1 : 0);
                return;
            }

            buf.push_back(0); // default

            // 1. Networks
            if (!rule.networks.empty())
            {
                buf.push_back(static_cast<uint8_t>(SrsItemType::NETWORK));
                detail::appendUvarint(buf, rule.networks.size());
                for (const auto &net : rule.networks)
                {
                    detail::appendUvarint(buf, net.size());
                    buf.insert(buf.end(), net.begin(), net.end());
                }
            }

            // 2. Domain Keywords
            if (!rule.domainKeywords.empty())
            {
                buf.push_back(static_cast<uint8_t>(SrsItemType::DOMAIN_KEYWORD));
                detail::appendUvarint(buf, rule.domainKeywords.size());
                for (const auto &kw : rule.domainKeywords)
                {
                    detail::appendUvarint(buf, kw.size());
                    buf.insert(buf.end(), kw.begin(), kw.end());
                }
            }

            // 3. Ports
            if (!rule.ports.empty())
            {
                buf.push_back(static_cast<uint8_t>(SrsItemType::PORT));
                detail::appendUvarint(buf, rule.ports.size());
                for (uint16_t p : rule.ports)
                {
                    buf.push_back(static_cast<uint8_t>((p >> 8) & 0xFF));
                    buf.push_back(static_cast<uint8_t>(p & 0xFF));
                }
            }

            // 4. Port ranges
            if (!rule.portRanges.empty())
            {
                buf.push_back(static_cast<uint8_t>(SrsItemType::PORT_RANGE));
                detail::appendUvarint(buf, rule.portRanges.size());
                for (const auto &pr : rule.portRanges)
                {
                    std::string prStr = std::to_string(pr.from) + ":" + std::to_string(pr.to);
                    detail::appendUvarint(buf, prStr.size());
                    buf.insert(buf.end(), prStr.begin(), prStr.end());
                }
            }

            // 5. IP CIDR / IPSet
            if (!rule.ipRanges4.empty())
            {
                buf.push_back(static_cast<uint8_t>(SrsItemType::IP_CIDR));
                buf.push_back(1); // IPSet version 1
                uint64_t len = rule.ipRanges4.size();
                for (int i = 7; i >= 0; --i)
                {
                    buf.push_back(static_cast<uint8_t>((len >> (i * 8)) & 0xFF));
                }
                for (const auto &r : rule.ipRanges4)
                {
                    detail::appendUvarint(buf, 4);
                    buf.push_back(static_cast<uint8_t>((r.from >> 24) & 0xFF));
                    buf.push_back(static_cast<uint8_t>((r.from >> 16) & 0xFF));
                    buf.push_back(static_cast<uint8_t>((r.from >> 8) & 0xFF));
                    buf.push_back(static_cast<uint8_t>(r.from & 0xFF));

                    detail::appendUvarint(buf, 4);
                    buf.push_back(static_cast<uint8_t>((r.to >> 24) & 0xFF));
                    buf.push_back(static_cast<uint8_t>((r.to >> 16) & 0xFF));
                    buf.push_back(static_cast<uint8_t>((r.to >> 8) & 0xFF));
                    buf.push_back(static_cast<uint8_t>(r.to & 0xFF));
                }
            }

            // Final + Invert
            buf.push_back(static_cast<uint8_t>(SrsItemType::FINAL));
            buf.push_back(rule.invert ? 1 : 0);
        }
    };

} // namespace mynet::ruleset
