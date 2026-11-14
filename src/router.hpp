#pragma once

/**
 * @file router.hpp
 * @brief 高性能规则分流路由器 (Router & Rule Matcher)。
 *
 * 借鉴 sing-box 与 dae 的分流引擎设计，提供基于多维特征的策略路由匹配：
 * 1. 域名多维匹配：完整域名精确匹配 (Domain)、域名后缀 (Domain Suffix)、域名关键字 (Domain Keyword)；
 * 2. IP CIDR 子网判定：支持 IPv4 CIDR 掩码计算、私有地址判定 (RFC 1918) 与源/目的地址范围匹配；
 * 3. 端口与端口段：支持单端口与范围端口 (Port / PortRange)；
 * 4. 深度协议嗅探协同：结合 Sniffer 嗅探出的应用层协议 (TLS, HTTP, QUIC, BitTorrent, DNS 等) 精准分流；
 * 5. 入站标签与网络类型：支持依据流量来源入站标签 (Inbound Tag) 与 L4 协议 (TCP / UDP) 调度；
 * 6. 条件组合与反转 (NOT)：支持多条件交集与命中逻辑反转；
 * 7. 规则命中统计：实时追踪每条分流规则的命中计数，便于可观测性分析。
 */

#include "error.hpp"
#include "handler/address.hpp"
#include "handler/sniffing/common.hpp"
#include "config/log.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace mynet
{

    /**
     * @brief 传输层网络协议类型
     */
    enum class NetworkType : uint8_t
    {
        ANY = 0, ///< 任意网络类型
        TCP = 1, ///< TCP 面向流式连接
        UDP = 2  ///< UDP 面向数据报
    };

    [[nodiscard]] constexpr std::string_view toString(NetworkType net) noexcept
    {
        switch (net)
        {
        case NetworkType::TCP:
            return "tcp";
        case NetworkType::UDP:
            return "udp";
        default:
            return "any";
        }
    }

    /**
     * @brief 端口与端口范围过滤抽象
     */
    struct PortRange
    {
        uint16_t start{0};
        uint16_t end{0};

        PortRange() noexcept = default;
        constexpr explicit PortRange(uint16_t port) noexcept : start(port), end(port) {}
        constexpr PortRange(uint16_t s, uint16_t e) noexcept : start(s), end(e) {}

        [[nodiscard]] constexpr bool matches(uint16_t port) const noexcept
        {
            return port >= start && port <= end;
        }

        /**
         * @brief 解析单端口或端口段文本（如 "80", "443", "8000-8080", "1000..2000"）
         */
        static std::optional<PortRange> parse(std::string_view str) noexcept
        {
            if (str.empty())
            {
                return std::nullopt;
            }

            size_t delim = str.find('-');
            size_t delimLen = 1;
            if (delim == std::string_view::npos)
            {
                delim = str.find("..");
                delimLen = 2;
            }

            if (delim == std::string_view::npos)
            {
                // 单端口
                uint32_t val = 0;
                for (char c : str)
                {
                    if (c < '0' || c > '9')
                        return std::nullopt;
                    val = val * 10 + static_cast<uint32_t>(c - '0');
                    if (val > 65535)
                        return std::nullopt;
                }
                return PortRange(static_cast<uint16_t>(val));
            }

            // 范围
            std::string_view s1 = str.substr(0, delim);
            std::string_view s2 = str.substr(delim + delimLen);
            auto p1 = parse(s1);
            auto p2 = parse(s2);
            if (!p1 || !p2)
            {
                return std::nullopt;
            }
            uint16_t startPort = p1->start;
            uint16_t endPort = p2->start;
            if (startPort > endPort)
            {
                std::swap(startPort, endPort);
            }
            return PortRange(startPort, endPort);
        }
    };

    /**
     * @brief IPv4 CIDR 子网掩码与范围判定
     */
    struct IpCidr
    {
        uint32_t networkBe{0}; ///< 网络字节序的网络地址
        uint32_t maskBe{0};    ///< 网络字节序的子网掩码
        uint8_t prefixLen{32}; ///< 前缀长度 (0 - 32)

        IpCidr() noexcept = default;

        IpCidr(uint32_t netBe, uint8_t prefix) noexcept
            : networkBe(netBe),
              prefixLen(std::min<uint8_t>(prefix, 32))
        {
            const uint32_t hostMask = (prefixLen == 0) ? 0U : (~0U << (32 - prefixLen));
            maskBe = htonl(hostMask);
            networkBe &= maskBe;
        }

        [[nodiscard]] inline bool matches(in_addr ip) const noexcept
        {
            return (ip.s_addr & maskBe) == networkBe;
        }

        [[nodiscard]] inline bool matches(uint32_t ipBe) const noexcept
        {
            return (ipBe & maskBe) == networkBe;
        }

        /**
         * @brief 从标准 CIDR 格式字符串解析（如 "192.168.1.0/24" 或单 IP "10.0.0.1"）
         */
        static std::optional<IpCidr> parse(std::string_view cidrStr) noexcept
        {
            if (cidrStr.empty())
            {
                return std::nullopt;
            }

            size_t slashPos = cidrStr.find('/');
            std::string ipPart(cidrStr.substr(0, slashPos));
            in_addr addr{};
            if (::inet_pton(AF_INET, ipPart.c_str(), &addr) != 1)
            {
                return std::nullopt;
            }

            uint8_t prefix = 32;
            if (slashPos != std::string_view::npos)
            {
                std::string_view prefixPart = cidrStr.substr(slashPos + 1);
                if (prefixPart.empty())
                    return std::nullopt;
                uint32_t val = 0;
                for (char c : prefixPart)
                {
                    if (c < '0' || c > '9')
                        return std::nullopt;
                    val = val * 10 + static_cast<uint32_t>(c - '0');
                    if (val > 32)
                        return std::nullopt;
                }
                prefix = static_cast<uint8_t>(val);
            }

            return IpCidr(addr.s_addr, prefix);
        }

        /**
         * @brief 判定目标是否为 RFC 1918 私有地址或回环地址 (Private / LAN / Loopback)
         */
        [[nodiscard]] static bool isPrivate(in_addr ip) noexcept
        {
            const uint32_t h = ntohl(ip.s_addr);
            // 10.0.0.0/8
            if ((h & 0xFF000000) == 0x0A000000)
                return true;
            // 172.16.0.0/12
            if ((h & 0xFFF00000) == 0xAC100000)
                return true;
            // 192.168.0.0/16
            if ((h & 0xFFFF0000) == 0xC0A80000)
                return true;
            // 127.0.0.0/8 (Loopback)
            if ((h & 0xFF000000) == 0x7F000000)
                return true;
            // 169.254.0.0/16 (Link Local)
            if ((h & 0xFFFF0000) == 0xA9FE0000)
                return true;
            // 0.0.0.0/8
            if ((h & 0xFF000000) == 0x00000000)
                return true;
            return false;
        }
    };

    /**
     * @brief 待路由决断的上下文特征包 (Route Context)
     */
    struct RouteContext
    {
        NetworkType network{NetworkType::TCP};                 ///< 传输协议 (TCP / UDP)
        std::string_view inboundTag{};                         ///< 接收流量的入站标签 (如 "socks-in")
        sockaddr_in clientAddr{};                              ///< 客户端源端点四元组信息
        handler::ProxyAddress target{};                        ///< 目标端点地址 (IP 或域名 + 端口)
        std::string_view sniffedDomain{};                      ///< 嗅探提取的真实域名 (SNI / HTTP Host)
        handler::sniffing::ProtocolType sniffedProtocol{       ///< 嗅探识别的应用层协议
            handler::sniffing::ProtocolType::UNKNOWN};

        RouteContext() noexcept = default;
    };

    /**
     * @brief 单条分流规则 (Routing Rule)
     */
    class RouteRule
    {
    public:
        std::string outboundTag{};               ///< 匹配成功时命中的出站标签 (如 "direct", "proxy", "block")
        NetworkType network{NetworkType::ANY};   ///< 限制网络类型
        bool invert{false};                      ///< 是否反转匹配结果 (NOT 逻辑)

        std::vector<std::string> inboundTags{};     ///< 来源入站标签白名单
        std::vector<std::string> domains{};         ///< 完整域名精确匹配
        std::vector<std::string> domainSuffixes{};  ///< 域名后缀匹配 (如 ".apple.com", "google.com")
        std::vector<std::string> domainKeywords{};  ///< 域名关键字匹配 (如 "youtube", "telegram")

        std::vector<IpCidr> ipCidrs{};              ///< 目标 IP CIDR 列表
        std::vector<IpCidr> sourceIpCidrs{};        ///< 客户端源 IP CIDR 列表
        std::vector<PortRange> portRanges{};        ///< 目标端口或端口段列表
        std::vector<std::string> protocols{};       ///< 协议特征名 (如 "tls", "http", "bittorrent")

        mutable std::atomic<uint64_t> hitCount_{0}; ///< 本规则被命中计数

        RouteRule() = default;
        explicit RouteRule(std::string tag) : outboundTag(std::move(tag)) {}

        RouteRule(const RouteRule &other)
            : outboundTag(other.outboundTag),
              network(other.network),
              invert(other.invert),
              inboundTags(other.inboundTags),
              domains(other.domains),
              domainSuffixes(other.domainSuffixes),
              domainKeywords(other.domainKeywords),
              ipCidrs(other.ipCidrs),
              sourceIpCidrs(other.sourceIpCidrs),
              portRanges(other.portRanges),
              protocols(other.protocols),
              hitCount_(other.hitCount_.load(std::memory_order_relaxed))
        {
        }

        RouteRule &operator=(const RouteRule &other)
        {
            if (this != &other)
            {
                outboundTag = other.outboundTag;
                network = other.network;
                invert = other.invert;
                inboundTags = other.inboundTags;
                domains = other.domains;
                domainSuffixes = other.domainSuffixes;
                domainKeywords = other.domainKeywords;
                ipCidrs = other.ipCidrs;
                sourceIpCidrs = other.sourceIpCidrs;
                portRanges = other.portRanges;
                protocols = other.protocols;
                hitCount_.store(other.hitCount_.load(std::memory_order_relaxed), std::memory_order_relaxed);
            }
            return *this;
        }

        [[nodiscard]] inline uint64_t hitCount() const noexcept
        {
            return hitCount_.load(std::memory_order_relaxed);
        }

        inline void resetHitCount() noexcept
        {
            hitCount_.store(0, std::memory_order_relaxed);
        }

        // =====================================================================
        // 流式配置构造器 (Fluent Builder API)
        // =====================================================================

        static RouteRule to(std::string tag) { return RouteRule(std::move(tag)); }

        RouteRule &forNetwork(NetworkType net) noexcept
        {
            network = net;
            return *this;
        }

        RouteRule &setInvert(bool inv = true) noexcept
        {
            invert = inv;
            return *this;
        }

        RouteRule &fromInbound(std::string inTag)
        {
            inboundTags.push_back(std::move(inTag));
            return *this;
        }

        RouteRule &domain(std::string d)
        {
            domains.push_back(normalizeString(d));
            return *this;
        }

        RouteRule &domainSuffix(std::string suffix)
        {
            domainSuffixes.push_back(normalizeString(suffix));
            return *this;
        }

        RouteRule &domainKeyword(std::string kw)
        {
            domainKeywords.push_back(normalizeString(kw));
            return *this;
        }

        RouteRule &cidr(std::string_view cidrStr)
        {
            if (auto parsed = IpCidr::parse(cidrStr); parsed.has_value())
            {
                ipCidrs.push_back(*parsed);
            }
            return *this;
        }

        RouteRule &sourceCidr(std::string_view cidrStr)
        {
            if (auto parsed = IpCidr::parse(cidrStr); parsed.has_value())
            {
                sourceIpCidrs.push_back(*parsed);
            }
            return *this;
        }

        RouteRule &port(uint16_t p)
        {
            portRanges.emplace_back(p);
            return *this;
        }

        RouteRule &portRange(uint16_t start, uint16_t end)
        {
            portRanges.emplace_back(start, end);
            return *this;
        }

        RouteRule &protocol(std::string proto)
        {
            protocols.push_back(normalizeString(proto));
            return *this;
        }

        // =====================================================================
        // 匹配决断核心
        // =====================================================================

        [[nodiscard]] bool matches(const RouteContext &ctx) const noexcept
        {
            // 1. 网络类型匹配
            if (network != NetworkType::ANY && network != ctx.network)
            {
                return invert ? true : false;
            }

            // 2. 入站标签匹配
            if (!inboundTags.empty())
            {
                bool matched = false;
                for (const auto &tag : inboundTags)
                {
                    if (tag == ctx.inboundTag)
                    {
                        matched = true;
                        break;
                    }
                }
                if (!matched)
                    return invert ? true : false;
            }

            // 3. 客户端源 IP 匹配
            if (!sourceIpCidrs.empty())
            {
                bool matched = false;
                for (const auto &cidr : sourceIpCidrs)
                {
                    if (cidr.matches(ctx.clientAddr.sin_addr))
                    {
                        matched = true;
                        break;
                    }
                }
                if (!matched)
                    return invert ? true : false;
            }

            // 4. 目标端口过滤
            if (!portRanges.empty())
            {
                bool matched = false;
                const uint16_t targetPort = ctx.target.port;
                for (const auto &pr : portRanges)
                {
                    if (pr.matches(targetPort))
                    {
                        matched = true;
                        break;
                    }
                }
                if (!matched)
                    return invert ? true : false;
            }

            // 5. 应用层嗅探协议名过滤
            if (!protocols.empty())
            {
                bool matched = false;
                std::string_view pName = handler::sniffing::protocolName(ctx.sniffedProtocol);
                for (const auto &p : protocols)
                {
                    if (p == pName)
                    {
                        matched = true;
                        break;
                    }
                }
                if (!matched)
                    return invert ? true : false;
            }

            // 6. 域名类条件匹配 (包含 target.host 与嗅探提取的真实域名)
            const bool hasDomainRules = !domains.empty() || !domainSuffixes.empty() || !domainKeywords.empty();
            if (hasDomainRules)
            {
                bool matched = false;
                // 优先考察嗅探域名，次选原始目标 host
                if (!ctx.sniffedDomain.empty())
                {
                    matched = matchDomainString(ctx.sniffedDomain);
                }
                if (!matched && !ctx.target.host.empty() && ctx.target.type == handler::AddressType::DOMAIN)
                {
                    matched = matchDomainString(ctx.target.host);
                }
                if (!matched)
                    return invert ? true : false;
            }

            // 7. 目标 IP CIDR 匹配
            if (!ipCidrs.empty())
            {
                bool matched = false;
                if (ctx.target.type == handler::AddressType::IPV4)
                {
                    for (const auto &cidr : ipCidrs)
                    {
                        if (cidr.matches(ctx.target.ipv4_))
                        {
                            matched = true;
                            break;
                        }
                    }
                }
                if (!matched)
                    return invert ? true : false;
            }

            // 命中成功（若未设置反转则命中；若设置反转则未命中间接命中）
            const bool finalMatch = !invert;
            if (finalMatch)
            {
                hitCount_.fetch_add(1, std::memory_order_relaxed);
            }
            return finalMatch;
        }

    private:
        [[nodiscard]] bool matchDomainString(std::string_view rawDomain) const noexcept
        {
            std::string d = normalizeString(rawDomain);

            // 精确域名
            for (const auto &exact : domains)
            {
                if (exact == d)
                    return true;
            }

            // 域名后缀匹配 (如 "google.com" 匹配 "google.com" 与 "*.google.com")
            for (const auto &suffix : domainSuffixes)
            {
                if (d == suffix)
                {
                    return true;
                }
                if (suffix.starts_with('.'))
                {
                    if (d.ends_with(suffix))
                        return true;
                }
                else
                {
                    if (d.size() > suffix.size() && d[d.size() - suffix.size() - 1] == '.' && d.ends_with(suffix))
                    {
                        return true;
                    }
                }
            }

            // 域名关键字匹配
            for (const auto &kw : domainKeywords)
            {
                if (d.find(kw) != std::string::npos)
                {
                    return true;
                }
            }

            return false;
        }

        [[nodiscard]] static std::string normalizeString(std::string_view sv)
        {
            std::string res;
            res.reserve(sv.size());
            for (char c : sv)
            {
                res.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
            }
            return res;
        }
    };

    /**
     * @brief 策略路由调度引擎 (Router Dispatcher)
     *
     * 维护有序的分流规则链表与默认出站降级标签，在收到连接时秒级完成决策调度。
     */
    class Router
    {
    private:
        std::string defaultOutbound_{"direct"};
        mutable std::mutex mutex_{};
        std::vector<RouteRule> rules_{};

    public:
        Router() = default;
        explicit Router(std::string defaultTag) : defaultOutbound_(std::move(defaultTag)) {}

        [[nodiscard]] inline std::string_view defaultOutbound() const noexcept
        {
            return defaultOutbound_;
        }

        inline void setDefaultOutbound(std::string tag)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            defaultOutbound_ = std::move(tag);
        }

        /**
         * @brief 向路由引擎追加一条策略分流规则（先添加的规则拥有更高优先级）
         */
        inline void addRule(RouteRule rule)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            rules_.push_back(std::move(rule));
        }

        /**
         * @brief 清空全部规则
         */
        inline void clearRules()
        {
            std::lock_guard<std::mutex> lock(mutex_);
            rules_.clear();
        }

        [[nodiscard]] inline size_t ruleCount() const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return rules_.size();
        }

        /**
         * @brief 依据上下文特征匹配对应的出站标签
         *
         * @param ctx 路由上下文包
         * @return std::string_view 命中的出站标签名称（若全未命中则回落至 defaultOutbound_）
         */
        [[nodiscard]] std::string_view match(const RouteContext &ctx) const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (const auto &rule : rules_)
            {
                if (rule.matches(ctx))
                {
                    return rule.outboundTag;
                }
            }
            return defaultOutbound_;
        }

        /**
         * @brief 获取所有规则的只读快照（诊断排查与统计视图）
         */
        [[nodiscard]] std::vector<RouteRule> rulesSnapshot() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return rules_;
        }
    };

} // namespace mynet
