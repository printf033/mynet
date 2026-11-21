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

#include "address.hpp"
#include "config/log.hpp"
#include "error.hpp"
#include "geo.hpp"
#include "ruleset.hpp"
#include "sniffer.hpp"
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
        constexpr explicit PortRange(uint16_t port) noexcept
            : start(port),
              end(port)
        {
        }
        constexpr PortRange(uint16_t s, uint16_t e) noexcept
            : start(s),
              end(e)
        {
        }

        [[nodiscard]] constexpr bool matches(uint16_t port) const noexcept { return port >= start && port <= end; }

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

    /// 复用 address.hpp 单一真实源 (Single Source of Truth)
    using IpCidr = handler::IpCidr;
    using Ip6Cidr = handler::Ip6Cidr;

    /**
     * @brief 待路由决断的上下文特征包 (Route Context)
     */
    struct RouteContext
    {
        NetworkType network{NetworkType::TCP};          ///< 传输协议 (TCP / UDP)
        std::string_view inboundTag{};                  ///< 接收流量的入站标签 (如 "socks-in")
        sockaddr_in clientAddr{};                       ///< 客户端源端点四元组信息
        handler::ProxyAddress target{};                 ///< 目标端点地址 (IP 或域名 + 端口)
        std::string_view sniffedDomain{};               ///< 嗅探提取的真实域名 (SNI / HTTP Host)
        std::string_view processName{};                 ///< 客户端发起进程名 (如 "curl", "chrome")
        handler::sniffing::ProtocolType sniffedProtocol{///< 嗅探识别的应用层协议
                                                        handler::sniffing::ProtocolType::UNKNOWN};
        uint8_t dscp{0};            ///< L3/L4 DSCP 优先级代码
        bool decisionLocked{false}; ///< 路由决策是否已被 must 规则锁定

        RouteContext() noexcept = default;
    };

    /**
     * @brief 单条分流规则 (Routing Rule)
     */
    class RouteRule
    {
    public:
        std::string outboundTag{};             ///< 匹配成功时命中的出站标签 (如 "direct", "proxy", "block")
        NetworkType network{NetworkType::ANY}; ///< 限制网络类型
        bool invert{false};                    ///< 是否反转匹配结果 (NOT 逻辑)

        std::vector<std::string> inboundTags{};    ///< 来源入站标签白名单
        std::vector<std::string> domains{};        ///< 完整域名精确匹配
        std::vector<std::string> domainSuffixes{}; ///< 域名后缀匹配 (如 ".apple.com", "google.com")
        std::vector<std::string> domainKeywords{}; ///< 域名关键字匹配 (如 "youtube", "telegram")

        std::vector<IpCidr> ipCidrs{};        ///< 目标 IP CIDR 列表
        std::vector<IpCidr> sourceIpCidrs{};  ///< 客户端源 IP CIDR 列表
        std::vector<PortRange> portRanges{};  ///< 目标端口或端口段列表
        std::vector<std::string> protocols{}; ///< 协议特征名 (如 "tls", "http", "bittorrent")
        std::vector<std::string> geoIps{};    ///< GeoIP 国家或私网代码 (如 "cn", "private")
        std::vector<std::string> geoSites{};  ///< GeoSite 域名分类资产 (如 "cn", "category-ads-all", "google")
        std::string processName{};            ///< 客户端进程名 (如 "curl", "chrome")
        std::vector<std::string> ruleSets{};  ///< 关联的 sing-box SRS 规则集标签 (Rule-Set Tags)
        std::vector<std::shared_ptr<ruleset::RuleSetSrs>> ruleSetInstances{}; ///< 规则集实例引用
        std::optional<uint8_t> dscp{};                                        ///< 限制 DSCP 代码
        bool isSniffPunt{false};                                              ///< 是否为智能推断出的嗅探绕转规则
        bool must{false}; ///< 强制锁定规则命中判定，禁止后续嗅探或重路由覆盖 (借鉴 dae must 规则)

        mutable std::atomic<uint64_t> hitCount_{0}; ///< 本规则被命中计数

        RouteRule() = default;
        explicit RouteRule(std::string tag)
            : outboundTag(std::move(tag))
        {
        }

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
              geoIps(other.geoIps),
              geoSites(other.geoSites),
              processName(other.processName),
              ruleSets(other.ruleSets),
              ruleSetInstances(other.ruleSetInstances),
              dscp(other.dscp),
              isSniffPunt(other.isSniffPunt),
              must(other.must),
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
                geoIps = other.geoIps;
                geoSites = other.geoSites;
                processName = other.processName;
                ruleSets = other.ruleSets;
                ruleSetInstances = other.ruleSetInstances;
                dscp = other.dscp;
                isSniffPunt = other.isSniffPunt;
                must = other.must;
                hitCount_.store(other.hitCount_.load(std::memory_order_relaxed), std::memory_order_relaxed);
            }
            return *this;
        }

        [[nodiscard]] inline uint64_t hitCount() const noexcept { return hitCount_.load(std::memory_order_relaxed); }

        inline void resetHitCount() noexcept { hitCount_.store(0, std::memory_order_relaxed); }

        // =====================================================================
        // 流式配置构造器 (Fluent Builder API)
        // =====================================================================

        static RouteRule to(std::string tag) { return RouteRule(std::move(tag)); }

        RouteRule &forNetwork(NetworkType net) noexcept
        {
            network = net;
            return *this;
        }

        RouteRule &forDscp(uint8_t val) noexcept
        {
            dscp = val;
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

        RouteRule &geoIp(std::string country)
        {
            geoIps.push_back(normalizeString(country));
            return *this;
        }

        RouteRule &geoSite(std::string cat)
        {
            geoSites.push_back(normalizeString(cat));
            return *this;
        }

        RouteRule &forProcess(std::string proc)
        {
            processName = std::move(proc);
            return *this;
        }

        RouteRule &ruleSet(std::string tag)
        {
            ruleSets.push_back(std::move(tag));
            return *this;
        }

        RouteRule &setMust(bool m = true) noexcept
        {
            must = m;
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

            // 2.5 DSCP 优先级过滤 (借鉴 dae dscp)
            if (dscp.has_value() && *dscp != ctx.dscp)
            {
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

            // 8. GeoIP 国家与私网判定
            if (!geoIps.empty())
            {
                bool matched = false;
                if (ctx.target.type == handler::AddressType::IPV4 && ctx.target.ipv4_.s_addr != 0)
                {
                    for (const auto &gip : geoIps)
                    {
                        if (GeoIpMatcher::instance().matches(ctx.target.ipv4_, gip))
                        {
                            matched = true;
                            break;
                        }
                    }
                }
                if (!matched)
                    return invert ? true : false;
            }

            // 9. GeoSite 域名资产分类匹配
            if (!geoSites.empty())
            {
                bool matched = false;
                std::string_view dom = !ctx.sniffedDomain.empty() ? ctx.sniffedDomain : ctx.target.host;
                if (!dom.empty())
                {
                    for (const auto &gsite : geoSites)
                    {
                        if (GeoSiteMatcher::instance().matches(dom, gsite))
                        {
                            matched = true;
                            break;
                        }
                    }
                }
                if (!matched)
                    return invert ? true : false;
            }

            // 10. 客户端发起进程名过滤
            if (!processName.empty())
            {
                if (ctx.processName != processName)
                {
                    return invert ? true : false;
                }
            }

            // 11. sing-box .srs 规则集 (Rule-Set) 匹配
            if (!ruleSetInstances.empty())
            {
                bool matched = false;
                std::string_view dom = !ctx.sniffedDomain.empty() ? ctx.sniffedDomain : ctx.target.host;
                sockaddr_in targetAddr{};
                if (ctx.target.type == handler::AddressType::IPV4)
                {
                    targetAddr.sin_family = AF_INET;
                    targetAddr.sin_addr = ctx.target.ipv4_;
                    targetAddr.sin_port = htons(ctx.target.port);
                }
                std::string_view netStr = (ctx.network == NetworkType::UDP) ? "udp" : "tcp";
                for (const auto &rs : ruleSetInstances)
                {
                    if (rs != nullptr)
                    {
                        if (rs->match(dom, ctx.target.type == handler::AddressType::IPV4 ? &targetAddr : nullptr,
                                      ctx.target.port, netStr))
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
        std::unordered_map<std::string, std::shared_ptr<ruleset::RuleSetSrs>> ruleSets_{};
        struct DomainCacheEntry
        {
            size_t ruleIndex{SIZE_MAX};
            std::string outboundTag{};
        };
        mutable std::unordered_map<std::string, DomainCacheEntry> domainMatchCache_{};

    public:
        Router() = default;
        explicit Router(std::string defaultTag)
            : defaultOutbound_(std::move(defaultTag))
        {
        }

        [[nodiscard]] inline std::string_view defaultOutbound() const noexcept { return defaultOutbound_; }

        [[nodiscard]] inline std::vector<RouteRule> rules() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return rules_;
        }

        inline void setDefaultOutbound(std::string tag)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            defaultOutbound_ = std::move(tag);
        }

        /**
         * @brief 注册一个 sing-box SRS 规则集
         */
        void addRuleSet(std::string tag, std::shared_ptr<ruleset::RuleSetSrs> rs)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            ruleSets_[std::move(tag)] = std::move(rs);
        }

        [[nodiscard]] std::shared_ptr<ruleset::RuleSetSrs> getRuleSet(std::string_view tag) const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = ruleSets_.find(std::string(tag));
            return (it != ruleSets_.end()) ? it->second : nullptr;
        }

        Result<> loadRuleSet(std::string tag, const std::string &path)
        {
            auto rs = ruleset::RuleSetSrs::loadFromFile(path);
            if (!rs)
            {
                LOG_ERROR("Router::loadRuleSet: failed to load '{}' from '{}': {}", tag, path,
                          ruleset::toString(rs.error()));
                return std::unexpected(ERR::NOT_INITIALISED);
            }
            addRuleSet(std::move(tag), std::make_shared<ruleset::RuleSetSrs>(std::move(*rs)));
            return {};
        }

        /**
         * @brief 向路由引擎追加一条策略分流规则（先添加的规则拥有更高优先级）
         */
        inline void addRule(RouteRule rule)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            domainMatchCache_.clear();
            for (const auto &tag : rule.ruleSets)
            {
                auto it = ruleSets_.find(tag);
                if (it != ruleSets_.end())
                {
                    rule.ruleSetInstances.push_back(it->second);
                }
            }
            rules_.push_back(std::move(rule));
        }

        /**
         * @brief 清空全部规则
         */
        inline void clearRules()
        {
            std::lock_guard<std::mutex> lock(mutex_);
            domainMatchCache_.clear();
            rules_.clear();
        }

        [[nodiscard]] inline size_t ruleCount() const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return rules_.size();
        }

        /**
         * @brief 智能推断并注入嗅探绕转规则 (借鉴 dae InferSniffPunt)
         */
        size_t inferSniffPunt()
        {
            std::lock_guard<std::mutex> lock(mutex_);
            std::vector<RouteRule> newRules;
            newRules.reserve(rules_.size() + 4);
            size_t injectedCount = 0;

            for (size_t i = 0; i < rules_.size(); ++i)
            {
                const auto &r = rules_[i];
                if (r.outboundTag == "direct" && !r.sourceIpCidrs.empty() && r.domains.empty() &&
                    r.domainSuffixes.empty() && r.domainKeywords.empty())
                {
                    bool hasEarlierDomainWhitelist = false;
                    for (size_t j = 0; j < i; ++j)
                    {
                        const auto &prev = rules_[j];
                        if (prev.outboundTag != "direct" && prev.outboundTag != "block" &&
                            !prev.sourceIpCidrs.empty() &&
                            (!prev.domains.empty() || !prev.domainSuffixes.empty() || !prev.domainKeywords.empty()))
                        {
                            for (const auto &s1 : r.sourceIpCidrs)
                            {
                                for (const auto &s2 : prev.sourceIpCidrs)
                                {
                                    if (s1.networkBe == s2.networkBe && s1.prefixLen == s2.prefixLen)
                                    {
                                        hasEarlierDomainWhitelist = true;
                                        break;
                                    }
                                }
                                if (hasEarlierDomainWhitelist)
                                    break;
                            }
                        }
                        if (hasEarlierDomainWhitelist)
                            break;
                    }

                    if (hasEarlierDomainWhitelist)
                    {
                        RouteRule puntRule;
                        puntRule.outboundTag = "control_plane_routing";
                        puntRule.sourceIpCidrs = r.sourceIpCidrs;
                        puntRule.isSniffPunt = true;
                        newRules.push_back(std::move(puntRule));
                        injectedCount++;
                    }
                }
                newRules.push_back(r);
            }
            if (injectedCount > 0)
            {
                rules_ = std::move(newRules);
                domainMatchCache_.clear();
            }
            return injectedCount;
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
            std::string_view domainKey =
                !ctx.sniffedDomain.empty()
                    ? ctx.sniffedDomain
                    : (ctx.target.type == handler::AddressType::DOMAIN ? std::string_view(ctx.target.host) : "");
            if (!domainKey.empty() && ctx.clientAddr.sin_addr.s_addr == 0 && ctx.dscp == 0)
            {
                auto it = domainMatchCache_.find(std::string(domainKey));
                if (it != domainMatchCache_.end())
                {
                    if (it->second.ruleIndex < rules_.size())
                    {
                        rules_[it->second.ruleIndex].hitCount_.fetch_add(1, std::memory_order_relaxed);
                    }
                    return it->second.outboundTag;
                }
            }
            for (size_t i = 0; i < rules_.size(); ++i)
            {
                const auto &rule = rules_[i];
                if (rule.matches(ctx))
                {
                    if (!domainKey.empty() && ctx.clientAddr.sin_addr.s_addr == 0 && ctx.dscp == 0 &&
                        domainMatchCache_.size() < 10000)
                    {
                        domainMatchCache_[std::string(domainKey)] = DomainCacheEntry{i, rule.outboundTag};
                    }
                    return rule.outboundTag;
                }
            }
            if (!domainKey.empty() && ctx.clientAddr.sin_addr.s_addr == 0 && ctx.dscp == 0 &&
                domainMatchCache_.size() < 10000)
            {
                domainMatchCache_[std::string(domainKey)] = DomainCacheEntry{SIZE_MAX, defaultOutbound_};
            }
            return defaultOutbound_;
        }

        /**
         * @brief 路由判决结果与锁定状态结构 (借鉴 dae must rule locking)
         */
        struct RouteDecision
        {
            std::string_view outboundTag{};
            bool locked{false};
        };

        /**
         * @brief 带 must 决策锁定感知的策略匹配
         */
        [[nodiscard]] RouteDecision matchWithDecision(const RouteContext &ctx) const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (size_t i = 0; i < rules_.size(); ++i)
            {
                const auto &rule = rules_[i];
                if (rule.matches(ctx))
                {
                    return RouteDecision{rule.outboundTag, rule.must};
                }
            }
            return RouteDecision{defaultOutbound_, false};
        }

        /**
         * @brief 智能判定是否需要执行应用层域名与协议嗅探 (借鉴 dae InferSniffPunt)
         *
         * 自动检查当前所有分流规则：
         * 若所有规则均只基于 IP/CIDR、端口、进程等 L3/L4 特征，且没有任何规则涉及
         * domains, domainSuffixes, domainKeywords, geoSites, ruleSets 或 protocols，
         * 则无需等待 TLS ClientHello / HTTP Host 嗅探，直接放行/直连，实现最低延迟。
         */
        [[nodiscard]] bool shouldSniff() const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (const auto &r : rules_)
            {
                if (!r.domains.empty() || !r.domainSuffixes.empty() || !r.domainKeywords.empty() ||
                    !r.geoSites.empty() || !r.ruleSets.empty() || !r.protocols.empty())
                {
                    return true;
                }
            }
            return false;
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
