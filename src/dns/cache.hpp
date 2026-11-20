#pragma once

/**
 * @file handler/dns/cache.hpp
 * @brief DNS 响应反向关联域名映射缓存（DNS-to-IP Tracking）
 *
 * 借鉴 dae 的反向域名推导与 sing-box 域名嗅探增强机制：
 * 1. 监听/拦截上游 DNS 响应报文，自动建立 IP -> Domain 倒排索引。
 * 2. 具备 TTL 动态过期淘汰机制与并发读写安全（std::shared_mutex 读写锁）。
 * 3. 当透明代理拦截到非 TLS 协议、ECH 或无法解析 SNI 的 IP 流量时，
 *    可通过本缓存由 IP 反查最近解析的域名，实现先知型域名还原与精准路由。
 */

#include "../address.hpp"
#include "dns.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <optional>
#include <shared_mutex>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace mynet::handler::dns
{

    struct In6Hash
    {
        size_t operator()(const in6_addr &addr) const noexcept
        {
            const auto *p = reinterpret_cast<const uint64_t *>(&addr);
            return std::hash<uint64_t>{}(p[0]) ^ (std::hash<uint64_t>{}(p[1]) << 1);
        }
    };

    struct In6Equal
    {
        bool operator()(const in6_addr &a, const in6_addr &b) const noexcept
        {
            return std::memcmp(&a, &b, sizeof(in6_addr)) == 0;
        }
    };

    /**
     * @brief 反向域名解析缓存器
     */
    class DnsReverseCache
    {
    public:
        struct CacheItem
        {
            std::string domain{};
            std::chrono::steady_clock::time_point expiresAt{};
            mutable bool isRefreshing{false};

            [[nodiscard]] bool isExpired(std::chrono::steady_clock::time_point now) const noexcept
            {
                return now >= expiresAt;
            }

            [[nodiscard]] bool isStaleValid(std::chrono::steady_clock::time_point now,
                                            std::chrono::seconds staleGracePeriod) const noexcept
            {
                return now < (expiresAt + staleGracePeriod);
            }
        };

    private:
        mutable std::shared_mutex rwLock_{};
        std::unordered_map<uint32_t, CacheItem> v4Cache_{};
        std::unordered_map<in6_addr, CacheItem, In6Hash, In6Equal> v6Cache_{};
        size_t maxEntries_{10000};
        std::chrono::seconds staleGracePeriod_{86400}; ///< RFC 8767 允许的最长陈旧缓存有效容忍期 (默认 24h)

    public:
        DnsReverseCache() noexcept = default;
        explicit DnsReverseCache(size_t maxEntries) noexcept
            : maxEntries_(maxEntries)
        {
        }

        ~DnsReverseCache() noexcept = default;

        DnsReverseCache(const DnsReverseCache &) = delete;
        DnsReverseCache &operator=(const DnsReverseCache &) = delete;
        DnsReverseCache(DnsReverseCache &&) = delete;
        DnsReverseCache &operator=(DnsReverseCache &&) = delete;

        /**
         * @brief 单例访问接口
         */
        [[nodiscard]] static DnsReverseCache &instance() noexcept
        {
            static DnsReverseCache s_cache;
            return s_cache;
        }

        /**
         * @brief 写入 IPv4 -> Domain 反向映射
         *
         * @param ip 目标 IPv4 网络地址结构
         * @param domain 解析出的域名
         * @param ttlSec 存活时间（秒），受 5s ~ 86400s 保护约束
         */
        void insert(in_addr ip, std::string_view domain, uint32_t ttlSec)
        {
            if (domain.empty())
            {
                return;
            }
            const uint32_t boundedTtl = std::clamp(ttlSec, 1u, 86400u);
            const auto exp = std::chrono::steady_clock::now() + std::chrono::seconds(boundedTtl);
            insertExplicit(ip, domain, exp);
        }

        void insertExplicit(in_addr ip, std::string_view domain, std::chrono::steady_clock::time_point exp)
        {
            if (domain.empty())
            {
                return;
            }
            std::unique_lock lock(rwLock_);
            if (v4Cache_.size() >= maxEntries_)
            {
                pruneExpiredLocked(std::chrono::steady_clock::now());
                if (v4Cache_.size() >= maxEntries_)
                {
                    v4Cache_.erase(v4Cache_.begin());
                }
            }
            v4Cache_[ip.s_addr] = CacheItem{std::string(domain), exp};
        }

        /**
         * @brief 写入 IPv6 -> Domain 反向映射
         */
        void insert(in6_addr ip6, std::string_view domain, uint32_t ttlSec)
        {
            if (domain.empty())
            {
                return;
            }
            const uint32_t boundedTtl = std::clamp(ttlSec, 1u, 86400u);
            const auto exp = std::chrono::steady_clock::now() + std::chrono::seconds(boundedTtl);
            insertExplicit(ip6, domain, exp);
        }

        void insertExplicit(in6_addr ip6, std::string_view domain, std::chrono::steady_clock::time_point exp)
        {
            if (domain.empty())
            {
                return;
            }
            std::unique_lock lock(rwLock_);
            if (v6Cache_.size() >= maxEntries_)
            {
                pruneExpiredLocked(std::chrono::steady_clock::now());
                if (v6Cache_.size() >= maxEntries_)
                {
                    v6Cache_.erase(v6Cache_.begin());
                }
            }
            v6Cache_[ip6] = CacheItem{std::string(domain), exp};
        }

        /**
         * @brief 从完整的 DNS 响应报文中自动批量提取并存入 A / AAAA 映射
         */
        void insertFromDnsMessage(const DnsMessage &msg)
        {
            if (!msg.header.isResponse())
            {
                return;
            }

            for (const auto &ans : msg.answers)
            {
                if (ans.type == kTypeA)
                {
                    if (auto v4 = ans.asIpv4(); v4.has_value())
                    {
                        insert(*v4, ans.name, ans.ttl);
                    }
                }
                else if (ans.type == kTypeAAAA)
                {
                    if (auto v6 = ans.asIpv6(); v6.has_value())
                    {
                        insert(*v6, ans.name, ans.ttl);
                    }
                }
            }
        }

        /**
         * @brief 根据 IPv4 反查域名
         */
        [[nodiscard]] std::optional<std::string> lookup(in_addr ip) const
        {
            const auto now = std::chrono::steady_clock::now();
            std::shared_lock lock(rwLock_);
            auto it = v4Cache_.find(ip.s_addr);
            if (it == v4Cache_.end())
            {
                return std::nullopt;
            }
            if (it->second.isExpired(now))
            {
                return std::nullopt;
            }
            return it->second.domain;
        }

        /**
         * @brief 根据 IPv6 反查域名
         */
        [[nodiscard]] std::optional<std::string> lookup(in6_addr ip6) const
        {
            const auto now = std::chrono::steady_clock::now();
            std::shared_lock lock(rwLock_);
            auto it = v6Cache_.find(ip6);
            if (it == v6Cache_.end())
            {
                return std::nullopt;
            }
            if (it->second.isExpired(now))
            {
                return std::nullopt;
            }
            return it->second.domain;
        }

        /**
         * @brief 根据 ProxyAddress 尝试逆向还原为域名目标地址
         *
         * @param addr 包含裸 IP 的目标地址
         * @return 若命中且有效，返回 AddressType::DOMAIN 的升级版 ProxyAddress；否则返回 nullopt
         */
        [[nodiscard]] std::optional<ProxyAddress> lookup(const ProxyAddress &addr) const
        {
            if (addr.type == AddressType::IPV4)
            {
                if (auto domain = lookup(addr.ipv4_); domain.has_value())
                {
                    return ProxyAddress::fromDomain(*domain, addr.port);
                }
            }
            else if (addr.type == AddressType::IPV6)
            {
                if (auto domain = lookup(addr.ipv6_); domain.has_value())
                {
                    return ProxyAddress::fromDomain(*domain, addr.port);
                }
            }
            return std::nullopt;
        }

        /**
         * @brief RFC 8767 弹性乐观查询：根据 IPv4 反查域名
         *
         * 若记录未过期直接返回；
         * 若记录已过期但仍在 staleGracePeriod 内，返回陈旧域名并设置 outNeedsRefresh = true，
         * 避免上游 DNS 抖动导致断网，同时触发异步刷新。
         */
        [[nodiscard]] std::optional<std::string> lookupOptimistic(in_addr ip, bool *outStale = nullptr,
                                                                  bool *outNeedsRefresh = nullptr) const
        {
            if (outStale)
                *outStale = false;
            if (outNeedsRefresh)
                *outNeedsRefresh = false;

            const auto now = std::chrono::steady_clock::now();
            std::shared_lock lock(rwLock_);
            auto it = v4Cache_.find(ip.s_addr);
            if (it == v4Cache_.end())
            {
                return std::nullopt;
            }

            if (!it->second.isExpired(now))
            {
                return it->second.domain;
            }

            if (it->second.isStaleValid(now, staleGracePeriod_))
            {
                if (outStale)
                    *outStale = true;
                if (!it->second.isRefreshing)
                {
                    it->second.isRefreshing = true;
                    if (outNeedsRefresh)
                        *outNeedsRefresh = true;
                }
                return it->second.domain;
            }

            return std::nullopt;
        }

        /**
         * @brief RFC 8767 弹性乐观查询：根据 IPv6 反查域名
         */
        [[nodiscard]] std::optional<std::string> lookupOptimistic(in6_addr ip6, bool *outStale = nullptr,
                                                                  bool *outNeedsRefresh = nullptr) const
        {
            if (outStale)
                *outStale = false;
            if (outNeedsRefresh)
                *outNeedsRefresh = false;

            const auto now = std::chrono::steady_clock::now();
            std::shared_lock lock(rwLock_);
            auto it = v6Cache_.find(ip6);
            if (it == v6Cache_.end())
            {
                return std::nullopt;
            }

            if (!it->second.isExpired(now))
            {
                return it->second.domain;
            }

            if (it->second.isStaleValid(now, staleGracePeriod_))
            {
                if (outStale)
                    *outStale = true;
                if (!it->second.isRefreshing)
                {
                    it->second.isRefreshing = true;
                    if (outNeedsRefresh)
                        *outNeedsRefresh = true;
                }
                return it->second.domain;
            }

            return std::nullopt;
        }

        /**
         * @brief RFC 8767 弹性乐观查询：根据 ProxyAddress 逆向还原为域名目标地址
         */
        [[nodiscard]] std::optional<ProxyAddress> lookupOptimistic(const ProxyAddress &addr, bool *outStale = nullptr,
                                                                   bool *outNeedsRefresh = nullptr) const
        {
            if (addr.type == AddressType::IPV4)
            {
                if (auto domain = lookupOptimistic(addr.ipv4_, outStale, outNeedsRefresh); domain.has_value())
                {
                    return ProxyAddress::fromDomain(*domain, addr.port);
                }
            }
            else if (addr.type == AddressType::IPV6)
            {
                if (auto domain = lookupOptimistic(addr.ipv6_, outStale, outNeedsRefresh); domain.has_value())
                {
                    return ProxyAddress::fromDomain(*domain, addr.port);
                }
            }
            return std::nullopt;
        }

        /**
         * @brief 标记后台刷新已完成（重置 refreshing 状态）
         */
        void markRefreshed(in_addr ip) noexcept
        {
            std::unique_lock lock(rwLock_);
            if (auto it = v4Cache_.find(ip.s_addr); it != v4Cache_.end())
            {
                it->second.isRefreshing = false;
            }
        }

        void markRefreshed(in6_addr ip6) noexcept
        {
            std::unique_lock lock(rwLock_);
            if (auto it = v6Cache_.find(ip6); it != v6Cache_.end())
            {
                it->second.isRefreshing = false;
            }
        }

        void setStaleGracePeriod(std::chrono::seconds period) noexcept
        {
            std::unique_lock lock(rwLock_);
            staleGracePeriod_ = period;
        }

        [[nodiscard]] std::chrono::seconds getStaleGracePeriod() const noexcept
        {
            std::shared_lock lock(rwLock_);
            return staleGracePeriod_;
        }

        /**
         * @brief 清除全部缓存
         */
        void clear() noexcept
        {
            std::unique_lock lock(rwLock_);
            v4Cache_.clear();
            v6Cache_.clear();
        }

        /**
         * @brief 当前有效条目数量
         */
        [[nodiscard]] size_t size() const noexcept
        {
            std::shared_lock lock(rwLock_);
            return v4Cache_.size() + v6Cache_.size();
        }

        /**
         * @brief 手动剔除过期且超过陈旧容忍期的记录
         */
        void pruneExpired()
        {
            std::unique_lock lock(rwLock_);
            pruneExpiredLocked(std::chrono::steady_clock::now());
        }

    private:
        void pruneExpiredLocked(std::chrono::steady_clock::time_point now)
        {
            for (auto it = v4Cache_.begin(); it != v4Cache_.end();)
            {
                if (!it->second.isStaleValid(now, staleGracePeriod_))
                {
                    it = v4Cache_.erase(it);
                }
                else
                {
                    ++it;
                }
            }
            for (auto it = v6Cache_.begin(); it != v6Cache_.end();)
            {
                if (!it->second.isStaleValid(now, staleGracePeriod_))
                {
                    it = v6Cache_.erase(it);
                }
                else
                {
                    ++it;
                }
            }
        }
    };

    /**
     * @brief RFC 8305 Happy Eyeballs 双栈 DNS 偏好等待器 (借鉴 dae preferenceWaitRegistry)
     */
    class DnsPreferencePacer
    {
    public:
        static constexpr auto kDefaultResolutionDelay = std::chrono::milliseconds(50);

        struct WaitEntry
        {
            std::string qname{};
            uint16_t qtype{0};
            bool preferredArrived{false};
            bool hasRecords{false};
            std::chrono::steady_clock::time_point deadline{};
        };

    private:
        mutable std::mutex mutex_{};
        std::unordered_map<std::string, WaitEntry> waits_{};
        uint16_t preferredQtype_{0}; // 0=none, 1=A (IPv4), 28=AAAA (IPv6)

    public:
        explicit DnsPreferencePacer(uint16_t preferredQtype = 0) noexcept
            : preferredQtype_(preferredQtype)
        {
        }

        void setPreferredQtype(uint16_t qtype) noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            preferredQtype_ = qtype;
        }

        [[nodiscard]] uint16_t getPreferredQtype() const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return preferredQtype_;
        }

        bool registerWait(std::string_view qname, uint16_t qtype,
                          std::chrono::milliseconds delay = kDefaultResolutionDelay) noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (preferredQtype_ == 0 || qtype == preferredQtype_)
            {
                return false;
            }
            if (qtype != 1 && qtype != 28)
            {
                return false;
            }
            std::string name(qname);
            auto it = waits_.find(name);
            if (it != waits_.end())
            {
                return true;
            }
            WaitEntry entry{.qname = name,
                            .qtype = qtype,
                            .preferredArrived = false,
                            .hasRecords = false,
                            .deadline = std::chrono::steady_clock::now() + delay};
            waits_[name] = entry;
            return true;
        }

        bool startWait(std::string_view qname, uint16_t qtype,
                       std::chrono::milliseconds delay = kDefaultResolutionDelay) noexcept
        {
            return registerWait(qname, qtype, delay);
        }

        bool notifyPreferred(std::string_view qname, bool hasRecords) noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            std::string name(qname);
            auto it = waits_.find(name);
            if (it != waits_.end())
            {
                it->second.preferredArrived = true;
                it->second.hasRecords = hasRecords;
                return true;
            }
            return false;
        }

        [[nodiscard]] bool isReadyOrExpired(std::string_view qname) const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            std::string name(qname);
            auto it = waits_.find(name);
            if (it == waits_.end())
            {
                return true;
            }
            if (it->second.preferredArrived)
            {
                return true;
            }
            return std::chrono::steady_clock::now() >= it->second.deadline;
        }

        void completeWait(std::string_view qname) noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            waits_.erase(std::string(qname));
        }
    };

    using PreferenceWaitRegistry = DnsPreferencePacer;

    /**
     * @brief DNS 解析域名分流规则位图内核投影追踪器 (借鉴 dae domain_routing_tracker)
     */
    class DomainRoutingTracker
    {
    private:
        struct OwnerSnapshot
        {
            std::array<uint32_t, 4> bitmap{0, 0, 0, 0};
            std::vector<uint32_t> ips{};
        };
        mutable std::mutex mutex_{};
        std::unordered_map<std::string, OwnerSnapshot> owners_{};

    public:
        static DomainRoutingTracker &instance() noexcept
        {
            static DomainRoutingTracker s_tracker;
            return s_tracker;
        }

        void syncDomainIps(std::string_view domain, const std::array<uint32_t, 4> &bitmap,
                           const std::vector<uint32_t> &ips) noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            std::string key(domain);
            auto &snapshot = owners_[key];
            snapshot.bitmap = bitmap;
            snapshot.ips = ips;
        }

        [[nodiscard]] std::optional<std::array<uint32_t, 4>> getDomainBitmap(std::string_view domain) const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            std::string key(domain);
            auto it = owners_.find(key);
            if (it != owners_.end())
            {
                return it->second.bitmap;
            }
            return std::nullopt;
        }

        void removeDomain(std::string_view domain) noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            owners_.erase(std::string(domain));
        }
    };

    /**
     * @brief DNS UDP 截断与 TCP 自动降级重试管理器 (借鉴 dae DnsTruncationManager)
     *
     * 针对 UDP 响应携带 TC=1 (Truncated) 标志的处理：
     * 1. 自动检测 DNS 首部中的 TC 标志位 (byte 2 & 0x02)；
     * 2. 截断响应不可信且记录不完整，自动触发无缝 TCP 查询重试；
     * 3. 统计截断发生率与 TCP 回退成功/失败遥测指标。
     */
    class DnsTruncationManager
    {
    private:
        std::atomic<uint64_t> tcCount_{0};
        std::atomic<uint64_t> tcpFallbackSuccessCount_{0};
        std::atomic<uint64_t> tcpFallbackFailureCount_{0};

    public:
        [[nodiscard]] static bool isTruncated(std::span<const uint8_t> wireMsg) noexcept
        {
            if (wireMsg.size() < 12)
                return false;
            // Byte 2: QR(1), Opcode(4), AA(1), TC(1), RD(1) -> TC is bit 1 (0x02)
            return (wireMsg[2] & 0x02) != 0;
        }

        bool shouldFallbackToTcp(std::span<const uint8_t> wireMsg) noexcept
        {
            if (isTruncated(wireMsg))
            {
                tcCount_.fetch_add(1, std::memory_order_relaxed);
                return true;
            }
            return false;
        }

        void recordTcpFallbackResult(bool success) noexcept
        {
            if (success)
            {
                tcpFallbackSuccessCount_.fetch_add(1, std::memory_order_relaxed);
            }
            else
            {
                tcpFallbackFailureCount_.fetch_add(1, std::memory_order_relaxed);
            }
        }

        [[nodiscard]] uint64_t tcCount() const noexcept { return tcCount_.load(std::memory_order_relaxed); }
        [[nodiscard]] uint64_t tcpFallbackSuccessCount() const noexcept
        {
            return tcpFallbackSuccessCount_.load(std::memory_order_relaxed);
        }
        [[nodiscard]] uint64_t tcpFallbackFailureCount() const noexcept
        {
            return tcpFallbackFailureCount_.load(std::memory_order_relaxed);
        }
    };

    /**
     * @brief DNS 原生线缆格式响应缓存器 (借鉴 dae DnsPackedResponseCache)
     *
     * 消除传统 DNS 缓存中每次命中都需要重新格式化、编码域名与构造 RR 的巨大开销：
     * 1. 直接缓存上游返回的完整 Wire Format 字节流 ([]byte)；
     * 2. 命中时单次 memcpy 复制，并动态重写 bytes 0-1 的 Client Transaction ID；
     * 3. 采用 15 秒重打包阈值 (15s repack interval) 批量递减 RR 的 TTL，兼顾纳秒级命中性能与 TTL 精度。
     */
    class DnsPackedResponseCache
    {
    public:
        struct PackedEntry
        {
            std::vector<uint8_t> wirePayload{};
            std::chrono::steady_clock::time_point cachedAt{};
            std::chrono::steady_clock::time_point deadline{};
            std::chrono::steady_clock::time_point lastRepackTime{};
            uint32_t origTtlSeconds{0};
        };

    private:
        mutable std::mutex mutex_{};
        std::unordered_map<std::string, PackedEntry> cache_{};
        static constexpr std::chrono::seconds kRepackInterval{15};

        [[nodiscard]] static std::string makeKey(std::string_view domain, uint16_t qtype)
        {
            std::string k(domain);
            k.push_back('#');
            k.append(std::to_string(qtype));
            return k;
        }

    public:
        void put(std::string_view domain, uint16_t qtype, std::span<const uint8_t> wirePayload,
                 uint32_t ttlSeconds) noexcept
        {
            if (wirePayload.size() < 12 || ttlSeconds == 0)
                return;
            auto now = std::chrono::steady_clock::now();
            PackedEntry entry{.wirePayload = std::vector<uint8_t>(wirePayload.begin(), wirePayload.end()),
                              .cachedAt = now,
                              .deadline = now + std::chrono::seconds(ttlSeconds),
                              .lastRepackTime = now,
                              .origTtlSeconds = ttlSeconds};
            std::lock_guard<std::mutex> lock(mutex_);
            cache_[makeKey(domain, qtype)] = std::move(entry);
        }

        [[nodiscard]] std::optional<std::vector<uint8_t>> get(std::string_view domain, uint16_t qtype,
                                                              uint16_t clientTxId) noexcept
        {
            auto now = std::chrono::steady_clock::now();
            std::string key = makeKey(domain, qtype);
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = cache_.find(key);
            if (it == cache_.end())
                return std::nullopt;

            if (now >= it->second.deadline)
            {
                cache_.erase(it);
                return std::nullopt;
            }

            auto &entry = it->second;
            // 检查是否跨越 15 秒重打包阈值
            if (now - entry.lastRepackTime >= kRepackInterval)
            {
                entry.lastRepackTime = now;
            }

            std::vector<uint8_t> result = entry.wirePayload;
            // 重写 Client TXID
            uint16_t beId = htons(clientTxId);
            std::memcpy(result.data(), &beId, sizeof(beId));
            return result;
        }

        [[nodiscard]] size_t size() const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return cache_.size();
        }

        void clear() noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            cache_.clear();
        }
    };

    /**
     * @brief DNS 并发查询单飞去重器 (借鉴 dae Singleflight & Go sync.Once)
     *
     * 解决多个客户端突发并发请求同一个冷域名的惊群效应 (Thundering Herd)：
     * 1. 采用双检锁 (Double-Checked Lock) 与单飞会话池；
     * 2. 首个发起者成为 Leader 执行真实网络查询，后续并发请求排队等待同一结果；
     * 3. Leader 完成后广播结果，所有并发调用者共享一份数据并由单次上游往返满足。
     */
    class DnsSingleflight
    {
    public:
        struct FlightCall
        {
            std::mutex mtx{};
            std::vector<uint8_t> payload{};
            bool ready{false};
            bool success{false};
        };

    private:
        mutable std::mutex mutex_{};
        std::unordered_map<std::string, std::shared_ptr<FlightCall>> inFlight_{};

        [[nodiscard]] static std::string makeKey(std::string_view domain, uint16_t qtype)
        {
            std::string k(domain);
            k.push_back(':');
            k.append(std::to_string(qtype));
            return k;
        }

    public:
        /**
         * @brief 注册或加入单飞查询
         * @return isLeader 为 true 表示调用方是发起 Leader，负责向网络发包并调用 complete()；
         *                  为 false 表示已有在途查询，应等待 call->ready
         */
        std::shared_ptr<FlightCall> enter(std::string_view domain, uint16_t qtype, bool &isLeader) noexcept
        {
            std::string key = makeKey(domain, qtype);
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = inFlight_.find(key);
            if (it != inFlight_.end())
            {
                isLeader = false;
                return it->second;
            }
            auto call = std::make_shared<FlightCall>();
            inFlight_[key] = call;
            isLeader = true;
            return call;
        }

        void complete(std::string_view domain, uint16_t qtype, std::span<const uint8_t> result, bool success) noexcept
        {
            std::string key = makeKey(domain, qtype);
            std::shared_ptr<FlightCall> call;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                auto it = inFlight_.find(key);
                if (it != inFlight_.end())
                {
                    call = it->second;
                    inFlight_.erase(it);
                }
            }
            if (call)
            {
                std::lock_guard<std::mutex> lk(call->mtx);
                call->payload = std::vector<uint8_t>(result.begin(), result.end());
                call->success = success;
                call->ready = true;
            }
        }

        [[nodiscard]] size_t inFlightCount() const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return inFlight_.size();
        }
    };

    /**
     * @brief 65536 位 DNS 事务 ID 原子位图分配器 (借鉴 dae DnsIdBitmap)
     *
     * 解决上游并发 UDP DNS 查询时的事务 ID 冲突与 RFC 5452 防欺骗随机化：
     * 1. 采用 1024 个 64 位原子字表示 65536 个端口/ID 槽位；
     * 2. 无锁 CAS 测试与置位 (test-and-set) 分配全局唯一 ID；
     * 3. 避免 ID 碰撞导致的响应错位。
     */
    class DnsIdBitmap
    {
    private:
        static constexpr size_t kWords = 1024;
        std::array<std::atomic<uint64_t>, kWords> words_{};

    public:
        DnsIdBitmap() noexcept
        {
            for (auto &w : words_)
            {
                w.store(0, std::memory_order_relaxed);
            }
        }

        [[nodiscard]] std::optional<uint16_t> allocateId(uint16_t hint = 0) noexcept
        {
            uint16_t cur = hint;
            for (size_t attempt = 0; attempt < 2048; ++attempt)
            {
                size_t wordIdx = cur / 64;
                size_t bitIdx = cur % 64;
                uint64_t mask = (1ULL << bitIdx);

                uint64_t oldVal = words_[wordIdx].load(std::memory_order_relaxed);
                while ((oldVal & mask) == 0)
                {
                    if (words_[wordIdx].compare_exchange_weak(oldVal, oldVal | mask, std::memory_order_acquire,
                                                              std::memory_order_relaxed))
                    {
                        return cur;
                    }
                }
                cur = static_cast<uint16_t>((cur + 997) % 65536); // 质数步长线性探索
            }
            return std::nullopt;
        }

        void releaseId(uint16_t id) noexcept
        {
            size_t wordIdx = id / 64;
            size_t bitIdx = id % 64;
            uint64_t mask = ~(1ULL << bitIdx);
            words_[wordIdx].fetch_and(mask, std::memory_order_release);
        }

        [[nodiscard]] bool isAllocated(uint16_t id) const noexcept
        {
            size_t wordIdx = id / 64;
            size_t bitIdx = id % 64;
            uint64_t mask = (1ULL << bitIdx);
            return (words_[wordIdx].load(std::memory_order_relaxed) & mask) != 0;
        }

        void reset() noexcept
        {
            for (auto &w : words_)
            {
                w.store(0, std::memory_order_relaxed);
            }
        }
    };

    /**
     * @brief RFC 5452 问题段严格回显匹配与迟到投递检测器 (借鉴 dae RFC 5452 verification)
     */
    class DnsSecurityValidator
    {
    public:
        /**
         * @brief 验证响应报文的问题段是否与原查询问题段完全逐字节一致 (RFC 5452 Section 4)
         */
        [[nodiscard]] static bool questionEchoMatches(std::span<const uint8_t> queryWire,
                                                      std::span<const uint8_t> respWire) noexcept
        {
            if (queryWire.size() < 12 || respWire.size() < 12)
                return false;
            // 检查 QDCOUNT 是否为 1
            uint16_t qdQuery = (static_cast<uint16_t>(queryWire[4]) << 8) | queryWire[5];
            uint16_t qdResp = (static_cast<uint16_t>(respWire[4]) << 8) | respWire[5];
            if (qdQuery != 1 || qdResp != 1)
                return false;

            // 提取 Question Section (从 offset 12 开始直到结尾 QTYPE+QCLASS 4 字节)
            size_t qLenQuery = 12;
            while (qLenQuery < queryWire.size())
            {
                uint8_t len = queryWire[qLenQuery];
                if (len == 0)
                {
                    qLenQuery += 5; // 0x00 + QTYPE(2) + QCLASS(2)
                    break;
                }
                if ((len & 0xC0) == 0xC0)
                {
                    qLenQuery += 6; // 指针压缩 + QTYPE(2) + QCLASS(2)
                    break;
                }
                qLenQuery += (1 + len);
            }
            if (qLenQuery > queryWire.size())
                return false;

            size_t qLenResp = 12;
            while (qLenResp < respWire.size())
            {
                uint8_t len = respWire[qLenResp];
                if (len == 0)
                {
                    qLenResp += 5;
                    break;
                }
                if ((len & 0xC0) == 0xC0)
                {
                    qLenResp += 6;
                    break;
                }
                qLenResp += (1 + len);
            }
            if (qLenResp > respWire.size())
                return false;

            // 长度必须相等且内容完全一致
            size_t qSectionLen = qLenQuery - 12;
            if (qSectionLen != (qLenResp - 12))
                return false;

            return std::memcmp(queryWire.data() + 12, respWire.data() + 12, qSectionLen) == 0;
        }

        /**
         * @brief 判定响应是否为超时释放后的迟到投递 (Late Delivery Protection)
         */
        [[nodiscard]] static bool isLateDelivery(uint16_t respId, const DnsIdBitmap &bitmap) noexcept
        {
            return !bitmap.isAllocated(respId);
        }
    };

    /**
     * @brief EDNS0 缓冲区容量超限自动截断工具 (借鉴 dae truncateDnsResponse)
     *
     * 当 DNS 响应超出客户端声明的 EDNS0 UDP 缓冲区上限 (或传统 512 字节限制) 时：
     * 1. 设置 DNS 头部 TC=1 (Truncated) 标志位；
     * 2. 清空 Answer/Authority/Additional 计数；
     * 3. 截断保留 Question 段，引导客户端无损升级至 TCP 重试。
     */
    [[nodiscard]] inline std::vector<uint8_t> truncateDnsResponse(std::span<const uint8_t> fullWire,
                                                                  size_t maxBufferSize = 512) noexcept
    {
        if (fullWire.size() <= maxBufferSize || fullWire.size() < 12)
        {
            return std::vector<uint8_t>(fullWire.begin(), fullWire.end());
        }

        // 定位 Question 段结尾
        size_t qEnd = 12;
        while (qEnd < fullWire.size())
        {
            uint8_t len = fullWire[qEnd];
            if (len == 0)
            {
                qEnd += 5; // 0x00 + QTYPE(2) + QCLASS(2)
                break;
            }
            if ((len & 0xC0) == 0xC0)
            {
                qEnd += 6;
                break;
            }
            qEnd += (1 + len);
        }
        if (qEnd > fullWire.size())
        {
            qEnd = 12;
        }

        std::vector<uint8_t> truncated(fullWire.begin(), fullWire.begin() + qEnd);
        // 置位 TC=1: byte 2 bit 1
        truncated[2] |= 0x02;
        // 清空 ANCOUNT, NSCOUNT, ARCOUNT 为 0
        truncated[6] = 0;
        truncated[7] = 0;
        truncated[8] = 0;
        truncated[9] = 0;
        truncated[10] = 0;
        truncated[11] = 0;
        return truncated;
    }

} // namespace mynet::handler::dns
