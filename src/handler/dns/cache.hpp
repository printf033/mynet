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
#include <chrono>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <netinet/in.h>
#include <optional>
#include <shared_mutex>
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

            [[nodiscard]] bool isExpired(std::chrono::steady_clock::time_point now) const noexcept
            {
                return now >= expiresAt;
            }
        };

    private:
        mutable std::shared_mutex rwLock_{};
        std::unordered_map<uint32_t, CacheItem> v4Cache_{};
        std::unordered_map<in6_addr, CacheItem, In6Hash, In6Equal> v6Cache_{};
        size_t maxEntries_{10000};

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
            const uint32_t boundedTtl = std::clamp(ttlSec, 5u, 86400u);
            const auto exp = std::chrono::steady_clock::now() + std::chrono::seconds(boundedTtl);

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
            const uint32_t boundedTtl = std::clamp(ttlSec, 5u, 86400u);
            const auto exp = std::chrono::steady_clock::now() + std::chrono::seconds(boundedTtl);

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
         * @brief 手动剔除过期记录
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
                if (it->second.isExpired(now))
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
                if (it->second.isExpired(now))
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

} // namespace mynet::handler::dns
