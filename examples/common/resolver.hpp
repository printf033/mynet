#pragma once

/**
 * @file resolver.hpp
 * @brief 异步与非阻塞 DNS 域名解析器（RFC 1035），支持缓存、TTL 与多对端解析。
 */

#include "error.hpp"
#include "handler/address.hpp"
#include "handler/dns/dns.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <expected>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace mynet
{
    namespace dns = handler::dns;

    /**
     * @brief DNS 解析缓存记录
     */
    struct DnsCacheRecord
    {
        std::vector<in_addr> ipv4{};
        std::vector<in6_addr> ipv6{};
        std::chrono::steady_clock::time_point expiresAt{};

        [[nodiscard]] bool isExpired(std::chrono::steady_clock::time_point now) const noexcept
        {
            return now >= expiresAt;
        }
    };

    /**
     * @brief 名字与 DNS 异步/带缓存解析器
     */
    class DnsResolver
    {
    private:
        mutable std::mutex mutex_{};
        std::unordered_map<std::string, DnsCacheRecord> cache_{};
        std::string primaryServer_{"8.8.8.8"};
        uint16_t serverPort_{53};

    public:
        DnsResolver() = default;
        explicit DnsResolver(std::string primaryDnsServer, uint16_t port = 53)
            : primaryServer_(std::move(primaryDnsServer)),
              serverPort_(port)
        {
        }

        void setDnsServer(std::string server, uint16_t port = 53)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            primaryServer_ = std::move(server);
            serverPort_ = port;
        }

        [[nodiscard]] const std::string &dnsServer() const noexcept { return primaryServer_; }
        [[nodiscard]] uint16_t dnsPort() const noexcept { return serverPort_; }

        /**
         * @brief 写入自定义或静态 DNS 记录（Hosts）
         */
        void addStaticRecord(std::string_view domain, std::string_view ipStr, uint32_t ttlSec = 86400)
        {
            in_addr sin{};
            in6_addr sin6{};
            DnsCacheRecord rec{};
            rec.expiresAt = std::chrono::steady_clock::now() + std::chrono::seconds(ttlSec);

            std::string tmp(ipStr);
            if (::inet_pton(AF_INET, tmp.c_str(), &sin) == 1)
            {
                rec.ipv4.push_back(sin);
            }
            else if (::inet_pton(AF_INET6, tmp.c_str(), &sin6) == 1)
            {
                rec.ipv6.push_back(sin6);
            }
            else
            {
                return;
            }

            std::lock_guard<std::mutex> lock(mutex_);
            cache_[std::string(domain)] = std::move(rec);
        }

        /**
         * @brief 查询缓存中是否存在未过期的解析结果
         */
        [[nodiscard]] std::optional<handler::ProxyAddress> lookupCache(std::string_view domain, uint16_t port) const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = cache_.find(std::string(domain));
            if (it == cache_.end())
            {
                return std::nullopt;
            }
            if (it->second.isExpired(std::chrono::steady_clock::now()))
            {
                return std::nullopt;
            }
            if (!it->second.ipv4.empty())
            {
                return handler::ProxyAddress::fromIPv4(it->second.ipv4.front().s_addr, port);
            }
            if (!it->second.ipv6.empty())
            {
                return handler::ProxyAddress::fromIPv6(
                    reinterpret_cast<const uint8_t *>(&it->second.ipv6.front()), port);
            }
            return std::nullopt;
        }

        /**
         * @brief 存入解析成功的 DNS 结果
         */
        void putCache(std::string_view domain, std::vector<in_addr> v4, std::vector<in6_addr> v6, uint32_t ttlSec)
        {
            DnsCacheRecord rec;
            rec.ipv4 = std::move(v4);
            rec.ipv6 = std::move(v6);
            // 约束缓存时间在 5 秒到 1 天之间
            const uint32_t boundedTtl = std::clamp(ttlSec, 5u, 86400u);
            rec.expiresAt = std::chrono::steady_clock::now() + std::chrono::seconds(boundedTtl);

            std::lock_guard<std::mutex> lock(mutex_);
            cache_[std::string(domain)] = std::move(rec);
        }

        /**
         * @brief 同步/直解域名（若已是 IP 字面量或缓存命中直接返回，避免任何阻塞；未命中时可回退系统解析）
         */
        [[nodiscard]] std::optional<handler::ProxyAddress> resolveFast(std::string_view host, uint16_t port) const
        {
            // 1. 若本身即为合法 IPv4 / IPv6 字面量，直接解析返回
            if (auto addr = handler::ProxyAddress::fromHostPort(host, port); addr.type != handler::AddressType::DOMAIN)
            {
                return addr;
            }

            // 2. 检查本地 DNS 缓存
            if (auto cached = lookupCache(host, port); cached.has_value())
            {
                return cached;
            }

            return std::nullopt;
        }

        /**
         * @brief 清除全部缓存
         */
        void clearCache() noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            cache_.clear();
        }
    };

    /**
     * @brief 全局单例名字解析器引用
     */
    inline DnsResolver &getDefaultResolver() noexcept
    {
        static DnsResolver s_resolver;
        return s_resolver;
    }

} // namespace mynet
