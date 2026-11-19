#pragma once

/**
 * @file ech.hpp
 * @brief ECH (Encrypted Client Hello) HTTPS/SVCB DNS 反向映射引擎 (借鉴 sing-box dns/router.go)
 *
 * 核心机制：
 * 1. 在 TLS 1.3 ECH 时代，客户端访问 real domain (如 secret.example.com)，
 *    外层未加密 ClientHello 仅携带 public_name (如 cloudflare-ech.com)，直接嗅探会导致分流路由误判；
 * 2. 在 DNS 解析阶阶段记录 Type 65 (HTTPS) 记录中的 ECH public_name 与真实域名的关联及解析 IP；
 * 3. 建立内存高速双向关联表：当后续入站连接携带 public_name 时，
 *    根据目标 IP 与时间窗口精准反查还原客户端真正的访问域名，彻底解决 ECH 场景下的透明分流路由失准问题。
 */

#include <cstdint>
#include <string>
#include <string_view>
#include <optional>
#include <unordered_map>
#include <mutex>
#include <chrono>

namespace mynet::dns
{

    struct EchMappingEntry
    {
        std::string realDomain{};
        std::string publicName{};
        uint32_t ip{0};
        std::chrono::steady_clock::time_point expireAt{};
    };

    class EchReverseMapper
    {
    private:
        // 以 IP + public_name 为复合主键
        struct EchKey
        {
            uint32_t ip{0};
            std::string publicName{};

            bool operator==(const EchKey& o) const noexcept
            {
                return ip == o.ip && publicName == o.publicName;
            }
        };

        struct EchKeyHash
        {
            size_t operator()(const EchKey& k) const noexcept
            {
                size_t h = std::hash<std::string>{}(k.publicName);
                h ^= static_cast<size_t>(k.ip) + 0x9e3779b9 + (h << 6) + (h >> 2);
                return h;
            }
        };

        static constexpr size_t MAX_CAPACITY = 65536;

        mutable std::mutex mutex_{};
        std::unordered_map<EchKey, EchMappingEntry, EchKeyHash> table_{};
        std::unordered_map<std::string, size_t> publicNameRefCount_{};

        void purgeExpiredLocked(std::chrono::steady_clock::time_point now) noexcept
        {
            for (auto it = table_.begin(); it != table_.end(); )
            {
                if (it->second.expireAt <= now)
                {
                    auto refIt = publicNameRefCount_.find(it->first.publicName);
                    if (refIt != publicNameRefCount_.end() && refIt->second > 0)
                    {
                        refIt->second--;
                        if (refIt->second == 0) publicNameRefCount_.erase(refIt);
                    }
                    it = table_.erase(it);
                }
                else
                {
                    ++it;
                }
            }
        }

    public:
        static EchReverseMapper& instance() noexcept
        {
            static EchReverseMapper s_inst;
            return s_inst;
        }

        /**
         * @brief 记录 DNS 阶段获知的 ECH public_name 映射关系
         *
         * @param realDomain 客户端真实请求的域名 (如 "chat.openai.com")
         * @param publicName ECH 配置中的公共域名 (如 "cloudflare-ech.com")
         * @param ip 解析得到的目的 IP (主机字节序)
         * @param ttl 缓存有效期 (秒)
         */
        void recordMapping(
            std::string_view realDomain,
            std::string_view publicName,
            uint32_t ip,
            std::chrono::seconds ttl = std::chrono::seconds(300)) noexcept
        {
            if (realDomain.empty() || publicName.empty() || realDomain == publicName)
            {
                return;
            }

            const auto now = std::chrono::steady_clock::now();
            EchKey key{ip, std::string(publicName)};

            std::lock_guard<std::mutex> lock(mutex_);
            if (table_.size() >= MAX_CAPACITY)
            {
                purgeExpiredLocked(now);
                if (table_.size() >= MAX_CAPACITY)
                {
                    auto victim = table_.begin();
                    auto refIt = publicNameRefCount_.find(victim->first.publicName);
                    if (refIt != publicNameRefCount_.end() && refIt->second > 0)
                    {
                        refIt->second--;
                        if (refIt->second == 0) publicNameRefCount_.erase(refIt);
                    }
                    table_.erase(victim);
                }
            }

            auto it = table_.find(key);
            if (it == table_.end())
            {
                publicNameRefCount_[std::string(publicName)]++;
            }

            table_[key] = EchMappingEntry{
                .realDomain = std::string(realDomain),
                .publicName = std::string(publicName),
                .ip = ip,
                .expireAt = now + ttl
            };
        }

        /**
         * @brief 根据入站报文嗅探出的外层 public_name 和目标 IP，反查客户端真正的域名
         */
        [[nodiscard]] std::optional<std::string> lookupRealDomain(
            std::string_view publicName,
            uint32_t ip) const noexcept
        {
            if (publicName.empty()) return std::nullopt;

            const auto now = std::chrono::steady_clock::now();
            EchKey key{ip, std::string(publicName)};

            std::lock_guard<std::mutex> lock(mutex_);
            auto it = table_.find(key);
            if (it != table_.end())
            {
                if (it->second.expireAt > now)
                {
                    return it->second.realDomain;
                }
            }
            return std::nullopt;
        }

        /**
         * @brief 快速检查某域名是否被已知作为 ECH 的 Public Name 使用
         */
        [[nodiscard]] bool isKnownPublicName(std::string_view publicName) const noexcept
        {
            if (publicName.empty()) return false;
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = publicNameRefCount_.find(std::string(publicName));
            return it != publicNameRefCount_.end() && it->second > 0;
        }

        /**
         * @brief 清空已过期的映射项
         */
        void purgeExpired() noexcept
        {
            const auto now = std::chrono::steady_clock::now();
            std::lock_guard<std::mutex> lock(mutex_);
            purgeExpiredLocked(now);
        }

        void clear() noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            table_.clear();
            publicNameRefCount_.clear();
        }
    };

} // namespace mynet::dns
