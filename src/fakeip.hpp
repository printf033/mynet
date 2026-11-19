#pragma once

/**
 * @file fakeip.hpp
 * @brief 高性能 FakeIP 虚拟地址池管理器 (Fake-IP Engine)。
 *
 * 遵循 RFC 6333 / 198.18.0.0/15 规范，借鉴 sing-box 与 dae 的透明代理设计：
 * 1. 消除 DNS 本地解析等待延迟：收到 DNS A 查询请求时立即分配并返回 198.18.0.0/15 虚拟私有 IP；
 * 2. 100% 准确策略分流：客户端向 FakeIP 发起 TCP/UDP 连接时，内核在路由分流前毫秒级反查出原始域名；
 * 3. 规避 DNS 污染与 CDN 调度偏差：真实 DNS 解析交由远端出站节点执行；
 * 4. 线程安全、LRU 自动淘汰机制与毫秒级双向极速索引 (Domain <-> FakeIP)。
 */

#include "error.hpp"
#include "configHolder.hpp"
#include "address.hpp"
#include <arpa/inet.h>
#include <cstdint>
#include <list>
#include <mutex>
#include <netinet/in.h>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace mynet
{

    /**
     * @brief FakeIP 虚拟地址池管理器
     */
    class FakeIPPool
    {
    public:
        // 198.18.0.0/15 保留地址段定义
        static constexpr uint32_t kPoolStart = 0xC6120001; // 198.18.0.1
        static constexpr uint32_t kPoolEnd   = 0xC613FFFE; // 198.19.255.254
        static constexpr uint32_t kPoolMask  = 0xFFFE0000; // 255.254.0.0
        static constexpr uint32_t kPoolNet   = 0xC6120000; // 198.18.0.0

    private:
        mutable std::mutex mutex_{};
        uint32_t currentIp_{kPoolStart};

        std::unordered_map<std::string, uint32_t> domainToIp_{};
        std::unordered_map<uint32_t, std::string> ipToDomain_{};
        std::list<uint32_t> lruList_{};
        std::unordered_map<uint32_t, std::list<uint32_t>::iterator> ipToLru_{};
        size_t maxCapacity_{65534};

    public:
        explicit FakeIPPool(size_t maxCap = 65534) noexcept : maxCapacity_(maxCap) {}
        ~FakeIPPool() noexcept = default;

        FakeIPPool(const FakeIPPool &) = delete;
        FakeIPPool &operator=(const FakeIPPool &) = delete;
        FakeIPPool(FakeIPPool &&) = delete;
        FakeIPPool &operator=(FakeIPPool &&) = delete;

        /**
         * @brief 单例访问入口
         */
        [[nodiscard]] static FakeIPPool &instance() noexcept
        {
            static FakeIPPool s_pool;
            return s_pool;
        }

        inline void applyConfig(const FakeIPConfig &cfg) noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            maxCapacity_ = cfg.maxCapacity;
        }

        inline void setMaxCapacity(size_t maxCap) noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            maxCapacity_ = maxCap;
        }

        [[nodiscard]] inline size_t maxCapacity() const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return maxCapacity_;
        }

        /**
         * @brief 判定目标 IPv4 是否属于 FakeIP (198.18.0.0/15) 保留地址范围
         */
        [[nodiscard]] inline bool isFakeIp(in_addr ip) const noexcept
        {
            return (ntohl(ip.s_addr) & kPoolMask) == kPoolNet;
        }

        [[nodiscard]] inline bool isFakeIp(uint32_t ipHostOrder) const noexcept
        {
            return (ipHostOrder & kPoolMask) == kPoolNet;
        }

        /**
         * @brief 为指定域名分配或复用一个 Fake IPv4 地址
         *
         * @param domain 请求的目标域名
         * @return in_addr 分配的 FakeIP（网络字节序）
         */
        in_addr allocate(std::string_view domain)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            std::string domStr(domain);

            // 若已有活跃映射，刷新 LRU 并直接返回
            if (auto it = domainToIp_.find(domStr); it != domainToIp_.end())
            {
                touchLru(it->second);
                in_addr sin{};
                sin.s_addr = htonl(it->second);
                return sin;
            }

            // 达到容量上限时，淘汰最老 LRU 项
            if (ipToDomain_.size() >= maxCapacity_)
            {
                evictOldest();
            }

            // 递增寻找下一个未被占用的 IP
            uint32_t candidate = currentIp_;
            while (ipToDomain_.contains(candidate))
            {
                candidate = (candidate >= kPoolEnd) ? kPoolStart : (candidate + 1);
                if (candidate == currentIp_)
                {
                    evictOldest();
                    break;
                }
            }
            currentIp_ = (candidate >= kPoolEnd) ? kPoolStart : (candidate + 1);

            domainToIp_[domStr] = candidate;
            ipToDomain_[candidate] = domStr;
            lruList_.push_front(candidate);
            ipToLru_[candidate] = lruList_.begin();

            in_addr sin{};
            sin.s_addr = htonl(candidate);
            return sin;
        }

        /**
         * @brief 根据 FakeIP 反查其绑定的原始域名
         */
        [[nodiscard]] std::optional<std::string> lookup(in_addr ip) const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            const uint32_t hIp = ntohl(ip.s_addr);
            auto it = ipToDomain_.find(hIp);
            if (it != ipToDomain_.end())
            {
                return it->second;
            }
            return std::nullopt;
        }

        /**
         * @brief 根据域名查询当前已分配的 FakeIP
         */
        [[nodiscard]] std::optional<in_addr> lookupIp(std::string_view domain) const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = domainToIp_.find(std::string(domain));
            if (it != domainToIp_.end())
            {
                in_addr sin{};
                sin.s_addr = htonl(it->second);
                return sin;
            }
            return std::nullopt;
        }

        [[nodiscard]] size_t size() const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return ipToDomain_.size();
        }

        void reset() noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            domainToIp_.clear();
            ipToDomain_.clear();
            lruList_.clear();
            ipToLru_.clear();
            currentIp_ = kPoolStart;
        }

    private:
        void touchLru(uint32_t ip)
        {
            if (auto it = ipToLru_.find(ip); it != ipToLru_.end())
            {
                lruList_.erase(it->second);
                lruList_.push_front(ip);
                it->second = lruList_.begin();
            }
        }

        void evictOldest()
        {
            if (lruList_.empty()) return;
            const uint32_t oldestIp = lruList_.back();
            lruList_.pop_back();
            ipToLru_.erase(oldestIp);

            if (auto it = ipToDomain_.find(oldestIp); it != ipToDomain_.end())
            {
                domainToIp_.erase(it->second);
                ipToDomain_.erase(it);
            }
        }
    };

} // namespace mynet
