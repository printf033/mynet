#pragma once

/**
 * @file outboundManager.hpp
 * @brief 拨号器管理器 (DialerManager) 与出站调度节点。
 *
 * 与 AcceptorManager 形成严格对称的架构设计：
 * 1. 统一拨号抽象：提供面向流式 (TCP) 与数据报 (UDP) 的异步非阻塞出站建连；
 * 2. 状态机就绪装配：拨号成功后自动构造匹配的出站协议状态机处理器 (HandlerOutboundConnection)；
 * 3. 统一出口策略：支持通过 DialerOptions 下发 Linux SO_MARK 策略路由打标、绑定物理网卡与超时；
 * 4. 节点调度与选择器：原生支持 Selector、UrlTest 与 Fallback 等节点调度组；
 * 5. 全生命周期描述符托管：确保套接字在拨号成功时通过 release() 安全转移给上层会话。
 */

#include "address.hpp"
#include "config/log.hpp"
#include "connection.hpp"
#include "dialer.hpp"
#include "error.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <netdb.h>
#include <netinet/in.h>
#include <optional>
#include <poll.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

namespace mynet
{

    /**
     * @brief 出站域名解析辅助函数（将域名解析为 IPv4 地址）
     */
    inline Result<in_addr> resolveDomainIpv4(std::string_view domain) noexcept
    {
        return Dialer::resolveIpv4Public(domain, SOCK_STREAM);
    }

    class DialerManager;

    /**
     * @brief 节点选择器 / 分组出站 (DialerSelector)
     */
    class DialerSelector : public Dialer
    {
    private:
        std::vector<std::string> candidateTags_{};
        std::string selectedTag_{};
        DialerManager *manager_{nullptr};

    public:
        DialerSelector(std::string tag, std::vector<std::string> candidates, DialerManager *mgr = nullptr)
            : Dialer(std::move(tag), "selector"),
              candidateTags_(std::move(candidates)),
              manager_(mgr)
        {
            if (!candidateTags_.empty())
            {
                selectedTag_ = candidateTags_.front();
            }
        }

        inline void setManager(DialerManager *mgr) noexcept override { manager_ = mgr; }
        [[nodiscard]] inline const std::vector<std::string> &candidates() const noexcept { return candidateTags_; }
        [[nodiscard]] inline std::string_view selected() const noexcept { return selectedTag_; }

        inline bool setSelected(std::string_view tag)
        {
            for (const auto &c : candidateTags_)
            {
                if (c == tag)
                {
                    selectedTag_ = tag;
                    return true;
                }
            }
            return false;
        }

        Result<> start() noexcept override
        {
            if (selectedTag_.empty() && !candidateTags_.empty())
            {
                selectedTag_ = candidateTags_.front();
            }
            return Dialer::start();
        }

        Result<OutboundDialResult> dialStream(const handler::ProxyAddress &target) override;
        Result<int> dialDatagram(const handler::ProxyAddress &target) override;
    };

    /**
     * @brief O(1) 环形滑动窗口延迟采样统计器 (借鉴 dae LatenciesN, 机制 64)
     *
     * 维护定长 N 次历史延迟样本，实时维护窗口总和 sum_，
     * 样本插入、最新样本获取与滑动均值计算均为严格 O(1) 复杂度。
     */
    template <size_t N = 10>
    class LatenciesN
    {
        static_assert(N > 0, "LatenciesN window size must be greater than 0");

    private:
        std::array<uint32_t, N> samples_{};
        size_t head_{0};
        size_t count_{0};
        uint64_t sum_{0};

    public:
        constexpr LatenciesN() noexcept = default;

        void add(uint32_t latencyMs) noexcept
        {
            if (count_ < N)
            {
                samples_[head_] = latencyMs;
                sum_ += latencyMs;
                count_++;
                head_ = (head_ + 1) % N;
            }
            else
            {
                sum_ -= samples_[head_];
                samples_[head_] = latencyMs;
                sum_ += latencyMs;
                head_ = (head_ + 1) % N;
            }
        }

        [[nodiscard]] uint32_t average() const noexcept
        {
            if (count_ == 0)
                return 9999;
            return static_cast<uint32_t>(sum_ / count_);
        }

        [[nodiscard]] uint32_t latest() const noexcept
        {
            if (count_ == 0)
                return 9999;
            size_t idx = (head_ + N - 1) % N;
            return samples_[idx];
        }

        [[nodiscard]] size_t size() const noexcept { return count_; }
        [[nodiscard]] constexpr size_t capacity() const noexcept { return N; }

        void reset() noexcept
        {
            samples_.fill(0);
            head_ = 0;
            count_ = 0;
            sum_ = 0;
        }
    };

    /**
     * @brief 出站节点选路策略 (借鉴 dae DialerSelectionPolicy)
     */
    enum class DialerSelectionPolicy : uint8_t
    {
        MIN = 0,       ///< 瞬时延迟最低最优 (默认，严格对齐 dae 行为)
        MIN_AVG10 = 1, ///< 10 样本滑动平均延迟最优 (Min Avg 10)
        RANDOM = 2     ///< 随机分发
    };

    /**
     * @brief URL 延迟测速自动优选出站 (DialerUrlTest, 结合机制 63 容差阻尼窗口与机制 64 LatenciesN)
     */
    class DialerUrlTest : public Dialer
    {
    private:
        std::vector<std::string> candidateTags_{};
        DialerManager *manager_{nullptr};
        std::string testUrl_{"http://cp.cloudflare.com/generate_204"};
        uint32_t intervalSecs_{300};
        uint32_t toleranceMs_{0};
        DialerSelectionPolicy policy_{DialerSelectionPolicy::MIN};

        mutable std::mutex rttMutex_{};
        mutable std::string currentBestTag_{};
        std::unordered_map<std::string, uint32_t> rttMap_{};
        std::unordered_map<std::string, LatenciesN<10>> latenciesMap_{};

    public:
        DialerUrlTest(std::string tag, std::vector<std::string> candidates, DialerManager *mgr = nullptr,
                      std::string url = "http://cp.cloudflare.com/generate_204", uint32_t intervalSecs = 300,
                      uint32_t toleranceMs = 0, DialerSelectionPolicy policy = DialerSelectionPolicy::MIN)
            : Dialer(std::move(tag), "urltest"),
              candidateTags_(std::move(candidates)),
              manager_(mgr),
              testUrl_(std::move(url)),
              intervalSecs_(intervalSecs),
              toleranceMs_(toleranceMs),
              policy_(policy)
        {
            for (const auto &c : candidateTags_)
            {
                rttMap_[c] = 9999;
                latenciesMap_[c] = LatenciesN<10>{};
            }
            if (!candidateTags_.empty())
            {
                currentBestTag_ = candidateTags_.front();
            }
        }

        inline void setManager(DialerManager *mgr) noexcept override { manager_ = mgr; }
        [[nodiscard]] inline const std::vector<std::string> &candidates() const noexcept { return candidateTags_; }
        [[nodiscard]] inline const std::string &testUrl() const noexcept { return testUrl_; }
        [[nodiscard]] inline uint32_t intervalSecs() const noexcept { return intervalSecs_; }
        [[nodiscard]] inline uint32_t toleranceMs() const noexcept { return toleranceMs_; }
        inline void setToleranceMs(uint32_t tolMs) noexcept { toleranceMs_ = tolMs; }
        inline void setSelectionPolicy(DialerSelectionPolicy p) noexcept { policy_ = p; }
        [[nodiscard]] inline DialerSelectionPolicy selectionPolicy() const noexcept { return policy_; }

        inline void setRtt(std::string_view tag, uint32_t rttMs)
        {
            std::lock_guard<std::mutex> lock(rttMutex_);
            std::string t(tag);
            rttMap_[t] = rttMs;
            latenciesMap_[t].add(rttMs);
        }

        [[nodiscard]] inline uint32_t getRtt(std::string_view tag) const
        {
            std::lock_guard<std::mutex> lock(rttMutex_);
            auto it = rttMap_.find(std::string(tag));
            return (it != rttMap_.end()) ? it->second : 9999;
        }

        [[nodiscard]] inline uint32_t getAverageRtt(std::string_view tag) const
        {
            std::lock_guard<std::mutex> lock(rttMutex_);
            auto it = latenciesMap_.find(std::string(tag));
            if (it != latenciesMap_.end() && it->second.size() > 0)
            {
                return it->second.average();
            }
            auto itOld = rttMap_.find(std::string(tag));
            return (itOld != rttMap_.end()) ? itOld->second : 9999;
        }

        [[nodiscard]] inline uint32_t getLatestRtt(std::string_view tag) const
        {
            std::lock_guard<std::mutex> lock(rttMutex_);
            auto it = latenciesMap_.find(std::string(tag));
            if (it != latenciesMap_.end() && it->second.size() > 0)
            {
                return it->second.latest();
            }
            auto itOld = rttMap_.find(std::string(tag));
            return (itOld != rttMap_.end()) ? itOld->second : 9999;
        }

        [[nodiscard]] std::string getBestTag() const
        {
            std::lock_guard<std::mutex> lock(rttMutex_);
            if (candidateTags_.empty())
                return "";

            std::string best = currentBestTag_.empty() ? candidateTags_.front() : currentBestTag_;
            auto getScore = [&](const std::string &t) -> uint32_t
            {
                if (policy_ == DialerSelectionPolicy::MIN_AVG10)
                {
                    auto it = latenciesMap_.find(t);
                    if (it != latenciesMap_.end() && it->second.size() > 0)
                        return it->second.average();
                }
                auto it = rttMap_.find(t);
                return (it != rttMap_.end()) ? it->second : 9999;
            };

            uint32_t currentBestScore = getScore(best);
            std::string candidateBest = best;
            uint32_t minScore = currentBestScore;

            for (const auto &tag : candidateTags_)
            {
                uint32_t score = getScore(tag);
                if (score < minScore)
                {
                    minScore = score;
                    candidateBest = tag;
                }
            }

            // 机制 63: 容差窗口阻尼 (Tolerance Window Damping, 严格对齐 dae AliveDialerSet)
            // 仅当新候选节点的延迟优势达到或超过 toleranceMs_ 时才触发切换
            if (candidateBest != best)
            {
                if (currentBestScore == 9999 ||
                    minScore <= (currentBestScore > toleranceMs_ ? currentBestScore - toleranceMs_ : 0))
                {
                    currentBestTag_ = candidateBest;
                    return candidateBest;
                }
                return best; // 维持当前主节点不变，防止微小抖动引发路由震荡
            }

            currentBestTag_ = best;
            return best;
        }

        uint32_t probeNode(std::string_view tag, std::chrono::milliseconds timeout = std::chrono::milliseconds(2000));
        void probeAll(std::chrono::milliseconds timeout = std::chrono::milliseconds(2000));

        Result<> start() noexcept override { return Dialer::start(); }

        Result<OutboundDialResult> dialStream(const handler::ProxyAddress &target) override;
        Result<int> dialDatagram(const handler::ProxyAddress &target) override;
    };

    /**
     * @brief 故障按序回退出站 (DialerFallback)
     */
    class DialerFallback : public Dialer
    {
    private:
        std::vector<std::string> candidateTags_{};
        DialerManager *manager_{nullptr};

    public:
        DialerFallback(std::string tag, std::vector<std::string> candidates, DialerManager *mgr = nullptr)
            : Dialer(std::move(tag), "fallback"),
              candidateTags_(std::move(candidates)),
              manager_(mgr)
        {
        }

        inline void setManager(DialerManager *mgr) noexcept override { manager_ = mgr; }
        [[nodiscard]] inline const std::vector<std::string> &candidates() const noexcept { return candidateTags_; }

        Result<> start() noexcept override { return Dialer::start(); }

        Result<OutboundDialResult> dialStream(const handler::ProxyAddress &target) override;
        Result<int> dialDatagram(const handler::ProxyAddress &target) override;
    };

} // namespace mynet

// 拆分到各协议独立目录下的具体出站端点实现
#include "block/outbound.hpp"
#include "direct/outbound.hpp"
#include "http/outbound.hpp"
#include "hysteria2/outbound.hpp"
#include "shadowsocks/outbound.hpp"
#include "socks/outbound.hpp"
#include "trojan/outbound.hpp"
#include "vless/outbound.hpp"
#include "vmess/outbound.hpp"

namespace mynet
{

    /**
     * @brief 统一拨号器管理器 (DialerManager)
     *
     * 维护系统所有出站节点的注册表，默认自动预置 direct 与 block 两个标准出口。
     */
    class DialerManager
    {
    private:
        mutable std::mutex mutex_{};
        std::unordered_map<std::string, std::shared_ptr<Dialer>> dialers_{};
        std::string defaultTag_{"direct"};
        std::atomic<bool> running_{false};

    public:
        DialerManager()
        {
            // 默认自动装配 direct 与 block 标准出口
            registerDialer(std::make_shared<DialerDirect>("direct"));
            registerDialer(std::make_shared<DialerBlock>("block"));
        }

        ~DialerManager() noexcept { stopAll(); }

        DialerManager(const DialerManager &) = delete;
        DialerManager &operator=(const DialerManager &) = delete;
        DialerManager(DialerManager &&) = delete;
        DialerManager &operator=(DialerManager &&) = delete;

        /**
         * @brief 批量启动所有注册的出站节点生命周期
         */
        Result<> startAll() noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto &[tag, dl] : dialers_)
            {
                if (dl != nullptr)
                {
                    auto res = dl->start();
                    if (!res)
                    {
                        return res;
                    }
                }
            }
            running_.store(true, std::memory_order_release);
            return {};
        }

        /**
         * @brief 批量停止所有出站节点生命周期
         */
        void stopAll() noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto &[tag, dl] : dialers_)
            {
                if (dl != nullptr)
                {
                    dl->stop();
                }
            }
            running_.store(false, std::memory_order_release);
        }

        void clear() noexcept
        {
            stopAll();
            {
                std::lock_guard<std::mutex> lock(mutex_);
                dialers_.clear();
                defaultTag_ = "direct";
            }
            registerDialer(std::make_shared<DialerDirect>("direct"));
            registerDialer(std::make_shared<DialerBlock>("block"));
        }

        [[nodiscard]] inline bool isRunning() const noexcept { return running_.load(std::memory_order_acquire); }

        [[nodiscard]] inline std::string_view defaultTag() const noexcept { return defaultTag_; }
        inline void setDefaultTag(std::string tag)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            defaultTag_ = std::move(tag);
        }

        /**
         * @brief 注册一个拨号器节点 (Dialer)
         */
        void registerDialer(std::shared_ptr<Dialer> dialer)
        {
            if (dialer == nullptr)
                return;
            std::lock_guard<std::mutex> lock(mutex_);
            dialer->setManager(this);
            dialers_[dialer->tag()] = std::move(dialer);
        }

        /**
         * @brief 根据标签获取出站节点指针
         */
        [[nodiscard]] std::shared_ptr<Dialer> get(std::string_view tag) const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = dialers_.find(std::string(tag));
            return (it != dialers_.end()) ? it->second : nullptr;
        }

        /**
         * @brief 根据标签获取拨号器节点指针
         */
        [[nodiscard]] inline std::shared_ptr<Dialer> getDialer(std::string_view tag) const
        {
            return get(tag);
        }

        [[nodiscard]] bool has(std::string_view tag) const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return dialers_.contains(std::string(tag));
        }

        inline void remove(std::string_view tag)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            dialers_.erase(std::string(tag));
        }

        [[nodiscard]] size_t size() const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return dialers_.size();
        }

        [[nodiscard]] std::vector<std::shared_ptr<Dialer>> dialers() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            std::vector<std::shared_ptr<Dialer>> list;
            list.reserve(dialers_.size());
            for (const auto &pair : dialers_)
            {
                list.push_back(pair.second);
            }
            return list;
        }

        [[nodiscard]] std::vector<std::string> listTags() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            std::vector<std::string> tags;
            tags.reserve(dialers_.size());
            for (const auto &pair : dialers_)
            {
                tags.push_back(pair.first);
            }
            return tags;
        }

        /**
         * @brief 根据出站标签与目标地址发起流式出站建连
         */
        Result<OutboundDialResult> dialStream(std::string_view tag, const handler::ProxyAddress &target)
        {
            std::shared_ptr<Dialer> dl = get(tag);
            if (dl == nullptr)
            {
                dl = get(defaultTag_);
            }
            if (dl == nullptr)
            {
                return std::unexpected(ERR::CONNECT_FAILED);
            }
            return dl->dialStream(target);
        }

        /**
         * @brief 根据出站标签与目标地址发起数据报出站建连
         */
        Result<int> dialDatagram(std::string_view tag, const handler::ProxyAddress &target)
        {
            std::shared_ptr<Dialer> dl = get(tag);
            if (dl == nullptr)
            {
                dl = get(defaultTag_);
            }
            if (dl == nullptr)
            {
                return std::unexpected(ERR::CONNECT_FAILED);
            }
            return dl->dialDatagram(target);
        }
    };

    // DialerSelector 延迟实现
    inline Result<OutboundDialResult> DialerSelector::dialStream(const handler::ProxyAddress &target)
    {
        if (manager_ == nullptr || selectedTag_.empty())
        {
            return std::unexpected(ERR::CONNECT_FAILED);
        }
        return manager_->dialStream(selectedTag_, target);
    }

    inline Result<int> DialerSelector::dialDatagram(const handler::ProxyAddress &target)
    {
        if (manager_ == nullptr || selectedTag_.empty())
        {
            return std::unexpected(ERR::CONNECT_FAILED);
        }
        return manager_->dialDatagram(selectedTag_, target);
    }

    // DialerUrlTest 延迟实现
    inline Result<OutboundDialResult> DialerUrlTest::dialStream(const handler::ProxyAddress &target)
    {
        if (manager_ == nullptr)
        {
            return std::unexpected(ERR::CONNECT_FAILED);
        }
        std::string best = getBestTag();
        if (best.empty())
        {
            return std::unexpected(ERR::CONNECT_FAILED);
        }
        return manager_->dialStream(best, target);
    }

    inline Result<int> DialerUrlTest::dialDatagram(const handler::ProxyAddress &target)
    {
        if (manager_ == nullptr)
        {
            return std::unexpected(ERR::CONNECT_FAILED);
        }
        std::string best = getBestTag();
        if (best.empty())
        {
            return std::unexpected(ERR::CONNECT_FAILED);
        }
        return manager_->dialDatagram(best, target);
    }

    inline uint32_t DialerUrlTest::probeNode(std::string_view tag, std::chrono::milliseconds timeout)
    {
        if (manager_ == nullptr)
            return 9999;
        auto outbound = manager_->get(tag);
        if (!outbound)
            return 9999;

        if (outbound->type() == "direct")
        {
            setRtt(tag, 1);
            return 1;
        }
        if (outbound->type() == "block")
        {
            setRtt(tag, 9999);
            return 9999;
        }

        handler::ProxyAddress probeTarget;
        probeTarget.type = handler::AddressType::DOMAIN;
        probeTarget.host = "127.0.0.1";
        probeTarget.port = 80;

        const auto tStart = std::chrono::steady_clock::now();
        auto dialRes = outbound->dialStream(probeTarget);
        if (!dialRes)
        {
            setRtt(tag, 9999);
            return 9999;
        }

        if (dialRes->fd >= 0)
        {
            if (!dialRes->immediateConnected)
            {
                struct pollfd pfd{};
                pfd.fd = dialRes->fd;
                pfd.events = POLLOUT;
                int pr = ::poll(&pfd, 1, static_cast<int>(timeout.count()));
                if (pr <= 0 || (pfd.revents & (POLLERR | POLLHUP)))
                {
                    ::close(dialRes->fd);
                    setRtt(tag, 9999);
                    return 9999;
                }
            }
            ::close(dialRes->fd);
            const auto tEnd = std::chrono::steady_clock::now();
            auto elapsedMs =
                static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::milliseconds>(tEnd - tStart).count());
            if (elapsedMs == 0)
                elapsedMs = 1;
            setRtt(tag, elapsedMs);
            return elapsedMs;
        }
        return 9999;
    }

    inline void DialerUrlTest::probeAll(std::chrono::milliseconds timeout)
    {
        for (const auto &tag : candidateTags_)
        {
            probeNode(tag, timeout);
        }
    }

    // DialerFallback 延迟实现
    inline Result<OutboundDialResult> DialerFallback::dialStream(const handler::ProxyAddress &target)
    {
        if (manager_ == nullptr || candidateTags_.empty())
        {
            return std::unexpected(ERR::CONNECT_FAILED);
        }
        for (const auto &tag : candidateTags_)
        {
            auto res = manager_->dialStream(tag, target);
            if (res.has_value())
            {
                return res;
            }
        }
        return std::unexpected(ERR::CONNECT_FAILED);
    }

    inline Result<int> DialerFallback::dialDatagram(const handler::ProxyAddress &target)
    {
        if (manager_ == nullptr || candidateTags_.empty())
        {
            return std::unexpected(ERR::CONNECT_FAILED);
        }
        for (const auto &tag : candidateTags_)
        {
            auto res = manager_->dialDatagram(tag, target);
            if (res.has_value())
            {
                return res;
            }
        }
        return std::unexpected(ERR::CONNECT_FAILED);
    }

} // namespace mynet
