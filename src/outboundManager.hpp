#pragma once

/**
 * @file outboundManager.hpp
 * @brief 出站节点抽象基类 (OutboundBase) 与统一出站管理器 (OutboundManager)。
 *
 * 与 InboundManager 形成严格对称的架构设计：
 * 1. 统一拨号抽象：提供面向流式 (TCP) 与数据报 (UDP) 的异步非阻塞出站建连；
 * 2. 状态机就绪装配：拨号成功后自动构造匹配的出站协议状态机处理器 (HandlerOutboundConnectionBase)；
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
     * @brief 统一出站拨号选项策略 (Dialer Options)
     */
    struct DialerOptions
    {
        uint32_t fwmark{0};                      ///< Linux SO_MARK 策略路由打标（防止回环死锁）
        std::string bindInterface{};             ///< SO_BINDTODEVICE 绑定出口网卡 (例如 eth0, wan1)
        std::string bindAddress{};               ///< 绑定本地特定出口 IP 地址
        bool tcpFastOpen{false};                 ///< 是否启用 TCP Fast Open (MSG_FASTOPEN)
        std::chrono::milliseconds timeout{5000}; ///< 拨号超时
    };

    /**
     * @brief 出站拨号结果
     */
    struct OutboundDialResult
    {
        int fd{-1};                                    ///< 拨号成功的套接字描述符
        std::unique_ptr<HandlerBase> handler{nullptr}; ///< 对应的出站协议状态机处理器
        std::string outboundTag{};                     ///< 命中的出站标签
        std::string targetEndpoint{};                  ///< 目标端点字符串表示
        bool immediateConnected{false};                ///< 连接是否立即可用（已非阻塞连上）

        [[nodiscard]] inline bool ok() const noexcept { return handler != nullptr; }
    };

    /**
     * @brief 出站域名解析辅助函数（将域名解析为 IPv4 地址）
     */
    inline Result<in_addr> resolveDomainIpv4(std::string_view domain) noexcept
    {
        if (domain.empty())
        {
            return std::unexpected(ERR::ADDR_INVALID);
        }

        std::string domStr(domain);
        in_addr addr{};
        if (::inet_pton(AF_INET, domStr.c_str(), &addr) == 1)
        {
            return addr;
        }

        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo *res = nullptr;
        if (::getaddrinfo(domStr.c_str(), nullptr, &hints, &res) != 0 || res == nullptr)
        {
            return std::unexpected(ERR::ADDR_INVALID);
        }

        const auto *sin = reinterpret_cast<const sockaddr_in *>(res->ai_addr);
        addr = sin->sin_addr;
        ::freeaddrinfo(res);
        return addr;
    }

    /**
     * @brief 出站节点抽象基类 (Abstract Outbound Base)
     *
     * 业务出站端点元数据描述符与出站协议装配中心。
     * 底层四元组建连与套接字描述符托管给基础传输设施 DialerBase。
     */
    class OutboundBase
    {
    protected:
        std::string tag_{};
        std::string type_{};
        DialerOptions options_{};
        std::atomic<bool> running_{false};

        /**
         * @brief 通用出站流式拨号建连与状态机处理器装配辅助函数 (DRY 统一代码复用)
         */
        template <typename HandlerType, typename... Args>
        Result<OutboundDialResult> dialStreamHelper(std::string_view serverHost, uint16_t serverPort,
                                                    const handler::ProxyAddress &target, Args &&...args)
        {
            Dialer<HandlerType> dialer;
            if (options_.fwmark != 0)
            {
                dialer.setMark(options_.fwmark);
            }
            if (!options_.bindInterface.empty())
            {
                dialer.setInterface(options_.bindInterface);
            }
            auto dialRes = dialer.dialTcp(serverHost, serverPort);
            if (!dialRes)
            {
                return std::unexpected(dialRes.error());
            }

            auto h = std::make_unique<HandlerType>(std::forward<Args>(args)..., target);
            h->handle();

            OutboundDialResult res;
            res.fd = dialer.release();
            res.handler = std::move(h);
            res.outboundTag = tag_;
            res.targetEndpoint = target.toString();
            res.immediateConnected = *dialRes;
            return res;
        }

    public:
        OutboundBase(std::string tag, std::string type, DialerOptions options = {})
            : tag_(std::move(tag)),
              type_(std::move(type)),
              options_(std::move(options))
        {
        }

        virtual ~OutboundBase() noexcept = default;

        [[nodiscard]] inline const std::string &tag() const noexcept { return tag_; }
        [[nodiscard]] inline const std::string &type() const noexcept { return type_; }
        [[nodiscard]] inline bool isRunning() const noexcept { return running_.load(std::memory_order_relaxed); }
        [[nodiscard]] inline const DialerOptions &options() const noexcept { return options_; }
        inline void setOptions(DialerOptions options) noexcept { options_ = std::move(options); }

        [[nodiscard]] virtual std::string_view serverHost() const noexcept { return ""; }
        [[nodiscard]] virtual uint16_t serverPort() const noexcept { return 0; }

        /**
         * @brief 启动出站节点生命周期
         */
        virtual Result<> start() noexcept
        {
            running_.store(true, std::memory_order_release);
            return {};
        }

        /**
         * @brief 停止出站节点生命周期
         */
        virtual void stop() noexcept { running_.store(false, std::memory_order_release); }

        /**
         * @brief 发起流式出站建连 (TCP / TLS / 代理协议)
         *
         * @param target 代理目标网络地址
         * @return Result<OutboundDialResult> 拨号结果
         */
        virtual Result<OutboundDialResult> dialStream(const handler::ProxyAddress &target) = 0;

        /**
         * @brief 发起数据报出站建连 (UDP)
         *
         * @param target 代理目标网络地址
         * @return Result<int> 已创建或连接的 UDP 套接字描述符
         */
        virtual Result<int> dialDatagram(const handler::ProxyAddress &target) = 0;
    };

    class OutboundManager;

    /**
     * @brief 节点选择器 / 分组出站 (OutboundSelector)
     */
    class OutboundSelector : public OutboundBase
    {
    private:
        std::vector<std::string> candidateTags_{};
        std::string selectedTag_{};
        OutboundManager *manager_{nullptr};

    public:
        OutboundSelector(std::string tag, std::vector<std::string> candidates, OutboundManager *mgr = nullptr)
            : OutboundBase(std::move(tag), "selector"),
              candidateTags_(std::move(candidates)),
              manager_(mgr)
        {
            if (!candidateTags_.empty())
            {
                selectedTag_ = candidateTags_.front();
            }
        }

        inline void setManager(OutboundManager *mgr) noexcept { manager_ = mgr; }
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
            return OutboundBase::start();
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
     * @brief URL 延迟测速自动优选出站 (OutboundUrlTest, 结合机制 63 容差阻尼窗口与机制 64 LatenciesN)
     */
    class OutboundUrlTest : public OutboundBase
    {
    private:
        std::vector<std::string> candidateTags_{};
        OutboundManager *manager_{nullptr};
        std::string testUrl_{"http://cp.cloudflare.com/generate_204"};
        uint32_t intervalSecs_{300};
        uint32_t toleranceMs_{0};
        DialerSelectionPolicy policy_{DialerSelectionPolicy::MIN};

        mutable std::mutex rttMutex_{};
        mutable std::string currentBestTag_{};
        std::unordered_map<std::string, uint32_t> rttMap_{};
        std::unordered_map<std::string, LatenciesN<10>> latenciesMap_{};

    public:
        OutboundUrlTest(std::string tag, std::vector<std::string> candidates, OutboundManager *mgr = nullptr,
                        std::string url = "http://cp.cloudflare.com/generate_204", uint32_t intervalSecs = 300,
                        uint32_t toleranceMs = 0, DialerSelectionPolicy policy = DialerSelectionPolicy::MIN)
            : OutboundBase(std::move(tag), "urltest"),
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

        inline void setManager(OutboundManager *mgr) noexcept { manager_ = mgr; }
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

        Result<> start() noexcept override { return OutboundBase::start(); }

        Result<OutboundDialResult> dialStream(const handler::ProxyAddress &target) override;
        Result<int> dialDatagram(const handler::ProxyAddress &target) override;
    };

    /**
     * @brief 故障按序回退出站 (OutboundFallback)
     */
    class OutboundFallback : public OutboundBase
    {
    private:
        std::vector<std::string> candidateTags_{};
        OutboundManager *manager_{nullptr};

    public:
        OutboundFallback(std::string tag, std::vector<std::string> candidates, OutboundManager *mgr = nullptr)
            : OutboundBase(std::move(tag), "fallback"),
              candidateTags_(std::move(candidates)),
              manager_(mgr)
        {
        }

        inline void setManager(OutboundManager *mgr) noexcept { manager_ = mgr; }
        [[nodiscard]] inline const std::vector<std::string> &candidates() const noexcept { return candidateTags_; }

        Result<> start() noexcept override { return OutboundBase::start(); }

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
     * @brief 统一出站管理器 (Outbound Manager)
     *
     * 维护系统所有出站节点的注册表，默认自动预置 direct 与 block 两个标准出口。
     */
    class OutboundManager
    {
    private:
        mutable std::mutex mutex_{};
        std::unordered_map<std::string, std::shared_ptr<OutboundBase>> outbounds_{};
        std::string defaultTag_{"direct"};
        std::atomic<bool> running_{false};

    public:
        OutboundManager()
        {
            // 默认自动装配 direct 与 block 标准出口
            registerOutbound(std::make_shared<OutboundDirect>("direct"));
            registerOutbound(std::make_shared<OutboundBlock>("block"));
        }

        ~OutboundManager() noexcept { stopAll(); }

        OutboundManager(const OutboundManager &) = delete;
        OutboundManager &operator=(const OutboundManager &) = delete;
        OutboundManager(OutboundManager &&) = delete;
        OutboundManager &operator=(OutboundManager &&) = delete;

        /**
         * @brief 批量启动所有注册的出站节点生命周期
         */
        Result<> startAll() noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto &[tag, ob] : outbounds_)
            {
                if (ob != nullptr)
                {
                    auto res = ob->start();
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
            for (auto &[tag, ob] : outbounds_)
            {
                if (ob != nullptr)
                {
                    ob->stop();
                }
            }
            running_.store(false, std::memory_order_release);
        }

        [[nodiscard]] inline bool isRunning() const noexcept { return running_.load(std::memory_order_acquire); }

        [[nodiscard]] inline std::string_view defaultTag() const noexcept { return defaultTag_; }
        inline void setDefaultTag(std::string tag)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            defaultTag_ = std::move(tag);
        }

        /**
         * @brief 注册一个出站节点
         */
        void registerOutbound(std::shared_ptr<OutboundBase> outbound)
        {
            if (outbound == nullptr)
                return;
            std::lock_guard<std::mutex> lock(mutex_);
            if (auto *sel = dynamic_cast<OutboundSelector *>(outbound.get()); sel != nullptr)
            {
                sel->setManager(this);
            }
            if (auto *ut = dynamic_cast<OutboundUrlTest *>(outbound.get()); ut != nullptr)
            {
                ut->setManager(this);
            }
            if (auto *fb = dynamic_cast<OutboundFallback *>(outbound.get()); fb != nullptr)
            {
                fb->setManager(this);
            }
            outbounds_[outbound->tag()] = std::move(outbound);
        }

        /**
         * @brief 根据标签获取出站节点指针
         */
        [[nodiscard]] std::shared_ptr<OutboundBase> get(std::string_view tag) const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = outbounds_.find(std::string(tag));
            return (it != outbounds_.end()) ? it->second : nullptr;
        }

        [[nodiscard]] bool has(std::string_view tag) const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return outbounds_.contains(std::string(tag));
        }

        inline void remove(std::string_view tag)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            outbounds_.erase(std::string(tag));
        }

        [[nodiscard]] size_t size() const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return outbounds_.size();
        }

        [[nodiscard]] std::vector<std::shared_ptr<OutboundBase>> outbounds() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            std::vector<std::shared_ptr<OutboundBase>> list;
            list.reserve(outbounds_.size());
            for (const auto &pair : outbounds_)
            {
                list.push_back(pair.second);
            }
            return list;
        }

        [[nodiscard]] std::vector<std::string> listTags() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            std::vector<std::string> tags;
            tags.reserve(outbounds_.size());
            for (const auto &pair : outbounds_)
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
            std::shared_ptr<OutboundBase> ob = get(tag);
            if (ob == nullptr)
            {
                ob = get(defaultTag_);
            }
            if (ob == nullptr)
            {
                return std::unexpected(ERR::CONNECT_FAILED);
            }
            return ob->dialStream(target);
        }

        /**
         * @brief 根据出站标签与目标地址发起数据报出站建连
         */
        Result<int> dialDatagram(std::string_view tag, const handler::ProxyAddress &target)
        {
            std::shared_ptr<OutboundBase> ob = get(tag);
            if (ob == nullptr)
            {
                ob = get(defaultTag_);
            }
            if (ob == nullptr)
            {
                return std::unexpected(ERR::CONNECT_FAILED);
            }
            return ob->dialDatagram(target);
        }
    };

    // OutboundSelector 延迟实现
    inline Result<OutboundDialResult> OutboundSelector::dialStream(const handler::ProxyAddress &target)
    {
        if (manager_ == nullptr || selectedTag_.empty())
        {
            return std::unexpected(ERR::CONNECT_FAILED);
        }
        return manager_->dialStream(selectedTag_, target);
    }

    inline Result<int> OutboundSelector::dialDatagram(const handler::ProxyAddress &target)
    {
        if (manager_ == nullptr || selectedTag_.empty())
        {
            return std::unexpected(ERR::CONNECT_FAILED);
        }
        return manager_->dialDatagram(selectedTag_, target);
    }

    // OutboundUrlTest 延迟实现
    inline Result<OutboundDialResult> OutboundUrlTest::dialStream(const handler::ProxyAddress &target)
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

    inline Result<int> OutboundUrlTest::dialDatagram(const handler::ProxyAddress &target)
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

    inline uint32_t OutboundUrlTest::probeNode(std::string_view tag, std::chrono::milliseconds timeout)
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

    inline void OutboundUrlTest::probeAll(std::chrono::milliseconds timeout)
    {
        for (const auto &tag : candidateTags_)
        {
            probeNode(tag, timeout);
        }
    }

    // OutboundFallback 延迟实现
    inline Result<OutboundDialResult> OutboundFallback::dialStream(const handler::ProxyAddress &target)
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

    inline Result<int> OutboundFallback::dialDatagram(const handler::ProxyAddress &target)
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
