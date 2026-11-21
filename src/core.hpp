#pragma once

/**
 * @file core.hpp
 * @brief 现代化统一网络代理内核门面 (Core Engine Facade)。
 *
 * 聚合 Engine (I/O 事件引擎)、Forwarder (双向流/数据报中继)、Router (策略路由分流)
 * 与 OutboundManager (出站管理器) 为一体，提供开箱即用的统一控制与数据平面。
 *
 * 核心流水线 (End-to-End Pipeline)：
 * 1. 流量接入：Inbound 提取原始目标网络地址 (ProxyAddress)；
 * 2. 深度嗅探：联动 DomainSniffer 提取加密流量的 SNI / Host 与应用协议；
 * 3. 策略路由：Router 基于域名、CIDR、端口、协议完成秒级调度决断；
 * 4. 动态出站：OutboundManager 解析并向远端发起非阻塞建连与状态机绑定；
 * 5. 零拷贝转发：Forwarder 建立双向流桥接，优先选用 Linux splice(2) 零拷贝穿透；
 * 6. 统一可观测性：全局聚合会话追踪、上下行吞吐统计与空闲会话超时排空。
 */

#include "config/log.hpp"
#include "ebpf.hpp"
#include "error.hpp"
#include "fakeip.hpp"
#include "forwarder.hpp"
#include "geo.hpp"
#include "inboundHandler.hpp"
#include "inboundManager.hpp"
#include "outboundHandler.hpp"
#include "outboundManager.hpp"
#include "router.hpp"
#include "sniffer.hpp"
#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace mynet
{

    /**
     * @brief 内核调度分流结果状态
     */
    enum class CoreDispatchStatus : uint8_t
    {
        SUCCESS,     ///< 调度成功并已建立 Forwarder 桥接
        BLOCKED,     ///< 流量命中了阻断黑洞 (Block) 并已安全关断
        DIAL_FAILED, ///< 出站拨号建连失败
        NO_TARGET    ///< 入站状态机尚未解析出合法目标地址
    };

    /**
     * @brief 内核单次调度产物
     */
    struct CoreDispatchResult
    {
        CoreDispatchStatus status{CoreDispatchStatus::SUCCESS};
        std::string outboundTag{};
        std::shared_ptr<ForwarderStreamSession> session{nullptr};
        handler::ProxyAddress target{};
        std::string sniffedDomain{};
        handler::sniffing::ProtocolType sniffedProtocol{handler::sniffing::ProtocolType::UNKNOWN};

        [[nodiscard]] inline bool ok() const noexcept { return status == CoreDispatchStatus::SUCCESS; }
    };

    /**
     * @brief 统一代理内核主体 (Core)
     */
    class Core
    {
    private:
        std::shared_ptr<InboundManager> inboundManager_{nullptr};
        std::shared_ptr<OutboundManager> outboundManager_{nullptr};
        std::shared_ptr<Router> router_{nullptr};
        std::shared_ptr<Forwarder> forwarder_{nullptr};
        std::shared_ptr<ebpf::EbpfEngine> ebpfEngine_{nullptr};

        mutable std::mutex mutex_{};
        MynetConfig mynetConfig_{};
        std::shared_ptr<const MynetConfig> mynetConfigShared_{std::make_shared<const MynetConfig>()};
        std::atomic<bool> running_{false};

    public:
        Core()
            : inboundManager_(std::make_shared<InboundManager>()),
              outboundManager_(std::make_shared<OutboundManager>()),
              router_(std::make_shared<Router>("direct")),
              forwarder_(std::make_shared<Forwarder>())
        {
        }

        explicit Core(ForwarderConfig fwdCfg)
            : inboundManager_(std::make_shared<InboundManager>()),
              outboundManager_(std::make_shared<OutboundManager>()),
              router_(std::make_shared<Router>("direct")),
              forwarder_(std::make_shared<Forwarder>(fwdCfg))
        {
        }

        explicit Core(const MynetConfig &cfg)
            : Core()
        {
            applyConfig(cfg);
        }

        /**
         * @brief 根据全局 MynetConfig 完整装配入站、出站、路由规则与转发器
         */
        inline void applyConfig(const MynetConfig &cfg)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            mynetConfig_ = cfg;
            mynetConfigShared_ = std::make_shared<const MynetConfig>(cfg);
            if (forwarder_ != nullptr)
            {
                forwarder_->setConfig(cfg.forwarder);
            }

            // 装配入站节点
            for (const auto &inCfg : cfg.inbounds)
            {
                if (inCfg.protocol == "socks5")
                {
                    inboundManager_->registerInbound(std::make_shared<InboundSocks5>(
                        inCfg.tag, inCfg.host, inCfg.port, inCfg.username, inCfg.password, inCfg.enableSniffing));
                }
                else if (inCfg.protocol == "http")
                {
                    inboundManager_->registerInbound(std::make_shared<InboundHttp>(
                        inCfg.tag, inCfg.host, inCfg.port, inCfg.username, inCfg.password, inCfg.enableSniffing));
                }
                else if (inCfg.protocol == "trojan")
                {
                    inboundManager_->registerInbound(std::make_shared<InboundTrojan>(
                        inCfg.tag, inCfg.host, inCfg.port, inCfg.password, inCfg.enableSniffing));
                }
                else if (inCfg.protocol == "tproxy")
                {
                    inboundManager_->registerInbound(
                        std::make_shared<InboundTransparent>(inCfg.tag, inCfg.host, inCfg.port, inCfg.enableSniffing));
                }
                else if (inCfg.protocol == "direct")
                {
                    inboundManager_->registerInbound(
                        std::make_shared<InboundDirect>(inCfg.tag, inCfg.host, inCfg.port, inCfg.enableSniffing));
                }
                else if (inCfg.protocol == "vless")
                {
                    inboundManager_->registerInbound(std::make_shared<InboundVless>(inCfg.tag, inCfg.host, inCfg.port,
                                                                                    inCfg.uuid, inCfg.enableSniffing));
                }
                else if (inCfg.protocol == "hysteria2")
                {
                    inboundManager_->registerInbound(std::make_shared<InboundHysteria2>(
                        inCfg.tag, inCfg.host, inCfg.port, inCfg.password, inCfg.enableSniffing));
                }
                else if (inCfg.protocol == "shadowsocks")
                {
                    inboundManager_->registerInbound(std::make_shared<InboundShadowsocks>(
                        inCfg.tag, inCfg.host, inCfg.port, inCfg.username.empty() ? "aes-128-gcm" : inCfg.username,
                        inCfg.password, inCfg.enableSniffing));
                }
                else if (inCfg.protocol == "tun")
                {
                    inboundManager_->registerInbound(
                        std::make_shared<InboundTun>(inCfg.tag, inCfg.ifName, inCfg.enableSniffing));
                }
                else if (inCfg.protocol == "vmess")
                {
                    inboundManager_->registerInbound(std::make_shared<InboundVmess>(inCfg.tag, inCfg.host, inCfg.port,
                                                                                    inCfg.uuid, inCfg.enableSniffing));
                }
            }

            // 装配出站节点
            for (const auto &outCfg : cfg.outbounds)
            {
                if (outCfg.type == "direct")
                {
                    outboundManager_->registerOutbound(std::make_shared<OutboundDirect>(outCfg.tag));
                }
                else if (outCfg.type == "block")
                {
                    outboundManager_->registerOutbound(std::make_shared<OutboundBlock>(outCfg.tag));
                }
                else if (outCfg.type == "http")
                {
                    outboundManager_->registerOutbound(std::make_shared<OutboundHttp>(
                        outCfg.tag, outCfg.host, outCfg.port, outCfg.username, outCfg.password));
                }
                else if (outCfg.type == "socks5")
                {
                    outboundManager_->registerOutbound(std::make_shared<OutboundSocks5>(
                        outCfg.tag, outCfg.host, outCfg.port, outCfg.username, outCfg.password));
                }
                else if (outCfg.type == "trojan")
                {
                    outboundManager_->registerOutbound(
                        std::make_shared<OutboundTrojan>(outCfg.tag, outCfg.host, outCfg.port, outCfg.password));
                }
                else if (outCfg.type == "vless")
                {
                    outboundManager_->registerOutbound(
                        std::make_shared<OutboundVless>(outCfg.tag, outCfg.host, outCfg.port, outCfg.uuid));
                }
                else if (outCfg.type == "vmess")
                {
                    outboundManager_->registerOutbound(std::make_shared<OutboundVmess>(
                        outCfg.tag, outCfg.host, outCfg.port, outCfg.uuid, outCfg.security));
                }
                else if (outCfg.type == "hysteria2")
                {
                    outboundManager_->registerOutbound(
                        std::make_shared<OutboundHysteria2>(outCfg.tag, outCfg.host, outCfg.port, outCfg.password));
                }
                else if (outCfg.type == "shadowsocks")
                {
                    outboundManager_->registerOutbound(std::make_shared<OutboundShadowsocks>(
                        outCfg.tag, outCfg.host, outCfg.port, outCfg.method.empty() ? "aes-128-gcm" : outCfg.method,
                        outCfg.password));
                }
                else if (outCfg.type == "urltest")
                {
                    outboundManager_->registerOutbound(
                        std::make_shared<OutboundUrlTest>(outCfg.tag, outCfg.outbounds, outboundManager_.get(),
                                                          outCfg.url, outCfg.intervalSecs, outCfg.toleranceMs));
                }
                else if (outCfg.type == "fallback")
                {
                    outboundManager_->registerOutbound(
                        std::make_shared<OutboundFallback>(outCfg.tag, outCfg.outbounds, outboundManager_.get()));
                }
                else if (outCfg.type == "selector")
                {
                    auto sel = std::make_shared<OutboundSelector>(outCfg.tag, outCfg.outbounds, outboundManager_.get());
                    if (!outCfg.defaultTag.empty())
                    {
                        sel->setSelected(outCfg.defaultTag);
                    }
                    outboundManager_->registerOutbound(sel);
                }
            }

            // 装配策略路由规则
            if (!cfg.router.defaultOutbound.empty())
            {
                router_->setDefaultOutbound(cfg.router.defaultOutbound);
            }
            for (const auto &r : cfg.router.rules)
            {
                auto rule = RouteRule::to(r.outbound);
                for (const auto &d : r.domains)
                    rule.domain(d);
                for (const auto &s : r.domainSuffixes)
                    rule.domainSuffix(s);
                for (const auto &k : r.domainKeywords)
                    rule.domainKeyword(k);
                for (const auto &c : r.ipCidrs)
                    rule.cidr(c);
                for (const auto &p : r.portRanges)
                {
                    if (auto parsed = PortRange::parse(p); parsed.has_value())
                    {
                        rule.portRange(parsed->start, parsed->end);
                    }
                }
                for (const auto &proto : r.protocols)
                    rule.protocol(proto);
                for (const auto &gip : r.geoIps)
                    rule.geoIp(gip);
                for (const auto &gsite : r.geoSites)
                    rule.geoSite(gsite);
                if (!r.processName.empty())
                    rule.forProcess(r.processName);
                if (r.network == "tcp")
                    rule.forNetwork(NetworkType::TCP);
                else if (r.network == "udp")
                    rule.forNetwork(NetworkType::UDP);
                for (const auto &inTag : r.inboundTags)
                    rule.fromInbound(inTag);
                if (r.invert)
                    rule.setInvert(true);
                router_->addRule(std::move(rule));
            }

            // 装配 eBPF 内核旁路与透明代理
            if (cfg.ebpf.enabled)
            {
                enableEbpfLocked(cfg.ebpf);
            }
            else
            {
                ebpfEngine_.reset();
                if (forwarder_ != nullptr)
                {
                    forwarder_->setSockmapFd(-1);
                }
            }

            // 装配 FakeIP 虚拟地址池
            if (cfg.fakeip.enabled)
            {
                FakeIPPool::instance().applyConfig(cfg.fakeip);
            }

            // 装配 Geo 资产规则文件
            if (!cfg.geo.geoIpPath.empty())
            {
                GeoIpMatcher::instance().loadFromFile(cfg.geo.geoIpPath, "custom");
            }
            if (!cfg.geo.geoSitePath.empty())
            {
                GeoSiteMatcher::instance().loadFromFile(cfg.geo.geoSitePath, "custom");
            }
        }

        ~Core() noexcept { stop(); }

        Core(const Core &) = delete;
        Core &operator=(const Core &) = delete;
        Core(Core &&) = delete;
        Core &operator=(Core &&) = delete;

        [[nodiscard]] inline InboundManager &inbounds() noexcept { return *inboundManager_; }
        [[nodiscard]] inline const InboundManager &inbounds() const noexcept { return *inboundManager_; }

        [[nodiscard]] inline OutboundManager &outbounds() noexcept { return *outboundManager_; }
        [[nodiscard]] inline const OutboundManager &outbounds() const noexcept { return *outboundManager_; }

        [[nodiscard]] inline Router &router() noexcept { return *router_; }
        [[nodiscard]] inline const Router &router() const noexcept { return *router_; }

        [[nodiscard]] inline std::shared_ptr<ebpf::EbpfEngine> ebpf() const noexcept { return ebpfEngine_; }
        inline void setEbpf(std::shared_ptr<ebpf::EbpfEngine> engine) noexcept
        {
            ebpfEngine_ = std::move(engine);
            if (forwarder_ != nullptr)
            {
                forwarder_->setSockmapFd(ebpfEngine_ ? ebpfEngine_->sockMapFd() : -1);
            }
        }

        inline std::shared_ptr<ebpf::EbpfEngine> enableEbpfLocked(const EbpfConfig &cfg = {})
        {
            ebpfEngine_ = std::make_shared<ebpf::EbpfEngine>(cfg);
            if (router_ != nullptr)
            {
                ebpfEngine_->syncFromRouter(*router_);
            }
            if (forwarder_ != nullptr)
            {
                forwarder_->setSockmapFd(ebpfEngine_->sockMapFd());
            }
            return ebpfEngine_;
        }

        inline std::shared_ptr<ebpf::EbpfEngine> enableEbpf(const EbpfConfig &cfg = {})
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return enableEbpfLocked(cfg);
        }

        inline void syncEbpfFromRouter()
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (ebpfEngine_ != nullptr && router_ != nullptr)
            {
                ebpfEngine_->syncFromRouter(*router_);
            }
        }

        [[nodiscard]] inline bool isRunning() const noexcept { return running_.load(std::memory_order_acquire); }

        inline Result<> start(int backlog = 128)
        {
            if (running_.load(std::memory_order_acquire))
            {
                return {};
            }

            // 1. 拓扑闭包校验 (Fail-Fast: 检查路由默认出站与各规则目标出站是否均已注册)
            if (router_ != nullptr && outboundManager_ != nullptr)
            {
                if (!router_->defaultOutbound().empty() && !outboundManager_->has(router_->defaultOutbound()))
                {
                    LOG_ERROR("Core start failed: default outbound '{}' not registered in OutboundManager",
                              router_->defaultOutbound());
                    return std::unexpected(ERR::CONNECT_FAILED);
                }
                for (const auto &rule : router_->rules())
                {
                    if (!rule.outboundTag.empty() && !outboundManager_->has(rule.outboundTag))
                    {
                        LOG_ERROR("Core start failed: route rule outbound '{}' not registered in OutboundManager",
                                  rule.outboundTag);
                        return std::unexpected(ERR::CONNECT_FAILED);
                    }
                }
            }

            // 2. 出站系统启动 (生命周期就绪与活动选择器装配)
            if (outboundManager_ != nullptr)
            {
                auto outRes = outboundManager_->startAll();
                if (!outRes)
                {
                    return outRes;
                }
            }

            // 3. 入站系统批量监听 (监听套接字绑定与非阻塞开始就绪)
            if (inboundManager_ != nullptr)
            {
                auto inRes = inboundManager_->startAll(backlog);
                if (!inRes)
                {
                    // 回滚已启动的出站
                    if (outboundManager_ != nullptr)
                    {
                        outboundManager_->stopAll();
                    }
                    return inRes;
                }
            }

            running_.store(true, std::memory_order_release);
            return {};
        }

        inline void stop() noexcept
        {
            if (running_.exchange(false, std::memory_order_acq_rel))
            {
                // 1. 关断入站监听 (停止接入新流量)
                if (inboundManager_ != nullptr)
                {
                    inboundManager_->stopAll();
                }
                // 2. 关断活跃中继会话 (安全释放描述符与零拷贝管道)
                if (forwarder_ != nullptr)
                {
                    forwarder_->closeAll();
                }
                // 3. 关断出站系统生命周期
                if (outboundManager_ != nullptr)
                {
                    outboundManager_->stopAll();
                }
            }
        }

        /**
         * @brief 定期排空超时的中继与 UDP 会话资源
         */
        inline size_t sweepIdleSessions(int maxAgeSecs = 60) noexcept
        {
            if (forwarder_ != nullptr)
            {
                return forwarder_->sweepIdleDatagramSessions(std::chrono::seconds(maxAgeSecs));
            }
            return 0;
        }

        /**
         * @brief 直接桥接入站与出站协议处理器并纳入数据面流中继
         */
        inline std::shared_ptr<ForwarderStreamSession> bridge(handler::HandlerInboundConnectionBase &inbound,
                                                              handler::HandlerOutboundConnectionBase &outbound,
                                                              std::optional<ForwarderConfig> cfg = std::nullopt)
        {
            if (forwarder_ != nullptr)
            {
                return forwarder_->bridge(inbound, outbound, cfg);
            }
            return nullptr;
        }

        /**
         * @brief 主动关断指定的活跃会话并回收底层资源
         */
        inline void closeSession(uint64_t id, bool force = false)
        {
            if (forwarder_ != nullptr)
            {
                forwarder_->closeStreamSession(id, force);
            }
        }

        /**
         * @brief 注册一个入站节点实例
         */
        inline void addInbound(std::shared_ptr<InboundBase> inbound)
        {
            if (inboundManager_ != nullptr)
            {
                inboundManager_->registerInbound(std::move(inbound));
            }
        }

        /**
         * @brief 注册一个出站节点实例
         */
        inline void addOutbound(std::shared_ptr<OutboundBase> outbound)
        {
            if (outboundManager_ != nullptr)
            {
                outboundManager_->registerOutbound(std::move(outbound));
            }
        }

        /**
         * @brief 注册一个入站配置并保存规范
         */
        inline void addInboundConfig(InboundConfig config)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            mynetConfig_.inbounds.push_back(std::move(config));
        }

        [[nodiscard]] inline std::vector<InboundConfig> inboundConfigs() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return mynetConfig_.inbounds;
        }

        /**
         * @brief 注册一个出站配置并保存规范
         */
        inline void addOutboundConfig(OutboundConfig config)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            mynetConfig_.outbounds.push_back(std::move(config));
        }

        [[nodiscard]] inline std::vector<OutboundConfig> outboundConfigs() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return mynetConfig_.outbounds;
        }

        [[nodiscard]] inline RouterConfig routerConfig() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return mynetConfig_.router;
        }

        [[nodiscard]] inline MynetConfig mynetConfig() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return mynetConfig_;
        }

        [[nodiscard]] inline std::shared_ptr<const MynetConfig> mynetConfigShared() const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return mynetConfigShared_;
        }

        /**
         * @brief 核心数据平面分发入口：接管一个已完成握手或就绪的入站连接并桥接至目标出站
         *
         * @param inbound 已完成握手的入站协议状态机
         * @param inFd 入站客户端底层套接字描述符
         * @param inboundTag 来源入站标签
         * @param enableSniffing 是否开启首包域名嗅探
         * @return CoreDispatchResult 调度决断与转发会话结果
         */
        CoreDispatchResult dispatch(handler::HandlerInboundConnectionBase &inbound, int inFd = -1,
                                    std::string_view inboundTag = "", bool enableSniffing = true)
        {
            CoreDispatchResult result;

            // 1. 提取目标端点地址
            if (!inbound.targetAddress().has_value() && inbound.target().host.empty() &&
                inbound.target().ipv4_.s_addr == 0)
            {
                result.status = CoreDispatchStatus::NO_TARGET;
                return result;
            }
            result.target = inbound.targetAddress().value_or(inbound.target());

            // 1.1 FakeIP 虚拟地址反解：若目标地址为 198.18.0.0/15 FakeIP，秒级还原原始域名
            if (result.target.type == handler::AddressType::IPV4 &&
                FakeIPPool::instance().isFakeIp(result.target.ipv4_))
            {
                if (auto orig = FakeIPPool::instance().lookup(result.target.ipv4_); orig.has_value())
                {
                    result.target = handler::ProxyAddress::fromDomain(*orig, result.target.port);
                    result.sniffedDomain = *orig;
                }
            }

            // 2. 深度数据包嗅探：从早期摄入用户态缓冲的数据中嗅探真实 SNI 与协议
            if (enableSniffing && inbound.requestBytes() > 0)
            {
                std::span<const uint8_t> earlyData(reinterpret_cast<const uint8_t *>(inbound.requestBegin()),
                                                   inbound.requestBytes());

                if (auto sniffRes = handler::sniffing::DomainSniffer::sniff(earlyData); sniffRes.has_value())
                {
                    result.sniffedProtocol = sniffRes->protocol;
                    if (!sniffRes->host.empty())
                    {
                        result.sniffedDomain = sniffRes->host;
                    }
                }
            }

            // 3. 构建路由上下文并执行策略匹配 (Router 为全网唯一策略中枢)
            RouteContext ctx;
            ctx.network = NetworkType::TCP;
            ctx.inboundTag = inboundTag;
            ctx.target = result.target;
            ctx.sniffedDomain = result.sniffedDomain;
            ctx.sniffedProtocol = result.sniffedProtocol;

            std::string_view outboundTag = router_->match(ctx);
            result.outboundTag = std::string(outboundTag);

            if (outboundTag == "block")
            {
                result.status = CoreDispatchStatus::BLOCKED;
                inbound.setCloseAfterResponse(true);
                return result;
            }

            // 4. 出站拨号建连与协议状态机装配
            auto dialRes = outboundManager_->dialStream(outboundTag, result.target);
            if (!dialRes)
            {
                result.status = CoreDispatchStatus::DIAL_FAILED;
                inbound.setCloseAfterResponse(true);
                return result;
            }

            // 若命中拦截黑洞 (Block)
            if (dialRes->handler->stage() == handler::OutboundStage::ERROR)
            {
                result.status = CoreDispatchStatus::BLOCKED;
                inbound.setCloseAfterResponse(true);
                return result;
            }

            // 5. 核心桥接：将 Inbound 与 Outbound 交由 Forwarder 纳管
            auto session = forwarder_->bridge(inbound, *dialRes->handler);
            session->setInboundFd((inFd >= 0) ? inFd : inbound.fd());
            session->setOutboundFd(dialRes->fd);
            session->setTarget(result.target);

            // 统一阶梯自适应：自动协商 Sockmap -> Splice -> Buffer Pump
            session->activateAdaptiveMode();

            result.session = std::move(session);
            result.status = CoreDispatchStatus::SUCCESS;
            return result;
        }

        /**
         * @brief 驱动一次全量会话泵送与空闲清理
         */
        inline size_t tick() { return forwarder_->pumpAll(); }

        // =====================================================================
        // 全局聚合监控指标
        // =====================================================================

        [[nodiscard]] inline size_t activeSessions() const noexcept { return forwarder_->activeStreamSessions(); }

        [[nodiscard]] inline uint64_t totalBytesUp() const noexcept { return forwarder_->totalBytesUp(); }

        [[nodiscard]] inline uint64_t totalBytesDown() const noexcept { return forwarder_->totalBytesDown(); }

        [[nodiscard]] inline uint64_t totalBytes() const noexcept { return totalBytesUp() + totalBytesDown(); }
    };

} // namespace mynet
