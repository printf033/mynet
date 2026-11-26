#pragma once

/**
 * @file core.hpp
 * @brief 现代化统一网络代理内核门面 (Core Engine Facade)。
 *
 * 聚合 Engine (I/O 事件引擎)、Forwarder (双向流/数据报中继)、Router (策略路由分流)
 * 与 DialerManager (拨号器管理器) 为一体，提供开箱即用的统一控制与数据平面。
 *
 * 核心流水线 (End-to-End Pipeline)：
 * 1. 流量接入：Acceptor 提取原始目标网络地址 (ProxyAddress)；
 * 2. 深度嗅探：联动 DomainSniffer 提取加密流量的 SNI / Host 与应用协议；
 * 3. 策略路由：Router 基于域名、CIDR、端口、协议完成秒级调度决断；
 * 4. 动态出站：DialerManager 解析并向远端发起非阻塞建连与状态机绑定；
 * 5. 零拷贝转发：Forwarder 建立双向流桥接，优先选用 Linux splice(2) 零拷贝穿透；
 * 6. 统一可观测性：全局聚合会话追踪、上下行吞吐统计与空闲会话超时排空。
 */

#include "config/log.hpp"
#include "connection.hpp"
#include "datagram.hpp"
#include "ebpf.hpp"
#include "error.hpp"
#include "fakeip.hpp"
#include "forwarder.hpp"
#include "geo.hpp"
#include "inboundManager.hpp"
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
        std::shared_ptr<AcceptorManager> acceptorManager_{nullptr};
        std::shared_ptr<DialerManager> dialerManager_{nullptr};
        std::shared_ptr<Router> router_{nullptr};
        std::shared_ptr<Forwarder> forwarder_{nullptr};
        std::shared_ptr<ebpf::EbpfEngine> ebpfEngine_{nullptr};

        mutable std::mutex mutex_{};
        std::shared_ptr<const MynetConfig> mynetConfig_{std::make_shared<const MynetConfig>()};
        std::atomic<bool> running_{false};

    public:
        Core()
            : acceptorManager_(std::make_shared<AcceptorManager>()),
              dialerManager_(std::make_shared<DialerManager>()),
              router_(std::make_shared<Router>("direct")),
              forwarder_(std::make_shared<Forwarder>())
        {
        }

        explicit Core(ForwarderConfig fwdCfg)
            : acceptorManager_(std::make_shared<AcceptorManager>()),
              dialerManager_(std::make_shared<DialerManager>()),
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
            mynetConfig_ = std::make_shared<const MynetConfig>(cfg);
            if (forwarder_ != nullptr)
            {
                forwarder_->setConfig(cfg.forwarder);
            }
            if (acceptorManager_ != nullptr)
            {
                acceptorManager_->stopAll();
                acceptorManager_->clear();
            }
            if (dialerManager_ != nullptr)
            {
                dialerManager_->clear();
            }
            if (router_ != nullptr)
            {
                router_->clearRules();
            }

            // 装配入站接收器
            for (const auto &inCfg : cfg.inbounds)
            {
                std::shared_ptr<Acceptor> acc;
                if (inCfg.protocol == "socks5")
                {
                    acc = std::make_shared<InboundSocks5>(
                        inCfg.tag, inCfg.host, inCfg.port, inCfg.username, inCfg.password, inCfg.enableSniffing);
                }
                else if (inCfg.protocol == "mixed")
                {
                    acc = std::make_shared<InboundMixed>(
                        inCfg.tag, inCfg.host, inCfg.port, inCfg.username, inCfg.password, inCfg.enableSniffing);
                }
                else if (inCfg.protocol == "http")
                {
                    acc = std::make_shared<InboundHttp>(
                        inCfg.tag, inCfg.host, inCfg.port, inCfg.username, inCfg.password, inCfg.enableSniffing);
                }
                else if (inCfg.protocol == "http2")
                {
                    acc = std::make_shared<InboundHttp2>(
                        inCfg.tag, inCfg.host, inCfg.port, inCfg.username, inCfg.password, inCfg.enableSniffing);
                }
                else if (inCfg.protocol == "http3")
                {
                    acc = std::make_shared<InboundHttp3>(
                        inCfg.tag, inCfg.host, inCfg.port, inCfg.password, inCfg.enableSniffing);
                }
                else if (inCfg.protocol == "trojan")
                {
                    acc = std::make_shared<InboundTrojan>(
                        inCfg.tag, inCfg.host, inCfg.port, inCfg.password, inCfg.enableSniffing);
                }
                else if (inCfg.protocol == "tproxy")
                {
                    acc = std::make_shared<InboundTransparent>(inCfg.tag, inCfg.host, inCfg.port, inCfg.enableSniffing);
                }
                else if (inCfg.protocol == "direct")
                {
                    acc = std::make_shared<InboundDirect>(inCfg.tag, inCfg.host, inCfg.port, inCfg.enableSniffing);
                }
                else if (inCfg.protocol == "vless")
                {
                    acc = std::make_shared<InboundVless>(inCfg.tag, inCfg.host, inCfg.port, inCfg.uuid,
                                                         inCfg.enableSniffing);
                }
                else if (inCfg.protocol == "hysteria2")
                {
                    acc = std::make_shared<InboundHysteria2>(
                        inCfg.tag, inCfg.host, inCfg.port, inCfg.password, inCfg.enableSniffing);
                }
                else if (inCfg.protocol == "shadowsocks")
                {
                    acc = std::make_shared<InboundShadowsocks>(
                        inCfg.tag, inCfg.host, inCfg.port, inCfg.username.empty() ? "aes-128-gcm" : inCfg.username,
                        inCfg.password, inCfg.enableSniffing);
                }
                else if (inCfg.protocol == "tun")
                {
                    acc = std::make_shared<InboundTun>(
                        inCfg.tag, inCfg.ifName, inCfg.inetIp, inCfg.inetMask, inCfg.mtu, inCfg.enableSniffing);
                }
                else if (inCfg.protocol == "vmess")
                {
                    acc = std::make_shared<InboundVmess>(inCfg.tag, inCfg.host, inCfg.port, inCfg.uuid,
                                                         inCfg.enableSniffing);
                }
                else if (inCfg.protocol == "datagram" || inCfg.protocol == "udp")
                {
                    acc = std::make_shared<AcceptorDatagram>(inCfg.tag, inCfg.host, inCfg.port);
                }
                if (acc != nullptr)
                {
                    if (inCfg.transport.enableTls || inCfg.transport.type != transport::TransportType::TCP)
                    {
                        if (auto tr = acc->setTransportConfig(inCfg.transport); !tr)
                        {
                            LOG_WARN("Core::applyConfig: inbound '{}' transport config failed: {}", inCfg.tag,
                                     toString(tr.error()));
                        }
                    }
                    acceptorManager_->registerAcceptor(std::move(acc));
                }
            }

            // 装配出站拨号器
            for (const auto &outCfg : cfg.outbounds)
            {
                std::shared_ptr<Dialer> dl;
                if (outCfg.type == "direct")
                {
                    dl = std::make_shared<DialerDirect>(outCfg.tag);
                }
                else if (outCfg.type == "block")
                {
                    dl = std::make_shared<DialerBlock>(outCfg.tag);
                }
                else if (outCfg.type == "http")
                {
                    dl = std::make_shared<DialerHttp>(
                        outCfg.tag, outCfg.host, outCfg.port, outCfg.username, outCfg.password);
                }
                else if (outCfg.type == "http2")
                {
                    dl = std::make_shared<DialerHttp2>(
                        outCfg.tag, outCfg.host, outCfg.port, outCfg.username, outCfg.password);
                }
                else if (outCfg.type == "http3")
                {
                    dl = std::make_shared<DialerHttp3>(outCfg.tag, outCfg.host, outCfg.port, outCfg.password);
                }
                else if (outCfg.type == "socks5")
                {
                    dl = std::make_shared<DialerSocks5>(
                        outCfg.tag, outCfg.host, outCfg.port, outCfg.username, outCfg.password);
                }
                else if (outCfg.type == "trojan")
                {
                    dl = std::make_shared<DialerTrojan>(outCfg.tag, outCfg.host, outCfg.port, outCfg.password);
                }
                else if (outCfg.type == "vless")
                {
                    dl = std::make_shared<DialerVless>(outCfg.tag, outCfg.host, outCfg.port, outCfg.uuid);
                }
                else if (outCfg.type == "vmess")
                {
                    dl = std::make_shared<DialerVmess>(
                        outCfg.tag, outCfg.host, outCfg.port, outCfg.uuid, outCfg.security);
                }
                else if (outCfg.type == "hysteria2")
                {
                    dl = std::make_shared<DialerHysteria2>(outCfg.tag, outCfg.host, outCfg.port, outCfg.password);
                }
                else if (outCfg.type == "shadowsocks")
                {
                    dl = std::make_shared<DialerShadowsocks>(
                        outCfg.tag, outCfg.host, outCfg.port, outCfg.method.empty() ? "aes-128-gcm" : outCfg.method,
                        outCfg.password);
                }
                else if (outCfg.type == "urltest")
                {
                    dl = std::make_shared<DialerUrlTest>(outCfg.tag, outCfg.outbounds, dialerManager_.get(),
                                                         outCfg.url, outCfg.intervalSecs, outCfg.toleranceMs);
                }
                else if (outCfg.type == "fallback")
                {
                    dl = std::make_shared<DialerFallback>(outCfg.tag, outCfg.outbounds, dialerManager_.get());
                }
                else if (outCfg.type == "selector")
                {
                    auto sel = std::make_shared<DialerSelector>(outCfg.tag, outCfg.outbounds, dialerManager_.get());
                    if (!outCfg.defaultTag.empty())
                    {
                        sel->setSelected(outCfg.defaultTag);
                    }
                    dl = std::move(sel);
                }
                else if (outCfg.type == "datagram" || outCfg.type == "udp")
                {
                    dl = std::make_shared<DialerDatagram>(outCfg.tag);
                }
                if (dl != nullptr)
                {
                    if (outCfg.transport.enableTls || outCfg.transport.type != transport::TransportType::TCP)
                    {
                        dl->setTransportConfig(outCfg.transport);
                    }
                    dialerManager_->registerDialer(std::move(dl));
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

        /**
         * @brief 为已注册的入站节点配置可叠加传输层 (TLS / WebSocket / gRPC)
         */
        [[nodiscard]] inline Result<> configureInboundTransport(std::string_view tag, transport::TransportConfig cfg)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (acceptorManager_ == nullptr)
            {
                return std::unexpected(ERR::NOT_INITIALISED);
            }
            auto acc = acceptorManager_->get(tag);
            if (acc == nullptr)
            {
                return std::unexpected(ERR::NOT_INITIALISED);
            }
            return acc->setTransportConfig(std::move(cfg));
        }

        /**
         * @brief 为已注册的出站拨号器配置可叠加传输层 (TLS / WebSocket / gRPC)
         */
        [[nodiscard]] inline Result<> configureOutboundTransport(std::string_view tag, transport::TransportConfig cfg)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (dialerManager_ == nullptr)
            {
                return std::unexpected(ERR::NOT_INITIALISED);
            }
            auto dl = dialerManager_->get(tag);
            if (dl == nullptr)
            {
                return std::unexpected(ERR::NOT_INITIALISED);
            }
            dl->setTransportConfig(std::move(cfg));
            return {};
        }

        /**
         * @brief 将底层 EventLoop 绑定至 Forwarder，使所有后续代理会话的 outboundFd 走纯事件驱动调度
         */
        template <typename LoopT>
        inline void attachEventLoop(LoopT &loop)
        {
            if (forwarder_ == nullptr)
            {
                return;
            }
            ForwarderLoopHooks hooks;
            hooks.addWatch = [&loop](int fd, uint32_t events, std::function<void(uint32_t)> cb)
            { return loop.addWatch(fd, events, std::move(cb)); };
            hooks.modWatch = [&loop](int fd, uint32_t events) { return loop.modWatch(fd, events); };
            hooks.delWatch = [&loop](int fd) { loop.delWatch(fd); };
            hooks.postTask = [&loop](std::function<void()> t) { loop.runInLoop(std::move(t)); };
            if constexpr (requires { loop.attachForwarderHooks(hooks); })
            {
                loop.attachForwarderHooks(hooks);
            }
            forwarder_->setLoopHooks(std::move(hooks));
        }

        inline void clearEventLoop() noexcept
        {
            if (forwarder_ != nullptr)
            {
                forwarder_->clearLoopHooks();
            }
        }

        ~Core() noexcept { stop(); }

        Core(const Core &) = delete;
        Core &operator=(const Core &) = delete;
        Core(Core &&) = delete;
        Core &operator=(Core &&) = delete;

        [[nodiscard]] inline AcceptorManager &acceptors() noexcept { return *acceptorManager_; }
        [[nodiscard]] inline const AcceptorManager &acceptors() const noexcept { return *acceptorManager_; }
        [[nodiscard]] inline AcceptorManager &inbounds() noexcept { return *acceptorManager_; }
        [[nodiscard]] inline const AcceptorManager &inbounds() const noexcept { return *acceptorManager_; }

        [[nodiscard]] inline DialerManager &dialers() noexcept { return *dialerManager_; }
        [[nodiscard]] inline const DialerManager &dialers() const noexcept { return *dialerManager_; }
        [[nodiscard]] inline DialerManager &outbounds() noexcept { return *dialerManager_; }
        [[nodiscard]] inline const DialerManager &outbounds() const noexcept { return *dialerManager_; }

        [[nodiscard]] inline Router &router() noexcept { return *router_; }
        [[nodiscard]] inline const Router &router() const noexcept { return *router_; }

        [[nodiscard]] inline std::shared_ptr<Forwarder> forwarder() const noexcept { return forwarder_; }

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
            // 为未显式设置 mark 的非 block 出站绑定 ebpf.fwmark，防止透明网关出站回环
            if (cfg.fwmark > 0 && dialerManager_ != nullptr)
            {
                for (const auto &dl : dialerManager_->dialers())
                {
                    if (dl != nullptr && dl->type() != "block" && dl->mark() == 0)
                    {
                        dl->setMark(cfg.fwmark);
                    }
                }
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
            if (router_ != nullptr && dialerManager_ != nullptr)
            {
                if (!router_->defaultOutbound().empty() && !dialerManager_->has(router_->defaultOutbound()))
                {
                    LOG_ERROR("Core start failed: default outbound '{}' not registered in DialerManager",
                              router_->defaultOutbound());
                    return std::unexpected(ERR::CONNECT_FAILED);
                }
                for (const auto &rule : router_->rules())
                {
                    if (!rule.outboundTag.empty() && !dialerManager_->has(rule.outboundTag))
                    {
                        LOG_ERROR("Core start failed: route rule outbound '{}' not registered in DialerManager",
                                  rule.outboundTag);
                        return std::unexpected(ERR::CONNECT_FAILED);
                    }
                }
            }

            // 2. 出站系统启动 (生命周期就绪与活动选择器装配)
            if (dialerManager_ != nullptr)
            {
                auto outRes = dialerManager_->startAll();
                if (!outRes)
                {
                    return outRes;
                }
            }

            // 3. 入站系统批量监听 (监听套接字绑定与非阻塞开始就绪)
            if (acceptorManager_ != nullptr)
            {
                auto inRes = acceptorManager_->startAll(backlog);
                if (!inRes)
                {
                    // 回滚已启动的出站
                    if (dialerManager_ != nullptr)
                    {
                        dialerManager_->stopAll();
                    }
                    return inRes;
                }

                // 若启用了 eBPF 透明网关拦截，将 TProxy TCP 与 UDP 监听套接字同步下发至内核映射
                if (ebpfEngine_ != nullptr)
                {
                    int tproxyTcpFd = -1;
                    int udpFd = -1;
                    for (const auto &acc : acceptorManager_->acceptors())
                    {
                        if (acc == nullptr || acc->listenFd() < 0)
                        {
                            continue;
                        }
                        if (acc->type() == "tproxy" && tproxyTcpFd < 0)
                        {
                            tproxyTcpFd = acc->listenFd();
                        }
                        else if ((acc->type() == "datagram" || acc->type() == "udp") && udpFd < 0)
                        {
                            udpFd = acc->listenFd();
                        }
                    }
                    if (tproxyTcpFd >= 0 || udpFd >= 0)
                    {
                        ebpfEngine_->setListeningSockets(tproxyTcpFd, udpFd);
                    }
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
                if (acceptorManager_ != nullptr)
                {
                    acceptorManager_->stopAll();
                }
                // 2. 关断活跃中继会话 (安全释放描述符与零拷贝管道)
                if (forwarder_ != nullptr)
                {
                    forwarder_->closeAll();
                }
                // 3. 关断出站系统生命周期
                if (dialerManager_ != nullptr)
                {
                    dialerManager_->stopAll();
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
        inline std::shared_ptr<ForwarderStreamSession> bridge(Handler &inbound, Handler &outbound,
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
         * @brief 注册一个接收器实例 (Acceptor)
         */
        inline void addAcceptor(std::shared_ptr<Acceptor> acceptor)
        {
            if (acceptorManager_ != nullptr)
            {
                acceptorManager_->registerAcceptor(std::move(acceptor));
            }
        }

        inline void addInbound(std::shared_ptr<Acceptor> inbound)
        {
            addAcceptor(std::move(inbound));
        }

        /**
         * @brief 注册一个拨号器实例 (Dialer)
         */
        inline void addDialer(std::shared_ptr<Dialer> dialer)
        {
            if (dialerManager_ != nullptr)
            {
                dialerManager_->registerDialer(std::move(dialer));
            }
        }

        inline void addOutbound(std::shared_ptr<Dialer> outbound)
        {
            addDialer(std::move(outbound));
        }

        /**
         * @brief 注册一个入站配置并保存规范
         */
        inline void addInboundConfig(InboundConfig config)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto next = std::make_shared<MynetConfig>(*mynetConfig_);
            next->inbounds.push_back(std::move(config));
            mynetConfig_ = std::move(next);
        }

        [[nodiscard]] inline std::vector<InboundConfig> inboundConfigs() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return mynetConfig_->inbounds;
        }

        /**
         * @brief 注册一个出站配置并保存规范
         */
        inline void addOutboundConfig(OutboundConfig config)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto next = std::make_shared<MynetConfig>(*mynetConfig_);
            next->outbounds.push_back(std::move(config));
            mynetConfig_ = std::move(next);
        }

        [[nodiscard]] inline std::vector<OutboundConfig> outboundConfigs() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return mynetConfig_->outbounds;
        }

        [[nodiscard]] inline RouterConfig routerConfig() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return mynetConfig_->router;
        }

        [[nodiscard]] inline MynetConfig mynetConfig() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return *mynetConfig_;
        }

        [[nodiscard]] inline std::shared_ptr<const MynetConfig> mynetConfigShared() const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return mynetConfig_;
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
        CoreDispatchResult dispatch(Handler &inbound, int inFd = -1, std::string_view inboundTag = "",
                                    bool enableSniffing = true, bool ownsOutboundFd = false)
        {
            CoreDispatchResult result;

            // 1. 提取目标端点地址
            if (!inbound.targetAddress().has_value() && inbound.target().host.empty() &&
                inbound.target().ipv4_.s_addr == 0)
            {
                result.status = CoreDispatchStatus::NO_TARGET;
                return result;
            }
            result.target = inbound.target();

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
            const bool deferConnect = (forwarder_ != nullptr && forwarder_->loopHooks().deferOutboundConnect);
            ScopedDeferTcpConnect deferGuard(deferConnect);
            auto dialRes = dialerManager_->dialStream(outboundTag, result.target);
            if (!dialRes)
            {
                result.status = CoreDispatchStatus::DIAL_FAILED;
                inbound.setCloseAfterResponse(true);
                return result;
            }

            // 若命中拦截黑洞 (Block)
            if (dialRes->handler->outboundStage() == handler::OutboundStage::ERROR)
            {
                if (dialRes->fd >= 0)
                {
                    ::close(dialRes->fd);
                }
                result.status = CoreDispatchStatus::BLOCKED;
                inbound.setCloseAfterResponse(true);
                return result;
            }

            // 5. 核心桥接：将 Inbound 与 Outbound 交由 Forwarder 纳管
            auto session = forwarder_->bridgeDispatched(
                inbound, std::move(dialRes->handler), (inFd >= 0) ? inFd : inbound.fd(), dialRes->fd,
                ownsOutboundFd, !dialRes->immediateConnected, dialRes->connectDeferred, dialRes->peerAddr,
                result.target, result.outboundTag);

            result.session = std::move(session);
            result.status = CoreDispatchStatus::SUCCESS;
            return result;
        }

        /**
         * @brief 调度与转发无连接 UDP 数据报（复用 Router 策略、DialerDatagram 与 ForwarderDatagramSession）
         */
        inline Result<size_t> dispatchDatagram(HandlerBase &inbound, const sockaddr_in &clientPeer,
                                               const handler::ProxyAddress &target, std::string_view payload,
                                               std::string_view inboundTag = "", bool enableSniffing = true)
        {
            RouteContext ctx;
            ctx.network = NetworkType::UDP;
            ctx.inboundTag = inboundTag;
            ctx.target = target;

            if (enableSniffing && !payload.empty())
            {
                std::span<const uint8_t> peekSpan(reinterpret_cast<const uint8_t *>(payload.data()), payload.size());
                if (auto sniffRes = handler::sniffing::DomainSniffer::sniff(peekSpan); sniffRes.has_value())
                {
                    ctx.sniffedProtocol = sniffRes->protocol;
                    ctx.sniffedDomain = sniffRes->host;
                    if (!sniffRes->host.empty() && ctx.target.type != handler::AddressType::DOMAIN)
                    {
                        const uint16_t p = (ctx.target.port != 0) ? ctx.target.port : sniffRes->port;
                        ctx.target = handler::ProxyAddress::fromDomain(sniffRes->host, p);
                    }
                }
            }

            const std::string_view outboundTag = router_->match(ctx);
            if (outboundTag == "block")
            {
                return std::unexpected(ERR::CONNECT_FAILED);
            }

            sockaddr_in remoteSin{};
            if (auto sin = ctx.target.toSockAddrIn(); sin.has_value())
            {
                remoteSin = *sin;
            }
            else if (!ctx.target.host.empty())
            {
                auto ipRes = Dialer::resolveIpv4Public(ctx.target.host, SOCK_DGRAM);
                if (!ipRes)
                {
                    return std::unexpected(ipRes.error());
                }
                remoteSin.sin_family = AF_INET;
                remoteSin.sin_addr = *ipRes;
                remoteSin.sin_port = ::htons(ctx.target.port);
            }
            else
            {
                return std::unexpected(ERR::ADDR_INVALID);
            }

            auto session = forwarder_->findDatagramSession(clientPeer, remoteSin);
            if (session == nullptr)
            {
                auto fdRes = dialerManager_->dialDatagram(outboundTag, ctx.target);
                if (!fdRes)
                {
                    return std::unexpected(fdRes.error());
                }
                session = forwarder_->getOrCreateDatagramSession(clientPeer, remoteSin, *fdRes);
                (void)forwarder_->activateDatagramWatch(session, inbound);
            }
            return forwarder_->forwardDatagramToRemote(*session, payload);
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
