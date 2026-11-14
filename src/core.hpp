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

#include "error.hpp"
#include "forwarder.hpp"
#include "inboundManager.hpp"
#include "outboundManager.hpp"
#include "router.hpp"
#include "handler/inbound.hpp"
#include "handler/outbound.hpp"
#include "handler/sniffing/sniffer.hpp"
#include "config/log.hpp"
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
     * @brief 入站监听配置规范
     */
    struct InboundConfig
    {
        std::string tag{"mixed-in"};            ///< 入站标签名称 (供分流规则匹配)
        std::string protocol{"mixed"};          ///< 入站协议类型 ("mixed", "socks5", "http", "trojan", "direct", "tproxy")
        std::string host{"0.0.0.0"};            ///< 监听绑定地址
        uint16_t port{1080};                    ///< 监听端口
        std::string username{};                 ///< 鉴权用户名 (可选)
        std::string password{};                 ///< 鉴权密码或密钥 (可选)
        bool enableSniffing{true};              ///< 是否启用首包域名与协议嗅探
    };

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

        mutable std::mutex mutex_{};
        std::vector<InboundConfig> inboundConfigs_{};
        std::atomic<bool> running_{false};

    public:
        Core()
            : inboundManager_(std::make_shared<InboundManager>()),
              outboundManager_(std::make_shared<OutboundManager>()),
              router_(std::make_shared<Router>("direct")),
              forwarder_(std::make_shared<Forwarder>())
        {
        }

        explicit Core(ForwarderOptions fwdOpts)
            : inboundManager_(std::make_shared<InboundManager>()),
              outboundManager_(std::make_shared<OutboundManager>()),
              router_(std::make_shared<Router>("direct")),
              forwarder_(std::make_shared<Forwarder>(fwdOpts))
        {
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

        [[nodiscard]] inline Forwarder &forwarder() noexcept { return *forwarder_; }
        [[nodiscard]] inline const Forwarder &forwarder() const noexcept { return *forwarder_; }

        [[nodiscard]] inline bool isRunning() const noexcept
        {
            return running_.load(std::memory_order_acquire);
        }

        inline Result<> start(int backlog = 128)
        {
            if (running_.exchange(true, std::memory_order_acq_rel))
            {
                return {};
            }
            if (inboundManager_ != nullptr)
            {
                return inboundManager_->startAll(backlog);
            }
            return {};
        }

        inline void stop() noexcept
        {
            if (running_.exchange(false, std::memory_order_acq_rel))
            {
                if (inboundManager_ != nullptr)
                {
                    inboundManager_->stopAll();
                }
                if (forwarder_ != nullptr)
                {
                    forwarder_->closeAll();
                }
            }
        }

        /**
         * @brief 注册一个入站节点实例
         */
        inline void addInbound(std::shared_ptr<Inbound> inbound)
        {
            if (inboundManager_ != nullptr)
            {
                inboundManager_->registerInbound(std::move(inbound));
            }
        }

        /**
         * @brief 注册一个入站配置并保存规范
         */
        inline void addInboundConfig(InboundConfig config)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            inboundConfigs_.push_back(std::move(config));
        }

        [[nodiscard]] inline std::vector<InboundConfig> inboundConfigs() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return inboundConfigs_;
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
        CoreDispatchResult dispatch(handler::HandlerInboundConnection &inbound,
                                   int inFd = -1,
                                   std::string_view inboundTag = "",
                                   bool enableSniffing = true)
        {
            CoreDispatchResult result;

            // 1. 提取目标端点地址
            if (!inbound.targetAddress().has_value() && inbound.target().host.empty() && inbound.target().ipv4_.s_addr == 0)
            {
                result.status = CoreDispatchStatus::NO_TARGET;
                return result;
            }
            result.target = inbound.targetAddress().value_or(inbound.target());

            // 2. 深度数据包嗅探：从早期摄入用户态缓冲的数据中嗅探真实 SNI 与协议
            if (enableSniffing && inbound.requestBytes() > 0)
            {
                std::span<const uint8_t> earlyData(
                    reinterpret_cast<const uint8_t *>(inbound.requestBegin()),
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

            // 3. 构建路由上下文并执行策略匹配
            RouteContext ctx;
            ctx.network = NetworkType::TCP;
            ctx.inboundTag = inboundTag;
            ctx.target = result.target;
            ctx.sniffedDomain = result.sniffedDomain;
            ctx.sniffedProtocol = result.sniffedProtocol;

            std::string_view outboundTag = router_->match(ctx);
            result.outboundTag = std::string(outboundTag);

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

            // 若满足条件，激活零拷贝或缓冲泵送
            if (session->options().enableSplice && session->inboundFd() >= 0 && session->outboundFd() >= 0)
            {
                session->activateSplice();
            }

            result.session = std::move(session);
            result.status = CoreDispatchStatus::SUCCESS;
            return result;
        }

        /**
         * @brief 驱动一次全量会话泵送与空闲清理
         */
        inline size_t tick()
        {
            return forwarder_->pumpAll();
        }

        // =====================================================================
        // 全局聚合监控指标
        // =====================================================================

        [[nodiscard]] inline size_t activeSessions() const noexcept
        {
            return forwarder_->activeStreamSessions();
        }

        [[nodiscard]] inline uint64_t totalBytesUp() const noexcept
        {
            return forwarder_->totalBytesUp();
        }

        [[nodiscard]] inline uint64_t totalBytesDown() const noexcept
        {
            return forwarder_->totalBytesDown();
        }

        [[nodiscard]] inline uint64_t totalBytes() const noexcept
        {
            return totalBytesUp() + totalBytesDown();
        }
    };

} // namespace mynet
