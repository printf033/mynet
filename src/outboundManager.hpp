#pragma once

/**
 * @file outboundManager.hpp
 * @brief 出站节点抽象与出站管理器 (Outbound & OutboundManager)。
 *
 * 统一管理网络内核的各类出站落地节点（Direct 直连、Block 黑洞、SOCKS5 代理、
 * Trojan 隧道代理、Selector 节点选择器等）：
 * 1. 统一拨号抽象：提供面向流式 (TCP) 与数据报 (UDP) 的异步非阻塞出站建连；
 * 2. 状态机就绪装配：拨号成功后自动构造匹配的出站协议状态机处理器 (HandlerOutboundConnection)；
 * 3. 域名解析与四元组确立：原生支持域名目标自动解析 (A/AAAA) 并发起非阻塞 TCP/UDP 握手；
 * 4. 节点调度与选择器 (Selector)：支持运行时动态切换活动节点或主备切换；
 * 5. 全生命周期描述符托管：确保套接字在拨号成功时安全转移给上层会话或连接。
 */

#include "dialer.hpp"
#include "error.hpp"
#include "handler/address.hpp"
#include "handler/block.hpp"
#include "handler/direct.hpp"
#include "handler/outbound.hpp"
#include "handler/proxy/trojan.hpp"
#include "handler/socks/socks5.hpp"
#include "config/log.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <netdb.h>
#include <netinet/in.h>
#include <optional>
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
     * @brief 出站拨号结果
     */
    struct OutboundDialResult
    {
        int fd{-1};                                                            ///< 拨号成功的套接字描述符
        std::unique_ptr<handler::HandlerOutboundConnection> handler{nullptr};  ///< 对应的出站协议状态机处理器
        std::string outboundTag{};                                             ///< 命中的出站标签
        std::string targetEndpoint{};                                          ///< 目标端点字符串表示
        bool immediateConnected{false};                                        ///< 连接是否立即可用（已非阻塞连上）

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
     */
    class Outbound
    {
    protected:
        std::string tag_{};
        std::string type_{};

    public:
        Outbound(std::string tag, std::string type)
            : tag_(std::move(tag)), type_(std::move(type))
        {
        }

        virtual ~Outbound() noexcept = default;

        [[nodiscard]] inline const std::string &tag() const noexcept { return tag_; }
        [[nodiscard]] inline const std::string &type() const noexcept { return type_; }

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

    /**
     * @brief 直连出站节点 (Direct Outbound)
     *
     * 直接向目标地址发起 TCP/UDP 建连，初始处于 STREAMING 状态，天然支持 splice 零拷贝。
     */
    class DirectOutbound : public Outbound
    {
    public:
        explicit DirectOutbound(std::string tag = "direct")
            : Outbound(std::move(tag), "direct")
        {
        }

        Result<OutboundDialResult> dialStream(const handler::ProxyAddress &target) override
        {
            DialerBase<handler::HandlerOutboundDirect> dialer;
            Result<bool> res;

            if (target.type == handler::AddressType::IPV4 && target.ipv4_.s_addr != 0)
            {
                sockaddr_in sin{};
                sin.sin_family = AF_INET;
                sin.sin_addr = target.ipv4_;
                sin.sin_port = htons(target.port);
                res = dialer.dialTcp(sin);
            }
            else
            {
                auto resolved = resolveDomainIpv4(target.host);
                if (!resolved)
                {
                    return std::unexpected(resolved.error());
                }
                sockaddr_in sin{};
                sin.sin_family = AF_INET;
                sin.sin_addr = *resolved;
                sin.sin_port = htons(target.port);
                res = dialer.dialTcp(sin);
            }

            if (!res)
            {
                return std::unexpected(res.error());
            }

            int socketFd = dialer.fd;
            dialer.fd = -1; // 转移描述符所有权，防止析构关闭

            OutboundDialResult outRes;
            outRes.fd = socketFd;
            outRes.handler = std::make_unique<handler::HandlerOutboundDirect>(target);
            outRes.outboundTag = tag_;
            outRes.targetEndpoint = target.toString();
            outRes.immediateConnected = *res;
            return outRes;
        }

        Result<int> dialDatagram(const handler::ProxyAddress &target) override
        {
            DialerBase<handler::HandlerOutboundDirect> dialer;
            sockaddr_in sin{};
            sin.sin_family = AF_INET;
            sin.sin_port = htons(target.port);

            if (target.type == handler::AddressType::IPV4 && target.ipv4_.s_addr != 0)
            {
                sin.sin_addr = target.ipv4_;
            }
            else
            {
                auto resolved = resolveDomainIpv4(target.host);
                if (!resolved)
                {
                    return std::unexpected(resolved.error());
                }
                sin.sin_addr = *resolved;
            }

            if (auto res = dialer.dialUdp(sin); !res)
            {
                return std::unexpected(res.error());
            }

            int socketFd = dialer.fd;
            dialer.fd = -1;
            return socketFd;
        }
    };

    /**
     * @brief 拦截黑洞出站节点 (Block Outbound / Blackhole)
     *
     * 阻断任何向外的流量，流式连接立刻进入 ERROR 并标记关闭。
     */
    class BlockOutbound : public Outbound
    {
    public:
        explicit BlockOutbound(std::string tag = "block")
            : Outbound(std::move(tag), "block")
        {
        }

        Result<OutboundDialResult> dialStream(const handler::ProxyAddress &target) override
        {
            OutboundDialResult res;
            res.fd = -1;
            res.handler = std::make_unique<handler::HandlerOutboundBlock>();
            res.outboundTag = tag_;
            res.targetEndpoint = target.toString();
            res.immediateConnected = false;
            return res;
        }

        Result<int> dialDatagram(const handler::ProxyAddress &target) override
        {
            (void)target;
            return std::unexpected(ERR::CONNECT_FAILED);
        }
    };

    /**
     * @brief SOCKS5 二级代理出站节点 (SOCKS5 Outbound Proxy)
     *
     * 将流量打入上游 SOCKS5 代理服务器。
     */
    class Socks5Outbound : public Outbound
    {
    private:
        std::string serverHost_{};
        uint16_t serverPort_{1080};
        std::string username_{};
        std::string password_{};

    public:
        Socks5Outbound(std::string tag, std::string serverHost, uint16_t serverPort,
                       std::string username = "", std::string password = "")
            : Outbound(std::move(tag), "socks5"),
              serverHost_(std::move(serverHost)),
              serverPort_(serverPort),
              username_(std::move(username)),
              password_(std::move(password))
        {
        }

        [[nodiscard]] const std::string &serverHost() const noexcept { return serverHost_; }
        [[nodiscard]] uint16_t serverPort() const noexcept { return serverPort_; }

        Result<OutboundDialResult> dialStream(const handler::ProxyAddress &target) override
        {
            auto resolved = resolveDomainIpv4(serverHost_);
            if (!resolved)
            {
                return std::unexpected(resolved.error());
            }

            sockaddr_in sin{};
            sin.sin_family = AF_INET;
            sin.sin_addr = *resolved;
            sin.sin_port = htons(serverPort_);

            DialerBase<handler::HandlerOutboundSocks5> dialer;
            auto dialRes = dialer.dialTcp(sin);
            if (!dialRes)
            {
                return std::unexpected(dialRes.error());
            }

            int socketFd = dialer.fd;
            dialer.fd = -1;

            auto h = std::make_unique<handler::HandlerOutboundSocks5>(target);
            h->process(); // 生成第一步认证握手报文

            OutboundDialResult res;
            res.fd = socketFd;
            res.handler = std::move(h);
            res.outboundTag = tag_;
            res.targetEndpoint = target.toString();
            res.immediateConnected = *dialRes;
            return res;
        }

        Result<int> dialDatagram(const handler::ProxyAddress &target) override
        {
            (void)target;
            // UDP 转发需要通过 SOCKS5 UDP Associate 扩展
            return std::unexpected(ERR::CONNECT_FAILED);
        }
    };

    /**
     * @brief Trojan 隧道代理出站节点 (Trojan Outbound Proxy)
     */
    class TrojanOutbound : public Outbound
    {
    private:
        std::string serverHost_{};
        uint16_t serverPort_{443};
        std::string password_{};

    public:
        TrojanOutbound(std::string tag, std::string serverHost, uint16_t serverPort, std::string password)
            : Outbound(std::move(tag), "trojan"),
              serverHost_(std::move(serverHost)),
              serverPort_(serverPort),
              password_(std::move(password))
        {
        }

        [[nodiscard]] const std::string &serverHost() const noexcept { return serverHost_; }
        [[nodiscard]] uint16_t serverPort() const noexcept { return serverPort_; }

        Result<OutboundDialResult> dialStream(const handler::ProxyAddress &target) override
        {
            auto resolved = resolveDomainIpv4(serverHost_);
            if (!resolved)
            {
                return std::unexpected(resolved.error());
            }

            sockaddr_in sin{};
            sin.sin_family = AF_INET;
            sin.sin_addr = *resolved;
            sin.sin_port = htons(serverPort_);

            DialerBase<handler::HandlerOutboundTrojan> dialer;
            auto dialRes = dialer.dialTcp(sin);
            if (!dialRes)
            {
                return std::unexpected(dialRes.error());
            }

            int socketFd = dialer.fd;
            dialer.fd = -1;

            auto h = std::make_unique<handler::HandlerOutboundTrojan>(password_, target);
            h->process(); // 生成 Trojan 认证头部与目标包裹帧

            OutboundDialResult res;
            res.fd = socketFd;
            res.handler = std::move(h);
            res.outboundTag = tag_;
            res.targetEndpoint = target.toString();
            res.immediateConnected = *dialRes;
            return res;
        }

        Result<int> dialDatagram(const handler::ProxyAddress &target) override
        {
            (void)target;
            return std::unexpected(ERR::CONNECT_FAILED);
        }
    };

    // 前向声明 OutboundManager 供 Selector 引用
    class OutboundManager;

    /**
     * @brief 节点选择器 / 分组出站 (Selector Outbound)
     *
     * 聚合多个出站标签，支持手动指定活动节点或自动按优先级故障回退。
     */
    class SelectorOutbound : public Outbound
    {
    private:
        std::vector<std::string> candidateTags_{};
        std::string selectedTag_{};
        OutboundManager *manager_{nullptr};

    public:
        SelectorOutbound(std::string tag, std::vector<std::string> candidates, OutboundManager *mgr = nullptr)
            : Outbound(std::move(tag), "selector"),
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

        Result<OutboundDialResult> dialStream(const handler::ProxyAddress &target) override;
        Result<int> dialDatagram(const handler::ProxyAddress &target) override;
    };

    /**
     * @brief 统一出站管理器 (Outbound Manager)
     *
     * 维护系统所有出站节点的注册表，默认自动预置 direct 与 block 两个标准出口。
     */
    class OutboundManager
    {
    private:
        mutable std::mutex mutex_{};
        std::unordered_map<std::string, std::shared_ptr<Outbound>> outbounds_{};
        std::string defaultTag_{"direct"};

    public:
        OutboundManager()
        {
            // 默认自动装配 direct 与 block 标准出口
            registerOutbound(std::make_shared<DirectOutbound>("direct"));
            registerOutbound(std::make_shared<BlockOutbound>("block"));
        }

        ~OutboundManager() noexcept = default;

        OutboundManager(const OutboundManager &) = delete;
        OutboundManager &operator=(const OutboundManager &) = delete;
        OutboundManager(OutboundManager &&) = delete;
        OutboundManager &operator=(OutboundManager &&) = delete;

        [[nodiscard]] inline std::string_view defaultTag() const noexcept { return defaultTag_; }
        inline void setDefaultTag(std::string tag)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            defaultTag_ = std::move(tag);
        }

        /**
         * @brief 注册一个出站节点
         */
        void registerOutbound(std::shared_ptr<Outbound> outbound)
        {
            if (outbound == nullptr)
                return;
            std::lock_guard<std::mutex> lock(mutex_);
            if (auto *sel = dynamic_cast<SelectorOutbound *>(outbound.get()); sel != nullptr)
            {
                sel->setManager(this);
            }
            outbounds_[outbound->tag()] = std::move(outbound);
        }

        /**
         * @brief 根据标签获取出站节点指针
         */
        [[nodiscard]] std::shared_ptr<Outbound> get(std::string_view tag) const
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
         *
         * @param tag 命中的出站标签（若未注册则自动降级到 defaultTag_）
         * @param target 代理目标端点地址
         * @return Result<OutboundDialResult> 拨号结果
         */
        Result<OutboundDialResult> dialStream(std::string_view tag, const handler::ProxyAddress &target)
        {
            std::shared_ptr<Outbound> ob = get(tag);
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
            std::shared_ptr<Outbound> ob = get(tag);
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

    // SelectorOutbound 延迟实现
    inline Result<OutboundDialResult> SelectorOutbound::dialStream(const handler::ProxyAddress &target)
    {
        if (manager_ == nullptr || selectedTag_.empty())
        {
            return std::unexpected(ERR::CONNECT_FAILED);
        }
        return manager_->dialStream(selectedTag_, target);
    }

    inline Result<int> SelectorOutbound::dialDatagram(const handler::ProxyAddress &target)
    {
        if (manager_ == nullptr || selectedTag_.empty())
        {
            return std::unexpected(ERR::CONNECT_FAILED);
        }
        return manager_->dialDatagram(selectedTag_, target);
    }

} // namespace mynet
