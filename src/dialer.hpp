#pragma once

/**
 * @file dialer.hpp
 * @brief 客户端出站拨号握手器（Dialer）基类与出站抽象。
 *
 * 与 Acceptor 严格对称：
 * 1. 专职负责出站协议握手 (Outbound Handshake)；
 * 2. 包含特定协议相关的 outbound_ 结构体（模板特化占位，不需要时为 EmptyOutbound，配合 [[no_unique_address]] 占 0
 * 字节）；
 * 3. 底层 TCP/UDP 传输建连系统调用托管给 socket.hpp 工具库；
 * 4. 结合 Linux SO_MARK 策略路由、IP_TRANSPARENT 与粘性 IP 缓存。
 */

#include "acceptor.hpp"
#include "config/log.hpp"
#include "connection.hpp"
#include "error.hpp"
#include "tls/fragmenter.hpp"
#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <concepts>
#include <csignal>
#include <fcntl.h>
#include <mutex>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <span>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

#ifndef IPPROTO_MPTCP
#define IPPROTO_MPTCP 262
#endif

namespace mynet
{

    class ConnectionBase;

    /**
     * @brief 空出站上下文结构（不占任何空间）
     */
    struct EmptyOutbound
    {
    };

    /**
     * @brief 出站节点粘性 IP 缓存器 (借鉴 dae StickyIpDialer)
     */
    class StickyIpCache
    {
    private:
        struct Entry
        {
            std::string ip{};
            std::chrono::steady_clock::time_point lastSeen{};
            uint32_t failCount{0};
        };
        mutable std::mutex mutex_{};
        std::unordered_map<std::string, Entry> cache_{};
        uint32_t maxFails_{3};

    public:
        static StickyIpCache &instance() noexcept
        {
            static StickyIpCache s_inst;
            return s_inst;
        }

        [[nodiscard]] std::optional<std::string> get(std::string_view host) const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = cache_.find(std::string(host));
            if (it != cache_.end() && it->second.failCount < maxFails_)
            {
                return it->second.ip;
            }
            return std::nullopt;
        }

        void recordSuccess(std::string_view host, std::string_view ip) noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto &entry = cache_[std::string(host)];
            entry.ip = std::string(ip);
            entry.lastSeen = std::chrono::steady_clock::now();
            entry.failCount = 0;
        }

        void recordFailure(std::string_view host) noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = cache_.find(std::string(host));
            if (it != cache_.end())
            {
                it->second.failCount++;
                if (it->second.failCount >= maxFails_)
                {
                    cache_.erase(it);
                }
            }
        }

        void invalidate(std::string_view host) noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            cache_.erase(std::string(host));
        }

        void clear() noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            cache_.clear();
        }
    };

    /**
     * @brief 拨号器纯虚抽象接口
     */
    class IDialer
    {
    public:
        int fd = -1;
        sockaddr_in targetAddr{};
        uint32_t fwmark{0};               ///< Linux SO_MARK 策略路由标记（防环路）
        bool transparent{false};          ///< Linux IP_TRANSPARENT 支持（绑定原始源 IP）
        uint8_t dscp{0};                  ///< DSCP 服务质量标记 (借鉴 dae dscp)
        bool enableMptcp{false};          ///< 是否启用 Multipath TCP (MPTCP)
        std::string bindInterface{};      ///< SO_BINDTODEVICE 绑定网卡
        std::vector<uint8_t> tcpPrefix{}; ///< TCP 前置注入前缀 (借鉴 sing-box tcp_prefix)

        virtual ~IDialer() noexcept { reset(); }

        virtual HandshakeStatus handshake(int targetFd, ConnectionBase *&outConn) = 0;

        virtual void reset() noexcept
        {
            if (fd != -1)
            {
                ::close(fd);
                fd = -1;
            }
            targetAddr = {};
        }

        inline void attach(int newFd) noexcept
        {
            if (fd != -1 && fd != newFd)
            {
                ::close(fd);
            }
            fd = newFd;
        }

        [[nodiscard]] inline int release() noexcept
        {
            int ret = fd;
            fd = -1;
            targetAddr = {};
            return ret;
        }

        inline void setTcpPrefix(std::span<const uint8_t> prefix) noexcept
        {
            tcpPrefix.assign(prefix.begin(), prefix.end());
        }
        [[nodiscard]] inline std::span<const uint8_t> getTcpPrefix() const noexcept { return tcpPrefix; }

        inline bool flushTcpPrefix(int socketFd = -1) noexcept
        {
            int target = socketFd >= 0 ? socketFd : fd;
            if (target < 0 || tcpPrefix.empty())
                return true;
            ssize_t n = ::send(target, tcpPrefix.data(), tcpPrefix.size(), MSG_NOSIGNAL);
            return n == static_cast<ssize_t>(tcpPrefix.size());
        }

        inline void setMark(uint32_t mark) noexcept { fwmark = mark; }
        [[nodiscard]] inline uint32_t mark() const noexcept { return fwmark; }

        inline void setTransparent(bool enable) noexcept { transparent = enable; }
        [[nodiscard]] inline bool isTransparent() const noexcept { return transparent; }

        inline void setDscp(uint8_t val) noexcept { dscp = val; }
        [[nodiscard]] inline uint8_t getDscp() const noexcept { return dscp; }

        inline void setMptcp(bool enable) noexcept { enableMptcp = enable; }
        [[nodiscard]] inline bool isMptcp() const noexcept { return enableMptcp; }

        inline void setInterface(std::string_view ifname) noexcept { bindInterface = ifname; }
        [[nodiscard]] inline std::string_view getInterface() const noexcept { return bindInterface; }

        [[nodiscard]] Result<bool> dialTcp(const char *ip, int port, const char *bindIface = nullptr) noexcept
        {
            contract_assert(ip != nullptr);
            reset();
            ::signal(SIGPIPE, SIG_IGN);

            targetAddr.sin_family = AF_INET;
            if (::inet_pton(AF_INET, ip, &targetAddr.sin_addr) <= 0) [[unlikely]]
            {
                LOG_ERROR("dialTcp {}:{}: not an IPv4 address literal", ip, port);
                reset();
                return std::unexpected(ERR::ADDR_INVALID);
            }
            targetAddr.sin_port = ::htons(static_cast<uint16_t>(port));
            return dialTcp(targetAddr, bindIface);
        }

        [[nodiscard]] Result<bool> dialTcp(std::string_view host, uint16_t port,
                                           const char *bindIface = nullptr) noexcept
        {
            if (host.empty())
            {
                return std::unexpected(ERR::ADDR_INVALID);
            }
            in_addr inAddr{};
            std::string hostStr(host);
            if (::inet_pton(AF_INET, hostStr.c_str(), &inAddr) != 1)
            {
                addrinfo hints{};
                hints.ai_family = AF_INET;
                hints.ai_socktype = SOCK_STREAM;
                addrinfo *res = nullptr;
                if (::getaddrinfo(hostStr.c_str(), nullptr, &hints, &res) != 0 || res == nullptr)
                {
                    return std::unexpected(ERR::ADDR_INVALID);
                }
                const auto *sin = reinterpret_cast<const sockaddr_in *>(res->ai_addr);
                inAddr = sin->sin_addr;
                ::freeaddrinfo(res);
            }

            sockaddr_in target{};
            target.sin_family = AF_INET;
            target.sin_addr = inAddr;
            target.sin_port = ::htons(port);
            return dialTcp(target, bindIface);
        }

        [[nodiscard]] Result<bool> dialTcp(const sockaddr_in &target, const char *bindIface = nullptr) noexcept
        {
            reset();
            ::signal(SIGPIPE, SIG_IGN);
            targetAddr = target;

#if defined(IPPROTO_MPTCP)
            if (enableMptcp)
            {
                fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_MPTCP);
            }
#endif
            if (fd < 0)
            {
                fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            }
            if (fd < 0) [[unlikely]]
            {
                LOG_ERROR("dialTcp: socket() failed: {}", errnoText(errno));
                reset();
                return std::unexpected(ERR::SOCKET_FAILED);
            }

            constexpr int opt = 1;
            [[maybe_unused]] auto _ = ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
            [[maybe_unused]] auto _keepalive = ::setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));

            const char *iface = (bindIface != nullptr && bindIface[0] != '\0')
                                    ? bindIface
                                    : (!this->bindInterface.empty() ? this->bindInterface.c_str() : nullptr);
            if (iface != nullptr && iface[0] != '\0')
            {
                if (::setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface, ::strlen(iface)) < 0) [[unlikely]]
                {
                    LOG_WARN("dialTcp: setsockopt(SO_BINDTODEVICE={}) failed: {}", iface, errnoText(errno));
                }
            }

            if (fwmark > 0)
            {
                if (::setsockopt(fd, SOL_SOCKET, SO_MARK, &fwmark, sizeof(fwmark)) < 0) [[unlikely]]
                {
                    LOG_WARN("dialTcp: setsockopt(SO_MARK={}) failed: {}", fwmark, errnoText(errno));
                }
            }

            if (transparent)
            {
                if (::setsockopt(fd, SOL_IP, IP_TRANSPARENT, &opt, sizeof(opt)) < 0) [[unlikely]]
                {
                    LOG_WARN("dialTcp: setsockopt(IP_TRANSPARENT) failed: {}", errnoText(errno));
                }
            }

            if (dscp > 0)
            {
                int tos = static_cast<int>(dscp) << 2;
                [[maybe_unused]] auto _ = ::setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
            }

            int rc = ::connect(fd, reinterpret_cast<const sockaddr *>(&targetAddr), sizeof(sockaddr_in));
            if (rc == 0)
            {
                return true;
            }
            if (errno == EINPROGRESS)
            {
                return false;
            }

            LOG_ERROR("dialTcp: connect() failed: {}", errnoText(errno));
            reset();
            return std::unexpected(ERR::CONNECT_FAILED);
        }

        [[nodiscard]] Result<> dialUdp(const char *ip, int port, const char *bindIface = nullptr) noexcept
        {
            contract_assert(ip != nullptr);
            reset();

            targetAddr.sin_family = AF_INET;
            if (::inet_pton(AF_INET, ip, &targetAddr.sin_addr) <= 0) [[unlikely]]
            {
                LOG_ERROR("dialUdp {}:{}: not an IPv4 address literal", ip, port);
                reset();
                return std::unexpected(ERR::ADDR_INVALID);
            }
            targetAddr.sin_port = ::htons(static_cast<uint16_t>(port));

            fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (fd < 0) [[unlikely]]
            {
                LOG_ERROR("dialUdp: socket() failed: {}", errnoText(errno));
                reset();
                return std::unexpected(ERR::SOCKET_FAILED);
            }

            const char *iface = (bindIface != nullptr && bindIface[0] != '\0')
                                    ? bindIface
                                    : (!this->bindInterface.empty() ? this->bindInterface.c_str() : nullptr);
            if (iface != nullptr && iface[0] != '\0')
            {
                if (::setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface, ::strlen(iface)) < 0) [[unlikely]]
                {
                    LOG_WARN("dialUdp: setsockopt(SO_BINDTODEVICE={}) failed: {}", iface, errnoText(errno));
                }
            }

            if (fwmark > 0)
            {
                if (::setsockopt(fd, SOL_SOCKET, SO_MARK, &fwmark, sizeof(fwmark)) < 0) [[unlikely]]
                {
                    LOG_WARN("dialUdp: setsockopt(SO_MARK={}) failed: {}", fwmark, errnoText(errno));
                }
            }

            if (::connect(fd, reinterpret_cast<const sockaddr *>(&targetAddr), sizeof(sockaddr_in)) < 0) [[unlikely]]
            {
                LOG_ERROR("dialUdp: connect() failed: {}", errnoText(errno));
                reset();
                return std::unexpected(ERR::CONNECT_FAILED);
            }

            return {};
        }

        [[nodiscard]] Result<> dialUdp(std::string_view host, uint16_t port, const char *bindIface = nullptr) noexcept
        {
            if (host.empty())
            {
                return std::unexpected(ERR::ADDR_INVALID);
            }
            in_addr inAddr{};
            std::string hostStr(host);
            if (::inet_pton(AF_INET, hostStr.c_str(), &inAddr) != 1)
            {
                addrinfo hints{};
                hints.ai_family = AF_INET;
                hints.ai_socktype = SOCK_DGRAM;
                addrinfo *res = nullptr;
                if (::getaddrinfo(hostStr.c_str(), nullptr, &hints, &res) != 0 || res == nullptr)
                {
                    return std::unexpected(ERR::ADDR_INVALID);
                }
                const auto *sin = reinterpret_cast<const sockaddr_in *>(res->ai_addr);
                inAddr = sin->sin_addr;
                ::freeaddrinfo(res);
            }

            sockaddr_in target{};
            target.sin_family = AF_INET;
            target.sin_addr = inAddr;
            target.sin_port = ::htons(port);
            return dialUdp(target, bindIface);
        }

        [[nodiscard]] Result<> dialUdp(const sockaddr_in &target, const char *bindIface = nullptr) noexcept
        {
            reset();
            targetAddr = target;

            fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (fd < 0) [[unlikely]]
            {
                LOG_ERROR("dialUdp: socket() failed: {}", errnoText(errno));
                reset();
                return std::unexpected(ERR::SOCKET_FAILED);
            }

            const char *iface = (bindIface != nullptr && bindIface[0] != '\0')
                                    ? bindIface
                                    : (!this->bindInterface.empty() ? this->bindInterface.c_str() : nullptr);
            if (iface != nullptr && iface[0] != '\0')
            {
                if (::setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface, ::strlen(iface)) < 0) [[unlikely]]
                {
                    LOG_WARN("dialUdp: setsockopt(SO_BINDTODEVICE={}) failed: {}", iface, errnoText(errno));
                }
            }

            if (fwmark > 0)
            {
                if (::setsockopt(fd, SOL_SOCKET, SO_MARK, &fwmark, sizeof(fwmark)) < 0) [[unlikely]]
                {
                    LOG_WARN("dialUdp: setsockopt(SO_MARK={}) failed: {}", fwmark, errnoText(errno));
                }
            }

            if (::connect(fd, reinterpret_cast<const sockaddr *>(&targetAddr), sizeof(sockaddr_in)) < 0) [[unlikely]]
            {
                LOG_ERROR("dialUdp: connect() failed: {}", errnoText(errno));
                reset();
                return std::unexpected(ERR::CONNECT_FAILED);
            }

            return {};
        }
    };

    /**
     * @brief 模板化客户端出站握手器基类
     *
     * @tparam OutboundContext 协议特有的 outbound_ 结构体。默认为 EmptyOutbound。
     */
    template <typename OutboundContext = EmptyOutbound>
    class Dialer : public IDialer
    {
    public:
        using Outbound = OutboundContext;
        using Handler = OutboundContext;

        [[no_unique_address]] Outbound outbound_{};

        Dialer() = default;
        explicit Dialer(OutboundContext outbound)
            : outbound_(std::move(outbound))
        {
        }
        ~Dialer() override = default;

        Dialer(const Dialer &) = delete;
        Dialer &operator=(const Dialer &) = delete;
        Dialer(Dialer &&other) noexcept
            : outbound_(std::move(other.outbound_))
        {
            fd = other.fd;
            targetAddr = other.targetAddr;
            fwmark = other.fwmark;
            transparent = other.transparent;
            dscp = other.dscp;
            enableMptcp = other.enableMptcp;
            bindInterface = std::move(other.bindInterface);
            tcpPrefix = std::move(other.tcpPrefix);
            other.fd = -1;
            other.targetAddr = {};
        }
        Dialer &operator=(Dialer &&other) noexcept
        {
            if (this != &other)
            {
                reset();
                outbound_ = std::move(other.outbound_);
                fd = other.fd;
                targetAddr = other.targetAddr;
                fwmark = other.fwmark;
                transparent = other.transparent;
                dscp = other.dscp;
                enableMptcp = other.enableMptcp;
                bindInterface = std::move(other.bindInterface);
                tcpPrefix = std::move(other.tcpPrefix);
                other.fd = -1;
                other.targetAddr = {};
            }
            return *this;
        }

        [[nodiscard]] inline Outbound &outbound() noexcept { return outbound_; }
        [[nodiscard]] inline const Outbound &outbound() const noexcept { return outbound_; }

        HandshakeStatus handshake(int targetFd, ConnectionBase *&outConn) override
        {
            (void)targetFd;
            outConn = nullptr;
            return HandshakeStatus::SUCCESS;
        }
    };

    template <typename OutboundContext = EmptyOutbound>
    using DialerBase = Dialer<OutboundContext>;

    template <typename OutboundContext = EmptyOutbound>
    using DialerBaseCompat = Dialer<OutboundContext>;

    template <typename D>
    concept DerivedFromDialer = std::derived_from<D, IDialer>;

    template <typename D>
    concept BaseDialer = DerivedFromDialer<D>;

    template <typename D>
    concept DerivedFromDialerBase = DerivedFromDialer<D>;

    /**
     * @brief 多网卡出站策略 (借鉴 sing-box C.NetworkStrategy)
     */
    enum class InterfaceStrategy : uint8_t
    {
        DEFAULT = 0, ///< 默认：仅走默认主路由网卡
        HYBRID = 1,  ///< 混合赛马：所有网卡同时发起握手，最快连通者获胜，其余立即安全释放
        FALLBACK = 2 ///< 分级回退：主网卡优先，若在 fallbackDelay 内未握手完成或快错，立即激活备选网卡
    };

    /**
     * @brief 网卡竞速赛马胜出结果
     */
    struct InterfaceRacerResult
    {
        int winnerFd{-1};
        std::string winningInterface{};
        bool isPrimary{false};
        std::chrono::microseconds latency{0};
    };

    /**
     * @brief 多网卡并发赛马与分级回退出站拨号器 (借鉴 sing-box default_parallel_interface.go)
     */
    class ParallelInterfaceDialer
    {
    private:
        struct Racer
        {
            int fd{-1};
            std::string ifname{};
            bool isPrimary{false};
            std::chrono::steady_clock::time_point startTime{};
        };

        static int initiateNonBlockingConnect(const sockaddr_in &targetAddr, const std::string &ifname,
                                              uint32_t fwmark) noexcept
        {
            int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (fd < 0)
                return -1;

            if (fwmark > 0)
            {
                ::setsockopt(fd, SOL_SOCKET, SO_MARK, &fwmark, sizeof(fwmark));
            }

            if (!ifname.empty())
            {
                struct ifreq ifr{};
                std::strncpy(ifr.ifr_name, ifname.c_str(), sizeof(ifr.ifr_name) - 1);
                ::setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr));
            }

            int res = ::connect(fd, reinterpret_cast<const sockaddr *>(&targetAddr), sizeof(targetAddr));
            if (res == 0)
            {
                // 立即建连成功（如本地回路）
                return fd;
            }
            if (res < 0 && errno == EINPROGRESS)
            {
                // 正在异步握手中
                return fd;
            }

            ::close(fd);
            return -1;
        }

    public:
        /**
         * @brief 发起多网卡并发赛马/分级回退拨号
         *
         * @param targetAddr 目标地址四元组
         * @param primaryInterfaces 主网卡列表 (如 {"eth0"})
         * @param fallbackInterfaces 备选网卡列表 (如 {"wlan0", "rmnet0"})
         * @param strategy 赛马策略 (HYBRID / FALLBACK)
         * @param fallbackDelay 回退激活延时 (默认 300ms)
         * @param totalTimeout 总超时时间
         * @param fwmark Linux SO_MARK
         */
        static InterfaceRacerResult
        dialParallelInterface(const sockaddr_in &targetAddr, const std::vector<std::string> &primaryInterfaces,
                              const std::vector<std::string> &fallbackInterfaces,
                              InterfaceStrategy strategy = InterfaceStrategy::FALLBACK,
                              std::chrono::milliseconds fallbackDelay = std::chrono::milliseconds(300),
                              std::chrono::milliseconds totalTimeout = std::chrono::milliseconds(3000),
                              uint32_t fwmark = 0) noexcept
        {
            const auto startTotal = std::chrono::steady_clock::now();
            std::vector<Racer> activeRacers;

            auto cleanupRacers = [&activeRacers](int exceptFd = -1) noexcept
            {
                for (auto &r : activeRacers)
                {
                    if (r.fd >= 0 && r.fd != exceptFd)
                    {
                        ::close(r.fd);
                        r.fd = -1;
                    }
                }
            };

            auto startInterfaceRacer = [&](const std::string &ifname, bool isPrimary) noexcept
            {
                int fd = initiateNonBlockingConnect(targetAddr, ifname, fwmark);
                if (fd >= 0)
                {
                    activeRacers.push_back(Racer{.fd = fd,
                                                 .ifname = ifname,
                                                 .isPrimary = isPrimary,
                                                 .startTime = std::chrono::steady_clock::now()});
                }
            };

            // 1. 启动主网卡
            for (const auto &ifname : primaryInterfaces)
            {
                startInterfaceRacer(ifname, true);
            }

            // 若无主网卡，或策略为 HYBRID，立即启动备选网卡
            bool fallbackStarted = false;
            if (primaryInterfaces.empty() || strategy == InterfaceStrategy::HYBRID)
            {
                for (const auto &ifname : fallbackInterfaces)
                {
                    startInterfaceRacer(ifname, false);
                }
                fallbackStarted = true;
            }

            if (activeRacers.empty())
            {
                return InterfaceRacerResult{};
            }

            // 轮询直至出现首个赢家或超时
            while (true)
            {
                const auto elapsedTotal = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - startTotal);
                if (elapsedTotal >= totalTimeout)
                {
                    break;
                }

                // 检查是否应当激活 fallback 网卡
                if (!fallbackStarted && strategy == InterfaceStrategy::FALLBACK)
                {
                    bool allPrimaryDead = true;
                    for (const auto &r : activeRacers)
                    {
                        if (r.isPrimary && r.fd >= 0)
                        {
                            allPrimaryDead = false;
                            break;
                        }
                    }

                    if (allPrimaryDead || elapsedTotal >= fallbackDelay)
                    {
                        for (const auto &ifname : fallbackInterfaces)
                        {
                            startInterfaceRacer(ifname, false);
                        }
                        fallbackStarted = true;
                    }
                }

                // 组装 pollfd
                std::vector<struct pollfd> pfds;
                std::vector<size_t> racerIdxs;
                for (size_t i = 0; i < activeRacers.size(); ++i)
                {
                    if (activeRacers[i].fd >= 0)
                    {
                        pfds.push_back(
                            pollfd{.fd = activeRacers[i].fd, .events = POLLOUT | POLLERR | POLLHUP, .revents = 0});
                        racerIdxs.push_back(i);
                    }
                }

                if (pfds.empty())
                {
                    // 所有网卡均已失败
                    break;
                }

                // 计算当前一轮 poll 的超时时间
                int pollWaitMs = 20;
                if (!fallbackStarted && strategy == InterfaceStrategy::FALLBACK)
                {
                    auto remainToFallback = fallbackDelay - elapsedTotal;
                    if (remainToFallback.count() > 0 && remainToFallback.count() < pollWaitMs)
                    {
                        pollWaitMs = static_cast<int>(remainToFallback.count());
                    }
                }

                int ret = ::poll(pfds.data(), pfds.size(), pollWaitMs);
                if (ret > 0)
                {
                    for (size_t p = 0; p < pfds.size(); ++p)
                    {
                        if (pfds[p].revents == 0)
                            continue;

                        size_t rIdx = racerIdxs[p];
                        auto &racer = activeRacers[rIdx];

                        if (pfds[p].revents & (POLLERR | POLLHUP))
                        {
                            // 该套接字发生故障，关闭淘汰
                            ::close(racer.fd);
                            racer.fd = -1;
                            continue;
                        }

                        if (pfds[p].revents & POLLOUT)
                        {
                            // 检查 connect 状态
                            int err = 0;
                            socklen_t elen = sizeof(err);
                            if (::getsockopt(racer.fd, SOL_SOCKET, SO_ERROR, &err, &elen) == 0 && err == 0)
                            {
                                // 赢家诞生！
                                int winnerFd = racer.fd;
                                std::string winIf = racer.ifname;
                                bool isPrim = racer.isPrimary;
                                auto latency = std::chrono::duration_cast<std::chrono::microseconds>(
                                    std::chrono::steady_clock::now() - racer.startTime);

                                // 立即关闭所有败选套接字
                                cleanupRacers(winnerFd);

                                return InterfaceRacerResult{.winnerFd = winnerFd,
                                                            .winningInterface = winIf,
                                                            .isPrimary = isPrim,
                                                            .latency = latency};
                            }
                            else
                            {
                                // 握手失败
                                ::close(racer.fd);
                                racer.fd = -1;
                            }
                        }
                    }
                }
            }

            cleanupRacers();
            return InterfaceRacerResult{};
        }
    };

} // namespace mynet
