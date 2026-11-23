#pragma once

/**
 * @file dialer.hpp
 * @brief 客户端出站拨号握手器（Dialer）基类与出站抽象。
 *
 * 与 Acceptor 严格对称：
 * 1. 纯虚/基类，无模板参数，零连接级可变成员（移除 fd、targetAddr 等会话级可变状态）；
 * 2. 专职负责出站建连、多网卡赛马、路由标记 (SO_MARK) 与出站协议握手；
 * 3. 各协议自身继承并实现定制出站握手协议；
 * 4. 握手成功后交付装配好对应 Handler 的 ConnectionBase 实例或出站结果结构体。
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
     * @brief 统一出站拨号选项策略 (Dialer Options)
     */
    struct DialerOptions
    {
        uint32_t fwmark{0};                      ///< Linux SO_MARK 策略路由打标（防止回环死锁）
        std::string bindInterface{};             ///< SO_BINDTODEVICE 绑定出口网卡 (例如 eth0, wan1)
        std::string bindAddress{};               ///< 绑定本地特定出口 IP 地址
        bool tcpFastOpen{false};                 ///< 是否启用 TCP Fast Open (MSG_FASTOPEN)
        bool transparent{false};                 ///< Linux IP_TRANSPARENT 支持（绑定原始源 IP）
        uint8_t dscp{0};                         ///< DSCP 服务质量标记 (借鉴 dae dscp)
        bool enableMptcp{false};                 ///< 是否启用 Multipath TCP (MPTCP)
        std::vector<uint8_t> tcpPrefix{};        ///< TCP 前置注入前缀 (借鉴 sing-box tcp_prefix)
        std::chrono::milliseconds timeout{5000}; ///< 拨号超时
    };

    /**
     * @brief TCP 拨号建连结果（解耦套接字描述符与握手状态）
     */
    struct DialTcpResult
    {
        int fd{-1};                     ///< 新建套接字描述符
        bool immediateConnected{false}; ///< 是否立即连通（如本地回环），false 表示处于 EINPROGRESS 异步握手中

        [[nodiscard]] inline explicit operator bool() const noexcept { return immediateConnected; }
        [[nodiscard]] inline bool ok() const noexcept { return fd >= 0; }
    };

    /**
     * @brief 拨号器纯虚抽象基类（零连接级可变成员）
     */
    class IDialer
    {
    protected:
        DialerOptions options_{};

    public:
        IDialer() = default;
        explicit IDialer(DialerOptions options)
            : options_(std::move(options))
        {
        }
        virtual ~IDialer() = default;

        IDialer(const IDialer &) = default;
        IDialer &operator=(const IDialer &) = default;
        IDialer(IDialer &&) noexcept = default;
        IDialer &operator=(IDialer &&) noexcept = default;

        [[nodiscard]] inline const DialerOptions &options() const noexcept { return options_; }
        inline void setOptions(DialerOptions options) noexcept { options_ = std::move(options); }

        inline void setTcpPrefix(std::span<const uint8_t> prefix) noexcept
        {
            options_.tcpPrefix.assign(prefix.begin(), prefix.end());
        }
        [[nodiscard]] inline std::span<const uint8_t> getTcpPrefix() const noexcept { return options_.tcpPrefix; }

        static inline bool flushTcpPrefix(int socketFd, std::span<const uint8_t> prefix) noexcept
        {
            if (socketFd < 0 || prefix.empty())
                return true;
            ssize_t n = ::send(socketFd, prefix.data(), prefix.size(), MSG_NOSIGNAL);
            return n == static_cast<ssize_t>(prefix.size());
        }

        inline bool flushTcpPrefix(int socketFd = -1) const noexcept
        {
            if (socketFd < 0)
                return true;
            return flushTcpPrefix(socketFd, options_.tcpPrefix);
        }

        inline void setMark(uint32_t mark) noexcept { options_.fwmark = mark; }
        [[nodiscard]] inline uint32_t mark() const noexcept { return options_.fwmark; }

        inline void setTransparent(bool enable) noexcept { options_.transparent = enable; }
        [[nodiscard]] inline bool isTransparent() const noexcept { return options_.transparent; }

        inline void setDscp(uint8_t val) noexcept { options_.dscp = val; }
        [[nodiscard]] inline uint8_t getDscp() const noexcept { return options_.dscp; }

        inline void setMptcp(bool enable) noexcept { options_.enableMptcp = enable; }
        [[nodiscard]] inline bool isMptcp() const noexcept { return options_.enableMptcp; }

        inline void setInterface(std::string_view ifname) noexcept { options_.bindInterface = ifname; }
        [[nodiscard]] inline std::string_view getInterface() const noexcept { return options_.bindInterface; }

        virtual HandshakeStatus handshake(int targetFd, ConnectionBase *&outConn)
        {
            (void)targetFd;
            outConn = nullptr;
            return HandshakeStatus::SUCCESS;
        }

        virtual void reset() noexcept {}

        [[nodiscard]] Result<DialTcpResult> dialTcp(const sockaddr_in &target,
                                                    const char *bindIface = nullptr) const noexcept
        {
            ::signal(SIGPIPE, SIG_IGN);

            int sockFd = -1;
#if defined(IPPROTO_MPTCP)
            if (options_.enableMptcp)
            {
                sockFd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_MPTCP);
            }
#endif
            if (sockFd < 0)
            {
                sockFd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            }
            if (sockFd < 0) [[unlikely]]
            {
                LOG_ERROR("dialTcp: socket() failed: {}", errnoText(errno));
                return std::unexpected(ERR::SOCKET_FAILED);
            }

            constexpr int opt = 1;
            [[maybe_unused]] auto _ = ::setsockopt(sockFd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
            [[maybe_unused]] auto _keepalive = ::setsockopt(sockFd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));

            const char *iface = (bindIface != nullptr && bindIface[0] != '\0')
                                    ? bindIface
                                    : (!options_.bindInterface.empty() ? options_.bindInterface.c_str() : nullptr);
            if (iface != nullptr && iface[0] != '\0')
            {
                if (::setsockopt(sockFd, SOL_SOCKET, SO_BINDTODEVICE, iface, ::strlen(iface)) < 0) [[unlikely]]
                {
                    LOG_WARN("dialTcp: setsockopt(SO_BINDTODEVICE={}) failed: {}", iface, errnoText(errno));
                }
            }

            if (options_.fwmark > 0)
            {
                if (::setsockopt(sockFd, SOL_SOCKET, SO_MARK, &options_.fwmark, sizeof(options_.fwmark)) < 0)
                    [[unlikely]]
                {
                    LOG_WARN("dialTcp: setsockopt(SO_MARK={}) failed: {}", options_.fwmark, errnoText(errno));
                }
            }

            if (options_.transparent)
            {
                if (::setsockopt(sockFd, SOL_IP, IP_TRANSPARENT, &opt, sizeof(opt)) < 0) [[unlikely]]
                {
                    LOG_WARN("dialTcp: setsockopt(IP_TRANSPARENT) failed: {}", errnoText(errno));
                }
            }

            if (options_.dscp > 0)
            {
                int tos = static_cast<int>(options_.dscp) << 2;
                [[maybe_unused]] auto _ = ::setsockopt(sockFd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
            }

            int rc = ::connect(sockFd, reinterpret_cast<const sockaddr *>(&target), sizeof(sockaddr_in));
            if (rc == 0)
            {
                return DialTcpResult{sockFd, true};
            }
            if (errno == EINPROGRESS)
            {
                return DialTcpResult{sockFd, false};
            }

            LOG_ERROR("dialTcp: connect() failed: {}", errnoText(errno));
            ::close(sockFd);
            return std::unexpected(ERR::CONNECT_FAILED);
        }

        [[nodiscard]] Result<DialTcpResult> dialTcp(std::string_view host, uint16_t port,
                                                    const char *bindIface = nullptr) const noexcept
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

        [[nodiscard]] Result<DialTcpResult> dialTcp(const char *ip, int port,
                                                    const char *bindIface = nullptr) const noexcept
        {
            if (ip == nullptr)
            {
                return std::unexpected(ERR::ADDR_INVALID);
            }
            sockaddr_in target{};
            target.sin_family = AF_INET;
            if (::inet_pton(AF_INET, ip, &target.sin_addr) <= 0) [[unlikely]]
            {
                LOG_ERROR("dialTcp {}:{}: not an IPv4 address literal", ip, port);
                return std::unexpected(ERR::ADDR_INVALID);
            }
            target.sin_port = ::htons(static_cast<uint16_t>(port));
            return dialTcp(target, bindIface);
        }

        [[nodiscard]] Result<int> dialUdp(const sockaddr_in &target, const char *bindIface = nullptr) const noexcept
        {
            int sockFd = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (sockFd < 0) [[unlikely]]
            {
                LOG_ERROR("dialUdp: socket() failed: {}", errnoText(errno));
                return std::unexpected(ERR::SOCKET_FAILED);
            }

            const char *iface = (bindIface != nullptr && bindIface[0] != '\0')
                                    ? bindIface
                                    : (!options_.bindInterface.empty() ? options_.bindInterface.c_str() : nullptr);
            if (iface != nullptr && iface[0] != '\0')
            {
                if (::setsockopt(sockFd, SOL_SOCKET, SO_BINDTODEVICE, iface, ::strlen(iface)) < 0) [[unlikely]]
                {
                    LOG_WARN("dialUdp: setsockopt(SO_BINDTODEVICE={}) failed: {}", iface, errnoText(errno));
                }
            }

            if (options_.fwmark > 0)
            {
                if (::setsockopt(sockFd, SOL_SOCKET, SO_MARK, &options_.fwmark, sizeof(options_.fwmark)) < 0)
                    [[unlikely]]
                {
                    LOG_WARN("dialUdp: setsockopt(SO_MARK={}) failed: {}", options_.fwmark, errnoText(errno));
                }
            }

            if (::connect(sockFd, reinterpret_cast<const sockaddr *>(&target), sizeof(sockaddr_in)) < 0) [[unlikely]]
            {
                LOG_ERROR("dialUdp: connect() failed: {}", errnoText(errno));
                ::close(sockFd);
                return std::unexpected(ERR::CONNECT_FAILED);
            }

            return sockFd;
        }

        [[nodiscard]] Result<int> dialUdp(std::string_view host, uint16_t port,
                                          const char *bindIface = nullptr) const noexcept
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

        [[nodiscard]] Result<int> dialUdp(const char *ip, int port, const char *bindIface = nullptr) const noexcept
        {
            if (ip == nullptr)
            {
                return std::unexpected(ERR::ADDR_INVALID);
            }
            sockaddr_in target{};
            target.sin_family = AF_INET;
            if (::inet_pton(AF_INET, ip, &target.sin_addr) <= 0) [[unlikely]]
            {
                LOG_ERROR("dialUdp {}:{}: not an IPv4 address literal", ip, port);
                return std::unexpected(ERR::ADDR_INVALID);
            }
            target.sin_port = ::htons(static_cast<uint16_t>(port));
            return dialUdp(target, bindIface);
        }
    };

    /**
     * @brief 兼容泛型出站拨号器模板包装（零数据成员，支持直接作为默认拨号器或兼容原有泛型写法）
     *
     * @tparam OutboundContext 协议特有的 outbound 上下文类型。默认为 EmptyOutbound。
     */
    template <typename OutboundContext = EmptyOutbound>
    class Dialer : public IDialer
    {
    public:
        using Outbound = OutboundContext;
        using Handler = OutboundContext;

        Dialer() = default;
        explicit Dialer([[maybe_unused]] OutboundContext outbound) {}
        explicit Dialer(DialerOptions options)
            : IDialer(std::move(options))
        {
        }
        ~Dialer() override = default;
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
            std::vector<Racer> activeRacers;
            auto startTime = std::chrono::steady_clock::now();

            auto cleanupRacers = [&](int exceptFd = -1)
            {
                for (auto &r : activeRacers)
                {
                    if (r.fd >= 0 && r.fd != exceptFd)
                    {
                        ::close(r.fd);
                        r.fd = -1;
                    }
                }
                activeRacers.clear();
            };

            // 1. 发起所有主网卡建连
            for (const auto &ifname : primaryInterfaces)
            {
                int fd = initiateNonBlockingConnect(targetAddr, ifname, fwmark);
                if (fd >= 0)
                {
                    activeRacers.push_back(Racer{
                        .fd = fd, .ifname = ifname, .isPrimary = true, .startTime = std::chrono::steady_clock::now()});
                }
            }

            // 若策略为 HYBRID，立即激活所有备用网卡一同参赛
            if (strategy == InterfaceStrategy::HYBRID)
            {
                for (const auto &ifname : fallbackInterfaces)
                {
                    int fd = initiateNonBlockingConnect(targetAddr, ifname, fwmark);
                    if (fd >= 0)
                    {
                        activeRacers.push_back(Racer{.fd = fd,
                                                     .ifname = ifname,
                                                     .isPrimary = false,
                                                     .startTime = std::chrono::steady_clock::now()});
                    }
                }
            }

            bool fallbackTriggered = (strategy == InterfaceStrategy::HYBRID);

            // 2. Poll 轮询等待连接就绪
            while (!activeRacers.empty())
            {
                auto now = std::chrono::steady_clock::now();
                if (now - startTime >= totalTimeout)
                {
                    break;
                }

                // 检查是否需要激活 Fallback 备用网卡
                if (strategy == InterfaceStrategy::FALLBACK && !fallbackTriggered && (now - startTime >= fallbackDelay))
                {
                    fallbackTriggered = true;
                    // 检查主网卡是否全挂或超时未连通
                    bool primaryStillConnecting = false;
                    for (const auto &r : activeRacers)
                    {
                        if (r.isPrimary && r.fd >= 0)
                        {
                            primaryStillConnecting = true;
                            break;
                        }
                    }

                    if (primaryStillConnecting || activeRacers.empty())
                    {
                        for (const auto &ifname : fallbackInterfaces)
                        {
                            int fd = initiateNonBlockingConnect(targetAddr, ifname, fwmark);
                            if (fd >= 0)
                            {
                                activeRacers.push_back(Racer{.fd = fd,
                                                             .ifname = ifname,
                                                             .isPrimary = false,
                                                             .startTime = std::chrono::steady_clock::now()});
                            }
                        }
                    }
                }

                std::vector<pollfd> pfds;
                std::vector<size_t> racerIdx;
                for (size_t i = 0; i < activeRacers.size(); ++i)
                {
                    if (activeRacers[i].fd >= 0)
                    {
                        pfds.push_back(
                            pollfd{.fd = activeRacers[i].fd, .events = POLLOUT | POLLERR | POLLHUP, .revents = 0});
                        racerIdx.push_back(i);
                    }
                }

                if (pfds.empty())
                    break;

                int remainingMs = static_cast<int>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(totalTimeout - (now - startTime)).count());
                int pollTimeout = std::min(50, std::max(1, remainingMs));

                int prc = ::poll(pfds.data(), pfds.size(), pollTimeout);
                if (prc < 0)
                {
                    if (errno == EINTR)
                        continue;
                    break;
                }

                if (prc > 0)
                {
                    for (size_t p = 0; p < pfds.size(); ++p)
                    {
                        auto &racer = activeRacers[racerIdx[p]];
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
