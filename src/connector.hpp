#pragma once

/**
 * @file connector.hpp
 * @brief 出站底层传输建连器（Connector），与 Listener 严格对称。
 *
 * 职责分层：
 * - Listener (入站底层): 管理 listenFd、bind/listen 与 accept()，不涉及上层协议；
 * - Connector (出站底层): 管理出站 socket 创建、路由/网卡选项 (SO_MARK / SO_BINDTODEVICE / DSCP / MPTCP)、
 *   DNS 解析与粘性 IP 缓存、以及 TCP/UDP 底层建连（支持 DialContext::deferConnect 延迟给 Proactor）。
 * - Dialer (出站协议层): 组合 Connector，负责将建好的 fd 装配协议 Handler 并交付给 Connection 或 Forwarder。
 */

#include "configHolder.hpp"
#include "config/log.hpp"
#include "datagram.hpp"
#include "error.hpp"
#include "listener.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <optional>
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
     * @brief TCP 底层建连结果（解耦套接字描述符与握手状态）
     */
    struct ConnectResult
    {
        int fd{-1};                     ///< 新建套接字描述符
        bool immediateConnected{false}; ///< 是否立即连通（如本地回环），false 表示处于 EINPROGRESS 或延迟异步握手中
        sockaddr_in peerAddr{};         ///< 目标 IPv4 地址（供 Proactor io_uring_prep_connect 使用）
        bool connectDeferred{false};    ///< true 表示已准备 socketOptions 仅延迟至 Proactor 异步发起 connect

        [[nodiscard]] inline explicit operator bool() const noexcept { return immediateConnected; }
        [[nodiscard]] inline bool ok() const noexcept { return fd >= 0; }
    };

    /**
     * @brief 显式出站拨号上下文参数（替代 thread_local 隐式守卫，协程与跨线程调度安全）
     */
    struct DialContext
    {
        bool deferConnect{false}; ///< 为 true 时由异步引擎（如 io_uring Proactor）接管 ::connect()
    };

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
     * @brief 出站底层传输建连器（与 Listener 对称）
     */
    class Connector
    {
    private:
        DialerOptions options_{};

        struct InterfaceRacer
        {
            int fd{-1};
            std::string ifname{};
            bool isPrimary{false};
            std::chrono::steady_clock::time_point startTime{};
        };

        static int initiateRacerConnect(const sockaddr_in &targetAddr, const std::string &ifname,
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
            if (res == 0 || (res < 0 && errno == EINPROGRESS))
            {
                return fd;
            }

            ::close(fd);
            return -1;
        }

    public:
        Connector() = default;
        explicit Connector(DialerOptions options) noexcept
            : options_(std::move(options))
        {
        }

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

        /**
         * @brief 解析主机名/字面值为 IPv4 地址（统一复用，消除 TCP / UDP 重复 DNS 解析逻辑）
         */
        [[nodiscard]] static Result<in_addr> resolveIpv4(std::string_view host, int sockType = SOCK_STREAM,
                                                         bool useCache = true) noexcept
        {
            if (host.empty())
            {
                return std::unexpected(ERR::ADDR_INVALID);
            }
            in_addr inAddr{};
            std::string hostStr(host);
            if (::inet_pton(AF_INET, hostStr.c_str(), &inAddr) == 1)
            {
                return inAddr;
            }

            const auto dnsCfg = getDnsConfig();
            const bool cacheEnabled = useCache && dnsCfg.enableCache;
            struct DnsCacheEntry
            {
                in_addr addr{};
                std::chrono::steady_clock::time_point expiresAt{};
            };
            static std::mutex s_dnsMutex;
            static std::unordered_map<std::string, DnsCacheEntry> s_dnsCache;

            const auto now = std::chrono::steady_clock::now();
            if (cacheEnabled)
            {
                std::lock_guard<std::mutex> lock(s_dnsMutex);
                auto it = s_dnsCache.find(hostStr);
                if (it != s_dnsCache.end() && it->second.expiresAt > now)
                {
                    return it->second.addr;
                }
            }

            addrinfo hints{};
            hints.ai_family = AF_INET;
            hints.ai_socktype = sockType;
            addrinfo *res = nullptr;
            if (::getaddrinfo(hostStr.c_str(), nullptr, &hints, &res) != 0 || res == nullptr)
            {
                return std::unexpected(ERR::ADDR_INVALID);
            }
            const auto *sin = reinterpret_cast<const sockaddr_in *>(res->ai_addr);
            inAddr = sin->sin_addr;
            ::freeaddrinfo(res);

            if (cacheEnabled)
            {
                const auto ttl = std::chrono::seconds(dnsCfg.ttlSecs > 0 ? dnsCfg.ttlSecs : 60);
                std::lock_guard<std::mutex> lock(s_dnsMutex);
                if (s_dnsCache.size() >= 1024)
                {
                    for (auto it = s_dnsCache.begin(); it != s_dnsCache.end();)
                    {
                        if (it->second.expiresAt <= now)
                        {
                            it = s_dnsCache.erase(it);
                        }
                        else
                        {
                            ++it;
                        }
                    }
                    if (s_dnsCache.size() >= 1024)
                    {
                        s_dnsCache.clear();
                    }
                }
                s_dnsCache[std::move(hostStr)] = DnsCacheEntry{inAddr, now + ttl};
            }
            return inAddr;
        }

        [[nodiscard]] Result<int> prepareTcpSocket(const char *bindIface = nullptr) const noexcept
        {
            ignoreSigpipeOnce();

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
                LOG_ERROR("Connector::prepareTcpSocket: socket() failed: {}", errnoText(errno));
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
                    LOG_WARN("Connector::prepareTcpSocket: setsockopt(SO_BINDTODEVICE={}) failed: {}", iface,
                             errnoText(errno));
                }
            }

            if (options_.fwmark > 0)
            {
                if (::setsockopt(sockFd, SOL_SOCKET, SO_MARK, &options_.fwmark, sizeof(options_.fwmark)) < 0)
                    [[unlikely]]
                {
                    LOG_WARN("Connector::prepareTcpSocket: setsockopt(SO_MARK={}) failed: {}", options_.fwmark,
                             errnoText(errno));
                }
            }

            if (options_.transparent)
            {
                if (::setsockopt(sockFd, SOL_IP, IP_TRANSPARENT, &opt, sizeof(opt)) < 0) [[unlikely]]
                {
                    LOG_WARN("Connector::prepareTcpSocket: setsockopt(IP_TRANSPARENT) failed: {}", errnoText(errno));
                }
            }

            if (options_.dscp > 0)
            {
                int tos = static_cast<int>(options_.dscp) << 2;
                [[maybe_unused]] auto _tos = ::setsockopt(sockFd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
            }

            return sockFd;
        }

        [[nodiscard]] Result<ConnectResult> connectTcp(const sockaddr_in &target,
                                                       const char *bindIface = nullptr,
                                                       DialContext ctx = {}) const noexcept
        {
            auto sockRes = prepareTcpSocket(bindIface);
            if (!sockRes)
            {
                return std::unexpected(sockRes.error());
            }
            const int sockFd = *sockRes;

            if (ctx.deferConnect)
            {
                return ConnectResult{sockFd, false, target, true};
            }

            int rc = ::connect(sockFd, reinterpret_cast<const sockaddr *>(&target), sizeof(sockaddr_in));
            if (rc == 0)
            {
                return ConnectResult{sockFd, true, target, false};
            }
            if (errno == EINPROGRESS)
            {
                return ConnectResult{sockFd, false, target, false};
            }

            LOG_ERROR("Connector::connectTcp: connect() failed: {}", errnoText(errno));
            ::close(sockFd);
            return std::unexpected(ERR::CONNECT_FAILED);
        }

        [[nodiscard]] Result<ConnectResult> connectTcp(std::string_view host, uint16_t port,
                                                       const char *bindIface = nullptr,
                                                       DialContext ctx = {}) const noexcept
        {
            in_addr literalAddr{};
            std::string hostStr(host);
            if (::inet_pton(AF_INET, hostStr.c_str(), &literalAddr) == 1)
            {
                sockaddr_in target{};
                target.sin_family = AF_INET;
                target.sin_addr = literalAddr;
                target.sin_port = ::htons(port);
                return connectTcp(target, bindIface, ctx);
            }

            if (auto cachedIp = StickyIpCache::instance().get(host); cachedIp.has_value())
            {
                sockaddr_in cachedTarget{};
                cachedTarget.sin_family = AF_INET;
                cachedTarget.sin_port = ::htons(port);
                if (::inet_pton(AF_INET, cachedIp->c_str(), &cachedTarget.sin_addr) == 1)
                {
                    auto cachedRes = connectTcp(cachedTarget, bindIface, ctx);
                    if (cachedRes)
                    {
                        return cachedRes;
                    }
                    StickyIpCache::instance().recordFailure(host);
                }
                else
                {
                    StickyIpCache::instance().invalidate(host);
                }
            }

            auto resolved = resolveIpv4(host, SOCK_STREAM);
            if (!resolved)
            {
                return std::unexpected(resolved.error());
            }

            sockaddr_in target{};
            target.sin_family = AF_INET;
            target.sin_addr = *resolved;
            target.sin_port = ::htons(port);
            auto res = connectTcp(target, bindIface, ctx);
            if (res)
            {
                char ipBuf[INET_ADDRSTRLEN]{};
                if (::inet_ntop(AF_INET, &target.sin_addr, ipBuf, sizeof(ipBuf)) != nullptr)
                {
                    StickyIpCache::instance().recordSuccess(host, ipBuf);
                }
            }
            return res;
        }

        [[nodiscard]] Result<ConnectResult> connectTcp(const char *ip, int port,
                                                       const char *bindIface = nullptr,
                                                       DialContext ctx = {}) const noexcept
        {
            if (ip == nullptr)
            {
                return std::unexpected(ERR::ADDR_INVALID);
            }
            sockaddr_in target{};
            target.sin_family = AF_INET;
            if (::inet_pton(AF_INET, ip, &target.sin_addr) <= 0) [[unlikely]]
            {
                LOG_ERROR("Connector::connectTcp {}:{}: not an IPv4 address literal", ip, port);
                return std::unexpected(ERR::ADDR_INVALID);
            }
            target.sin_port = ::htons(static_cast<uint16_t>(port));
            return connectTcp(target, bindIface, ctx);
        }

        [[nodiscard]] Result<Datagram> createConfiguredDatagram(const char *bindIface = nullptr) const noexcept
        {
            auto dgramRes = Datagram::create(true);
            if (!dgramRes) [[unlikely]]
            {
                LOG_ERROR("Connector::createConfiguredDatagram: socket() failed: {}", errnoText(errno));
                return std::unexpected(dgramRes.error());
            }

            const char *iface = (bindIface != nullptr && bindIface[0] != '\0')
                                    ? bindIface
                                    : (!options_.bindInterface.empty() ? options_.bindInterface.c_str() : nullptr);
            if (iface != nullptr && iface[0] != '\0')
            {
                if (auto r = dgramRes->setInterface(iface); !r) [[unlikely]]
                {
                    LOG_WARN("Connector::createConfiguredDatagram: setsockopt(SO_BINDTODEVICE={}) failed: {}", iface,
                             errnoText(errno));
                }
            }

            if (options_.fwmark > 0)
            {
                if (auto r = dgramRes->setMark(options_.fwmark); !r) [[unlikely]]
                {
                    LOG_WARN("Connector::createConfiguredDatagram: setsockopt(SO_MARK={}) failed: {}", options_.fwmark,
                             errnoText(errno));
                }
            }

            if (options_.transparent)
            {
                if (auto r = dgramRes->setTransparent(true); !r) [[unlikely]]
                {
                    LOG_WARN("Connector::createConfiguredDatagram: setsockopt(IP_TRANSPARENT) failed: {}",
                             errnoText(errno));
                }
            }

            if (options_.dscp > 0)
            {
                (void)dgramRes->setDscp(options_.dscp);
            }

            return dgramRes;
        }

        [[nodiscard]] Result<int> connectUdp(const sockaddr_in &target,
                                             const char *bindIface = nullptr) const noexcept
        {
            auto dgramRes = createConfiguredDatagram(bindIface);
            if (!dgramRes) [[unlikely]]
            {
                return std::unexpected(dgramRes.error());
            }

            if (auto r = dgramRes->connect(target); !r) [[unlikely]]
            {
                LOG_ERROR("Connector::connectUdp: connect() failed: {}", errnoText(errno));
                return std::unexpected(r.error());
            }

            return dgramRes->release();
        }

        [[nodiscard]] Result<int> connectUdp(std::string_view host, uint16_t port,
                                             const char *bindIface = nullptr) const noexcept
        {
            auto resolved = resolveIpv4(host, SOCK_DGRAM);
            if (!resolved)
            {
                return std::unexpected(resolved.error());
            }

            sockaddr_in target{};
            target.sin_family = AF_INET;
            target.sin_addr = *resolved;
            target.sin_port = ::htons(port);
            return connectUdp(target, bindIface);
        }

        [[nodiscard]] Result<int> connectUdp(const char *ip, int port,
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
                LOG_ERROR("Connector::connectUdp {}:{}: not an IPv4 address literal", ip, port);
                return std::unexpected(ERR::ADDR_INVALID);
            }
            target.sin_port = ::htons(static_cast<uint16_t>(port));
            return connectUdp(target, bindIface);
        }

        /**
         * @brief 多网卡并发赛马 / 分级回退 TCP 建连（原 ParallelInterfaceDialer 能力合并入 Connector）
         */
        static InterfaceRacerResult
        connectParallelInterface(const sockaddr_in &targetAddr, const std::vector<std::string> &primaryInterfaces,
                                 const std::vector<std::string> &fallbackInterfaces,
                                 InterfaceStrategy strategy = InterfaceStrategy::FALLBACK,
                                 std::chrono::milliseconds fallbackDelay = std::chrono::milliseconds(300),
                                 std::chrono::milliseconds totalTimeout = std::chrono::milliseconds(3000),
                                 uint32_t fwmark = 0) noexcept
        {
            std::vector<InterfaceRacer> activeRacers;
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

            auto launchRacers = [&](const std::vector<std::string> &ifaces, bool isPrimary)
            {
                for (const auto &ifname : ifaces)
                {
                    int fd = initiateRacerConnect(targetAddr, ifname, fwmark);
                    if (fd >= 0)
                    {
                        activeRacers.push_back(InterfaceRacer{
                            .fd = fd,
                            .ifname = ifname,
                            .isPrimary = isPrimary,
                            .startTime = std::chrono::steady_clock::now()});
                    }
                }
            };

            launchRacers(primaryInterfaces, true);
            if (strategy == InterfaceStrategy::HYBRID)
            {
                launchRacers(fallbackInterfaces, false);
            }

            bool fallbackTriggered = (strategy == InterfaceStrategy::HYBRID);

            while (!activeRacers.empty())
            {
                auto now = std::chrono::steady_clock::now();
                if (now - startTime >= totalTimeout)
                {
                    break;
                }

                if (strategy == InterfaceStrategy::FALLBACK && !fallbackTriggered && (now - startTime >= fallbackDelay))
                {
                    fallbackTriggered = true;
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
                        launchRacers(fallbackInterfaces, false);
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
                            ::close(racer.fd);
                            racer.fd = -1;
                            continue;
                        }

                        if (pfds[p].revents & POLLOUT)
                        {
                            int err = 0;
                            socklen_t elen = sizeof(err);
                            if (::getsockopt(racer.fd, SOL_SOCKET, SO_ERROR, &err, &elen) == 0 && err == 0)
                            {
                                int winnerFd = racer.fd;
                                std::string winIf = racer.ifname;
                                bool isPrim = racer.isPrimary;
                                auto latency = std::chrono::duration_cast<std::chrono::microseconds>(
                                    std::chrono::steady_clock::now() - racer.startTime);

                                cleanupRacers(winnerFd);
                                return InterfaceRacerResult{.winnerFd = winnerFd,
                                                            .winningInterface = winIf,
                                                            .isPrimary = isPrim,
                                                            .latency = latency};
                            }
                            else
                            {
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
