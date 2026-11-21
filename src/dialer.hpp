#pragma once

#include "config/log.hpp"
#include "constraints.hpp"
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
     * @brief TLS ClientHello 分片绕过中间件 DPI 检查辅助工具 (复用 mynet::tls::TlsFragmenter)
     */
    struct TlsFragmentHelper
    {
        static std::vector<std::vector<uint8_t>> fragmentClientHello(std::span<const uint8_t> clientHello,
                                                                     size_t minChunk = 50, size_t maxChunk = 100)
        {
            if (clientHello.empty())
                return {};
            if (auto sni = tls::TlsFragmenter::findSni(clientHello); sni.has_value())
            {
                auto splits = tls::TlsFragmenter::computeSplitOffsets(clientHello, *sni);
                return tls::TlsFragmenter::buildSplitRecords(clientHello, splits);
            }
            std::vector<std::vector<uint8_t>> fragments;
            size_t offset = 0;
            while (offset < clientHello.size())
            {
                size_t remaining = clientHello.size() - offset;
                size_t chunkSize = std::min(remaining, maxChunk);
                if (chunkSize < minChunk && remaining >= minChunk)
                {
                    chunkSize = minChunk;
                }
                fragments.emplace_back(clientHello.subspan(offset, chunkSize).begin(),
                                       clientHello.subspan(offset, chunkSize).end());
                offset += chunkSize;
            }
            return fragments;
        }
    };

    /**
     * @brief 客户端出站拨号建连基类（与 AcceptorBase 严格对称）
     *
     * 负责发起并建立客户端到对端服务器的 TCP / UDP 连接（确立四元组）。
     * 处理器只需满足 HandlerConstraint。
     * 后续传输层出站建连器（如 DialerSsl、DialerQuic 等）均直接派生自本类。
     */
    template <typename HandlerType>
        requires HandlerConstraint<HandlerType>
    struct Dialer
    {
    public:
        int fd = -1;
        using Handler = HandlerType;
        sockaddr_in targetAddr{};
        uint32_t fwmark{0};               ///< Linux SO_MARK 策略路由标记（防环路）
        bool transparent{false};          ///< Linux IP_TRANSPARENT 支持（绑定原始源 IP）
        uint8_t dscp{0};                  ///< DSCP 服务质量标记 (借鉴 dae dscp)
        bool enableMptcp{false};          ///< 是否启用 Multipath TCP (MPTCP)
        std::string bindInterface{};      ///< SO_BINDTODEVICE 绑定网卡
        std::vector<uint8_t> tcpPrefix{}; ///< TCP 前置注入前缀 (借鉴 sing-box tcp_prefix)

        Dialer() = default;
        virtual ~Dialer() noexcept { reset(); }

        Dialer(const Dialer &) = delete;
        Dialer &operator=(const Dialer &) = delete;

        Dialer(Dialer &&other) noexcept
            : fd(other.fd),
              targetAddr(other.targetAddr),
              fwmark(other.fwmark),
              transparent(other.transparent),
              dscp(other.dscp),
              enableMptcp(other.enableMptcp),
              bindInterface(std::move(other.bindInterface)),
              tcpPrefix(std::move(other.tcpPrefix))
        {
            other.fd = -1;
            other.targetAddr = {};
            other.fwmark = 0;
            other.transparent = false;
            other.dscp = 0;
            other.enableMptcp = false;
            other.bindInterface.clear();
            other.tcpPrefix.clear();
        }

        Dialer &operator=(Dialer &&other) noexcept
        {
            if (this != &other)
            {
                reset();
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
                other.fwmark = 0;
                other.transparent = false;
                other.dscp = 0;
                other.enableMptcp = false;
                other.bindInterface.clear();
                other.tcpPrefix.clear();
            }
            return *this;
        }

        inline void setTcpPrefix(std::span<const uint8_t> prefix) noexcept
        {
            tcpPrefix.assign(prefix.begin(), prefix.end());
        }
        [[nodiscard]] inline std::span<const uint8_t> getTcpPrefix() const noexcept { return tcpPrefix; }

        /**
         * @brief 在连接成功建立时排出 TCP 前缀 (若有)
         */
        inline bool flushTcpPrefix() noexcept
        {
            if (fd < 0 || tcpPrefix.empty())
                return true;
            ssize_t n = ::send(fd, tcpPrefix.data(), tcpPrefix.size(), MSG_NOSIGNAL);
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

        inline void reset() noexcept
        {
            if (fd != -1)
            {
                ::close(fd);
                fd = -1;
            }
            targetAddr = {};
        }

        inline void attach(int newFd, const sockaddr_in &newAddr = {}) noexcept
        {
            reset();
            fd = newFd;
            targetAddr = newAddr;
        }

        [[nodiscard]] inline int release() noexcept
        {
            int ret = fd;
            fd = -1;
            targetAddr = {};
            return ret;
        }

        /**
         * @brief 检查非阻塞 connect 是否成功完成
         *
         * 在收到 Reactor 的可写事件 (EPOLLOUT) 时调用。
         *
         * @param socketFd 待检验的套接字描述符
         * @return 成功返回 {}，对端拒绝或超时返回错误码
         */
        [[nodiscard]] static Result<> checkConnectError(int socketFd) noexcept
        {
            if (socketFd < 0)
            {
                return std::unexpected(ERR::SOCKET_FAILED);
            }
            int err = 0;
            socklen_t len = sizeof(err);
            if (::getsockopt(socketFd, SOL_SOCKET, SO_ERROR, &err, &len) < 0)
            {
                return std::unexpected(ERR::SOCKET_FAILED);
            }
            if (err != 0)
            {
                return std::unexpected(ERR::CONNECT_FAILED);
            }
            return {};
        }

        /**
         * @brief 创建非阻塞 TCP 套接字并向远端发起异步建连
         *
         * @param ip 目标服务端 IPv4 地址字面量
         * @param port 目标服务端端口号
         * @param bindInterface 可选的出口网卡绑定（SO_BINDTODEVICE）
         * @return Result<bool> 成功返回布尔值：
         *         - true: 连接立即可用（已连上，如本机回环）；
         *         - false: 连接处于非阻塞握手中（EINPROGRESS），需向 Reactor 挂载 EPOLLOUT 或等待 Proactor CQE；
         *         - unexpected: 发生系统调用错误。
         */
        [[nodiscard]] Result<bool> dialTcp(const char *ip, int port, const char *bindInterface = nullptr) noexcept
        {
            contract_assert(ip != nullptr);
            contract_assert(port >= 0 && port <= ((1 << 16) - 1));
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

            return dialTcp(targetAddr, bindInterface);
        }

        /**
         * @brief 通过域名或 IP 字符串及端口发起非阻塞 TCP 建连（自动域名解析）
         */
        [[nodiscard]] Result<bool> dialTcp(std::string_view host, uint16_t port,
                                           const char *bindInterface = nullptr) noexcept
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
            return dialTcp(target, bindInterface);
        }

        /**
         * @brief 从目标地址结构体发起非阻塞 TCP 建连
         */
        [[nodiscard]] Result<bool> dialTcp(const sockaddr_in &target, const char *bindInterface = nullptr) noexcept
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

            // TCP Keepalive & NODELAY
            constexpr int opt = 1;
            [[maybe_unused]] auto _ = ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
            [[maybe_unused]] auto _keepalive = ::setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));

            const char *iface = (bindInterface != nullptr && bindInterface[0] != '\0')
                                    ? bindInterface
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
                return true; // 立即完成
            }
            if (errno == EINPROGRESS)
            {
                return false; // 非阻塞握手中
            }

            LOG_ERROR("dialTcp: connect() failed: {}", errnoText(errno));
            reset();
            return std::unexpected(ERR::CONNECT_FAILED);
        }

        /**
         * @brief 创建非阻塞已连接 UDP 套接字（已关联目标四元组，可用 send/recv 直读）
         *
         * @param ip 目标服务端 IPv4 地址字面量
         * @param port 目标服务端端口号
         * @param bindInterface 可选的出口网卡绑定（SO_BINDTODEVICE）
         */
        [[nodiscard]] Result<> dialUdp(const char *ip, int port, const char *bindInterface = nullptr) noexcept
        {
            contract_assert(ip != nullptr);
            contract_assert(port >= 0 && port <= ((1 << 16) - 1));
            reset();
            ::signal(SIGPIPE, SIG_IGN);

            targetAddr.sin_family = AF_INET;
            if (::inet_pton(AF_INET, ip, &targetAddr.sin_addr) <= 0) [[unlikely]]
            {
                LOG_ERROR("dialUdp {}:{}: not an IPv4 address literal", ip, port);
                reset();
                return std::unexpected(ERR::ADDR_INVALID);
            }
            targetAddr.sin_port = ::htons(static_cast<uint16_t>(port));

            return dialUdp(targetAddr, bindInterface);
        }

        /**
         * @brief 通过域名或 IP 字符串及端口创建非阻塞已连接 UDP 套接字（自动域名解析）
         */
        [[nodiscard]] Result<> dialUdp(std::string_view host, uint16_t port,
                                       const char *bindInterface = nullptr) noexcept
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
            return dialUdp(target, bindInterface);
        }

        /**
         * @brief 从目标地址结构体创建非阻塞已连接 UDP 套接字
         *
         * @param target 目标 sockaddr_in 地址结构
         * @param bindInterface 可选的出口网卡绑定（SO_BINDTODEVICE）
         */
        [[nodiscard]] Result<> dialUdp(const sockaddr_in &target, const char *bindInterface = nullptr) noexcept
        {
            reset();
            ::signal(SIGPIPE, SIG_IGN);
            targetAddr = target;

            fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (fd < 0) [[unlikely]]
            {
                LOG_ERROR("dialUdp: socket() failed: {}", errnoText(errno));
                reset();
                return std::unexpected(ERR::SOCKET_FAILED);
            }

            const char *iface = (bindInterface != nullptr && bindInterface[0] != '\0')
                                    ? bindInterface
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

            if (transparent)
            {
                constexpr int opt = 1;
                if (::setsockopt(fd, SOL_IP, IP_TRANSPARENT, &opt, sizeof(opt)) < 0) [[unlikely]]
                {
                    LOG_WARN("dialUdp: setsockopt(IP_TRANSPARENT) failed: {}", errnoText(errno));
                }
            }

            if (dscp > 0)
            {
                int tos = static_cast<int>(dscp) << 2;
                [[maybe_unused]] auto _ = ::setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
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
     * @brief 出站建连器兼容别名
     */
    template <typename HandlerType>
    using DialerBase = Dialer<HandlerType>;

    /**
     * @brief 约束从 Dialer 派生或满足的出站通道类型
     */
    template <typename D>
    concept DerivedFromDialer = requires { typename D::Handler; } && std::derived_from<D, Dialer<typename D::Handler>>;

    template <typename D>
    concept DerivedFromDialerBase = DerivedFromDialer<D>;

    /**
     * @brief 基础出站建连器通道约束
     */
    template <typename D>
    concept BaseDialer = requires { typename D::Handler; } && std::same_as<D, Dialer<typename D::Handler>>;

    template <typename HandlerType>
    using DialerSsl = Dialer<HandlerType>;

    template <typename HandlerType>
    using DialerQuic = Dialer<HandlerType>;

    template <typename D>
    concept SslDialer = DerivedFromDialer<D>;

    template <typename D>
    concept QuicDialer = DerivedFromDialer<D>;

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
