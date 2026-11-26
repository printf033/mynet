#pragma once

/**
 * @file transparent.hpp
 * @brief Linux Netfilter 透明代理入站状态机处理器、UDP TProxy 报文流水线与透明入站端点 (InboundTransparent, InboundTun)
 *
 * 借鉴 dae 与 sing-box 设计：
 * 1. HandlerInboundRedirect: iptables -j REDIRECT (SO_ORIGINAL_DST 提取 + L7 零拷贝域名嗅探 + DNS 反向还原)
 * 2. HandlerInboundTProxy: iptables -j TPROXY (getsockname 原始目的提取 + 域名嗅探)
 * 3. HandlerInboundDatagramTProxy: UDP TProxy 数据报透明代理 (IP_RECVORIGDSTADDR + QUIC/DNS 嗅探)
 * 4. InboundTransparent: Linux TProxy 透明代理入站端点 (setsockopt IP_TRANSPARENT)
 * 5. InboundTun: Linux TUN 虚拟网络接口端点 (/dev/net/tun)
 */

#include "address.hpp"
#include "connection.hpp"
#include "dns/cache.hpp"
#include "inboundManager.hpp"
#include "sniffer.hpp"
#include "tun.hpp"
#include "tunPacket.hpp"
#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <linux/if_tun.h>
#include <memory>
#include <net/if.h>
#include <netinet/in.h>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <utility>

#ifndef IP_ORIGDSTADDR
#define IP_ORIGDSTADDR 20
#endif
#ifndef IP_RECVORIGDSTADDR
#define IP_RECVORIGDSTADDR 20
#endif

namespace mynet::handler
{

    enum class TransparentStage : uint8_t
    {
        RESOLVING, ///< 正在从套接字提取原始目的地址
        SNIFFING,  ///< 正在零拷贝嗅探首包应用层域名 (TLS SNI / HTTP Host)
        STREAMING, ///< 目标已确定，处于直接透明转发中
        ERROR      ///< 无法提取原始目的地址或严重协议错误
    };

    /**
     * @brief Linux Redirect 透明代理入站处理器 (iptables -j REDIRECT)
     */
    class HandlerInboundRedirect : public HandlerInboundConnectionBase
    {
    protected:
        TransparentStage transparentStage_{TransparentStage::RESOLVING};
        int clientFd_{-1};
        bool sniffingEnabled_{true};
        size_t maxSniffBytes_{4096};

    public:
        HandlerInboundRedirect() noexcept = default;
        explicit HandlerInboundRedirect(int clientFd) noexcept
            : clientFd_(clientFd)
        {
        }
        ~HandlerInboundRedirect() noexcept override = default;

        HandlerInboundRedirect(const HandlerInboundRedirect &) = delete;
        HandlerInboundRedirect &operator=(const HandlerInboundRedirect &) = delete;
        HandlerInboundRedirect(HandlerInboundRedirect &&) = delete;
        HandlerInboundRedirect &operator=(HandlerInboundRedirect &&) = delete;

        void setClientFd(int fd) noexcept { clientFd_ = fd; }
        void setSniffing(bool enable) noexcept { sniffingEnabled_ = enable; }
        [[nodiscard]] bool isSniffingEnabled() const noexcept { return sniffingEnabled_; }
        void setMaxSniffBytes(size_t maxBytes) noexcept { maxSniffBytes_ = maxBytes; }

        [[nodiscard]] TransparentStage stage() const noexcept { return transparentStage_; }

        void onConnect(int fd) noexcept override
        {
            HandlerInboundConnectionBase::onConnect(fd);
            clientFd_ = fd;
        }

        void reset() noexcept override
        {
            HandlerInboundConnectionBase::reset();
            transparentStage_ = TransparentStage::RESOLVING;
            clientFd_ = -1;
        }

        void onMessageComplete() noexcept override {}

        void onParseError(const char *reason) noexcept override
        {
            (void)reason;
            transparentStage_ = TransparentStage::ERROR;
            setStage(InboundStage::ERROR);
        }

        void handle() override
        {
            if (transparentStage_ == TransparentStage::RESOLVING)
            {
                resolveOriginalDst();
                if (transparentStage_ != TransparentStage::SNIFFING && transparentStage_ != TransparentStage::STREAMING)
                {
                    return;
                }
            }

            if (transparentStage_ == TransparentStage::SNIFFING)
            {
                sniffPayload();
            }
        }

    protected:
        virtual std::optional<ProxyAddress> fetchOriginalDst()
        {
            const int targetFd = (clientFd_ >= 0) ? clientFd_ : fd();
            if (targetFd >= 0)
            {
                return ProxyAddress::fromOriginalDst(targetFd);
            }
            return std::nullopt;
        }

        void resolveOriginalDst()
        {
            targetAddress_ = fetchOriginalDst();
            if (!targetAddress_.has_value())
            {
                onParseError("Redirect: SO_ORIGINAL_DST not found on socket");
                transparentStage_ = TransparentStage::ERROR;
                setStage(InboundStage::ERROR);
                setCloseAfterResponse(true);
                return;
            }

            if (!sniffingEnabled_)
            {
                // 若禁用嗅探，尝试反查 DNS 逆向缓存后直接就绪
                tryFallbackReverseDns();
                transparentStage_ = TransparentStage::STREAMING;
                setStage(InboundStage::STREAMING);
                command_ = 0x01;
                onMessageComplete();
                if (requestCallback_)
                {
                    requestCallback_(0x01, *targetAddress_);
                }
                return;
            }

            // 进入嗅探状态，等待首包负载到达
            transparentStage_ = TransparentStage::SNIFFING;
            setStage(InboundStage::HANDSHAKE);
        }

        void sniffPayload()
        {
            const size_t avail = requestBytes();
            if (avail == 0)
            {
                setStage(InboundStage::HANDSHAKE);
                return;
            }

            std::span<const uint8_t> data(reinterpret_cast<const uint8_t *>(requestBegin()), avail);
            auto sniffResult = sniffing::DomainSniffer::sniff(data);

            if (sniffResult.has_value())
            {
                if (!sniffResult->host.empty())
                {
                    const uint16_t port = sniffResult->port != 0 ? sniffResult->port : targetAddress_->port;
                    targetAddress_ = ProxyAddress::fromDomain(sniffResult->host, port);
                }
                transitionToStreaming();
                return;
            }

            // 检查首字节是否可能属于已知可嗅探协议 (TCP 嗅探 TLS / HTTP / BitTorrent / SSH / RDP)
            const uint8_t b0 = data[0];
            const bool couldBeTls = (b0 == 0x16);
            const bool couldBeHttp =
                (b0 == 'G' || b0 == 'P' || b0 == 'H' || b0 == 'D' || b0 == 'C' || b0 == 'O' || b0 == 'T');
            const bool couldBeBt = (b0 == 19);
            const bool couldBeSsh = (b0 == 'S');
            const bool couldBeRdp = (b0 == 0x03);
            const bool couldBeSniffable = couldBeTls || couldBeHttp || couldBeBt || couldBeSsh || couldBeRdp;

            // 报文长度已超过嗅探窗口，或已知不可能属于嗅探协议，执行 DNS 反向还原兜底
            if (avail >= maxSniffBytes_ || !couldBeSniffable || avail >= 512)
            {
                tryFallbackReverseDns();
                transitionToStreaming();
            }
            else
            {
                setStage(InboundStage::HANDSHAKE);
            }
        }

        void tryFallbackReverseDns()
        {
            if (!targetAddress_.has_value())
            {
                return;
            }
            if (auto rev = dns::DnsReverseCache::instance().lookup(*targetAddress_); rev.has_value())
            {
                targetAddress_ = *rev;
            }
        }

        void transitionToStreaming()
        {
            transparentStage_ = TransparentStage::STREAMING;
            setStage(InboundStage::STREAMING);
            command_ = 0x01;
            onMessageComplete();

            if (requestCallback_)
            {
                requestCallback_(0x01, *targetAddress_);
            }
        }
    };

    /**
     * @brief Linux TProxy 透明代理处理器 (iptables -j TPROXY)
     *
     * 与 Redirect 相比，TProxy 连接通过 getsockname 直接读取真实目的地址，
     * 具备原生全锥型保留特性。
     */
    class HandlerInboundTProxy : public HandlerInboundRedirect
    {
    public:
        using HandlerInboundRedirect::HandlerInboundRedirect;

    protected:
        std::optional<ProxyAddress> fetchOriginalDst() override
        {
            const int targetFd = (clientFd_ >= 0) ? clientFd_ : fd();
            if (targetFd >= 0)
            {
                return ProxyAddress::fromTProxyDst(targetFd);
            }
            return std::nullopt;
        }
    };

    /**
     * @brief UDP TProxy 数据报透明代理入站处理器
     *
     * 负责解析带有 IP_RECVORIGDSTADDR 原始目的地址控制消息的 UDP 报文，
     * 联动 QUIC Initial 与 DNS 嗅探器还原目标域名。
     */
    class HandlerInboundDatagramTProxy : public HandlerInboundDatagramBase
    {
    public:
        using TProxyPacketCallback =
            std::function<void(const sockaddr_in &clientPeer, const ProxyAddress &target, const char *data, size_t n)>;

    private:
        TProxyPacketCallback packetCallback_{nullptr};
        bool sniffingEnabled_{true};

    public:
        HandlerInboundDatagramTProxy() noexcept = default;
        explicit HandlerInboundDatagramTProxy(TProxyPacketCallback cb) noexcept
            : packetCallback_(std::move(cb))
        {
        }
        ~HandlerInboundDatagramTProxy() noexcept override = default;

        void setPacketCallback(TProxyPacketCallback cb) noexcept { packetCallback_ = std::move(cb); }
        void setSniffing(bool enable) noexcept { sniffingEnabled_ = enable; }
        [[nodiscard]] bool isSniffingEnabled() const noexcept { return sniffingEnabled_; }

        void reset() noexcept override { HandlerInboundDatagramBase::reset(); }

        /**
         * @brief 处理带有原始目的地址的入站 UDP 报文
         *
         * @param peer 客户端真实源地址
         * @param origDst 报文原本要发往的目标地址
         * @param data 报文载荷
         * @param n 报文有效长度
         */
        void onDatagramWithDst(const sockaddr_in &peer, const sockaddr_in &origDst, const char *data, size_t n) noexcept
        {
            if (data == nullptr || n == 0)
            {
                return;
            }

            ProxyAddress target = ProxyAddress::fromIPv4(origDst.sin_addr.s_addr, ntohs(origDst.sin_port));

            // 尝试应用层深度嗅探（QUIC Initial SNI / DNS）
            if (sniffingEnabled_)
            {
                std::span<const uint8_t> payload(reinterpret_cast<const uint8_t *>(data), n);
                if (auto res = sniffing::DomainSniffer::sniff(payload); res.has_value())
                {
                    if (!res->host.empty())
                    {
                        const uint16_t p = res->port != 0 ? res->port : target.port;
                        target = ProxyAddress::fromDomain(res->host, p);
                    }
                }
                else
                {
                    // 嗅探未命中，查询 DNS 逆向缓存
                    if (auto rev = dns::DnsReverseCache::instance().lookup(target); rev.has_value())
                    {
                        target = *rev;
                    }
                }
            }
            else
            {
                if (auto rev = dns::DnsReverseCache::instance().lookup(target); rev.has_value())
                {
                    target = *rev;
                }
            }

            if (packetCallback_)
            {
                packetCallback_(peer, target, data, n);
            }
        }

        /**
         * @brief 从 msghdr 辅助控制信息中提取原始目的 IPv4 地址 (Linux IP_ORIGDSTADDR / IP_RECVORIGDSTADDR)
         */
        [[nodiscard]] static std::optional<sockaddr_in> extractOrigDst(const msghdr &msg) noexcept
        {
            for (auto *cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr;
                 cmsg = CMSG_NXTHDR(const_cast<msghdr *>(&msg), cmsg))
            {
                if (cmsg->cmsg_level == SOL_IP &&
                    (cmsg->cmsg_type == IP_ORIGDSTADDR || cmsg->cmsg_type == IP_RECVORIGDSTADDR))
                {
                    const auto *sin = reinterpret_cast<const sockaddr_in *>(CMSG_DATA(cmsg));
                    return *sin;
                }
            }
            return std::nullopt;
        }
    };

} // namespace mynet::handler

namespace mynet
{

    /**
     * @brief Linux TProxy 透明代理接收器 (AcceptorTransparent / InboundTransparent)
     */
    class AcceptorTransparent : public Acceptor
    {
    public:
        AcceptorTransparent(std::string tag, std::string host, uint16_t port, bool enableSniffing = true)
            : Acceptor(std::move(tag), "tproxy", std::move(host), port, enableSniffing)
        {
        }

        Result<> listen(int backlog = 128, bool reuseAddr = true, bool reusePort = true) noexcept override
        {
            if (running_ && socket_.valid())
            {
                return {};
            }
            close();

            auto res = socket_.listenTcp(host_.c_str(), port_, backlog, reuseAddr, reusePort);
            if (!res)
            {
                return std::unexpected(res.error());
            }

            int transparentOpt = 1;
            if (::setsockopt(socket_.fd, SOL_IP, IP_TRANSPARENT, &transparentOpt, sizeof(transparentOpt)) < 0)
            {
                LOG_WARN("AcceptorTransparent: setsockopt IP_TRANSPARENT on fd {} failed: {}", socket_.fd,
                         errnoText(errno));
            }

            if (port_ == 0)
            {
                port_ = ntohs(socket_.addr.sin_port);
            }

            running_ = true;
            return {};
        }

        [[nodiscard]] std::unique_ptr<Handler> createHandler() override
        {
            auto h = std::make_unique<handler::HandlerInboundTProxy>();
            h->setSniffing(enableSniffing_);
            return h;
        }
    };

    using InboundTransparent = AcceptorTransparent;

    /**
     * @brief Linux 虚拟网卡接口配置辅助工具 (配置 IP、掩码与 MTU 并将接口置为 UP)
     */
    inline bool configureTunInterface(const std::string &ifName, const std::string &ip, const std::string &netmask,
                                      uint32_t mtu) noexcept
    {
        int s = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (s < 0)
        {
            return false;
        }

        struct ifreq ifr{};
        std::strncpy(ifr.ifr_name, ifName.c_str(), IFNAMSIZ - 1);

        // 1. 设置 MTU
        if (mtu > 0)
        {
            ifr.ifr_mtu = static_cast<int>(mtu);
            ::ioctl(s, SIOCSIFMTU, &ifr);
        }

        // 2. 设置本地 IPv4 地址
        if (!ip.empty())
        {
            struct sockaddr_in sin{};
            sin.sin_family = AF_INET;
            if (::inet_pton(AF_INET, ip.c_str(), &sin.sin_addr) == 1)
            {
                std::memcpy(&ifr.ifr_addr, &sin, sizeof(sin));
                ::ioctl(s, SIOCSIFADDR, &ifr);
            }
        }

        // 3. 设置子网掩码
        if (!netmask.empty())
        {
            struct sockaddr_in sin{};
            sin.sin_family = AF_INET;
            if (::inet_pton(AF_INET, netmask.c_str(), &sin.sin_addr) == 1)
            {
                std::memcpy(&ifr.ifr_netmask, &sin, sizeof(sin));
                ::ioctl(s, SIOCSIFNETMASK, &ifr);
            }
        }

        // 4. 将网卡置为 UP 且 RUNNING
        if (::ioctl(s, SIOCGIFFLAGS, &ifr) == 0)
        {
            ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
            ::ioctl(s, SIOCSIFFLAGS, &ifr);
        }

        ::close(s);
        return true;
    }

    /**
     * @brief Linux TUN 虚拟网络接口接收器 (AcceptorTun / InboundTun)
     */
    class AcceptorTun : public Acceptor
    {
    private:
        std::string ifName_{"tun0"};
        std::string inetIp_{};
        std::string netmask_{};
        uint32_t mtu_{1500};
        int tunFd_{-1};
        int mockPeerFd_{-1};
        bool mockMode_{false};
        std::shared_ptr<tun::TunEngine> engine_{nullptr};

    public:
        AcceptorTun(std::string tag, std::string ifName = "tun0", bool enableSniffing = true)
            : Acceptor(std::move(tag), "tun", "0.0.0.0", 0, enableSniffing),
              ifName_(std::move(ifName))
        {
        }

        AcceptorTun(std::string tag, std::string ifName, std::string inetIp, std::string netmask = "255.255.255.0",
                    uint32_t mtu = 1500, bool enableSniffing = true)
            : Acceptor(std::move(tag), "tun", "0.0.0.0", 0, enableSniffing),
              ifName_(std::move(ifName)),
              inetIp_(std::move(inetIp)),
              netmask_(std::move(netmask)),
              mtu_(mtu)
        {
        }

        ~AcceptorTun() noexcept override { close(); }

        [[nodiscard]] inline int tunFd() const noexcept { return tunFd_; }
        [[nodiscard]] inline int mockPeerFd() const noexcept { return mockPeerFd_; }
        [[nodiscard]] inline const std::string &ifName() const noexcept { return ifName_; }
        [[nodiscard]] inline const std::string &interfaceName() const noexcept { return ifName_; }
        [[nodiscard]] inline const std::string &inetIp() const noexcept { return inetIp_; }
        [[nodiscard]] inline const std::string &netmask() const noexcept { return netmask_; }
        [[nodiscard]] inline uint32_t mtu() const noexcept { return mtu_; }
        [[nodiscard]] inline std::shared_ptr<tun::TunEngine> engine() const noexcept { return engine_; }

        void setTunFd(int fd) noexcept
        {
            tunFd_ = fd;
            socket_.fd = fd;
        }

        void setMockMode(bool enable) noexcept { mockMode_ = enable; }
        [[nodiscard]] bool isMockMode() const noexcept { return mockMode_; }

        Result<> listen(int = 128, bool = true, bool = true) noexcept override
        {
            if (running_ && tunFd_ >= 0)
            {
                return {};
            }

            if (mockMode_)
            {
                int sv[2];
                if (::socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sv) == 0)
                {
                    tunFd_ = sv[0];
                    mockPeerFd_ = sv[1];
                    LOG_INFO("AcceptorTun: initialized mock TUN socketpair (fd={}, peer={})", tunFd_, mockPeerFd_);
                }
                else
                {
                    return std::unexpected(ERR::SOCKET_FAILED);
                }
            }
            else if (tunFd_ < 0)
            {
                tunFd_ = ::open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
                bool ioctlOk = false;
                if (tunFd_ >= 0)
                {
                    struct ifreq ifr{};
                    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
                    std::strncpy(ifr.ifr_name, ifName_.c_str(), IFNAMSIZ - 1);

                    if (::ioctl(tunFd_, TUNSETIFF, &ifr) >= 0)
                    {
                        ioctlOk = true;
                        // 尝试配置网卡 IP / 掩码 / MTU (若进程具备相应网络管理权限)
                        configureTunInterface(ifName_, inetIp_, netmask_, mtu_);
                    }
                    else
                    {
                        LOG_WARN("AcceptorTun: ioctl(TUNSETIFF) on '{}' failed: {}", ifName_, errnoText(errno));
                        ::close(tunFd_);
                        tunFd_ = -1;
                    }
                }

                if (!ioctlOk)
                {
                    if (std::getenv("MYNET_MOCK_TUN") != nullptr)
                    {
                        int sv[2];
                        if (::socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sv) == 0)
                        {
                            tunFd_ = sv[0];
                            mockPeerFd_ = sv[1];
                            LOG_INFO("AcceptorTun: fallback to mock TUN socketpair (fd={}, peer={})", tunFd_,
                                     mockPeerFd_);
                        }
                        else
                        {
                            return std::unexpected(ERR::SOCKET_FAILED);
                        }
                    }
                    else
                    {
                        return std::unexpected(ERR::SOCKET_FAILED);
                    }
                }
            }

            socket_.fd = tunFd_;
            engine_ = std::make_shared<tun::TunEngine>(tunFd_, mtu_, enableSniffing_);
            engine_->start();

            running_ = true;
            return {};
        }

        void close() noexcept override
        {
            if (engine_ != nullptr)
            {
                engine_->stop();
                engine_.reset();
            }
            if (mockPeerFd_ >= 0)
            {
                ::close(mockPeerFd_);
                mockPeerFd_ = -1;
            }
            if (tunFd_ >= 0)
            {
                ::close(tunFd_);
                tunFd_ = -1;
            }
            socket_.fd = -1;
            Acceptor::close();
        }

        [[nodiscard]] std::unique_ptr<Handler> createHandler() override
        {
            auto h = std::make_unique<handler::HandlerInboundTProxy>();
            h->setSniffing(enableSniffing_);
            return h;
        }
    };

    using InboundTun = AcceptorTun;

} // namespace mynet
