#pragma once

/**
 * @file tun/inbound.hpp
 * @brief Linux TUN 虚拟网络接口接收器 (AcceptorTun)
 */

#include "../acceptor.hpp"
#include "../transparent.hpp"
#include "engine.hpp"
#include "packet.hpp"
#include <arpa/inet.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <memory>
#include <net/if.h>
#include <netinet/in.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>

namespace mynet
{

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
            socket_.setFd(fd);
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

            socket_.setFd(tunFd_);
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
            socket_.setFd(-1);
            Acceptor::close();
        }

        [[nodiscard]] std::unique_ptr<Handler> createHandler() override
        {
            auto h = std::make_unique<handler::HandlerInboundTProxy>();
            h->setSniffing(enableSniffing_);
            return h;
        }
    };

} // namespace mynet
