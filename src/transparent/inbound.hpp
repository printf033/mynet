#pragma once

#include "../inboundManager.hpp"
#include "transparent.hpp"
#include <fcntl.h>
#include <linux/if_tun.h>
#include <memory>
#include <net/if.h>
#include <string>
#include <sys/ioctl.h>
#include <utility>

namespace mynet
{

    /**
     * @brief Linux TProxy 透明代理入站端点 (InboundTransparent)
     */
    class InboundTransparent : public InboundBase
    {
    public:
        InboundTransparent(std::string tag, std::string host, uint16_t port, bool enableSniffing = true)
            : InboundBase(std::move(tag), "tproxy", std::move(host), port, enableSniffing)
        {
        }

        Result<> listen(int backlog = 128, bool reuseAddr = true, bool reusePort = true) noexcept override
        {
            if (running_ && acceptor_.fd >= 0)
            {
                return {};
            }
            close();

            auto res = acceptor_.listenTcp(host_.c_str(), port_, backlog, reuseAddr, reusePort);
            if (!res)
            {
                return res;
            }

            int transparentOpt = 1;
            if (::setsockopt(acceptor_.fd, SOL_IP, IP_TRANSPARENT, &transparentOpt, sizeof(transparentOpt)) < 0)
            {
                LOG_WARN("InboundTransparent: setsockopt IP_TRANSPARENT on fd {} failed: {}",
                         acceptor_.fd, errnoText(errno));
            }

            if (port_ == 0)
            {
                port_ = ntohs(acceptor_.addr.sin_port);
            }

            running_ = true;
            return {};
        }

        [[nodiscard]] std::unique_ptr<handler::HandlerInboundConnection> createHandler() override
        {
            return std::make_unique<handler::HandlerInboundTProxy>();
        }
    };

    /**
     * @brief Linux TUN 虚拟网络接口端点 (InboundTun)
     */
    class InboundTun : public InboundBase
    {
    private:
        std::string ifName_{"tun0"};
        std::string inetIp_{};
        std::string netmask_{};
        uint32_t mtu_{1500};
        int tunFd_{-1};

    public:
        InboundTun(std::string tag, std::string ifName = "tun0", bool enableSniffing = true)
            : InboundBase(std::move(tag), "tun", "0.0.0.0", 0, enableSniffing),
              ifName_(std::move(ifName))
        {
        }

        InboundTun(std::string tag, std::string ifName, std::string inetIp,
                   std::string netmask = "255.255.255.0", uint32_t mtu = 1500, bool enableSniffing = true)
            : InboundBase(std::move(tag), "tun", "0.0.0.0", 0, enableSniffing),
              ifName_(std::move(ifName)),
              inetIp_(std::move(inetIp)),
              netmask_(std::move(netmask)),
              mtu_(mtu)
        {
        }

        ~InboundTun() noexcept override { close(); }

        [[nodiscard]] inline int tunFd() const noexcept { return tunFd_; }
        [[nodiscard]] inline const std::string &ifName() const noexcept { return ifName_; }
        [[nodiscard]] inline const std::string &interfaceName() const noexcept { return ifName_; }
        [[nodiscard]] inline const std::string &inetIp() const noexcept { return inetIp_; }
        [[nodiscard]] inline const std::string &netmask() const noexcept { return netmask_; }
        [[nodiscard]] inline uint32_t mtu() const noexcept { return mtu_; }

        Result<> listen(int = 128, bool = true, bool = true) noexcept override
        {
            if (tunFd_ >= 0)
            {
                return {};
            }

            tunFd_ = ::open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
            if (tunFd_ < 0)
            {
                LOG_ERROR("InboundTun: opening /dev/net/tun failed: {}", errnoText(errno));
                return std::unexpected(ERR::SOCKET_FAILED);
            }

            struct ifreq ifr{};
            ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
            std::strncpy(ifr.ifr_name, ifName_.c_str(), IFNAMSIZ - 1);

            if (::ioctl(tunFd_, TUNSETIFF, &ifr) < 0)
            {
                LOG_ERROR("InboundTun: ioctl(TUNSETIFF) on '{}' failed: {}", ifName_, errnoText(errno));
                ::close(tunFd_);
                tunFd_ = -1;
                return std::unexpected(ERR::SOCKET_FAILED);
            }

            running_ = true;
            return {};
        }

        void close() noexcept override
        {
            if (tunFd_ >= 0)
            {
                ::close(tunFd_);
                tunFd_ = -1;
            }
            InboundBase::close();
        }

        [[nodiscard]] std::unique_ptr<handler::HandlerInboundConnection> createHandler() override
        {
            return std::make_unique<handler::HandlerInboundTProxy>();
        }
    };

} // namespace mynet
