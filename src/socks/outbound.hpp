#pragma once

#include "../dialerManager.hpp"
#include "socks5.hpp"
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace mynet
{

    /**
     * @brief SOCKS5 二级代理拨号器 (DialerSocks5 / OutboundSocks5)
     */
    class DialerSocks5 : public Dialer
    {
    private:
        std::string serverHost_{};
        uint16_t serverPort_{1080};
        std::string username_{};
        std::string password_{};

    public:
        DialerSocks5(std::string tag, std::string serverHost, uint16_t serverPort, std::string username = "",
                     std::string password = "", DialerOptions options = {})
            : Dialer(std::move(tag), "socks5", std::move(options)),
              serverHost_(std::move(serverHost)),
              serverPort_(serverPort),
              username_(std::move(username)),
              password_(std::move(password))
        {
        }

        [[nodiscard]] std::string_view serverHost() const noexcept override { return serverHost_; }
        [[nodiscard]] uint16_t serverPort() const noexcept override { return serverPort_; }
        [[nodiscard]] const std::string &username() const noexcept { return username_; }
        [[nodiscard]] const std::string &password() const noexcept { return password_; }

        Result<OutboundDialResult> dialForwarder(const Address &target, DialContext ctx = {}) override
        {
            return dialForwarderHelper<handler::HandlerOutboundSocks5>(serverHost_, serverPort_, target, ctx);
        }

        Result<int> dialDatagram(const Address &target) override
        {
            (void)target;
            return std::unexpected(ERR::CONNECT_FAILED);
        }
    };


} // namespace mynet
