#pragma once

#include "../outboundManager.hpp"
#include "socks5.hpp"
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace mynet
{

    /**
     * @brief SOCKS5 二级代理出站端点 (OutboundSocks5)
     */
    class OutboundSocks5 : public OutboundBase
    {
    private:
        std::string serverHost_{};
        uint16_t serverPort_{1080};
        std::string username_{};
        std::string password_{};

    public:
        OutboundSocks5(std::string tag, std::string serverHost, uint16_t serverPort, std::string username = "",
                       std::string password = "", DialerOptions options = {})
            : OutboundBase(std::move(tag), "socks5", std::move(options)),
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

        Result<OutboundDialResult> dialStream(const handler::ProxyAddress &target) override
        {
            return dialStreamHelper<handler::HandlerOutboundSocks5>(serverHost_, serverPort_, target);
        }

        Result<int> dialDatagram(const handler::ProxyAddress &target) override
        {
            (void)target;
            return std::unexpected(ERR::CONNECT_FAILED);
        }
    };

    using DialerSocks5 = OutboundSocks5;

} // namespace mynet
