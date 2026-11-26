#pragma once

#include "../outboundManager.hpp"
#include "shadowsocks.hpp"
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace mynet
{

    /**
     * @brief Shadowsocks AEAD 协议拨号器 (DialerShadowsocks / OutboundShadowsocks)
     */
    class DialerShadowsocks : public Dialer
    {
    private:
        std::string serverHost_{};
        uint16_t serverPort_{8388};
        std::string method_{"aes-128-gcm"};
        std::string password_{};

    public:
        DialerShadowsocks(std::string tag, std::string serverHost, uint16_t serverPort, std::string method,
                          std::string password, DialerOptions options = {})
            : Dialer(std::move(tag), "shadowsocks", std::move(options)),
              serverHost_(std::move(serverHost)),
              serverPort_(serverPort),
              method_(std::move(method)),
              password_(std::move(password))
        {
        }

        [[nodiscard]] std::string_view serverHost() const noexcept override { return serverHost_; }
        [[nodiscard]] uint16_t serverPort() const noexcept override { return serverPort_; }
        [[nodiscard]] const std::string &method() const noexcept { return method_; }
        [[nodiscard]] const std::string &password() const noexcept { return password_; }

        Result<OutboundDialResult> dialStream(const handler::ProxyAddress &target) override
        {
            return dialStreamHelper<handler::HandlerOutboundShadowsocks>(serverHost_, serverPort_, target, method_,
                                                                         password_);
        }

        Result<int> dialDatagram(const handler::ProxyAddress &target) override
        {
            (void)target;
            return std::unexpected(ERR::CONNECT_FAILED);
        }
    };

    using OutboundShadowsocks = DialerShadowsocks;

} // namespace mynet
