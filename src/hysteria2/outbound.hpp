#pragma once

#include "../outboundManager.hpp"
#include "hysteria2.hpp"
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace mynet
{

    /**
     * @brief Hysteria 2 协议出站拨号器 (DialerHysteria2 / OutboundHysteria2)
     */
    class DialerHysteria2 : public Dialer
    {
    private:
        std::string serverHost_{};
        uint16_t serverPort_{443};
        std::string password_{};

    public:
        DialerHysteria2(std::string tag, std::string serverHost, uint16_t serverPort, std::string password,
                        DialerOptions options = {})
            : Dialer(std::move(tag), "hysteria2", std::move(options)),
              serverHost_(std::move(serverHost)),
              serverPort_(serverPort),
              password_(std::move(password))
        {
        }

        [[nodiscard]] std::string_view serverHost() const noexcept override { return serverHost_; }
        [[nodiscard]] uint16_t serverPort() const noexcept override { return serverPort_; }

        Result<OutboundDialResult> dialStream(const handler::ProxyAddress &target) override
        {
            return dialStreamHelper<handler::HandlerOutboundHysteria2>(serverHost_, serverPort_, target, password_);
        }

        Result<int> dialDatagram(const handler::ProxyAddress &target) override
        {
            (void)target;
            return std::unexpected(ERR::CONNECT_FAILED);
        }
    };

    using OutboundHysteria2 = DialerHysteria2;

} // namespace mynet
