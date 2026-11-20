#pragma once

#include "../outboundManager.hpp"
#include "vless.hpp"
#include <array>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace mynet
{

    /**
     * @brief VLESS 协议出站端点 (OutboundVless)
     */
    class OutboundVless : public OutboundBase
    {
    private:
        std::string serverHost_{};
        uint16_t serverPort_{443};
        std::array<uint8_t, 16> uuid_{};

    public:
        OutboundVless(std::string tag, std::string serverHost, uint16_t serverPort, std::string_view uuidStr,
                      DialerOptions options = {})
            : OutboundBase(std::move(tag), "vless", std::move(options)),
              serverHost_(std::move(serverHost)),
              serverPort_(serverPort)
        {
            if (auto u = encoding::parseUuid(uuidStr); u.has_value())
            {
                uuid_ = *u;
            }
        }

        [[nodiscard]] std::string_view serverHost() const noexcept override { return serverHost_; }
        [[nodiscard]] uint16_t serverPort() const noexcept override { return serverPort_; }
        [[nodiscard]] const std::array<uint8_t, 16> &uuid() const noexcept { return uuid_; }

        Result<OutboundDialResult> dialStream(const handler::ProxyAddress &target) override
        {
            return dialStreamHelper<handler::HandlerOutboundVless>(serverHost_, serverPort_, target, uuid_);
        }

        Result<int> dialDatagram(const handler::ProxyAddress &target) override
        {
            (void)target;
            return std::unexpected(ERR::CONNECT_FAILED);
        }
    };

} // namespace mynet
