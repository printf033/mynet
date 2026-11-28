#pragma once

#include "../dialerManager.hpp"
#include "vless.hpp"
#include <array>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace mynet
{

    /**
     * @brief VLESS 协议出站拨号器 (DialerVless / OutboundVless)
     */
    class DialerVless : public Dialer
    {
    private:
        std::string serverHost_{};
        uint16_t serverPort_{443};
        std::array<uint8_t, 16> uuid_{};

    public:
        DialerVless(std::string tag, std::string serverHost, uint16_t serverPort, std::string_view uuidStr,
                    DialerOptions options = {})
            : Dialer(std::move(tag), "vless", std::move(options)),
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

        Result<OutboundDialResult> dialForwarder(const Address &target, DialContext ctx = {}) override
        {
            return dialForwarderHelper<handler::HandlerOutboundVless>(serverHost_, serverPort_, target, ctx, uuid_);
        }

        Result<int> dialDatagram(const Address &target) override
        {
            (void)target;
            return std::unexpected(ERR::CONNECT_FAILED);
        }
    };


} // namespace mynet
