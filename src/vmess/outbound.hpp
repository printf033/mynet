#pragma once

/**
 * @file vmess/outbound.hpp
 * @brief VMess 代理协议拨号器 (DialerVmess / OutboundVmess)。
 */

#include "../connection.hpp"
#include "../dialerManager.hpp"
#include "vmess.hpp"
#include <cstdint>
#include <string>
#include <string_view>

namespace mynet
{

    class DialerVmess : public Dialer
    {
    private:
        std::string serverHost_{};
        uint16_t serverPort_{10086};
        std::string uuid_{};
        std::string security_{"auto"};

    public:
        DialerVmess(std::string tag, std::string host, uint16_t port, std::string uuid, std::string security = "auto",
                    DialerOptions options = {})
            : Dialer(std::move(tag), "vmess", std::move(options)),
              serverHost_(std::move(host)),
              serverPort_(port),
              uuid_(std::move(uuid)),
              security_(std::move(security))
        {
        }

        [[nodiscard]] std::string_view serverHost() const noexcept override { return serverHost_; }
        [[nodiscard]] uint16_t serverPort() const noexcept override { return serverPort_; }
        [[nodiscard]] std::string_view uuid() const noexcept { return uuid_; }
        [[nodiscard]] std::string_view security() const noexcept { return security_; }

        Result<OutboundDialResult> dialForwarder(const Address &target, DialContext ctx = {}) override
        {
            return dialForwarderHelper<handler::HandlerOutboundVmess>(serverHost_, serverPort_, target, ctx, uuid_,
                                                                      security_);
        }

        Result<int> dialDatagram(const Address &) override
        {
            return std::unexpected(ERR::CONNECT_FAILED);
        }
    };


} // namespace mynet
