#pragma once

/**
 * @file http/outbound.hpp
 * @brief HTTP 代理协议出站节点 (OutboundHttp)。
 */

#include "../outboundHandler.hpp"
#include "../outboundManager.hpp"
#include "http.hpp"
#include <cstdint>
#include <string>
#include <string_view>

namespace mynet
{

    class OutboundHttp : public OutboundBase
    {
    private:
        std::string serverHost_{};
        uint16_t serverPort_{8080};
        std::string username_{};
        std::string password_{};

    public:
        OutboundHttp(std::string tag, std::string host, uint16_t port, std::string username = "",
                     std::string password = "", DialerOptions options = {})
            : OutboundBase(std::move(tag), "http", std::move(options)),
              serverHost_(std::move(host)),
              serverPort_(port),
              username_(std::move(username)),
              password_(std::move(password))
        {
        }

        [[nodiscard]] std::string_view serverHost() const noexcept override { return serverHost_; }
        [[nodiscard]] uint16_t serverPort() const noexcept override { return serverPort_; }
        [[nodiscard]] std::string_view username() const noexcept { return username_; }
        [[nodiscard]] std::string_view password() const noexcept { return password_; }

        Result<OutboundDialResult> dialStream(const handler::ProxyAddress &target) override
        {
            return dialStreamHelper<handler::HandlerOutboundHttp>(serverHost_, serverPort_, target, username_,
                                                                  password_);
        }

        Result<int> dialDatagram(const handler::ProxyAddress &) override
        {
            return std::unexpected(ERR::CONNECT_FAILED);
        }
    };

} // namespace mynet
