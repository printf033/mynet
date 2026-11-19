#pragma once

#include "../inboundManager.hpp"
#include "shadowsocks.hpp"
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace mynet
{

    /**
     * @brief Shadowsocks AEAD 协议入站端点 (InboundShadowsocks)
     */
    class InboundShadowsocks : public InboundBase
    {
    private:
        std::string method_{"aes-128-gcm"};
        std::string password_{};

    public:
        InboundShadowsocks(std::string tag, std::string host, uint16_t port,
                           std::string method, std::string password, bool enableSniffing = true)
            : InboundBase(std::move(tag), "shadowsocks", std::move(host), port, enableSniffing),
              method_(std::move(method)),
              password_(std::move(password))
        {
        }

        [[nodiscard]] inline const std::string &method() const noexcept { return method_; }
        [[nodiscard]] inline const std::string &password() const noexcept { return password_; }

        [[nodiscard]] std::unique_ptr<handler::HandlerInboundConnection> createHandler() override
        {
            return std::make_unique<handler::HandlerInboundShadowsocks>(method_, password_);
        }
    };

} // namespace mynet
