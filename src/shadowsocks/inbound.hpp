#pragma once

#include "../acceptorManager.hpp"
#include "shadowsocks.hpp"
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace mynet
{

    /**
     * @brief Shadowsocks AEAD 协议接收器 (AcceptorShadowsocks / InboundShadowsocks)
     */
    class AcceptorShadowsocks : public Acceptor
    {
    private:
        std::string method_{"aes-128-gcm"};
        std::string password_{};

    public:
        AcceptorShadowsocks(std::string tag = "shadowsocks", std::string host = "0.0.0.0", uint16_t port = 8388,
                            std::string method = "aes-128-gcm", std::string password = "", bool enableSniffing = true)
            : Acceptor(std::move(tag), "shadowsocks", std::move(host), port, enableSniffing),
              method_(std::move(method)),
              password_(std::move(password))
        {
        }

        [[nodiscard]] inline const std::string &method() const noexcept { return method_; }
        [[nodiscard]] inline const std::string &password() const noexcept { return password_; }

        [[nodiscard]] std::unique_ptr<Handler> createHandler() override
        {
            return std::make_unique<handler::HandlerInboundShadowsocks>(method_, password_);
        }
    };


} // namespace mynet
