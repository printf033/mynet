#pragma once

#include "../inboundManager.hpp"
#include "hysteria2.hpp"
#include <memory>
#include <string>
#include <utility>

namespace mynet
{

    /**
     * @brief Hysteria 2 协议接收器 (AcceptorHysteria2 / InboundHysteria2)
     */
    class AcceptorHysteria2 : public Acceptor
    {
    private:
        std::string password_{};

    public:
        AcceptorHysteria2(std::string tag = "hysteria2", std::string host = "0.0.0.0", uint16_t port = 443,
                          std::string password = "", bool enableSniffing = true)
            : Acceptor(std::move(tag), "hysteria2", std::move(host), port, enableSniffing),
              password_(std::move(password))
        {
        }

        [[nodiscard]] inline const std::string &password() const noexcept { return password_; }

        [[nodiscard]] std::unique_ptr<Handler> createHandler() override
        {
            return std::make_unique<handler::HandlerInboundHysteria2>(password_);
        }
    };

    using InboundHysteria2 = AcceptorHysteria2;

} // namespace mynet
