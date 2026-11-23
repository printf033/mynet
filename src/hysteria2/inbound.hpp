#pragma once

#include "../inboundManager.hpp"
#include "hysteria2.hpp"
#include <memory>
#include <string>
#include <utility>

namespace mynet
{

    /**
     * @brief Hysteria 2 协议入站端点 (InboundHysteria2)
     */
    class InboundHysteria2 : public InboundBase
    {
    private:
        std::string password_{};

    public:
        InboundHysteria2(std::string tag = "hysteria2", std::string host = "0.0.0.0", uint16_t port = 443,
                         std::string password = "", bool enableSniffing = true)
            : InboundBase(std::move(tag), "hysteria2", std::move(host), port, enableSniffing),
              password_(std::move(password))
        {
        }

        [[nodiscard]] inline const std::string &password() const noexcept { return password_; }

        [[nodiscard]] std::unique_ptr<HandlerBase> createHandler() override
        {
            return std::make_unique<handler::HandlerInboundHysteria2>(password_);
        }
    };

    using AcceptorHysteria2 = InboundHysteria2;

} // namespace mynet
