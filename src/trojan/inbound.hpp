#pragma once

#include "../inboundManager.hpp"
#include "trojan.hpp"
#include <memory>
#include <string>
#include <utility>

namespace mynet
{

    /**
     * @brief Trojan 协议入站端点 (InboundTrojan)
     */
    class InboundTrojan : public InboundBase
    {
    private:
        std::string password_{};

    public:
        InboundTrojan(std::string tag, std::string host, uint16_t port, std::string password,
                      bool enableSniffing = true)
            : InboundBase(std::move(tag), "trojan", std::move(host), port, enableSniffing),
              password_(std::move(password))
        {
        }

        [[nodiscard]] inline const std::string &password() const noexcept { return password_; }

        [[nodiscard]] std::unique_ptr<HandlerBase> createHandler() override
        {
            return std::make_unique<handler::HandlerInboundTrojan>(password_);
        }
    };

} // namespace mynet
