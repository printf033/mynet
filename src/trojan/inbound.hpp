#pragma once

#include "../acceptorManager.hpp"
#include "trojan.hpp"
#include <memory>
#include <string>
#include <utility>

namespace mynet
{

    /**
     * @brief Trojan 协议接收器 (AcceptorTrojan / InboundTrojan)
     */
    class AcceptorTrojan : public Acceptor
    {
    private:
        std::string password_{};

    public:
        AcceptorTrojan(std::string tag = "trojan", std::string host = "0.0.0.0", uint16_t port = 443,
                       std::string password = "", bool enableSniffing = true)
            : Acceptor(std::move(tag), "trojan", std::move(host), port, enableSniffing),
              password_(std::move(password))
        {
        }

        [[nodiscard]] bool match(std::span<const uint8_t> initialBytes) const noexcept override
        {
            // Trojan 首包为 56 字节密码哈希后跟 CRLF (0x0D, 0x0A)
            return initialBytes.size() >= 58 && initialBytes[56] == '\r' && initialBytes[57] == '\n';
        }

        [[nodiscard]] inline const std::string &password() const noexcept { return password_; }

        [[nodiscard]] std::unique_ptr<Handler> createHandler() override
        {
            return std::make_unique<handler::HandlerInboundTrojan>(password_);
        }
    };


} // namespace mynet
