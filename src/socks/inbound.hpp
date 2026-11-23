#pragma once

#include "../inboundManager.hpp"
#include "socks5.hpp"
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace mynet
{

    /**
     * @brief SOCKS5 协议入站端点 (InboundSocks5)
     */
    class InboundSocks5 : public InboundBase
    {
    private:
        std::string username_{};
        std::string password_{};

    public:
        InboundSocks5(std::string tag = "socks5", std::string host = "0.0.0.0", uint16_t port = 1080,
                      std::string username = "", std::string password = "", bool enableSniffing = true)
            : InboundBase(std::move(tag), "socks5", std::move(host), port, enableSniffing),
              username_(std::move(username)),
              password_(std::move(password))
        {
        }

        [[nodiscard]] bool match(std::span<const uint8_t> initialBytes) const noexcept override
        {
            if (initialBytes.empty())
                return false;
            return initialBytes[0] == 0x05 || initialBytes[0] == 0x04;
        }

        [[nodiscard]] inline const std::string &username() const noexcept { return username_; }
        [[nodiscard]] inline const std::string &password() const noexcept { return password_; }

        [[nodiscard]] std::unique_ptr<HandlerBase> createHandler() override
        {
            auto h = std::make_unique<handler::HandlerInboundSocks5>();
            if (!username_.empty() || !password_.empty())
            {
                std::string u = username_;
                std::string p = password_;
                h->setAuthenticator([u, p](std::string_view user, std::string_view pass)
                                    { return user == u && pass == p; });
            }
            return h;
        }
    };

    using AcceptorSocks5 = InboundSocks5;

} // namespace mynet
