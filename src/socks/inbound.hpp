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
        InboundSocks5(std::string tag, std::string host, uint16_t port, std::string username = "",
                      std::string password = "", bool enableSniffing = true)
            : InboundBase(std::move(tag), "socks5", std::move(host), port, enableSniffing),
              username_(std::move(username)),
              password_(std::move(password))
        {
        }

        [[nodiscard]] inline const std::string &username() const noexcept { return username_; }
        [[nodiscard]] inline const std::string &password() const noexcept { return password_; }

        [[nodiscard]] std::unique_ptr<handler::HandlerInboundConnection> createHandler() override
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

} // namespace mynet
