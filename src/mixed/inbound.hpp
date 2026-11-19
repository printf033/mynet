#pragma once

#include "../inboundManager.hpp"
#include "mixed.hpp"
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace mynet
{

    /**
     * @brief 自动多协议自适应入站端点 (InboundMixed)
     */
    class InboundMixed : public InboundBase
    {
    private:
        std::string username_{};
        std::string password_{};

    public:
        InboundMixed(std::string tag, std::string host, uint16_t port,
                     std::string username = "", std::string password = "", bool enableSniffing = true)
            : InboundBase(std::move(tag), "mixed", std::move(host), port, enableSniffing),
              username_(std::move(username)),
              password_(std::move(password))
        {
        }

        [[nodiscard]] std::unique_ptr<handler::HandlerInboundConnection> createHandler() override
        {
            auto h = std::make_unique<handler::HandlerInboundMixed>();
            if (!username_.empty() || !password_.empty())
            {
                std::string u = username_;
                std::string p = password_;
                h->setAuthenticator([u, p](std::string_view user, std::string_view pass) {
                    return user == u && (p.empty() || pass == p);
                });
            }
            return h;
        }
    };

} // namespace mynet
