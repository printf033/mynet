#pragma once

#include "../inboundManager.hpp"
#include "http.hpp"
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace mynet
{

    /**
     * @brief HTTP 代理协议入站端点 (InboundHttp)
     */
    class InboundHttp : public InboundBase
    {
    private:
        std::string username_{};
        std::string password_{};

    public:
        InboundHttp(std::string tag, std::string host, uint16_t port, std::string username = "",
                    std::string password = "", bool enableSniffing = true)
            : InboundBase(std::move(tag), "http", std::move(host), port, enableSniffing),
              username_(std::move(username)),
              password_(std::move(password))
        {
        }

        [[nodiscard]] std::unique_ptr<HandlerBase> createHandler() override
        {
            auto h = std::make_unique<handler::HandlerInboundHttpProxy>();
            if (!username_.empty() || !password_.empty())
            {
                std::string u = username_;
                std::string p = password_;
                h->setAuthenticator([u, p](std::string_view user, std::string_view pass)
                                    { return user == u && (p.empty() || pass == p); });
            }
            return h;
        }
    };

} // namespace mynet
