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
        InboundHttp(std::string tag = "http", std::string host = "0.0.0.0", uint16_t port = 8080,
                    std::string username = "", std::string password = "", bool enableSniffing = true)
            : InboundBase(std::move(tag), "http", std::move(host), port, enableSniffing),
              username_(std::move(username)),
              password_(std::move(password))
        {
        }

        [[nodiscard]] bool match(std::span<const uint8_t> initialBytes) const noexcept override
        {
            if (initialBytes.size() < 3)
                return false;
            std::string_view sv(reinterpret_cast<const char *>(initialBytes.data()), initialBytes.size());
            return sv.starts_with("GET ") || sv.starts_with("POST ") || sv.starts_with("CONNECT ") ||
                   sv.starts_with("HEAD ") || sv.starts_with("PUT ") || sv.starts_with("DELETE ") ||
                   sv.starts_with("OPTIONS ");
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

    using AcceptorHttp = InboundHttp;

} // namespace mynet
