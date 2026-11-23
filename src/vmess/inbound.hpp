#pragma once

/**
 * @file vmess/inbound.hpp
 * @brief VMess 代理协议入站节点 (InboundVmess)。
 */

#include "../connection.hpp"
#include "../inboundManager.hpp"
#include "vmess.hpp"
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

namespace mynet
{

    class InboundVmess : public InboundBase
    {
    private:
        std::string uuid_{};

    public:
        InboundVmess(std::string tag = "vmess", std::string host = "0.0.0.0", uint16_t port = 443,
                     std::string uuid = "", bool enableSniffing = true)
            : InboundBase(std::move(tag), "vmess", std::move(host), port, enableSniffing),
              uuid_(std::move(uuid))
        {
        }

        [[nodiscard]] std::string_view uuid() const noexcept { return uuid_; }

        [[nodiscard]] std::unique_ptr<HandlerBase> createHandler() override
        {
            auto h = std::make_unique<handler::HandlerInboundVmess>(uuid_);
            return h;
        }
    };

    using AcceptorVmess = InboundVmess;

} // namespace mynet
