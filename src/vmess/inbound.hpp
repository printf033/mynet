#pragma once

/**
 * @file vmess/inbound.hpp
 * @brief VMess 代理协议入站节点 (InboundVmess)。
 */

#include "../inboundHandler.hpp"
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
        InboundVmess(std::string tag, std::string host, uint16_t port, std::string uuid, bool enableSniffing = true)
            : InboundBase(std::move(tag), "vmess", std::move(host), port, enableSniffing),
              uuid_(std::move(uuid))
        {
        }

        [[nodiscard]] std::string_view uuid() const noexcept { return uuid_; }

        [[nodiscard]] std::unique_ptr<handler::HandlerInboundConnectionBase> createHandler() override
        {
            auto h = std::make_unique<handler::HandlerInboundVmess>(uuid_);
            return h;
        }
    };

} // namespace mynet
