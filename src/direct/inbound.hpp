#pragma once

#include "../inboundManager.hpp"
#include "direct.hpp"
#include <memory>
#include <string>
#include <utility>

namespace mynet
{

    /**
     * @brief TCP/UDP 直通入站端点 (InboundDirect)
     */
    class InboundDirect : public InboundBase
    {
    public:
        InboundDirect(std::string tag = "direct", std::string host = "0.0.0.0", uint16_t port = 0,
                      bool enableSniffing = true)
            : InboundBase(std::move(tag), "direct", std::move(host), port, enableSniffing)
        {
        }

        [[nodiscard]] bool match(std::span<const uint8_t> initialBytes) const noexcept override
        {
            (void)initialBytes;
            return true;
        }

        [[nodiscard]] std::unique_ptr<HandlerBase> createHandler() override
        {
            return std::make_unique<handler::HandlerInboundDirect>();
        }
    };

    using AcceptorDirect = InboundDirect;

} // namespace mynet
