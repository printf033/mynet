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
        InboundDirect(std::string tag, std::string host, uint16_t port, bool enableSniffing = true)
            : InboundBase(std::move(tag), "direct", std::move(host), port, enableSniffing)
        {
        }

        [[nodiscard]] std::unique_ptr<HandlerBase> createHandler() override
        {
            return std::make_unique<handler::HandlerInboundDirect>();
        }
    };

} // namespace mynet
