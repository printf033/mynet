#pragma once

#include "../inboundManager.hpp"
#include "direct.hpp"
#include <memory>
#include <string>
#include <utility>

namespace mynet
{

    /**
     * @brief TCP/UDP 直通接收器 (AcceptorDirect / InboundDirect)
     */
    class AcceptorDirect : public Acceptor
    {
    public:
        AcceptorDirect(std::string tag = "direct", std::string host = "0.0.0.0", uint16_t port = 0,
                       bool enableSniffing = true)
            : Acceptor(std::move(tag), "direct", std::move(host), port, enableSniffing)
        {
        }

        [[nodiscard]] bool match(std::span<const uint8_t> initialBytes) const noexcept override
        {
            (void)initialBytes;
            return true;
        }

        [[nodiscard]] std::unique_ptr<Handler> createHandler() override
        {
            return std::make_unique<handler::HandlerInboundDirect>();
        }
    };

    using InboundDirect = AcceptorDirect;

} // namespace mynet
