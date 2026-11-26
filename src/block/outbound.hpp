#pragma once

#include "../dialer.hpp"
#include "block.hpp"
#include <memory>
#include <string>
#include <utility>

namespace mynet
{

    /**
     * @brief 拦截黑洞拨号器 (DialerBlock / OutboundBlock)
     */
    class DialerBlock : public Dialer
    {
    public:
        explicit DialerBlock(std::string tag = "block", DialerOptions options = {})
            : Dialer(std::move(tag), "block", std::move(options))
        {
        }

        Result<OutboundDialResult> dialStream(const handler::ProxyAddress &target) override
        {
            OutboundDialResult res;
            res.fd = -1;
            res.handler = std::make_unique<handler::HandlerOutboundBlock>();
            res.outboundTag = tag_;
            res.targetEndpoint = target.toString();
            res.immediateConnected = false;
            return res;
        }

        Result<int> dialDatagram(const handler::ProxyAddress &target) override
        {
            (void)target;
            return std::unexpected(ERR::CONNECT_FAILED);
        }
    };

    using OutboundBlock = DialerBlock;

} // namespace mynet
