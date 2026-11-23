#pragma once

#include "../outboundManager.hpp"
#include "block.hpp"
#include <memory>
#include <string>
#include <utility>

namespace mynet
{

    /**
     * @brief 拦截黑洞出站端点 (OutboundBlock)
     */
    class OutboundBlock : public OutboundBase
    {
    public:
        explicit OutboundBlock(std::string tag = "block", DialerOptions options = {})
            : OutboundBase(std::move(tag), "block", std::move(options))
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

    using DialerBlock = OutboundBlock;

} // namespace mynet
