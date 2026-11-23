#pragma once

#include "../outboundManager.hpp"
#include "direct.hpp"
#include <memory>
#include <string>
#include <utility>

namespace mynet
{

    /**
     * @brief 直连出站端点 (OutboundDirect)
     */
    class OutboundDirect : public OutboundBase
    {
    public:
        explicit OutboundDirect(std::string tag = "direct", DialerOptions options = {})
            : OutboundBase(std::move(tag), "direct", std::move(options))
        {
        }

        Result<OutboundDialResult> dialStream(const handler::ProxyAddress &target) override
        {
            Result<DialTcpResult> res;

            if (auto sin = target.toSockAddrIn(); sin.has_value())
            {
                res = dialTcp(*sin);
            }
            else
            {
                res = dialTcp(target.host, target.port);
            }

            if (!res)
            {
                return std::unexpected(res.error());
            }

            OutboundDialResult outRes;
            outRes.fd = res->fd;
            outRes.handler = std::make_unique<handler::HandlerOutboundDirect>(target);
            outRes.outboundTag = tag_;
            outRes.targetEndpoint = target.toString();
            outRes.immediateConnected = res->immediateConnected;
            return outRes;
        }

        Result<int> dialDatagram(const handler::ProxyAddress &target) override
        {
            Result<int> res;

            if (auto sin = target.toSockAddrIn(); sin.has_value())
            {
                res = dialUdp(*sin);
            }
            else
            {
                res = dialUdp(target.host, target.port);
            }

            if (!res)
            {
                return std::unexpected(res.error());
            }

            return *res;
        }
    };

} // namespace mynet
