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
            Dialer<handler::HandlerOutboundDirect> dialer;
            if (options_.fwmark != 0)
            {
                dialer.setMark(options_.fwmark);
            }
            if (!options_.bindInterface.empty())
            {
                dialer.setInterface(options_.bindInterface);
            }
            Result<bool> res;

            if (auto sin = target.toSockAddrIn(); sin.has_value())
            {
                res = dialer.dialTcp(*sin);
            }
            else
            {
                res = dialer.dialTcp(target.host, target.port);
            }

            if (!res)
            {
                return std::unexpected(res.error());
            }

            OutboundDialResult outRes;
            outRes.fd = dialer.release();
            outRes.handler = std::make_unique<handler::HandlerOutboundDirect>(target);
            outRes.outboundTag = tag_;
            outRes.targetEndpoint = target.toString();
            outRes.immediateConnected = *res;
            return outRes;
        }

        Result<int> dialDatagram(const handler::ProxyAddress &target) override
        {
            Dialer<handler::HandlerOutboundDirect> dialer;
            if (options_.fwmark != 0)
            {
                dialer.setMark(options_.fwmark);
            }
            if (!options_.bindInterface.empty())
            {
                dialer.setInterface(options_.bindInterface);
            }
            Result<> res;

            if (auto sin = target.toSockAddrIn(); sin.has_value())
            {
                res = dialer.dialUdp(*sin);
            }
            else
            {
                res = dialer.dialUdp(target.host, target.port);
            }

            if (!res)
            {
                return std::unexpected(res.error());
            }

            return dialer.release();
        }
    };

} // namespace mynet
