#pragma once

#include "../dialer.hpp"
#include "direct.hpp"
#include <memory>
#include <string>
#include <utility>

namespace mynet
{

    /**
     * @brief 直连拨号器 (DialerDirect / OutboundDirect)
     */
    class DialerDirect : public Dialer
    {
    public:
        explicit DialerDirect(std::string tag = "direct", DialerOptions options = {})
            : Dialer(std::move(tag), "direct", std::move(options))
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
            outRes.peerAddr = res->peerAddr;
            outRes.connectDeferred = res->connectDeferred;
            return outRes;
        }

        Result<int> dialDatagram(const handler::ProxyAddress &target) override
        {
            (void)target;
            auto dgramRes = createConfiguredDatagram();
            if (!dgramRes)
            {
                return std::unexpected(dgramRes.error());
            }
            return dgramRes->release();
        }
    };

    using OutboundDirect = DialerDirect;

} // namespace mynet
