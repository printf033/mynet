#pragma once

#include "../datagram.hpp"
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

        Result<OutboundDialResult> dialForwarder(const Address &target, DialContext ctx = {}) override
        {
            Result<ConnectResult> res;

            if (auto sin = target.toSockAddrIn(); sin.has_value())
            {
                res = dialTcp(*sin, nullptr, ctx);
            }
            else
            {
                res = dialTcp(target.host, target.port, nullptr, ctx);
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

        Result<int> dialDatagram(const Address &target) override
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

    /**
     * @brief 数据报出站拨号器 (DialerDatagram)
     *
     * 复用 Dialer::createConfiguredDatagram 创建与打标无状态 UDP 报文通道。
     */
    class DialerDatagram : public Dialer
    {
    public:
        explicit DialerDatagram(std::string tag = "datagram", DialerOptions options = {})
            : Dialer(std::move(tag), "datagram", std::move(options))
        {
        }

        Result<int> dialDatagram(const Address &target) override
        {
            (void)target;
            auto dgramRes = createConfiguredDatagram();
            if (!dgramRes)
                return std::unexpected(dgramRes.error());
            return dgramRes->release();
        }

        Result<Datagram> dialDatagramEndpoint(const Address &target)
        {
            (void)target;
            return createConfiguredDatagram();
        }
    };


} // namespace mynet
