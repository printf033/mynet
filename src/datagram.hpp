#pragma once

/**
 * @file datagram.hpp
 * @brief 统一数据报抽象与 Inbound / Outbound 编排适配 (AcceptorDatagram / DialerDatagram)
 */

#include "acceptor.hpp"
#include "datagramCore.hpp"
#include "dialer.hpp"
#include <memory>
#include <string>
#include <utility>

namespace mynet
{

    /**
     * @brief 数据报入站接收器 (AcceptorDatagram / InboundDatagram)
     *
     * 专职负责无状态 UDP 报文监听与收发派发，支持 TProxy 透明代理与标准 UDP 端口绑定。
     */
    class AcceptorDatagram : public Acceptor
    {
    private:
        Datagram datagram_{};
        bool transparent_{false};
        bool recvOrigDst_{false};

    public:
        AcceptorDatagram(std::string tag, std::string host, uint16_t port,
                         bool transparent = false, bool recvOrigDst = false)
            : Acceptor(std::move(tag), "datagram", std::move(host), port, false),
              transparent_(transparent),
              recvOrigDst_(recvOrigDst)
        {
        }

        Result<> listen(int backlog = 128, bool reuseAddr = true, bool reusePort = true) noexcept override
        {
            (void)backlog;
            if (running_ && datagram_.valid())
                return {};
            close();

            auto res = Datagram::bind(host_.c_str(), port_, reuseAddr, reusePort);
            if (!res)
                return std::unexpected(res.error());

            datagram_ = std::move(*res);
            if (transparent_)
            {
                (void)datagram_.setTransparent(true);
            }
            if (recvOrigDst_)
            {
                (void)datagram_.setRecvOrigDst(true);
                (void)datagram_.setPacketInfo(true);
            }

            if (port_ == 0)
            {
                port_ = datagram_.localPort();
            }

            socket_.fd = datagram_.fd();
            socket_.addr = datagram_.localAddr();

            running_ = true;
            return {};
        }

        void close() noexcept override
        {
            running_ = false;
            datagram_.close();
            socket_.fd = -1;
            socket_.addr = {};
        }

        [[nodiscard]] inline Datagram &datagram() noexcept { return datagram_; }
        [[nodiscard]] inline const Datagram &datagram() const noexcept { return datagram_; }

        [[nodiscard]] std::unique_ptr<Handler> createHandler() override
        {
            return std::make_unique<handler::Handler>();
        }
    };

    using InboundDatagram = AcceptorDatagram;

    /**
     * @brief 数据报出站拨号器 (DialerDatagram / OutboundDatagram)
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

        Result<int> dialDatagram(const handler::ProxyAddress &target) override
        {
            (void)target;
            auto dgramRes = createConfiguredDatagram();
            if (!dgramRes)
                return std::unexpected(dgramRes.error());
            return dgramRes->release();
        }

        Result<Datagram> dialDatagramEndpoint(const handler::ProxyAddress &target)
        {
            (void)target;
            return createConfiguredDatagram();
        }
    };

    using OutboundDatagram = DialerDatagram;

} // namespace mynet
