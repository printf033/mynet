#pragma once

#include "../datagram.hpp"
#include "../acceptorManager.hpp"
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

    /**
     * @brief 数据报入站接收器 (AcceptorDatagram)
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

            socket_.setFd(datagram_.fd());
            socket_.setAddr(datagram_.localAddr());

            running_ = true;
            return {};
        }

        void close() noexcept override
        {
            running_ = false;
            datagram_.close();
            socket_.setFd(-1);
            socket_.setAddr({});
        }

        [[nodiscard]] inline Datagram &datagram() noexcept { return datagram_; }
        [[nodiscard]] inline const Datagram &datagram() const noexcept { return datagram_; }

        [[nodiscard]] std::unique_ptr<Handler> createHandler() override
        {
            return std::make_unique<Handler>();
        }
    };


} // namespace mynet
