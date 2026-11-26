#pragma once

/**
 * @file http/outbound.hpp
 * @brief HTTP 代理协议拨号器 (DialerHttp / OutboundHttp)。
 */

#include "../connection.hpp"
#include "../outboundManager.hpp"
#include "http.hpp"
#include <cstdint>
#include <string>
#include <string_view>

namespace mynet
{

    class DialerHttp : public Dialer
    {
    private:
        std::string serverHost_{};
        uint16_t serverPort_{8080};
        std::string username_{};
        std::string password_{};

    public:
        DialerHttp(std::string tag, std::string host, uint16_t port, std::string username = "",
                   std::string password = "", DialerOptions options = {})
            : Dialer(std::move(tag), "http", std::move(options)),
              serverHost_(std::move(host)),
              serverPort_(port),
              username_(std::move(username)),
              password_(std::move(password))
        {
        }

        [[nodiscard]] std::string_view serverHost() const noexcept override { return serverHost_; }
        [[nodiscard]] uint16_t serverPort() const noexcept override { return serverPort_; }
        [[nodiscard]] std::string_view username() const noexcept { return username_; }
        [[nodiscard]] std::string_view password() const noexcept { return password_; }

        Result<OutboundDialResult> dialStream(const handler::ProxyAddress &target) override
        {
            return dialStreamHelper<handler::HandlerOutboundHttp>(serverHost_, serverPort_, target, username_,
                                                                  password_);
        }

        Result<int> dialDatagram(const handler::ProxyAddress &) override
        {
            return std::unexpected(ERR::CONNECT_FAILED);
        }
    };

    using OutboundHttp = DialerHttp;

    /**
     * @brief HTTP/2 代理协议拨号器 (DialerHttp2 / OutboundHttp2)
     */
    class DialerHttp2 : public Dialer
    {
    private:
        std::string serverHost_{};
        uint16_t serverPort_{8443};
        std::string username_{};
        std::string password_{};

    public:
        DialerHttp2(std::string tag, std::string host, uint16_t port, std::string username = "",
                    std::string password = "", DialerOptions options = {})
            : Dialer(std::move(tag), "http2", std::move(options)),
              serverHost_(std::move(host)),
              serverPort_(port),
              username_(std::move(username)),
              password_(std::move(password))
        {
        }

        [[nodiscard]] std::string_view serverHost() const noexcept override { return serverHost_; }
        [[nodiscard]] uint16_t serverPort() const noexcept override { return serverPort_; }
        [[nodiscard]] std::string_view username() const noexcept { return username_; }
        [[nodiscard]] std::string_view password() const noexcept { return password_; }

        Result<OutboundDialResult> dialStream(const handler::ProxyAddress &target) override
        {
            return dialStreamHelper<handler::HandlerOutboundHttp2>(serverHost_, serverPort_, target, username_,
                                                                   password_);
        }

        Result<int> dialDatagram(const handler::ProxyAddress &) override
        {
            return std::unexpected(ERR::CONNECT_FAILED);
        }
    };

    using OutboundHttp2 = DialerHttp2;

    /**
     * @brief HTTP/3 (QUIC/UDP) 代理协议拨号器 (DialerHttp3 / OutboundHttp3)
     */
    class DialerHttp3 : public Dialer
    {
    private:
        std::string serverHost_{};
        uint16_t serverPort_{443};
        std::string password_{};

    public:
        DialerHttp3(std::string tag, std::string host, uint16_t port, std::string password = "",
                    DialerOptions options = {})
            : Dialer(std::move(tag), "http3", std::move(options)),
              serverHost_(std::move(host)),
              serverPort_(port),
              password_(std::move(password))
        {
        }

        [[nodiscard]] std::string_view serverHost() const noexcept override { return serverHost_; }
        [[nodiscard]] uint16_t serverPort() const noexcept override { return serverPort_; }
        [[nodiscard]] std::string_view password() const noexcept { return password_; }

        Result<OutboundDialResult> dialStream(const handler::ProxyAddress &target) override
        {
            auto udpRes = dialUdp(serverHost_, serverPort_);
            if (!udpRes)
            {
                return std::unexpected(udpRes.error());
            }

            auto h = std::make_unique<handler::HandlerOutboundHttp3>(target);
            h->handle();

            OutboundDialResult res;
            res.fd = *udpRes;
            res.handler = std::move(h);
            res.outboundTag = tag_;
            res.targetEndpoint = target.toString();
            res.immediateConnected = true;
            return res;
        }

        Result<int> dialDatagram(const handler::ProxyAddress &target) override
        {
            (void)target;
            return dialUdp(serverHost_, serverPort_);
        }
    };

    using OutboundHttp3 = DialerHttp3;

} // namespace mynet
