#pragma once

#include "../inboundManager.hpp"
#include "http.hpp"
#include "v2/handler.hpp"
#include "v3/handler.hpp"
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace mynet
{

    /**
     * @brief HTTP 代理协议接收器 (AcceptorHttp / InboundHttp)
     */
    class AcceptorHttp : public Acceptor
    {
    private:
        std::string username_{};
        std::string password_{};

    public:
        AcceptorHttp(std::string tag = "http", std::string host = "0.0.0.0", uint16_t port = 8080,
                    std::string username = "", std::string password = "", bool enableSniffing = true)
            : Acceptor(std::move(tag), "http", std::move(host), port, enableSniffing),
              username_(std::move(username)),
              password_(std::move(password))
        {
        }

        [[nodiscard]] bool match(std::span<const uint8_t> initialBytes) const noexcept override
        {
            if (initialBytes.size() < 3)
                return false;
            std::string_view sv(reinterpret_cast<const char *>(initialBytes.data()), initialBytes.size());
            return sv.starts_with("GET ") || sv.starts_with("POST ") || sv.starts_with("CONNECT ") ||
                   sv.starts_with("HEAD ") || sv.starts_with("PUT ") || sv.starts_with("DELETE ") ||
                   sv.starts_with("OPTIONS ");
        }

        [[nodiscard]] std::unique_ptr<Handler> createHandler() override
        {
            auto h = std::make_unique<handler::HandlerInboundHttpProxy>();
            if (!username_.empty() || !password_.empty())
            {
                std::string u = username_;
                std::string p = password_;
                h->setAuthenticator([u, p](std::string_view user, std::string_view pass)
                                    { return user == u && (p.empty() || pass == p); });
            }
            return h;
        }
    };

    using InboundHttp = AcceptorHttp;

    /**
     * @brief HTTP/2 接收器 (AcceptorHttp2 / InboundHttp2)
     */
    class AcceptorHttp2 : public Acceptor
    {
    private:
        std::string username_{};
        std::string password_{};

    public:
        AcceptorHttp2(std::string tag = "http2", std::string host = "0.0.0.0", uint16_t port = 8443,
                      std::string username = "", std::string password = "", bool enableSniffing = true)
            : Acceptor(std::move(tag), "http2", std::move(host), port, enableSniffing),
              username_(std::move(username)),
              password_(std::move(password))
        {
        }

        [[nodiscard]] inline std::string_view username() const noexcept { return username_; }
        [[nodiscard]] inline std::string_view password() const noexcept { return password_; }

        [[nodiscard]] bool match(std::span<const uint8_t> initialBytes) const noexcept override
        {
            if (initialBytes.size() < 24)
                return false;
            std::string_view sv(reinterpret_cast<const char *>(initialBytes.data()), 24);
            return sv.starts_with("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        }

        [[nodiscard]] std::unique_ptr<Handler> createHandler() override
        {
            auto h = std::make_unique<handler::HandlerInboundHttp2Proxy>();
            if (!username_.empty() || !password_.empty())
            {
                std::string u = username_;
                std::string p = password_;
                h->setAuthenticator([u, p](std::string_view user, std::string_view pass)
                                    { return user == u && (p.empty() || pass == p); });
            }
            return h;
        }
    };

    using InboundHttp2 = AcceptorHttp2;

    /**
     * @brief HTTP/3 接收器 (AcceptorHttp3 / InboundHttp3)
     */
    class AcceptorHttp3 : public Acceptor
    {
    private:
        std::string password_{};

    public:
        AcceptorHttp3(std::string tag = "http3", std::string host = "0.0.0.0", uint16_t port = 443,
                      std::string password = "", bool enableSniffing = true)
            : Acceptor(std::move(tag), "http3", std::move(host), port, enableSniffing),
              password_(std::move(password))
        {
        }

        [[nodiscard]] inline std::string_view password() const noexcept { return password_; }

        Result<> listen(int backlog = 128, bool reuseAddr = true, bool reusePort = true) noexcept override
        {
            (void)backlog;
            if (running_ && socket_.valid())
            {
                return {};
            }
            close();

            auto res = socket_.listenUdp(host_.c_str(), port_, reuseAddr, reusePort);
            if (!res)
            {
                LOG_ERROR("AcceptorHttp3 '{}': listenUdp {}:{} failed", tag_, host_, port_);
                return std::unexpected(res.error());
            }

            if (port_ == 0)
            {
                port_ = ntohs(socket_.addr.sin_port);
            }

            running_ = true;
            return {};
        }

        [[nodiscard]] bool match(std::span<const uint8_t> initialBytes) const noexcept override
        {
            if (initialBytes.empty())
                return false;
            // QUIC 报文首字节分析 (RFC 9000):
            // Header Form (bit 7) = 1 为 Long Header (Initial / Handshake / Retry / 0-RTT)
            const uint8_t first = initialBytes[0];
            return (first & 0x80) != 0;
        }

        [[nodiscard]] std::unique_ptr<Handler> createHandler() override
        {
            return std::make_unique<handler::HandlerInboundHttp3Proxy>();
        }
    };

    using InboundHttp3 = AcceptorHttp3;

} // namespace mynet
