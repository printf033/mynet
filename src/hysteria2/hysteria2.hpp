#pragma once

/**
 * @file handler/proxy/hysteria2.hpp
 * @brief Hysteria 2 代理协议入站状态机处理器 (HandlerInboundHysteria2) 与出站协议处理器 (HandlerOutboundHysteria2)。
 */

#include "../address.hpp"
#include "../connection.hpp"
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mynet::handler
{

    namespace hysteria2
    {
        inline constexpr uint8_t kCmdTcp = 0x01;
        inline constexpr uint8_t kCmdUdp = 0x02;

        inline constexpr uint8_t kStatusOk = 0x00;
        inline constexpr uint8_t kStatusAuthFailed = 0x01;
    } // namespace hysteria2

    /**
     * @brief Hysteria 2 协议入站状态机处理器
     */
    class HandlerInboundHysteria2 : public HandlerInbound
    {
    public:
        using AuthCallback = std::function<bool(std::string_view authStr)>;

    private:
        std::string password_{};
        AuthCallback authCallback_{nullptr};
        bool autoReplyOk_{true};

    public:
        HandlerInboundHysteria2() noexcept = default;
        explicit HandlerInboundHysteria2(std::string_view password)
            : password_(password)
        {
        }
        ~HandlerInboundHysteria2() noexcept override = default;

        HandlerInboundHysteria2(const HandlerInboundHysteria2 &) = delete;
        HandlerInboundHysteria2 &operator=(const HandlerInboundHysteria2 &) = delete;
        HandlerInboundHysteria2(HandlerInboundHysteria2 &&) = delete;
        HandlerInboundHysteria2 &operator=(HandlerInboundHysteria2 &&) = delete;

        void setPassword(std::string_view pass) { password_ = std::string(pass); }
        void setAuthenticator(AuthCallback cb) noexcept { authCallback_ = std::move(cb); }
        void setAutoReply(bool autoReply) noexcept { autoReplyOk_ = autoReply; }

        void reset() noexcept override { HandlerInbound::reset(); }

        void handle() override
        {
            if (inboundStage() == InboundStage::HANDSHAKE)
            {
                if (!processAuth())
                {
                    return;
                }
            }
        }

        void sendReply(uint8_t status)
        {
            const char reply[1] = {static_cast<char>(status)};
            [[maybe_unused]] auto _ = pushResponse(std::string_view(reply, 1));
        }

    private:
        bool processAuth()
        {
            // 首部格式：[AuthLen 1B][AuthStr AuthLen B][CMD 1B][Address (SOCKS5)]
            const size_t avail = requestBytes();
            if (avail < 1)
            {
                return false;
            }

            const auto *data = reinterpret_cast<const uint8_t *>(requestBegin());
            const uint8_t authLen = data[0];
            const size_t minHeader = 1 + static_cast<size_t>(authLen) + 1 + 7;
            if (avail < minHeader)
            {
                return false;
            }

            std::string_view authStr(reinterpret_cast<const char *>(data + 1), authLen);

            bool ok = false;
            if (authCallback_)
            {
                ok = authCallback_(authStr);
            }
            else
            {
                ok = (authStr == password_);
            }

            if (!ok)
            {
                sendReply(hysteria2::kStatusAuthFailed);
                onParseError("Hysteria2: Authentication failed");
                setStage(InboundStage::ERROR);
                setCloseAfterResponse(true);
                return false;
            }

            const size_t cmdOffset = 1 + authLen;
            const uint8_t cmd = data[cmdOffset];
            const size_t addrOffset = cmdOffset + 1;

            size_t addrConsumed = 0;
            std::span<const uint8_t> addrSpan(data + addrOffset, avail - addrOffset);
            auto target = Address::decodeSocks5(addrSpan, addrConsumed);
            if (!target.has_value())
            {
                return false;
            }

            const size_t totalHeader = addrOffset + addrConsumed;
            command_ = cmd;
            targetAddress_ = std::move(target);
            requestConsume(totalHeader);

            if (autoReplyOk_)
            {
                sendReply(hysteria2::kStatusOk);
            }

            setStage(InboundStage::STREAMING);
            onMessageComplete();

            if (requestCallback_)
            {
                requestCallback_(command_, *targetAddress_);
            }
            return true;
        }
    };

    /**
     * @brief Hysteria 2 协议出站客户端处理器 (Hysteria 2 Outbound)
     *
     * 自动向上游发送 [AuthLen 1B][AuthStr][CMD 0x01][Target Address]，并等待 1 字节状态码 0x00。
     */
    class HandlerOutboundHysteria2 : public HandlerOutbound
    {
    private:
        std::string password_{};
        bool headerSent_{false};

    public:
        HandlerOutboundHysteria2() noexcept = default;
        HandlerOutboundHysteria2(std::string_view password, const Address &target)
            : HandlerOutbound(target),
              password_(password)
        {
        }

        void setPassword(std::string_view password) { password_ = std::string(password); }

        void reset() noexcept override
        {
            HandlerOutbound::reset();
            headerSent_ = false;
        }

        void handle() override
        {
            if (!headerSent_)
            {
                sendHandshakeHeader();
            }

            if (outboundStage() == OutboundStage::CONNECTING)
            {
                if (requestBytes() >= 1)
                {
                    const auto *resp = reinterpret_cast<const uint8_t *>(requestBegin());
                    if (resp[0] != hysteria2::kStatusOk)
                    {
                        onParseError("HandlerOutboundHysteria2: Server rejected handshake");
                        return;
                    }
                    requestConsume(1);
                    setStage(OutboundStage::STREAMING);
                }
            }
        }

    private:
        void sendHandshakeHeader()
        {
            std::vector<uint8_t> header;
            header.reserve(1 + password_.size() + 1 + 64);

            header.push_back(static_cast<uint8_t>(password_.size() > 255 ? 255 : password_.size()));
            header.insert(header.end(), password_.begin(),
                          password_.begin() + (password_.size() > 255 ? 255 : password_.size()));

            header.push_back(hysteria2::kCmdTcp);

            target().encodeSocks5(header);

            [[maybe_unused]] auto _ =
                pushResponse(std::string_view(reinterpret_cast<const char *>(header.data()), header.size()));
            headerSent_ = true;
            setStage(OutboundStage::CONNECTING);
        }
    };

} // namespace mynet::handler
