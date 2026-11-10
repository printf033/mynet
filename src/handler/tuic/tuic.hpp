#pragma once

/**
 * @file handler/tuic/tuic.hpp
 * @brief TUIC (v5) 代理协议入站状态机处理器 (HandlerInboundTuic)。
 */

#include "../address.hpp"
#include "../crypto.hpp"
#include "../inbound.hpp"
#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mynet::handler
{

    namespace tuic
    {
        inline constexpr uint8_t kCmdConnect = 0x01;
        inline constexpr uint8_t kCmdPacket = 0x02;
        inline constexpr uint8_t kCmdHeartbeat = 0x03;

        inline constexpr uint8_t kRepSuccess = 0x00;
        inline constexpr uint8_t kRepAuthFailure = 0x01;
    } // namespace tuic

    /**
     * @brief TUIC 协议入站状态机处理器
     */
    class HandlerInboundTuic : public HandlerInboundConnection
    {
    public:
        using AuthCallback = std::function<bool(const std::array<uint8_t, 16> &uuid)>;

    private:
        std::array<uint8_t, 16> expectedUuid_{};
        AuthCallback authCallback_{nullptr};
        bool autoReplySuccess_{true};

    public:
        HandlerInboundTuic() noexcept = default;
        explicit HandlerInboundTuic(std::string_view uuidStr) { setUuid(uuidStr); }
        ~HandlerInboundTuic() noexcept override = default;

        HandlerInboundTuic(const HandlerInboundTuic &) = delete;
        HandlerInboundTuic &operator=(const HandlerInboundTuic &) = delete;
        HandlerInboundTuic(HandlerInboundTuic &&) = delete;
        HandlerInboundTuic &operator=(HandlerInboundTuic &&) = delete;

        void setUuid(std::string_view uuidStr)
        {
            if (auto u = crypto::parseUuid(uuidStr); u.has_value())
            {
                expectedUuid_ = *u;
            }
        }

        void setAuthenticator(AuthCallback cb) noexcept { authCallback_ = std::move(cb); }
        void setAutoReply(bool autoReply) noexcept { autoReplySuccess_ = autoReply; }

        void reset() noexcept override
        {
            HandlerInboundConnection::reset();
        }

        void process() override
        {
            if (stage_ == InboundStage::HANDSHAKE)
            {
                if (!processHeader())
                {
                    return;
                }
            }
        }

        void sendReply(uint8_t rep)
        {
            const char reply[1] = {static_cast<char>(rep)};
            [[maybe_unused]] auto _ = pushResponse(std::string_view(reply, 1));
        }

    private:
        bool processHeader()
        {
            // 首部格式：[UUID 16B][CMD 1B][Address (SOCKS5)]
            const size_t avail = requestBytes();
            if (avail < 16 + 1 + 7)
            {
                return false;
            }

            const auto *data = reinterpret_cast<const uint8_t *>(requestBegin());

            std::array<uint8_t, 16> clientUuid{};
            std::memcpy(clientUuid.data(), data, 16);

            bool authOk = false;
            if (authCallback_)
            {
                authOk = authCallback_(clientUuid);
            }
            else
            {
                authOk = crypto::constantTimeEqual(clientUuid, expectedUuid_);
            }

            if (!authOk)
            {
                sendReply(tuic::kRepAuthFailure);
                onParseError("TUIC: Unauthorized UUID");
                stage_ = InboundStage::ERROR;
                setCloseAfterResponse(true);
                return false;
            }

            const uint8_t cmd = data[16];
            const size_t addrOffset = 17;

            size_t addrConsumed = 0;
            std::span<const uint8_t> addrSpan(data + addrOffset, avail - addrOffset);
            auto target = ProxyAddress::decodeSocks5(addrSpan, addrConsumed);
            if (!target.has_value())
            {
                return false;
            }

            const size_t totalHeader = addrOffset + addrConsumed;
            command_ = cmd;
            targetAddress_ = std::move(target);
            requestConsume(totalHeader);

            if (autoReplySuccess_)
            {
                sendReply(tuic::kRepSuccess);
            }

            stage_ = InboundStage::STREAMING;
            onMessageComplete();

            if (requestCallback_)
            {
                requestCallback_(command_, *targetAddress_);
            }
            return true;
        }
    };

} // namespace mynet::handler
