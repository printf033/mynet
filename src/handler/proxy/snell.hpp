#pragma once

/**
 * @file handler/proxy/snell.hpp
 * @brief Snell 代理协议入站状态机处理器 (HandlerInboundSnell)。
 */

#include "../address.hpp"
#include "../inbound.hpp"
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace mynet::handler
{

    namespace snell
    {
        inline constexpr uint8_t kCmdConnect = 0x01;
        inline constexpr uint8_t kCmdPing = 0x00;
    } // namespace snell

    /**
     * @brief Snell 协议入站状态机处理器
     */
    class HandlerInboundSnell : public HandlerInboundConnection
    {
    public:
        static constexpr bool kEnableSplice = true;

    private:
        uint8_t version_{2};
        std::string psk_{};

    public:
        HandlerInboundSnell() noexcept = default;
        HandlerInboundSnell(uint8_t version, std::string_view psk)
            : version_(version),
              psk_(psk)
        {
        }
        ~HandlerInboundSnell() noexcept override = default;

        HandlerInboundSnell(const HandlerInboundSnell &) = delete;
        HandlerInboundSnell &operator=(const HandlerInboundSnell &) = delete;
        HandlerInboundSnell(HandlerInboundSnell &&) = delete;
        HandlerInboundSnell &operator=(HandlerInboundSnell &&) = delete;

        void setVersion(uint8_t ver) noexcept { version_ = ver; }
        void setPsk(std::string_view psk) { psk_ = std::string(psk); }

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

    private:
        bool processHeader()
        {
            // 首部格式：[Version 1B][CMD 1B][Address (SOCKS5)]
            const size_t avail = requestBytes();
            if (avail < 2 + 7)
            {
                return false;
            }

            const auto *data = reinterpret_cast<const uint8_t *>(requestBegin());
            const uint8_t ver = data[0];
            const uint8_t cmd = data[1];

            if (ver != version_ && version_ != 0)
            {
                onParseError("Snell: Version mismatch");
                stage_ = InboundStage::ERROR;
                setCloseAfterResponse(true);
                return false;
            }

            if (cmd == snell::kCmdPing)
            {
                static constexpr char kPong[2] = {0x00, 0x00};
                [[maybe_unused]] auto _ = pushResponse(std::string_view(kPong, 2));
                requestConsume(2);
                return true;
            }

            size_t addrConsumed = 0;
            std::span<const uint8_t> addrSpan(data + 2, avail - 2);
            auto target = ProxyAddress::decodeSocks5(addrSpan, addrConsumed);
            if (!target.has_value())
            {
                return false;
            }

            const size_t totalHeaderSize = 2 + addrConsumed;
            command_ = cmd;
            targetAddress_ = std::move(target);
            requestConsume(totalHeaderSize);

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
