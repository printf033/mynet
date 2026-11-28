#pragma once

#include "../acceptorManager.hpp"
#include "vless.hpp"
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace mynet
{

    /**
     * @brief VLESS 协议接收器 (AcceptorVless / InboundVless)
     */
    class AcceptorVless : public Acceptor
    {
    private:
        std::string uuidStr_{};
        std::array<uint8_t, 16> uuid_{};

    public:
        AcceptorVless(std::string tag = "vless", std::string host = "0.0.0.0", uint16_t port = 443,
                      std::string uuidStr = "", bool enableSniffing = true)
            : Acceptor(std::move(tag), "vless", std::move(host), port, enableSniffing),
              uuidStr_(std::move(uuidStr))
        {
            if (auto u = encoding::parseUuid(uuidStr_); u.has_value())
            {
                uuid_ = *u;
            }
        }

        [[nodiscard]] bool match(std::span<const uint8_t> initialBytes) const noexcept override
        {
            // VLESS 首包第一个字节为协议版本 (0x00)
            return !initialBytes.empty() && initialBytes[0] == 0x00;
        }

        [[nodiscard]] inline std::string_view uuid() const noexcept { return uuidStr_; }
        [[nodiscard]] inline const std::array<uint8_t, 16> &uuidBytes() const noexcept { return uuid_; }

        [[nodiscard]] std::unique_ptr<Handler> createHandler() override
        {
            return std::make_unique<handler::HandlerInboundVless>(uuid_);
        }
    };


} // namespace mynet
