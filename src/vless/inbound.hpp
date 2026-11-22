#pragma once

#include "../inboundManager.hpp"
#include "vless.hpp"
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace mynet
{

    /**
     * @brief VLESS 协议入站端点 (InboundVless)
     */
    class InboundVless : public InboundBase
    {
    private:
        std::string uuidStr_{};
        std::array<uint8_t, 16> uuid_{};

    public:
        InboundVless(std::string tag, std::string host, uint16_t port, std::string uuidStr, bool enableSniffing = true)
            : InboundBase(std::move(tag), "vless", std::move(host), port, enableSniffing),
              uuidStr_(std::move(uuidStr))
        {
            if (auto u = encoding::parseUuid(uuidStr_); u.has_value())
            {
                uuid_ = *u;
            }
        }

        [[nodiscard]] inline std::string_view uuid() const noexcept { return uuidStr_; }
        [[nodiscard]] inline const std::array<uint8_t, 16> &uuidBytes() const noexcept { return uuid_; }

        [[nodiscard]] std::unique_ptr<HandlerBase> createHandler() override
        {
            return std::make_unique<handler::HandlerInboundVless>(uuid_);
        }
    };

} // namespace mynet
