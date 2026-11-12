#pragma once

#include "common.hpp"
#include <cstdint>
#include <span>

namespace mynet::handler::sniffing
{

    /**
     * @brief 嗅探 STUN 协议报文 (RFC 5389 / RFC 8489)
     */
    [[nodiscard]] inline bool sniffStun(std::span<const uint8_t> data) noexcept
    {
        if (data.size() < 20)
        {
            return false;
        }
        // STUN Magic Cookie = 0x2112A442
        const uint32_t magic = (static_cast<uint32_t>(data[4]) << 24) |
                               (static_cast<uint32_t>(data[5]) << 16) |
                               (static_cast<uint32_t>(data[6]) << 8) |
                               static_cast<uint32_t>(data[7]);
        if (magic != 0x2112A442)
        {
            return false;
        }
        const uint16_t msgLen = (static_cast<uint16_t>(data[2]) << 8) | data[3];
        return data.size() >= static_cast<size_t>(20 + msgLen);
    }

} // namespace mynet::handler::sniffing
