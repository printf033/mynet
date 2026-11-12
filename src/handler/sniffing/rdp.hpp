#pragma once

#include "common.hpp"
#include <cstdint>
#include <span>

namespace mynet::handler::sniffing
{

    /**
     * @brief 嗅探 RDP 协议连接请求 (TPKT + COTP)
     */
    [[nodiscard]] inline bool sniffRdp(std::span<const uint8_t> data) noexcept
    {
        if (data.size() < 11)
        {
            return false;
        }
        if (data[0] != 0x03 || data[1] != 0x00) // TPKT Version 3, Reserved 0
        {
            return false;
        }
        const uint16_t tpktLen = (static_cast<uint16_t>(data[2]) << 8) | data[3];
        if (tpktLen != 19 || data.size() < 19)
        {
            return false;
        }
        // COTP: length 14, type 0xE0 (Connection Request)
        return (data[4] == 14 && data[5] == 0xE0);
    }

} // namespace mynet::handler::sniffing
