#pragma once

#include "common.hpp"
#include <cstdint>
#include <span>

namespace mynet::handler::sniffing
{

    /**
     * @brief 嗅探 NTP 客户端请求报文 (RFC 5905)
     */
    [[nodiscard]] inline bool sniffNtp(std::span<const uint8_t> data) noexcept
    {
        if (data.size() < 48)
        {
            return false;
        }
        const uint8_t b0 = data[0];
        const uint8_t li = (b0 >> 6) & 0x03;
        const uint8_t vn = (b0 >> 3) & 0x07;
        const uint8_t mode = b0 & 0x07;
        if (li > 3 || (vn != 3 && vn != 4) || mode != 3)
        {
            return false;
        }
        return true;
    }

} // namespace mynet::handler::sniffing
