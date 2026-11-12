#pragma once

#include "common.hpp"
#include <cstdint>
#include <span>

namespace mynet::handler::sniffing
{

    /**
     * @brief 嗅探 DTLS 协议记录层 (RFC 6347 / RFC 9147)
     */
    [[nodiscard]] inline bool sniffDtls(std::span<const uint8_t> data) noexcept
    {
        if (data.size() < 13)
        {
            return false;
        }
        const uint8_t contentType = data[0];
        if (contentType != 20 && contentType != 21 && contentType != 22 &&
            contentType != 23 && contentType != 25)
        {
            return false;
        }
        const uint8_t verMajor = data[1];
        const uint8_t verMinor = data[2];
        if (verMajor != 0xfe)
        {
            return false;
        }
        return (verMinor == 0xff || verMinor == 0xfd); // DTLS 1.0 or DTLS 1.2
    }

} // namespace mynet::handler::sniffing
