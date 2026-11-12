#pragma once

#include "common.hpp"
#include <cstdint>
#include <cstring>
#include <span>

namespace mynet::handler::sniffing
{

    /**
     * @brief 嗅探 BitTorrent 协议握手
     */
    [[nodiscard]] inline bool sniffBitTorrent(std::span<const uint8_t> data) noexcept
    {
        if (data.size() < 20)
        {
            return false;
        }
        if (data[0] != 19)
        {
            return false;
        }
        static constexpr char kBtHeader[] = "BitTorrent protocol";
        return std::memcmp(data.data() + 1, kBtHeader, 19) == 0;
    }

} // namespace mynet::handler::sniffing
