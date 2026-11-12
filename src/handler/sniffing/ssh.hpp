#pragma once

#include "common.hpp"
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string_view>

namespace mynet::handler::sniffing
{

    /**
     * @brief 嗅探 SSH 协议版本握手
     */
    [[nodiscard]] inline std::optional<std::string_view> sniffSsh(std::span<const uint8_t> data) noexcept
    {
        if (data.size() < 8)
        {
            return std::nullopt;
        }
        static constexpr char kSshPrefix[] = "SSH-2.0-";
        if (std::memcmp(data.data(), kSshPrefix, 8) == 0)
        {
            return std::string_view(reinterpret_cast<const char *>(data.data()), data.size());
        }
        return std::nullopt;
    }

} // namespace mynet::handler::sniffing
