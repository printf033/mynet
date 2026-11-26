#pragma once

/**
 * @file kdf.hpp
 * @brief 代理协议通用密钥派生函数（HKDF-SHA1, HKDF-SHA256, RFC 8446 / 9000 HKDF-Expand-Label）
 */

#include "digest.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace mynet::kdf
{

    /**
     * @brief Shadowsocks SIP002 规范 HKDF-SHA1 子密钥派生 (Extract & Expand)
     *
     * PRK = HMAC-SHA1(salt, key)
     * subkey = HMAC-SHA1(PRK, info || 0x01) [|| HMAC-SHA1(PRK, subkey_prev || info || 0x02) ...]
     */
    inline bool hkdfSha1(std::span<const uint8_t> secret, std::span<const uint8_t> salt, std::span<const uint8_t> info,
                         std::span<uint8_t> out) noexcept
    {
        if (out.empty())
        {
            return true;
        }

        // 1. Extract: PRK = HMAC-SHA1(salt, secret)
        std::array<uint8_t, 20> prk{};
        if (!digest::hmacSha1(salt, secret, prk))
        {
            return false;
        }

        // 2. Expand: T(1) = HMAC-SHA1(PRK, info || 0x01), ...
        size_t generated = 0;
        uint8_t counter = 1;
        std::array<uint8_t, 20> prevBlock{};
        bool hasPrev = false;

        while (generated < out.size())
        {
            std::vector<uint8_t> stepData;
            if (hasPrev)
            {
                stepData.insert(stepData.end(), prevBlock.begin(), prevBlock.end());
            }
            stepData.insert(stepData.end(), info.begin(), info.end());
            stepData.push_back(counter);

            std::array<uint8_t, 20> block{};
            if (!digest::hmacSha1(prk, stepData, block))
            {
                return false;
            }

            const size_t toCopy = std::min<size_t>(out.size() - generated, 20);
            std::memcpy(out.data() + generated, block.data(), toCopy);
            generated += toCopy;
            prevBlock = block;
            hasPrev = true;
            ++counter;
        }

        return true;
    }

    /**
     * @brief RFC 5869 HKDF-SHA256 Extract 步骤（PRK = HMAC-SHA256(salt, ikm)）
     */
    inline std::optional<std::array<uint8_t, 32>> hkdfSha256Extract(std::span<const uint8_t> salt,
                                                                    std::span<const uint8_t> ikm) noexcept
    {
        std::array<uint8_t, 32> zeroSalt{};
        std::span<const uint8_t> actualSalt = salt.empty() ? std::span<const uint8_t>(zeroSalt) : salt;
        return digest::hmacSha256(actualSalt, ikm);
    }

    /**
     * @brief RFC 5869 HKDF-SHA256 Expand 步骤
     */
    inline bool hkdfSha256Expand(std::span<const uint8_t> prk, std::span<const uint8_t> info,
                                 std::span<uint8_t> out) noexcept
    {
        if (out.empty())
        {
            return true;
        }

        size_t generated = 0;
        uint8_t counter = 1;
        std::array<uint8_t, 32> prevBlock{};
        bool hasPrev = false;

        while (generated < out.size())
        {
            std::vector<uint8_t> stepData;
            if (hasPrev)
            {
                stepData.insert(stepData.end(), prevBlock.begin(), prevBlock.end());
            }
            stepData.insert(stepData.end(), info.begin(), info.end());
            stepData.push_back(counter);

            auto block = digest::hmacSha256(prk, stepData);
            if (!block.has_value())
            {
                return false;
            }

            const size_t toCopy = std::min<size_t>(out.size() - generated, 32);
            std::memcpy(out.data() + generated, block->data(), toCopy);
            generated += toCopy;
            prevBlock = *block;
            hasPrev = true;
            ++counter;
        }

        return true;
    }

    /**
     * @brief RFC 5869 HKDF-SHA256 Extract & Expand
     */
    inline bool hkdfSha256(std::span<const uint8_t> secret, std::span<const uint8_t> salt,
                           std::span<const uint8_t> info, std::span<uint8_t> out) noexcept
    {
        // 1. Extract: PRK = HMAC-SHA256(salt, secret)
        std::array<uint8_t, 32> zeroSalt{};
        std::span<const uint8_t> actualSalt = salt.empty() ? std::span<const uint8_t>(zeroSalt) : salt;

        auto prk = digest::hmacSha256(actualSalt, secret);
        if (!prk.has_value())
        {
            return false;
        }

        // 2. Expand
        return hkdfSha256Expand(*prk, info, out);
    }

    /**
     * @brief RFC 8446 / RFC 9000 HKDF-Expand-Label (基于 SHA-256)
     */
    inline bool hkdfExpandLabel(std::span<const uint8_t> secret, std::string_view label,
                                std::span<const uint8_t> context, size_t length, std::span<uint8_t> out) noexcept
    {
        if (out.size() != length)
        {
            return false;
        }

        std::vector<uint8_t> hkdfLabel;
        hkdfLabel.reserve(2 + 1 + 6 + label.size() + 1 + context.size());
        // 2B length
        hkdfLabel.push_back(static_cast<uint8_t>((length >> 8) & 0xFF));
        hkdfLabel.push_back(static_cast<uint8_t>(length & 0xFF));
        // 1B label length = 6 ("tls13 ") + label.size()
        hkdfLabel.push_back(static_cast<uint8_t>(6 + label.size()));
        hkdfLabel.insert(hkdfLabel.end(), {'t', 'l', 's', '1', '3', ' '});
        hkdfLabel.insert(hkdfLabel.end(), label.begin(), label.end());
        // 1B context length
        hkdfLabel.push_back(static_cast<uint8_t>(context.size()));
        if (!context.empty())
        {
            hkdfLabel.insert(hkdfLabel.end(), context.begin(), context.end());
        }

        return hkdfSha256Expand(secret, hkdfLabel, out);
    }

} // namespace mynet::kdf

namespace mynet::handler
{
    namespace kdf = mynet::kdf;
}
