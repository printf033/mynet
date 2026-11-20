#pragma once

/**
 * @file digest.hpp
 * @brief 代理协议通用哈希散列与消息认证码 (MAC) 算法封装（基于 OpenSSL EVP）
 */

#include "encoding.hpp"
#include <array>
#include <cstdint>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mynet::digest
{

    /**
     * @brief 计算 SHA-224 摘要并输出 56 字符小写十六进制（Trojan 密码认证规范）
     */
    inline std::string sha224Hex(std::string_view input)
    {
        std::array<uint8_t, 28> hash{};
        unsigned int len = 0;
        if (EVP_Digest(input.data(), input.size(), hash.data(), &len, EVP_sha224(), nullptr) != 1)
        {
            return {};
        }
        return encoding::toHex(std::span<const uint8_t>(hash.data(), len));
    }

    /**
     * @brief 计算 SHA-1 摘要 (20 字节，WebSocket 握手规范)
     */
    inline std::optional<std::array<uint8_t, 20>> sha1(std::span<const uint8_t> input) noexcept
    {
        std::array<uint8_t, 20> hash{};
        unsigned int len = 0;
        if (EVP_Digest(input.data(), input.size(), hash.data(), &len, EVP_sha1(), nullptr) != 1 || len != 20)
        {
            return std::nullopt;
        }
        return hash;
    }

    /**
     * @brief 计算 SHA-256 摘要
     */
    inline std::optional<std::array<uint8_t, 32>> sha256(std::span<const uint8_t> input) noexcept
    {
        std::array<uint8_t, 32> hash{};
        unsigned int len = 0;
        if (EVP_Digest(input.data(), input.size(), hash.data(), &len, EVP_sha256(), nullptr) != 1 || len != 32)
        {
            return std::nullopt;
        }
        return hash;
    }

    /**
     * @brief 计算 HMAC-SHA256 认证码（ShadowTLS 规范）
     */
    inline std::optional<std::array<uint8_t, 32>> hmacSha256(std::span<const uint8_t> key,
                                                             std::span<const uint8_t> data) noexcept
    {
        std::array<uint8_t, 32> out{};
        unsigned int outLen = 0;
        if (HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(), data.size(), out.data(),
                 &outLen) == nullptr ||
            outLen != 32)
        {
            return std::nullopt;
        }
        return out;
    }

    /**
     * @brief 计算 MD5 摘要 (16 字节，VMess / Shadowsocks legacy 兼容)
     */
    inline std::optional<std::array<uint8_t, 16>> md5(std::span<const uint8_t> input) noexcept
    {
        std::array<uint8_t, 16> hash{};
        unsigned int len = 0;
        if (EVP_Digest(input.data(), input.size(), hash.data(), &len, EVP_md5(), nullptr) != 1 || len != 16)
        {
            return std::nullopt;
        }
        return hash;
    }

    /**
     * @brief 计算 HMAC-MD5 (16 字节，VMess 头部认证)
     */
    inline std::optional<std::array<uint8_t, 16>> hmacMd5(std::span<const uint8_t> key,
                                                          std::span<const uint8_t> data) noexcept
    {
        std::array<uint8_t, 16> out{};
        unsigned int outLen = 0;
        if (HMAC(EVP_md5(), key.data(), static_cast<int>(key.size()), data.data(), data.size(), out.data(), &outLen) ==
                nullptr ||
            outLen != 16)
        {
            return std::nullopt;
        }
        return out;
    }

    /**
     * @brief HMAC-SHA1 基础实现
     */
    inline bool hmacSha1(std::span<const uint8_t> key, std::span<const uint8_t> data,
                         std::span<uint8_t, 20> out) noexcept
    {
        unsigned int outLen = 0;
        return HMAC(EVP_sha1(), key.data(), static_cast<int>(key.size()), data.data(), data.size(), out.data(),
                    &outLen) != nullptr &&
               outLen == 20;
    }

} // namespace mynet::digest

namespace mynet
{
    namespace digest = mynet::digest;
}

namespace mynet::handler
{
    namespace digest = mynet::digest;
}
