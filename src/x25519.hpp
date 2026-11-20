#pragma once

/**
 * @file x25519.hpp
 * @brief X25519 密钥对生成、公钥派生与 ECDH 共享秘密协商（基于 OpenSSL EVP_PKEY）
 */

#include <array>
#include <cstdint>
#include <openssl/evp.h>
#include <optional>
#include <span>

namespace mynet::x25519
{

    /**
     * @brief X25519 密钥对结构体
     */
    struct X25519KeyPair
    {
        std::array<uint8_t, 32> privKey{};
        std::array<uint8_t, 32> pubKey{};
    };

    /**
     * @brief 生成随机 X25519 密钥对
     */
    inline std::optional<X25519KeyPair> generateKeyPair()
    {
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
        if (!pctx)
            return std::nullopt;

        EVP_PKEY *pkey = nullptr;
        if (EVP_PKEY_keygen_init(pctx) != 1 || EVP_PKEY_keygen(pctx, &pkey) != 1 || !pkey)
        {
            EVP_PKEY_CTX_free(pctx);
            return std::nullopt;
        }
        EVP_PKEY_CTX_free(pctx);

        X25519KeyPair kp;
        size_t privLen = 32;
        size_t pubLen = 32;
        if (EVP_PKEY_get_raw_private_key(pkey, kp.privKey.data(), &privLen) != 1 ||
            EVP_PKEY_get_raw_public_key(pkey, kp.pubKey.data(), &pubLen) != 1)
        {
            EVP_PKEY_free(pkey);
            return std::nullopt;
        }
        EVP_PKEY_free(pkey);
        return kp;
    }

    inline std::optional<X25519KeyPair> generateX25519KeyPair()
    {
        return generateKeyPair();
    }

    /**
     * @brief 由 32 字节 X25519 私钥派生对应公钥
     */
    inline std::optional<std::array<uint8_t, 32>> derivePublicKey(std::span<const uint8_t, 32> privKey)
    {
        EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, privKey.data(), 32);
        if (!pkey)
            return std::nullopt;

        std::array<uint8_t, 32> pubKey{};
        size_t len = 32;
        if (EVP_PKEY_get_raw_public_key(pkey, pubKey.data(), &len) != 1)
        {
            EVP_PKEY_free(pkey);
            return std::nullopt;
        }
        EVP_PKEY_free(pkey);
        return pubKey;
    }

    inline std::optional<std::array<uint8_t, 32>> deriveX25519PublicKey(std::span<const uint8_t, 32> privKey)
    {
        return derivePublicKey(privKey);
    }

    /**
     * @brief 计算 X25519 ECDH 共享秘密
     */
    inline std::optional<std::array<uint8_t, 32>> computeSharedSecret(std::span<const uint8_t, 32> privKey,
                                                                      std::span<const uint8_t, 32> peerPubKey)
    {
        EVP_PKEY *myPriv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, privKey.data(), 32);
        if (!myPriv)
            return std::nullopt;

        EVP_PKEY *peerPub = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peerPubKey.data(), 32);
        if (!peerPub)
        {
            EVP_PKEY_free(myPriv);
            return std::nullopt;
        }

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(myPriv, nullptr);
        if (!ctx)
        {
            EVP_PKEY_free(peerPub);
            EVP_PKEY_free(myPriv);
            return std::nullopt;
        }

        std::array<uint8_t, 32> secret{};
        size_t secretLen = 32;
        bool ok = false;
        if (EVP_PKEY_derive_init(ctx) == 1 && EVP_PKEY_derive_set_peer(ctx, peerPub) == 1 &&
            EVP_PKEY_derive(ctx, secret.data(), &secretLen) == 1 && secretLen == 32)
        {
            ok = true;
        }

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peerPub);
        EVP_PKEY_free(myPriv);
        return ok ? std::optional<std::array<uint8_t, 32>>(secret) : std::nullopt;
    }

    inline std::optional<std::array<uint8_t, 32>> computeX25519SharedSecret(std::span<const uint8_t, 32> privKey,
                                                                            std::span<const uint8_t, 32> peerPubKey)
    {
        return computeSharedSecret(privKey, peerPubKey);
    }

} // namespace mynet::x25519

namespace mynet
{
    namespace x25519 = mynet::x25519;
}

namespace mynet::handler
{
    namespace x25519 = mynet::x25519;
}
