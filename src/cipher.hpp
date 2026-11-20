#pragma once

/**
 * @file cipher.hpp
 * @brief 对称加密与 AEAD 算法封装（Shadowsocks AEAD, AES-GCM, AES-ECB, ChaCha20-Poly1305）
 */

#include <cstdint>
#include <openssl/evp.h>
#include <span>
#include <vector>

namespace mynet::cipher
{

    /**
     * @brief Shadowsocks AEAD 加密块
     */
    inline bool aeadEncrypt(const EVP_CIPHER *cipher, std::span<const uint8_t> key, std::span<const uint8_t> nonce,
                            std::span<const uint8_t> plaintext, std::vector<uint8_t> &ciphertext,
                            std::span<uint8_t, 16> tag)
    {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
        {
            return false;
        }

        bool ok = false;
        do
        {
            if (EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1)
            {
                break;
            }
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1)
            {
                break;
            }
            if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1)
            {
                break;
            }

            int outLen = 0;
            ciphertext.resize(plaintext.size());
            if (EVP_EncryptUpdate(ctx, ciphertext.data(), &outLen, plaintext.data(),
                                  static_cast<int>(plaintext.size())) != 1)
            {
                break;
            }
            int finalLen = 0;
            if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + outLen, &finalLen) != 1)
            {
                break;
            }
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag.data()) != 1)
            {
                break;
            }
            ok = true;
        } while (false);

        EVP_CIPHER_CTX_free(ctx);
        return ok;
    }

    /**
     * @brief Shadowsocks AEAD 解密块
     */
    inline bool aeadDecrypt(const EVP_CIPHER *cipher, std::span<const uint8_t> key, std::span<const uint8_t> nonce,
                            std::span<const uint8_t> ciphertext, std::span<const uint8_t, 16> tag,
                            std::vector<uint8_t> &plaintext)
    {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
        {
            return false;
        }

        bool ok = false;
        do
        {
            if (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1)
            {
                break;
            }
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1)
            {
                break;
            }
            if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1)
            {
                break;
            }

            int outLen = 0;
            plaintext.resize(ciphertext.size());
            if (EVP_DecryptUpdate(ctx, plaintext.data(), &outLen, ciphertext.data(),
                                  static_cast<int>(ciphertext.size())) != 1)
            {
                break;
            }
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, const_cast<uint8_t *>(tag.data())) != 1)
            {
                break;
            }
            int finalLen = 0;
            if (EVP_DecryptFinal_ex(ctx, plaintext.data() + outLen, &finalLen) != 1)
            {
                break;
            }
            ok = true;
        } while (false);

        EVP_CIPHER_CTX_free(ctx);
        return ok;
    }

    /**
     * @brief 带 AAD (附加认证数据) 的 AEAD 加密块 (如 AES-256-GCM / ChaCha20-Poly1305)
     */
    inline bool aeadEncryptWithAad(const EVP_CIPHER *cipher, std::span<const uint8_t> key,
                                   std::span<const uint8_t> nonce, std::span<const uint8_t> aad,
                                   std::span<const uint8_t> plaintext, std::vector<uint8_t> &ciphertext,
                                   std::span<uint8_t, 16> tag)
    {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
            return false;

        bool ok = false;
        do
        {
            if (EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1)
                break;
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1)
                break;
            if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1)
                break;

            int outLen = 0;
            if (!aad.empty())
            {
                if (EVP_EncryptUpdate(ctx, nullptr, &outLen, aad.data(), static_cast<int>(aad.size())) != 1)
                    break;
            }

            ciphertext.resize(plaintext.size());
            if (EVP_EncryptUpdate(ctx, ciphertext.data(), &outLen, plaintext.data(),
                                  static_cast<int>(plaintext.size())) != 1)
                break;
            int finalLen = 0;
            if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + outLen, &finalLen) != 1)
                break;
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag.data()) != 1)
                break;
            ok = true;
        } while (false);

        EVP_CIPHER_CTX_free(ctx);
        return ok;
    }

    /**
     * @brief 带 AAD 的 AEAD 解密块
     */
    inline bool aeadDecryptWithAad(const EVP_CIPHER *cipher, std::span<const uint8_t> key,
                                   std::span<const uint8_t> nonce, std::span<const uint8_t> aad,
                                   std::span<const uint8_t> ciphertext, std::span<const uint8_t, 16> tag,
                                   std::vector<uint8_t> &plaintext)
    {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
            return false;

        bool ok = false;
        do
        {
            if (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1)
                break;
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1)
                break;
            if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1)
                break;

            int outLen = 0;
            if (!aad.empty())
            {
                if (EVP_DecryptUpdate(ctx, nullptr, &outLen, aad.data(), static_cast<int>(aad.size())) != 1)
                    break;
            }

            plaintext.resize(ciphertext.size());
            if (EVP_DecryptUpdate(ctx, plaintext.data(), &outLen, ciphertext.data(),
                                  static_cast<int>(ciphertext.size())) != 1)
                break;
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, const_cast<uint8_t *>(tag.data())) != 1)
                break;
            int finalLen = 0;
            if (EVP_DecryptFinal_ex(ctx, plaintext.data() + outLen, &finalLen) != 1)
                break;
            ok = true;
        } while (false);

        EVP_CIPHER_CTX_free(ctx);
        return ok;
    }

    /**
     * @brief AES-128-ECB 单块加密（用于 QUIC 报头掩码生成 RFC 9000）
     */
    inline bool aes128EcbEncryptBlock(std::span<const uint8_t, 16> key, std::span<const uint8_t, 16> in,
                                      std::span<uint8_t, 16> out) noexcept
    {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
        {
            return false;
        }

        bool ok = false;
        do
        {
            if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key.data(), nullptr) != 1)
            {
                break;
            }
            EVP_CIPHER_CTX_set_padding(ctx, 0);

            int outLen = 0;
            if (EVP_EncryptUpdate(ctx, out.data(), &outLen, in.data(), 16) != 1)
            {
                break;
            }
            int finalLen = 0;
            if (EVP_EncryptFinal_ex(ctx, out.data() + outLen, &finalLen) != 1)
            {
                break;
            }
            ok = true;
        } while (false);

        EVP_CIPHER_CTX_free(ctx);
        return ok;
    }

    /**
     * @brief AES-128-GCM 加密（支持 AAD 关联数据，用于 QUIC 报文封装与测试）
     */
    inline bool aes128GcmEncryptWithAad(std::span<const uint8_t, 16> key, std::span<const uint8_t, 12> nonce,
                                        std::span<const uint8_t> aad, std::span<const uint8_t> plaintext,
                                        std::vector<uint8_t> &ciphertext, std::span<uint8_t, 16> tag) noexcept
    {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
        {
            return false;
        }

        bool ok = false;
        do
        {
            if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1)
            {
                break;
            }
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1)
            {
                break;
            }
            if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1)
            {
                break;
            }

            int outLen = 0;
            if (!aad.empty())
            {
                if (EVP_EncryptUpdate(ctx, nullptr, &outLen, aad.data(), static_cast<int>(aad.size())) != 1)
                {
                    break;
                }
            }

            ciphertext.resize(plaintext.size());
            if (!plaintext.empty())
            {
                if (EVP_EncryptUpdate(ctx, ciphertext.data(), &outLen, plaintext.data(),
                                      static_cast<int>(plaintext.size())) != 1)
                {
                    break;
                }
            }
            int finalLen = 0;
            if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + outLen, &finalLen) != 1)
            {
                break;
            }
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag.data()) != 1)
            {
                break;
            }
            ok = true;
        } while (false);

        EVP_CIPHER_CTX_free(ctx);
        return ok;
    }

    /**
     * @brief AES-128-GCM 解密（带 AAD 关联数据校验，用于 QUIC Initial RFC 9000 报文解密）
     */
    inline bool aes128GcmDecryptWithAad(std::span<const uint8_t, 16> key, std::span<const uint8_t, 12> nonce,
                                        std::span<const uint8_t> aad, std::span<const uint8_t> ciphertext,
                                        std::span<const uint8_t, 16> tag, std::vector<uint8_t> &plaintext) noexcept
    {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
        {
            return false;
        }

        bool ok = false;
        do
        {
            if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1)
            {
                break;
            }
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1)
            {
                break;
            }
            if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1)
            {
                break;
            }

            int outLen = 0;
            if (!aad.empty())
            {
                if (EVP_DecryptUpdate(ctx, nullptr, &outLen, aad.data(), static_cast<int>(aad.size())) != 1)
                {
                    break;
                }
            }

            plaintext.resize(ciphertext.size());
            if (!ciphertext.empty())
            {
                if (EVP_DecryptUpdate(ctx, plaintext.data(), &outLen, ciphertext.data(),
                                      static_cast<int>(ciphertext.size())) != 1)
                {
                    break;
                }
            }
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, const_cast<uint8_t *>(tag.data())) != 1)
            {
                break;
            }
            int finalLen = 0;
            if (EVP_DecryptFinal_ex(ctx, plaintext.data() + outLen, &finalLen) != 1)
            {
                break;
            }
            plaintext.resize(outLen + finalLen);
            ok = true;
        } while (false);

        EVP_CIPHER_CTX_free(ctx);
        return ok;
    }

} // namespace mynet::cipher

namespace mynet
{
    namespace cipher = mynet::cipher;
}

namespace mynet::handler
{
    namespace cipher = mynet::cipher;
}
