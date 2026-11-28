#pragma once

/**
 * @file cipher.hpp
 * @brief 对称加密与 AEAD 算法封装（Shadowsocks AEAD, AES-GCM, AES-ECB, ChaCha20-Poly1305）
 */

#include <cstdint>
#include <memory>
#include <openssl/evp.h>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace mynet::cipher
{

    /**
     * @brief 可复用有状态 AEAD 加密/解密上下文（单会话仅分配一次 EVP_CIPHER_CTX，零热路径上下文分配）
     */
    class AeadCipherContext
    {
    private:
        EVP_CIPHER_CTX *ctx_{nullptr};
        const EVP_CIPHER *cipher_{nullptr};
        size_t nonceLen_{12};
        bool encryptMode_{true};
        bool initialized_{false};

    public:
        AeadCipherContext() noexcept = default;

        ~AeadCipherContext() noexcept { reset(); }

        AeadCipherContext(const AeadCipherContext &) = delete;
        AeadCipherContext &operator=(const AeadCipherContext &) = delete;

        AeadCipherContext(AeadCipherContext &&other) noexcept
            : ctx_(other.ctx_),
              cipher_(other.cipher_),
              nonceLen_(other.nonceLen_),
              encryptMode_(other.encryptMode_),
              initialized_(other.initialized_)
        {
            other.ctx_ = nullptr;
            other.cipher_ = nullptr;
            other.initialized_ = false;
        }

        AeadCipherContext &operator=(AeadCipherContext &&other) noexcept
        {
            if (this != &other)
            {
                reset();
                ctx_ = other.ctx_;
                cipher_ = other.cipher_;
                nonceLen_ = other.nonceLen_;
                encryptMode_ = other.encryptMode_;
                initialized_ = other.initialized_;
                other.ctx_ = nullptr;
                other.cipher_ = nullptr;
                other.initialized_ = false;
            }
            return *this;
        }

        void reset() noexcept
        {
            if (ctx_ != nullptr)
            {
                EVP_CIPHER_CTX_free(ctx_);
                ctx_ = nullptr;
            }
            cipher_ = nullptr;
            nonceLen_ = 12;
            initialized_ = false;
        }

        [[nodiscard]] bool valid() const noexcept { return initialized_ && ctx_ != nullptr; }

        /**
         * @brief 初始化持久化密钥上下文（同一密钥后续 encrypt/decrypt 调用免去 EVP_CIPHER_CTX_new 与密钥扩展）
         */
        [[nodiscard]] bool init(const EVP_CIPHER *cipher, std::span<const uint8_t> key, bool encrypt,
                                size_t nonceLen = 12) noexcept
        {
            if (cipher == nullptr || key.empty() || nonceLen == 0)
            {
                return false;
            }
            if (ctx_ == nullptr)
            {
                ctx_ = EVP_CIPHER_CTX_new();
                if (ctx_ == nullptr)
                {
                    return false;
                }
            }
            else
            {
                EVP_CIPHER_CTX_reset(ctx_);
            }

            const int ok = encrypt ? EVP_EncryptInit_ex(ctx_, cipher, nullptr, nullptr, nullptr)
                                   : EVP_DecryptInit_ex(ctx_, cipher, nullptr, nullptr, nullptr);
            if (ok != 1)
            {
                return false;
            }
            if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(nonceLen), nullptr) != 1)
            {
                return false;
            }
            const int keyOk = encrypt ? EVP_EncryptInit_ex(ctx_, nullptr, nullptr, key.data(), nullptr)
                                      : EVP_DecryptInit_ex(ctx_, nullptr, nullptr, key.data(), nullptr);
            if (keyOk != 1)
            {
                return false;
            }

            cipher_ = cipher;
            nonceLen_ = nonceLen;
            encryptMode_ = encrypt;
            initialized_ = true;
            return true;
        }

        [[nodiscard]] bool encrypt(std::span<const uint8_t> nonce, std::span<const uint8_t> aad,
                                   std::span<const uint8_t> plaintext, std::vector<uint8_t> &ciphertext,
                                   std::span<uint8_t, 16> tag) noexcept
        {
            if (!initialized_ || !encryptMode_ || nonce.size() != nonceLen_)
            {
                return false;
            }
            if (EVP_EncryptInit_ex(ctx_, nullptr, nullptr, nullptr, nonce.data()) != 1)
            {
                return false;
            }
            int outLen = 0;
            if (!aad.empty() &&
                EVP_EncryptUpdate(ctx_, nullptr, &outLen, aad.data(), static_cast<int>(aad.size())) != 1)
            {
                return false;
            }
            ciphertext.resize(plaintext.size());
            outLen = 0;
            if (!plaintext.empty() && EVP_EncryptUpdate(ctx_, ciphertext.data(), &outLen, plaintext.data(),
                                                        static_cast<int>(plaintext.size())) != 1)
            {
                return false;
            }
            int finalLen = 0;
            if (EVP_EncryptFinal_ex(ctx_, ciphertext.data() + outLen, &finalLen) != 1)
            {
                return false;
            }
            ciphertext.resize(static_cast<size_t>(outLen + finalLen));
            return EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_AEAD_GET_TAG, 16, tag.data()) == 1;
        }

        [[nodiscard]] bool decrypt(std::span<const uint8_t> nonce, std::span<const uint8_t> aad,
                                   std::span<const uint8_t> ciphertext, std::span<const uint8_t, 16> tag,
                                   std::vector<uint8_t> &plaintext) noexcept
        {
            if (!initialized_ || encryptMode_ || nonce.size() != nonceLen_)
            {
                return false;
            }
            if (EVP_DecryptInit_ex(ctx_, nullptr, nullptr, nullptr, nonce.data()) != 1)
            {
                return false;
            }
            int outLen = 0;
            if (!aad.empty() &&
                EVP_DecryptUpdate(ctx_, nullptr, &outLen, aad.data(), static_cast<int>(aad.size())) != 1)
            {
                return false;
            }
            plaintext.resize(ciphertext.size());
            outLen = 0;
            if (!ciphertext.empty() && EVP_DecryptUpdate(ctx_, plaintext.data(), &outLen, ciphertext.data(),
                                                         static_cast<int>(ciphertext.size())) != 1)
            {
                return false;
            }
            if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_AEAD_SET_TAG, 16, const_cast<uint8_t *>(tag.data())) != 1)
            {
                return false;
            }
            int finalLen = 0;
            if (EVP_DecryptFinal_ex(ctx_, plaintext.data() + outLen, &finalLen) != 1)
            {
                return false;
            }
            plaintext.resize(static_cast<size_t>(outLen + finalLen));
            return true;
        }
    };

    /**
     * @brief 带 AAD (附加认证数据) 的 AEAD 加密块 (统一委托至 AeadCipherContext，消除重复 OpenSSL 样板)
     */
    inline bool aeadEncryptWithAad(const EVP_CIPHER *cipher, std::span<const uint8_t> key,
                                   std::span<const uint8_t> nonce, std::span<const uint8_t> aad,
                                   std::span<const uint8_t> plaintext, std::vector<uint8_t> &ciphertext,
                                   std::span<uint8_t, 16> tag) noexcept
    {
        AeadCipherContext ctx;
        return ctx.init(cipher, key, true, nonce.size()) && ctx.encrypt(nonce, aad, plaintext, ciphertext, tag);
    }

    /**
     * @brief 带 AAD 的 AEAD 解密块 (统一委托至 AeadCipherContext)
     */
    inline bool aeadDecryptWithAad(const EVP_CIPHER *cipher, std::span<const uint8_t> key,
                                   std::span<const uint8_t> nonce, std::span<const uint8_t> aad,
                                   std::span<const uint8_t> ciphertext, std::span<const uint8_t, 16> tag,
                                   std::vector<uint8_t> &plaintext) noexcept
    {
        AeadCipherContext ctx;
        return ctx.init(cipher, key, false, nonce.size()) && ctx.decrypt(nonce, aad, ciphertext, tag, plaintext);
    }

    inline bool aeadEncrypt(const EVP_CIPHER *cipher, std::span<const uint8_t> key, std::span<const uint8_t> nonce,
                            std::span<const uint8_t> plaintext, std::vector<uint8_t> &ciphertext,
                            std::span<uint8_t, 16> tag) noexcept
    {
        return aeadEncryptWithAad(cipher, key, nonce, {}, plaintext, ciphertext, tag);
    }

    inline bool aeadDecrypt(const EVP_CIPHER *cipher, std::span<const uint8_t> key, std::span<const uint8_t> nonce,
                            std::span<const uint8_t> ciphertext, std::span<const uint8_t, 16> tag,
                            std::vector<uint8_t> &plaintext) noexcept
    {
        return aeadDecryptWithAad(cipher, key, nonce, {}, ciphertext, tag, plaintext);
    }

    /**
     * @brief AES-128-ECB 单块加密（用于 QUIC 报头掩码生成 RFC 9000）
     */
    inline bool aes128EcbEncryptBlock(std::span<const uint8_t, 16> key, std::span<const uint8_t, 16> in,
                                      std::span<uint8_t, 16> out) noexcept
    {
        struct CtxDeleter
        {
            void operator()(EVP_CIPHER_CTX *c) const noexcept { EVP_CIPHER_CTX_free(c); }
        };
        std::unique_ptr<EVP_CIPHER_CTX, CtxDeleter> ctx(EVP_CIPHER_CTX_new());
        if (!ctx)
        {
            return false;
        }
        if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_ecb(), nullptr, key.data(), nullptr) != 1)
        {
            return false;
        }
        EVP_CIPHER_CTX_set_padding(ctx.get(), 0);
        int outLen = 0;
        if (EVP_EncryptUpdate(ctx.get(), out.data(), &outLen, in.data(), 16) != 1)
        {
            return false;
        }
        int finalLen = 0;
        return EVP_EncryptFinal_ex(ctx.get(), out.data() + outLen, &finalLen) == 1;
    }

    inline bool aes128GcmEncryptWithAad(std::span<const uint8_t, 16> key, std::span<const uint8_t, 12> nonce,
                                        std::span<const uint8_t> aad, std::span<const uint8_t> plaintext,
                                        std::vector<uint8_t> &ciphertext, std::span<uint8_t, 16> tag) noexcept
    {
        return aeadEncryptWithAad(EVP_aes_128_gcm(), key, nonce, aad, plaintext, ciphertext, tag);
    }

    inline bool aes128GcmDecryptWithAad(std::span<const uint8_t, 16> key, std::span<const uint8_t, 12> nonce,
                                        std::span<const uint8_t> aad, std::span<const uint8_t> ciphertext,
                                        std::span<const uint8_t, 16> tag, std::vector<uint8_t> &plaintext) noexcept
    {
        return aeadDecryptWithAad(EVP_aes_128_gcm(), key, nonce, aad, ciphertext, tag, plaintext);
    }

    /**
     * @brief 支持的 AEAD 算法枚举（统一各代理与传输层协议选型，消除重复字符串分支）
     */
    enum class AeadAlgorithm : uint8_t
    {
        AES_128_GCM = 0,
        AES_256_GCM = 1,
        CHACHA20_POLY1305 = 2,
        NONE = 3
    };

    [[nodiscard]] constexpr std::optional<AeadAlgorithm> parseAeadAlgorithm(std::string_view method) noexcept
    {
        if (method == "aes-128-gcm")
            return AeadAlgorithm::AES_128_GCM;
        if (method == "aes-256-gcm")
            return AeadAlgorithm::AES_256_GCM;
        if (method == "chacha20-poly1305" || method == "chacha20-ietf-poly1305")
            return AeadAlgorithm::CHACHA20_POLY1305;
        if (method == "none" || method == "plain")
            return AeadAlgorithm::NONE;
        return std::nullopt;
    }

    [[nodiscard]] constexpr size_t aeadKeySize(AeadAlgorithm alg) noexcept
    {
        switch (alg)
        {
        case AeadAlgorithm::AES_128_GCM:
            return 16;
        case AeadAlgorithm::AES_256_GCM:
        case AeadAlgorithm::CHACHA20_POLY1305:
            return 32;
        default:
            return 0;
        }
    }

    [[nodiscard]] inline const EVP_CIPHER *resolveEvpCipher(AeadAlgorithm alg) noexcept
    {
        switch (alg)
        {
        case AeadAlgorithm::AES_128_GCM:
            return EVP_aes_128_gcm();
        case AeadAlgorithm::AES_256_GCM:
            return EVP_aes_256_gcm();
        case AeadAlgorithm::CHACHA20_POLY1305:
            return EVP_chacha20_poly1305();
        default:
            return nullptr;
        }
    }

    inline void incrementLittleEndianNonce(std::span<uint8_t> nonce) noexcept
    {
        for (uint8_t &b : nonce)
        {
            if (++b != 0)
            {
                break;
            }
        }
    }

    inline void incrementBigEndianNonce(std::span<uint8_t> nonce) noexcept
    {
        for (size_t i = nonce.size(); i-- > 0;)
        {
            if (++nonce[i] != 0)
            {
                break;
            }
        }
    }

} // namespace mynet::cipher

