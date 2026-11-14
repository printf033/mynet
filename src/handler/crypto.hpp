#pragma once

/**
 * @file handler/crypto.hpp
 * @brief 代理协议通用加密、摘要与认证辅助工具（基于 OpenSSL 3.x）
 */

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mynet::handler::crypto
{

    /**
     * @brief 恒定时间内存比较（防御时序攻击）
     */
    inline bool constantTimeEqual(std::string_view a, std::string_view b) noexcept
    {
        if (a.size() != b.size())
        {
            return false;
        }
        return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
    }

    /**
     * @brief 恒定时间字节数组比较
     */
    inline bool constantTimeEqual(std::span<const uint8_t> a, std::span<const uint8_t> b) noexcept
    {
        if (a.size() != b.size())
        {
            return false;
        }
        return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
    }

    /**
     * @brief 二进制转小写十六进制字符串
     */
    inline std::string toHex(std::span<const uint8_t> data)
    {
        static constexpr char kHexDigits[] = "0123456789abcdef";
        std::string s;
        s.reserve(data.size() * 2);
        for (uint8_t b : data)
        {
            s.push_back(kHexDigits[(b >> 4) & 0x0F]);
            s.push_back(kHexDigits[b & 0x0F]);
        }
        return s;
    }

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
        return toHex(std::span<const uint8_t>(hash.data(), len));
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
        if (HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(), data.size(),
                 out.data(), &outLen) == nullptr ||
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
        if (HMAC(EVP_md5(), key.data(), static_cast<int>(key.size()), data.data(), data.size(),
                 out.data(), &outLen) == nullptr ||
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
        return HMAC(EVP_sha1(), key.data(), static_cast<int>(key.size()), data.data(), data.size(),
                    out.data(), &outLen) != nullptr &&
               outLen == 20;
    }

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
        if (!hmacSha1(salt, secret, prk))
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
            if (!hmacSha1(prk, stepData, block))
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
     * @brief 解析 36 字符标准 UUID 字符串 (如 "de04add9-5c1a-4b08-8e65-244e45cf5483") 为 16 字节数组
     */
    inline std::optional<std::array<uint8_t, 16>> parseUuid(std::string_view str) noexcept
    {
        std::array<uint8_t, 16> result{};
        size_t byteIdx = 0;
        int highNibble = -1;

        auto hexVal = [](char c) -> int
        {
            if (c >= '0' && c <= '9')
            {
                return c - '0';
            }
            if (c >= 'a' && c <= 'f')
            {
                return c - 'a' + 10;
            }
            if (c >= 'A' && c <= 'F')
            {
                return c - 'A' + 10;
            }
            return -1;
        };

        for (char c : str)
        {
            if (c == '-')
            {
                continue;
            }
            int val = hexVal(c);
            if (val < 0)
            {
                return std::nullopt;
            }
            if (highNibble < 0)
            {
                highNibble = val;
            }
            else
            {
                if (byteIdx >= 16)
                {
                    return std::nullopt;
                }
                result[byteIdx++] = static_cast<uint8_t>((highNibble << 4) | val);
                highNibble = -1;
            }
        }

        if (byteIdx != 16 || highNibble >= 0)
        {
            return std::nullopt;
        }
        return result;
    }

    /**
     * @brief 将 16 字节数组转换为标准 UUID 字符串
     */
    inline std::string uuidToString(const std::array<uint8_t, 16> &uuid)
    {
        static constexpr char kHex[] = "0123456789abcdef";
        std::string s;
        s.reserve(36);
        for (size_t i = 0; i < 16; ++i)
        {
            if (i == 4 || i == 6 || i == 8 || i == 10)
            {
                s.push_back('-');
            }
            s.push_back(kHex[(uuid[i] >> 4) & 0x0F]);
            s.push_back(kHex[uuid[i] & 0x0F]);
        }
        return s;
    }

    /**
     * @brief 简易 Base64 解码器（用于 HTTP Basic 认证）
     */
    inline bool base64Decode(std::string_view in, std::string &out)
    {
        static const auto kDecodeTable = []()
        {
            std::array<int, 256> table{};
            table.fill(-1);
            for (int i = 0; i < 26; ++i)
            {
                table[static_cast<uint8_t>('A' + i)] = i;
                table[static_cast<uint8_t>('a' + i)] = i + 26;
            }
            for (int i = 0; i < 10; ++i)
            {
                table[static_cast<uint8_t>('0' + i)] = i + 52;
            }
            table[static_cast<uint8_t>('+')] = 62;
            table[static_cast<uint8_t>('/')] = 63;
            return table;
        }();

        out.clear();
        uint32_t val = 0;
        int valb = -8;
        for (char c : in)
        {
            if (c == '=' || c == '\r' || c == '\n' || c == ' ')
            {
                continue;
            }
            int d = kDecodeTable[static_cast<uint8_t>(c)];
            if (d < 0)
            {
                return false;
            }
            val = (val << 6) | d;
            valb += 6;
            if (valb >= 0)
            {
                out.push_back(static_cast<char>((val >> valb) & 0xFF));
                valb -= 8;
            }
        }
        return true;
    }

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
     * @brief RFC 5869 HKDF-SHA256 Extract 步骤（PRK = HMAC-SHA256(salt, ikm)）
     */
    inline std::optional<std::array<uint8_t, 32>> hkdfSha256Extract(std::span<const uint8_t> salt,
                                                                    std::span<const uint8_t> ikm) noexcept
    {
        std::array<uint8_t, 32> zeroSalt{};
        std::span<const uint8_t> actualSalt = salt.empty() ? std::span<const uint8_t>(zeroSalt) : salt;
        return hmacSha256(actualSalt, ikm);
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

            auto block = hmacSha256(prk, stepData);
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

        auto prk = hmacSha256(actualSalt, secret);
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
                                std::span<const uint8_t> context, size_t length,
                                std::span<uint8_t> out) noexcept
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

    /**
     * @brief AES-128-ECB 单块加密（用于 QUIC 报头掩码生成 RFC 9000）
     */
    inline bool aes128EcbEncryptBlock(std::span<const uint8_t, 16> key,
                                      std::span<const uint8_t, 16> in,
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
    inline bool aes128GcmEncryptWithAad(std::span<const uint8_t, 16> key,
                                        std::span<const uint8_t, 12> nonce,
                                        std::span<const uint8_t> aad,
                                        std::span<const uint8_t> plaintext,
                                        std::vector<uint8_t> &ciphertext,
                                        std::span<uint8_t, 16> tag) noexcept
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
    inline bool aes128GcmDecryptWithAad(std::span<const uint8_t, 16> key,
                                        std::span<const uint8_t, 12> nonce,
                                        std::span<const uint8_t> aad,
                                        std::span<const uint8_t> ciphertext,
                                        std::span<const uint8_t, 16> tag,
                                        std::vector<uint8_t> &plaintext) noexcept
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

} // namespace mynet::handler::crypto
