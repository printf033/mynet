#pragma once

#include "../crypto.hpp"
#include "common.hpp"
#include "tls.hpp"
#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace mynet::handler::sniffing
{

    namespace detail
    {
        // QUIC RFC 9000 Initial Salt (v1)
        inline constexpr uint8_t kQuicSaltV1[20] = {
            0x38, 0x7b, 0x23, 0x23, 0x9f, 0x61, 0xca, 0x73, 0x01, 0x21,
            0x2c, 0x29, 0x60, 0x53, 0x98, 0x8d, 0x85, 0x29, 0xae, 0x4d};

        // QUIC RFC 9369 Initial Salt (v2)
        inline constexpr uint8_t kQuicSaltV2[20] = {
            0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
            0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9};

        // draft-29 Salt
        inline constexpr uint8_t kQuicSaltDraft29[20] = {
            0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
            0x86, 0xf1, 0x9c, 0x3f, 0xe1, 0x44, 0x75, 0xe8, 0x35, 0x44};

        /**
         * @brief 读取 QUIC 变长整数 (RFC 9000 Section 16 Variable-Length Integer Encoding)
         *
         * @param data 字节流切片
         * @return std::pair<uint64_t, size_t> 数值与消费的字节数（0 表示错误）
         */
        [[nodiscard]] inline std::pair<uint64_t, size_t> readUvarint(std::span<const uint8_t> data) noexcept
        {
            if (data.empty())
            {
                return {0, 0};
            }
            const uint8_t first = data[0];
            const size_t len = 1ULL << ((first & 0xC0) >> 6);
            if (data.size() < len)
            {
                return {0, 0};
            }
            uint64_t val = first & 0x3F;
            for (size_t i = 1; i < len; ++i)
            {
                val = (val << 8) | data[i];
            }
            return {val, len};
        }

        inline void appendUvarint(std::vector<uint8_t> &buf, uint64_t val)
        {
            if (val <= 63)
            {
                buf.push_back(static_cast<uint8_t>(val));
            }
            else if (val <= 16383)
            {
                buf.push_back(static_cast<uint8_t>(0x40 | ((val >> 8) & 0x3F)));
                buf.push_back(static_cast<uint8_t>(val & 0xFF));
            }
            else if (val <= 1073741823)
            {
                buf.push_back(static_cast<uint8_t>(0x80 | ((val >> 24) & 0x3F)));
                buf.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
                buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
                buf.push_back(static_cast<uint8_t>(val & 0xFF));
            }
            else
            {
                buf.push_back(static_cast<uint8_t>(0xC0 | ((val >> 56) & 0x3F)));
                for (int i = 6; i >= 0; --i)
                {
                    buf.push_back(static_cast<uint8_t>((val >> (i * 8)) & 0xFF));
                }
            }
        }
    } // namespace detail

    /**
     * @brief 嗅探 QUIC Initial 报文中的 SNI (RFC 9000 Initial 解密)
     *
     * @param data 报文字节切片
     * @return std::optional<std::string> 成功提取出的 SNI 域名
     */
    [[nodiscard]] inline std::optional<std::string> sniffQuicSni(std::span<const uint8_t> data) noexcept
    {
        if (data.size() < 7)
        {
            return std::nullopt;
        }

        const uint8_t firstByte = data[0];
        // Header Form: 必须为 Long Header (bit 7 = 1)
        if ((firstByte & 0x80) == 0)
        {
            return std::nullopt;
        }

        // 版本号 (4B BE)
        const uint32_t version = (static_cast<uint32_t>(data[1]) << 24) |
                                 (static_cast<uint32_t>(data[2]) << 16) |
                                 (static_cast<uint32_t>(data[3]) << 8) | static_cast<uint32_t>(data[4]);

        // Packet Type (bits 4..5)
        const uint8_t packetType = (firstByte & 0x30) >> 4;
        // RFC 9000 v1 & draft-29: Initial = 0x00
        // RFC 9369 v2: Initial = 0x01
        if (version == 0x6b3343cf)
        {
            if (packetType != 0x01)
            {
                return std::nullopt;
            }
        }
        else
        {
            if (packetType != 0x00)
            {
                return std::nullopt;
            }
        }

        // Destination Connection ID (DCID)
        const uint8_t dcidLen = data[5];
        if (dcidLen == 0 || dcidLen > 20 || data.size() < static_cast<size_t>(6 + dcidLen + 1))
        {
            return std::nullopt;
        }
        auto dcid = data.subspan(6, dcidLen);
        size_t offset = 6 + dcidLen;

        // Source Connection ID (SCID)
        const uint8_t scidLen = data[offset++];
        if (offset + scidLen > data.size())
        {
            return std::nullopt;
        }
        offset += scidLen;

        // Token Length (uvarint) & Token
        auto [tokenLen, nToken] = detail::readUvarint(data.subspan(offset));
        if (nToken == 0 || offset + nToken + tokenLen > data.size())
        {
            return std::nullopt;
        }
        offset += nToken + tokenLen;

        // Packet Length (uvarint)
        auto [packetLen, nLen] = detail::readUvarint(data.subspan(offset));
        if (nLen == 0)
        {
            return std::nullopt;
        }
        offset += nLen;
        const size_t hdrLen = offset;

        if (hdrLen + packetLen > data.size() || packetLen < 20)
        {
            return std::nullopt;
        }

        // 采样样本：从 hdrLen + 4 开始提取 16 字节
        if (hdrLen + 4 + 16 > hdrLen + packetLen)
        {
            return std::nullopt;
        }
        std::array<uint8_t, 16> sample{};
        std::memcpy(sample.data(), data.data() + hdrLen + 4, 16);

        // 选择 Salt 与 HKDF 标签
        std::span<const uint8_t> salt = detail::kQuicSaltV1;
        std::string_view labelHp = "quic hp";
        std::string_view labelKey = "quic key";
        std::string_view labelIv = "quic iv";

        if (version == 0x6b3343cf) // v2
        {
            salt = detail::kQuicSaltV2;
            labelHp = "quicv2 hp";
            labelKey = "quicv2 key";
            labelIv = "quicv2 iv";
        }
        else if (version == 0xff00001d) // draft-29
        {
            salt = detail::kQuicSaltDraft29;
        }

        // HKDF 密钥派生 (RFC 9000 Initial secrets)
        auto initialSecret = crypto::hkdfSha256Extract(salt, dcid);
        if (!initialSecret.has_value())
        {
            return std::nullopt;
        }

        std::array<uint8_t, 32> clientInitialSecret{};
        if (!crypto::hkdfExpandLabel(*initialSecret, "client in", {}, 32, clientInitialSecret))
        {
            return std::nullopt;
        }

        std::array<uint8_t, 16> hpKey{};
        std::array<uint8_t, 16> key{};
        std::array<uint8_t, 12> iv{};

        if (!crypto::hkdfExpandLabel(clientInitialSecret, labelHp, {}, 16, hpKey) ||
            !crypto::hkdfExpandLabel(clientInitialSecret, labelKey, {}, 16, key) ||
            !crypto::hkdfExpandLabel(clientInitialSecret, labelIv, {}, 12, iv))
        {
            return std::nullopt;
        }

        // 计算报头掩码
        std::array<uint8_t, 16> mask{};
        if (!crypto::aes128EcbEncryptBlock(hpKey, sample, mask))
        {
            return std::nullopt;
        }

        // 复制待解密报文并解除报头掩码
        std::vector<uint8_t> pkt(data.data(), data.data() + hdrLen + packetLen);
        pkt[0] ^= (mask[0] & 0x0F);
        const size_t pnLen = (pkt[0] & 0x03) + 1;

        if (hdrLen + pnLen + 16 > hdrLen + packetLen)
        {
            return std::nullopt;
        }

        for (size_t i = 0; i < pnLen; ++i)
        {
            pkt[hdrLen + i] ^= mask[1 + i];
        }

        // 提取 Packet Number (1..4 字节)
        uint64_t pn = 0;
        for (size_t i = 0; i < pnLen; ++i)
        {
            pn = (pn << 8) | pkt[hdrLen + i];
        }

        const size_t extHdrLen = hdrLen + pnLen;

        // 构造 Nonce: IV 异或 Packet Number
        std::array<uint8_t, 12> nonce = iv;
        for (size_t i = 0; i < 8; ++i)
        {
            nonce[4 + i] ^= static_cast<uint8_t>((pn >> ((7 - i) * 8)) & 0xFF);
        }

        // AEAD 解密
        std::span<const uint8_t> aad(pkt.data(), extHdrLen);
        const size_t cipherAndTagLen = (hdrLen + packetLen) - extHdrLen;
        if (cipherAndTagLen < 16)
        {
            return std::nullopt;
        }
        const size_t cipherLen = cipherAndTagLen - 16;
        std::span<const uint8_t> ciphertext(pkt.data() + extHdrLen, cipherLen);
        std::array<uint8_t, 16> tag{};
        std::memcpy(tag.data(), pkt.data() + extHdrLen + cipherLen, 16);

        std::vector<uint8_t> plaintext;
        if (!crypto::aes128GcmDecryptWithAad(key, nonce, aad, ciphertext, tag, plaintext))
        {
            return std::nullopt;
        }

        // 解析明文中的 CRYPTO 帧 (Type 0x06)
        size_t pOffset = 0;
        while (pOffset < plaintext.size())
        {
            const uint8_t frameType = plaintext[pOffset++];
            if (frameType == 0x00) // PADDING
            {
                continue;
            }
            if (frameType == 0x01) // PING
            {
                continue;
            }
            if (frameType == 0x02 || frameType == 0x03) // ACK
            {
                auto [largestAck, n1] = detail::readUvarint(std::span(plaintext).subspan(pOffset));
                pOffset += n1;
                auto [ackDelay, n2] = detail::readUvarint(std::span(plaintext).subspan(pOffset));
                pOffset += n2;
                auto [rangeCount, n3] = detail::readUvarint(std::span(plaintext).subspan(pOffset));
                pOffset += n3;
                auto [firstRange, n4] = detail::readUvarint(std::span(plaintext).subspan(pOffset));
                pOffset += n4;
                for (uint64_t r = 0; r < rangeCount && pOffset < plaintext.size(); ++r)
                {
                    auto [gap, ng] = detail::readUvarint(std::span(plaintext).subspan(pOffset));
                    pOffset += ng;
                    auto [len, nl] = detail::readUvarint(std::span(plaintext).subspan(pOffset));
                    pOffset += nl;
                }
                if (frameType == 0x03)
                {
                    auto [ect0, nE0] = detail::readUvarint(std::span(plaintext).subspan(pOffset));
                    pOffset += nE0;
                    auto [ect1, nE1] = detail::readUvarint(std::span(plaintext).subspan(pOffset));
                    pOffset += nE1;
                    auto [ecnce, nEc] = detail::readUvarint(std::span(plaintext).subspan(pOffset));
                    pOffset += nEc;
                }
                continue;
            }
            if (frameType == 0x06) // CRYPTO 帧
            {
                auto [crOffset, nCrOff] = detail::readUvarint(std::span(plaintext).subspan(pOffset));
                pOffset += nCrOff;
                auto [crLen, nCrLen] = detail::readUvarint(std::span(plaintext).subspan(pOffset));
                pOffset += nCrLen;
                if (pOffset + crLen > plaintext.size())
                {
                    break;
                }

                std::span<const uint8_t> cryptoPayload(plaintext.data() + pOffset, crLen);
                if (auto sni = sniffTlsSni(cryptoPayload); sni.has_value())
                {
                    return std::string(*sni);
                }
                pOffset += crLen;
                continue;
            }
            if (frameType == 0x1C || frameType == 0x1D) // CONNECTION_CLOSE
            {
                break;
            }
            break;
        }

        return std::nullopt;
    }

} // namespace mynet::handler::sniffing
