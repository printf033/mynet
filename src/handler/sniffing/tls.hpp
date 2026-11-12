#pragma once

#include "common.hpp"
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace mynet::handler::sniffing
{

    /**
     * @brief 嗅探 TLS ClientHello 中的 Server Name Indication (SNI)
     *
     * 支持两种输入：
     * 1. 完整的 TLS 记录层报文（0x16 0x03 0x01..0x03 开头）；
     * 2. QUIC CRYPTO 帧解密出来的原始 TLS Handshake 报文（0x01 ClientHello 开头）。
     *
     * 全程基于内存切片，零堆内存分配。
     */
    [[nodiscard]] inline std::optional<std::string_view> sniffTlsSni(std::span<const uint8_t> data) noexcept
    {
        if (data.size() < 9)
        {
            return std::nullopt;
        }

        const uint8_t *handshake = nullptr;
        size_t handshakeLen = 0;

        // 1. 区分 TLS 记录层报文 vs 裸 Handshake ClientHello
        if (data[0] == 0x16) // ContentType == Handshake
        {
            if (data.size() < 5)
            {
                return std::nullopt;
            }
            // 校验 TLS 记录层协议版本 (SSL 3.0 / TLS 1.0..1.3 为 0x03, 0x00..0x03)
            if (data[1] != 0x03 || data[2] > 0x03)
            {
                return std::nullopt;
            }
            const size_t recordLen = (static_cast<size_t>(data[3]) << 8) | data[4];
            if (data.size() < 5 + recordLen)
            {
                return std::nullopt;
            }
            handshake = data.data() + 5;
            handshakeLen = recordLen;
        }
        else if (data[0] == 0x01)
        {
            // 裸 TLS Handshake ClientHello（如 QUIC CRYPTO 帧载荷）
            handshake = data.data();
            handshakeLen = data.size();
        }
        else
        {
            return std::nullopt;
        }

        // 2. 校验 Handshake 头部: [Type=1 (1B)][Length (3B)][Version (2B)][Random (32B)]
        if (handshakeLen < 4 + 2 + 32 + 1)
        {
            return std::nullopt;
        }
        if (handshake[0] != 0x01)
        {
            return std::nullopt; // 非 ClientHello
        }

        const size_t hsMsgLen = (static_cast<size_t>(handshake[1]) << 16) |
                                (static_cast<size_t>(handshake[2]) << 8) | handshake[3];
        if (handshakeLen < 4 + hsMsgLen)
        {
            return std::nullopt;
        }

        size_t offset = 4 + 2 + 32; // 跳过 Type(1) + Len(3) + Ver(2) + Random(32)

        // Session ID
        if (offset >= handshakeLen)
        {
            return std::nullopt;
        }
        const uint8_t sessionIdLen = handshake[offset++];
        offset += sessionIdLen;
        if (offset + 2 > handshakeLen)
        {
            return std::nullopt;
        }

        // Cipher Suites
        const uint16_t cipherLen = (static_cast<uint16_t>(handshake[offset]) << 8) | handshake[offset + 1];
        offset += 2 + cipherLen;
        if (offset + 1 > handshakeLen)
        {
            return std::nullopt;
        }

        // Compression Methods
        const uint8_t compLen = handshake[offset++];
        offset += compLen;
        if (offset + 2 > handshakeLen)
        {
            return std::nullopt;
        }

        // Extensions Block
        const uint16_t extTotalLen = (static_cast<uint16_t>(handshake[offset]) << 8) | handshake[offset + 1];
        offset += 2;
        const size_t extEnd = offset + extTotalLen;
        if (extEnd > handshakeLen)
        {
            return std::nullopt;
        }

        // 遍历 Extensions
        while (offset + 4 <= extEnd)
        {
            const uint16_t extType = (static_cast<uint16_t>(handshake[offset]) << 8) | handshake[offset + 1];
            const uint16_t extLen = (static_cast<uint16_t>(handshake[offset + 2]) << 8) | handshake[offset + 3];
            offset += 4;
            if (offset + extLen > extEnd)
            {
                break;
            }

            if (extType == 0x0000) // Server Name Indication (SNI)
            {
                if (extLen >= 5)
                {
                    // [ServerNameListLen (2B)][ServerNameType (1B)][NameLen (2B)][Name Data]
                    const uint8_t nameType = handshake[offset + 2];
                    const uint16_t nameLen =
                        (static_cast<uint16_t>(handshake[offset + 3]) << 8) | handshake[offset + 4];
                    if (nameType == 0x00 && (offset + 5 + nameLen <= extEnd))
                    {
                        return std::string_view(reinterpret_cast<const char *>(handshake + offset + 5), nameLen);
                    }
                }
                break;
            }
            offset += extLen;
        }

        return std::nullopt;
    }

} // namespace mynet::handler::sniffing
