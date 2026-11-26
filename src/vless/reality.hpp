#pragma once

/**
 * @file vless/reality.hpp
 * @brief VLESS REALITY 协议认证与无证书透明借壳实现
 */

#include "../cipher.hpp"
#include "../encoding.hpp"
#include "../kdf.hpp"
#include "../tls/fragmenter.hpp"
#include "../x25519.hpp"
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mynet::handler::vless::reality
{

    inline constexpr uint8_t kVersionMagic[4] = {1, 8, 2, 0};
    inline constexpr std::string_view kRealityHkdfInfo = "REALITY";

    /**
     * @brief Base64 RawURL 编码解码器 (兼容 URL 安全无填充规范 RFC 4648)
     */
    inline std::optional<std::vector<uint8_t>> decodeBase64RawUrl(std::string_view in)
    {
        std::vector<uint8_t> res;
        if (!encoding::base64UrlDecode(in, res))
        {
            return std::nullopt;
        }
        return res;
    }

    inline std::string encodeBase64RawUrl(std::span<const uint8_t> in)
    {
        return encoding::base64UrlEncode(in, false);
    }

    /**
     * @brief 16 进制转 8 字节 shortID
     */
    inline std::optional<std::array<uint8_t, 8>> parseShortId(std::string_view hex)
    {
        std::array<uint8_t, 8> out{};
        if (hex.empty())
        {
            return out;
        }
        if (hex.size() > 16 || hex.size() % 2 != 0)
        {
            return std::nullopt;
        }
        for (size_t i = 0; i < hex.size(); i += 2)
        {
            int hi = encoding::hexCharToNibble(hex[i]);
            int lo = encoding::hexCharToNibble(hex[i + 1]);
            if (hi < 0 || lo < 0)
                return std::nullopt;
            out[i / 2] = static_cast<uint8_t>((hi << 4) | lo);
        }
        return out;
    }

    /**
     * @brief REALITY 服务端配置
     */
    struct ServerConfig
    {
        std::string serverName{};
        std::vector<std::string> serverNames{};
        std::string destHost{"www.apple.com"};
        uint16_t destPort{443};
        std::array<uint8_t, 32> privateKey{};
        std::vector<std::array<uint8_t, 8>> shortIds{};
        uint32_t maxTimeDifference{60}; // 秒
    };

    /**
     * @brief REALITY 客户端配置
     */
    struct ClientConfig
    {
        std::string serverName{};
        std::array<uint8_t, 32> publicKey{};
        std::array<uint8_t, 8> shortId{};
    };

    /**
     * @brief REALITY 认证决断结果
     */
    enum class AuthStatus : uint8_t
    {
        AUTHENTICATED = 0, ///< 确认为合法 Reality 客户端，接管并建立代理连接
        FALLBACK_DEST = 1, ///< 主动探测/常规访客，透明转发到被借壳的 dest SNI
        INVALID_PACKET = 2 ///< 非 TLS ClientHello 畸变报文
    };

    struct AuthResult
    {
        AuthStatus status{AuthStatus::FALLBACK_DEST};
        std::array<uint8_t, 32> authKey{};
        std::string sni{};
        std::array<uint8_t, 8> shortId{};
    };

    /**
     * @brief 简易 TLS 1.3 ClientHello 扩展提取器
     */
    struct ClientHelloInfo
    {
        std::array<uint8_t, 32> clientRandom{};
        std::array<uint8_t, 32> sessionId{};
        size_t sessionIdOffset{0};
        std::string sni{};
        std::array<uint8_t, 32> keyShareX25519{};
        bool hasKeyShare{false};
    };

    inline std::optional<ClientHelloInfo> parseClientHello(std::span<const uint8_t> data)
    {
        auto view = tls::TlsFragmenter::parseClientHello(data);
        if (!view.has_value() || view->sessionIdLength != 32 || view->sessionIdData == nullptr)
        {
            return std::nullopt;
        }

        ClientHelloInfo info;
        info.clientRandom = view->clientRandom;
        std::memcpy(info.sessionId.data(), view->sessionIdData, 32);
        info.sessionIdOffset = view->sessionIdOffset;
        info.sni = std::string(view->serverName);
        info.keyShareX25519 = view->keyShareX25519;
        info.hasKeyShare = view->hasKeyShare;
        return info;
    }

    /**
     * @brief 客户端封包：生成带有 REALITY 签名认证的 Session ID 并写回 ClientHello
     */
    inline bool sealClientHello(std::span<uint8_t> clientHelloRaw, const ClientConfig &config,
                                std::span<const uint8_t, 32> clientEcdhePrivKey)
    {
        auto info = parseClientHello(clientHelloRaw);
        if (!info.has_value() || !info->hasKeyShare)
        {
            return false;
        }

        // 1. 计算 authKey = X25519(clientECDHEKey, serverPublicKey)
        auto authKey = x25519::computeSharedSecret(clientEcdhePrivKey, config.publicKey);
        if (!authKey.has_value())
        {
            return false;
        }

        // 2. 派生 derivedKey = HKDF-SHA256(authKey, clientRandom[0..20], "REALITY")
        std::array<uint8_t, 32> derivedKey{};
        std::span<const uint8_t> salt(info->clientRandom.data(), 20);
        std::span<const uint8_t> hkdfInfo(reinterpret_cast<const uint8_t *>(kRealityHkdfInfo.data()),
                                          kRealityHkdfInfo.size());
        if (!kdf::hkdfSha256(*authKey, salt, hkdfInfo, derivedKey))
        {
            return false;
        }

        // 3. 构造 Session ID 明文 (16 字节)
        // [Version 4B][Timestamp 4B BE][ShortId 8B]
        std::array<uint8_t, 16> plainSessionId{};
        std::memcpy(plainSessionId.data(), kVersionMagic, 4);

        auto nowSec = static_cast<uint32_t>(
            std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
                .count());
        plainSessionId[4] = static_cast<uint8_t>((nowSec >> 24) & 0xFF);
        plainSessionId[5] = static_cast<uint8_t>((nowSec >> 16) & 0xFF);
        plainSessionId[6] = static_cast<uint8_t>((nowSec >> 8) & 0xFF);
        plainSessionId[7] = static_cast<uint8_t>(nowSec & 0xFF);

        std::memcpy(plainSessionId.data() + 8, config.shortId.data(), 8);

        // 4. AES-256-GCM 加密 (Nonce 取 clientRandom 后 12 字节: random[20..32])
        std::array<uint8_t, 12> nonce{};
        std::memcpy(nonce.data(), info->clientRandom.data() + 20, 12);

        std::vector<uint8_t> ciphertext;
        std::array<uint8_t, 16> tag{};
        if (!cipher::aeadEncryptWithAad(EVP_aes_256_gcm(), derivedKey, nonce, {}, plainSessionId, ciphertext, tag))
        {
            return false;
        }

        // 密文 16 字节 + Tag 16 字节 = 32 字节 SessionID
        std::memcpy(clientHelloRaw.data() + info->sessionIdOffset, ciphertext.data(), 16);
        std::memcpy(clientHelloRaw.data() + info->sessionIdOffset + 16, tag.data(), 16);
        return true;
    }

    /**
     * @brief 服务端验证：解析 ClientHello 判定是否为合法的 REALITY 客户端
     */
    inline AuthResult verifyClientHello(std::span<const uint8_t> clientHelloRaw, const ServerConfig &config)
    {
        AuthResult result;
        auto info = parseClientHello(clientHelloRaw);
        if (!info.has_value())
        {
            result.status = AuthStatus::INVALID_PACKET;
            return result;
        }

        result.sni = info->sni;

        // 校验 SNI
        bool sniAllowed = false;
        if (config.serverName.empty() && config.serverNames.empty())
        {
            sniAllowed = true;
        }
        else
        {
            if (config.serverName == info->sni)
            {
                sniAllowed = true;
            }
            else
            {
                for (const auto &sn : config.serverNames)
                {
                    if (sn == info->sni)
                    {
                        sniAllowed = true;
                        break;
                    }
                }
            }
        }

        if (!sniAllowed || !info->hasKeyShare)
        {
            result.status = AuthStatus::FALLBACK_DEST;
            return result;
        }

        // 1. 计算 authKey = X25519(serverPrivateKey, clientKeySharePubKey)
        auto authKey = x25519::computeSharedSecret(config.privateKey, info->keyShareX25519);
        if (!authKey.has_value())
        {
            result.status = AuthStatus::FALLBACK_DEST;
            return result;
        }
        result.authKey = *authKey;

        // 2. 派生 derivedKey = HKDF-SHA256(authKey, clientRandom[0..20], "REALITY")
        std::array<uint8_t, 32> derivedKey{};
        std::span<const uint8_t> salt(info->clientRandom.data(), 20);
        std::span<const uint8_t> hkdfInfo(reinterpret_cast<const uint8_t *>(kRealityHkdfInfo.data()),
                                          kRealityHkdfInfo.size());
        if (!kdf::hkdfSha256(*authKey, salt, hkdfInfo, derivedKey))
        {
            result.status = AuthStatus::FALLBACK_DEST;
            return result;
        }

        // 3. AES-256-GCM 解密 Session ID
        // Session ID 前 16 字节为密文，后 16 字节为 Tag
        std::array<uint8_t, 12> nonce{};
        std::memcpy(nonce.data(), info->clientRandom.data() + 20, 12);

        std::span<const uint8_t> cipherSpan(info->sessionId.data(), 16);
        std::span<const uint8_t, 16> tagSpan(info->sessionId.data() + 16, 16);
        std::vector<uint8_t> plain;

        if (!cipher::aeadDecryptWithAad(EVP_aes_256_gcm(), derivedKey, nonce, {}, cipherSpan, tagSpan, plain) ||
            plain.size() != 16)
        {
            // 解密失败或 Tag 校验不匹配 -> 非合法 Reality 客户端，转入目标站点回落
            result.status = AuthStatus::FALLBACK_DEST;
            return result;
        }

        // 4. 校验版本 Magic
        if (std::memcmp(plain.data(), kVersionMagic, 4) != 0)
        {
            result.status = AuthStatus::FALLBACK_DEST;
            return result;
        }

        // 5. 校验时间戳 (防御重放攻击)
        uint32_t ts = (static_cast<uint32_t>(plain[4]) << 24) | (static_cast<uint32_t>(plain[5]) << 16) |
                      (static_cast<uint32_t>(plain[6]) << 8) | static_cast<uint32_t>(plain[7]);
        auto nowSec = static_cast<uint32_t>(
            std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
                .count());
        uint32_t diff = (nowSec > ts) ? (nowSec - ts) : (ts - nowSec);
        if (diff > config.maxTimeDifference)
        {
            result.status = AuthStatus::FALLBACK_DEST;
            return result;
        }

        // 6. 校验 shortId
        std::memcpy(result.shortId.data(), plain.data() + 8, 8);
        bool shortIdValid = false;
        if (config.shortIds.empty())
        {
            shortIdValid = true;
        }
        else
        {
            for (const auto &sid : config.shortIds)
            {
                if (std::memcmp(sid.data(), result.shortId.data(), 8) == 0)
                {
                    shortIdValid = true;
                    break;
                }
            }
        }

        if (!shortIdValid)
        {
            result.status = AuthStatus::FALLBACK_DEST;
            return result;
        }

        result.status = AuthStatus::AUTHENTICATED;
        return result;
    }

} // namespace mynet::handler::vless::reality
