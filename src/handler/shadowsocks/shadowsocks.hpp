#pragma once

/**
 * @file proxy/shadowsocks/shadowsocks.hpp
 * @brief Shadowsocks AEAD 代理协议服务端状态机处理器（RFC/SIP002 规范）。
 */

#include "../../connection.hpp"
#include "../address.hpp"
#include "../crypto.hpp"
#include "../inbound.hpp"
#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mynet::handler
{

    enum class ShadowsocksCipher : uint8_t
    {
        AES_128_GCM,
        AES_256_GCM,
        CHACHA20_POLY1305,
        NONE
    };

    /**
     * @brief Shadowsocks 会话阶段
     */
    enum class ShadowsocksStage : uint8_t
    {
        SALT,          ///< 读取客户端发来的初始随机盐 (Salt)
        CHUNK_LEN,     ///< 解密下一个数据分块的载荷长度 (2B + 16B Tag)
        CHUNK_PAYLOAD, ///< 解密数据分块载荷 (Length B + 16B Tag)
        STREAMING,     ///< 握手完成并解析得目标地址，持续转发解密数据
        ERROR          ///< 密文解密失败或格式错误
    };

    /**
     * @brief Shadowsocks AEAD 协议入站状态机处理器
     */
    class HandlerInboundShadowsocks : public HandlerInboundConnection
    {
    public:
        static constexpr bool kEnableSplice = false;

    private:
        ShadowsocksStage ssStage_{ShadowsocksStage::SALT};
        ShadowsocksCipher cipherType_{ShadowsocksCipher::AES_128_GCM};

        size_t keyLen_{16};
        size_t saltLen_{16};
        std::vector<uint8_t> masterKey_{};
        std::vector<uint8_t> rxSubkey_{};
        std::array<uint8_t, 12> rxNonce_{};

        size_t currentChunkLen_{0};
        bool targetResolved_{false};

    public:
        HandlerInboundShadowsocks() noexcept { setMethod("aes-128-gcm", "password"); }

        HandlerInboundShadowsocks(std::string_view method, std::string_view password) { setMethod(method, password); }

        ~HandlerInboundShadowsocks() noexcept override = default;

        HandlerInboundShadowsocks(const HandlerInboundShadowsocks &) = delete;
        HandlerInboundShadowsocks &operator=(const HandlerInboundShadowsocks &) = delete;
        HandlerInboundShadowsocks(HandlerInboundShadowsocks &&) = delete;
        HandlerInboundShadowsocks &operator=(HandlerInboundShadowsocks &&) = delete;

        void setMethod(std::string_view method, std::string_view password)
        {
            if (method == "aes-256-gcm")
            {
                cipherType_ = ShadowsocksCipher::AES_256_GCM;
                keyLen_ = 32;
                saltLen_ = 32;
            }
            else if (method == "chacha20-ietf-poly1305")
            {
                cipherType_ = ShadowsocksCipher::CHACHA20_POLY1305;
                keyLen_ = 32;
                saltLen_ = 32;
            }
            else if (method == "none")
            {
                cipherType_ = ShadowsocksCipher::NONE;
                keyLen_ = 0;
                saltLen_ = 0;
            }
            else
            {
                // 默认 aes-128-gcm
                cipherType_ = ShadowsocksCipher::AES_128_GCM;
                keyLen_ = 16;
                saltLen_ = 16;
            }

            // 使用 EVP_BytesToKey 从 password 派生主密钥
            deriveKey(password);
        }

        void setOnRequest(RequestCallback cb) noexcept { requestCallback_ = std::move(cb); }

        [[nodiscard]] ShadowsocksStage stage() const noexcept { return ssStage_; }
        [[nodiscard]] bool isEstablished() const noexcept { return targetResolved_; }

        void reset() noexcept override
        {
            HandlerInboundConnection::reset();
            ssStage_ =
                (cipherType_ == ShadowsocksCipher::NONE) ? ShadowsocksStage::CHUNK_PAYLOAD : ShadowsocksStage::SALT;
            rxSubkey_.clear();
            std::memset(rxNonce_.data(), 0, rxNonce_.size());
            currentChunkLen_ = 0;
            targetResolved_ = false;
        }

        void onMessageComplete() noexcept {}
        void onParseError(const char *reason) noexcept
        {
            (void)reason;
            ssStage_ = ShadowsocksStage::ERROR;
            stage_ = InboundStage::ERROR;
        }

        void process()
        {
            if (cipherType_ == ShadowsocksCipher::NONE)
            {
                processNone();
                return;
            }

            while (true)
            {
                if (ssStage_ == ShadowsocksStage::SALT)
                {
                    if (!processSalt())
                    {
                        return;
                    }
                }

                if (ssStage_ == ShadowsocksStage::CHUNK_LEN)
                {
                    if (!processChunkLen())
                    {
                        return;
                    }
                }

                if (ssStage_ == ShadowsocksStage::CHUNK_PAYLOAD)
                {
                    if (!processChunkPayload())
                    {
                        return;
                    }
                }

                if (ssStage_ == ShadowsocksStage::STREAMING)
                {
                    // 在数据流转发阶段，持续解析后续 AEAD 块
                    if (!processChunkLen())
                    {
                        return;
                    }
                }

                if (ssStage_ == ShadowsocksStage::ERROR)
                {
                    return;
                }
            }
        }

    private:
        void deriveKey(std::string_view password)
        {
            if (keyLen_ == 0)
            {
                masterKey_.clear();
                return;
            }
            masterKey_.resize(keyLen_);
            const EVP_CIPHER *c = (keyLen_ == 16) ? EVP_aes_128_gcm() : EVP_aes_256_gcm();
            EVP_BytesToKey(c, EVP_md5(), nullptr, reinterpret_cast<const unsigned char *>(password.data()),
                           password.size(), 1, masterKey_.data(), nullptr);
        }

        void incrementNonce() noexcept
        {
            for (size_t i = 0; i < rxNonce_.size(); ++i)
            {
                if (++rxNonce_[i] != 0)
                {
                    break;
                }
            }
        }

        const EVP_CIPHER *getEvpCipher() const noexcept
        {
            switch (cipherType_)
            {
            case ShadowsocksCipher::AES_128_GCM:
                return EVP_aes_128_gcm();
            case ShadowsocksCipher::AES_256_GCM:
                return EVP_aes_256_gcm();
            case ShadowsocksCipher::CHACHA20_POLY1305:
                return EVP_chacha20_poly1305();
            default:
                return nullptr;
            }
        }

        void processNone()
        {
            if (!targetResolved_)
            {
                const size_t avail = requestBytes();
                if (avail < 7)
                {
                    return;
                }
                const auto *data = reinterpret_cast<const uint8_t *>(requestBegin());
                size_t consumed = 0;
                std::span<const uint8_t> span(data, avail);
                auto target = ProxyAddress::decodeSocks5(span, consumed);
                if (!target.has_value())
                {
                    return;
                }
                targetAddress_ = std::move(target);
                targetResolved_ = true;
                requestConsume(consumed);
                ssStage_ = ShadowsocksStage::STREAMING;
                stage_ = InboundStage::STREAMING;
                onMessageComplete();

                if (requestCallback_)
                {
                    requestCallback_(0x01, *targetAddress_);
                }
            }
        }

        bool processSalt()
        {
            const size_t avail = requestBytes();
            if (avail < saltLen_)
            {
                return false;
            }

            const auto *data = reinterpret_cast<const uint8_t *>(requestBegin());
            std::span<const uint8_t> salt(data, saltLen_);

            // 派生子密钥 subkey = HKDF-SHA1(masterKey, salt, "ss-subkey")
            static constexpr uint8_t kInfo[] = {'s', 's', '-', 's', 'u', 'b', 'k', 'e', 'y'};
            rxSubkey_.resize(keyLen_);
            if (!crypto::hkdfSha1(masterKey_, salt, kInfo, rxSubkey_))
            {
                onParseError("Shadowsocks: HKDF subkey derivation failed");
                ssStage_ = ShadowsocksStage::ERROR;
                stage_ = InboundStage::ERROR;
                setCloseAfterResponse(true);
                return false;
            }

            std::memset(rxNonce_.data(), 0, rxNonce_.size());
            requestConsume(saltLen_);
            ssStage_ = ShadowsocksStage::CHUNK_LEN;
            return true;
        }

        bool processChunkLen()
        {
            // 块长度密文结构：[2B encrypted length][16B tag] -> 共 18 字节
            constexpr size_t kLenPacketSize = 2 + 16;
            const size_t avail = requestBytes();
            if (avail < kLenPacketSize)
            {
                return false;
            }

            const auto *data = reinterpret_cast<const uint8_t *>(requestBegin());
            std::span<const uint8_t> cipherLen(data, 2);
            std::array<uint8_t, 16> tag{};
            std::memcpy(tag.data(), data + 2, 16);

            std::vector<uint8_t> plainLen{};
            if (!crypto::aeadDecrypt(getEvpCipher(), rxSubkey_, rxNonce_, cipherLen, tag, plainLen))
            {
                onParseError("Shadowsocks: Decrypt chunk length failed");
                ssStage_ = ShadowsocksStage::ERROR;
                stage_ = InboundStage::ERROR;
                setCloseAfterResponse(true);
                return false;
            }
            incrementNonce();

            if (plainLen.size() < 2)
            {
                onParseError("Shadowsocks: Invalid decrypted chunk length");
                ssStage_ = ShadowsocksStage::ERROR;
                stage_ = InboundStage::ERROR;
                setCloseAfterResponse(true);
                return false;
            }

            currentChunkLen_ = (static_cast<size_t>(plainLen[0]) << 8) | static_cast<size_t>(plainLen[1]);
            // RFC 约束：分块最大不超过 0x3FFF (16383 字节)
            if (currentChunkLen_ > 0x3FFF)
            {
                onParseError("Shadowsocks: Chunk length exceeds 0x3FFF");
                ssStage_ = ShadowsocksStage::ERROR;
                stage_ = InboundStage::ERROR;
                setCloseAfterResponse(true);
                return false;
            }

            requestConsume(kLenPacketSize);
            ssStage_ = ShadowsocksStage::CHUNK_PAYLOAD;
            return true;
        }

        bool processChunkPayload()
        {
            // 载荷结构：[Length B encrypted payload][16B tag]
            const size_t totalExpected = currentChunkLen_ + 16;
            const size_t avail = requestBytes();
            if (avail < totalExpected)
            {
                return false;
            }

            const auto *data = reinterpret_cast<const uint8_t *>(requestBegin());
            std::span<const uint8_t> cipherPayload(data, currentChunkLen_);
            std::array<uint8_t, 16> tag{};
            std::memcpy(tag.data(), data + currentChunkLen_, 16);

            std::vector<uint8_t> plainPayload{};
            if (!crypto::aeadDecrypt(getEvpCipher(), rxSubkey_, rxNonce_, cipherPayload, tag, plainPayload))
            {
                onParseError("Shadowsocks: Decrypt chunk payload failed");
                ssStage_ = ShadowsocksStage::ERROR;
                stage_ = InboundStage::ERROR;
                setCloseAfterResponse(true);
                return false;
            }
            incrementNonce();
            requestConsume(totalExpected);

            // 如果这是首个解密载荷，其中必定包含目标 SOCKS5 代理地址
            if (!targetResolved_)
            {
                size_t addrConsumed = 0;
                auto target = ProxyAddress::decodeSocks5(plainPayload, addrConsumed);
                if (!target.has_value())
                {
                    onParseError("Shadowsocks: Failed to decode initial destination address");
                    ssStage_ = ShadowsocksStage::ERROR;
                    stage_ = InboundStage::ERROR;
                    setCloseAfterResponse(true);
                    return false;
                }

                targetAddress_ = std::move(target);
                targetResolved_ = true;
                ssStage_ = ShadowsocksStage::STREAMING;
                stage_ = InboundStage::STREAMING;
                onMessageComplete();

                if (requestCallback_)
                {
                    requestCallback_(0x01, *targetAddress_);
                }
            }
            else
            {
                ssStage_ = ShadowsocksStage::CHUNK_LEN;
            }

            return true;
        }
    };

} // namespace mynet::handler
