#pragma once

/**
 * @file shadowsocks/shadowsocks.hpp
 * @brief Shadowsocks AEAD 代理协议双向状态机编解码器（RFC/SIP002 规范）。
 *
 * 彻底复用基础设施：
 * 1. 基于 Handler 双缓冲/编解码分层（wireRxBuffer_ 收密文 -> requestBuffer_ 吐明文），
 *    不再自建 rawRx_ 也不再混淆明密文；
 * 2. 基于 cipher::AeadCipherContext 持久化单连接 EVP_CIPHER_CTX，零热路径上下文分配；
 * 3. 入站/出站共享 ShadowsocksAeadStream 状态机，支持完整的双向加解密与 TLS/WS 叠加承载。
 */

#include "../address.hpp"
#include "../cipher.hpp"
#include "../connection.hpp"
#include "../kdf.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <openssl/rand.h>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#if defined(__ANDROID__)
extern "C" inline const EVP_CIPHER *EVP_chacha20_poly1305()
{
    return nullptr;
}
#endif

namespace mynet::handler
{

    using ShadowsocksCipher = mynet::cipher::AeadAlgorithm;

    /**
     * @brief Shadowsocks 会话阶段
     */
    enum class ShadowsocksStage : uint8_t
    {
        SALT,          ///< 读取初始随机盐 (Salt)
        CHUNK_LEN,     ///< 解密下一个数据分块的载荷长度 (2B + 16B Tag)
        CHUNK_PAYLOAD, ///< 解密数据分块载荷 (Length B + 16B Tag)
        STREAMING,     ///< 握手完成并解析得目标地址，持续转发解密数据
        ERROR          ///< 密文解密失败或格式错误
    };

    /**
     * @brief Shadowsocks AEAD 双向共享流式编解码内核 (RX 解密状态机 + TX 分块加密器)
     */
    struct ShadowsocksCodecCore
    {
        ShadowsocksCipher cipherType{ShadowsocksCipher::AES_128_GCM};
        size_t keyLen{16};
        size_t saltLen{16};
        std::vector<uint8_t> masterKey{};

        ShadowsocksStage rxStage{ShadowsocksStage::SALT};
        std::vector<uint8_t> rxSubkey{};
        std::array<uint8_t, 12> rxNonce{};
        size_t rxChunkLen{0};
        cipher::AeadCipherContext rxCtx{};

        bool txInitialized{false};
        std::vector<uint8_t> txSubkey{};
        std::array<uint8_t, 12> txNonce{};
        cipher::AeadCipherContext txCtx{};

        void setMethod(std::string_view method, std::string_view password)
        {
            cipherType = cipher::parseAeadAlgorithm(method).value_or(ShadowsocksCipher::AES_128_GCM);
            keyLen = cipher::aeadKeySize(cipherType);
            saltLen = keyLen;
            deriveMasterKey(password);
        }

        void deriveMasterKey(std::string_view password)
        {
            if (keyLen == 0)
            {
                masterKey.clear();
                return;
            }
            masterKey.resize(keyLen);
            const EVP_CIPHER *c = (keyLen == 16) ? EVP_aes_128_gcm() : EVP_aes_256_gcm();
            EVP_BytesToKey(c, EVP_md5(), nullptr, reinterpret_cast<const unsigned char *>(password.data()),
                           password.size(), 1, masterKey.data(), nullptr);
        }

        [[nodiscard]] const EVP_CIPHER *evpCipher() const noexcept
        {
            return cipher::resolveEvpCipher(cipherType);
        }

        void reset() noexcept
        {
            rxStage = (cipherType == ShadowsocksCipher::NONE) ? ShadowsocksStage::CHUNK_PAYLOAD : ShadowsocksStage::SALT;
            rxSubkey.clear();
            std::memset(rxNonce.data(), 0, rxNonce.size());
            rxChunkLen = 0;
            rxCtx.reset();

            txInitialized = false;
            txSubkey.clear();
            std::memset(txNonce.data(), 0, txNonce.size());
            txCtx.reset();
        }

        [[nodiscard]] bool initTxHeader(std::string &outSalt)
        {
            if (txInitialized)
            {
                return true;
            }
            outSalt.resize(saltLen);
            if (RAND_bytes(reinterpret_cast<uint8_t *>(outSalt.data()), static_cast<int>(saltLen)) != 1)
            {
                return false;
            }
            static constexpr uint8_t kInfo[] = {'s', 's', '-', 's', 'u', 'b', 'k', 'e', 'y'};
            txSubkey.resize(keyLen);
            std::span<const uint8_t> saltSpan(reinterpret_cast<const uint8_t *>(outSalt.data()), outSalt.size());
            if (!kdf::hkdfSha1(masterKey, saltSpan, kInfo, txSubkey))
            {
                return false;
            }
            std::memset(txNonce.data(), 0, txNonce.size());
            if (!txCtx.init(evpCipher(), txSubkey, true, txNonce.size()))
            {
                return false;
            }
            txInitialized = true;
            return true;
        }

        [[nodiscard]] bool encryptChunk(std::span<const uint8_t> plain, std::string &packet)
        {
            const uint16_t plen = htons(static_cast<uint16_t>(plain.size()));
            std::span<const uint8_t> plainLenSpan(reinterpret_cast<const uint8_t *>(&plen), 2);
            std::vector<uint8_t> cipherLen;
            std::array<uint8_t, 16> lenTag{};
            if (!txCtx.encrypt(txNonce, {}, plainLenSpan, cipherLen, lenTag))
            {
                return false;
            }
            cipher::incrementLittleEndianNonce(txNonce);

            std::vector<uint8_t> cipherPayload;
            std::array<uint8_t, 16> payloadTag{};
            if (!txCtx.encrypt(txNonce, {}, plain, cipherPayload, payloadTag))
            {
                return false;
            }
            cipher::incrementLittleEndianNonce(txNonce);

            packet.reserve(packet.size() + cipherLen.size() + lenTag.size() + cipherPayload.size() + payloadTag.size());
            packet.append(reinterpret_cast<const char *>(cipherLen.data()), cipherLen.size());
            packet.append(reinterpret_cast<const char *>(lenTag.data()), lenTag.size());
            packet.append(reinterpret_cast<const char *>(cipherPayload.data()), cipherPayload.size());
            packet.append(reinterpret_cast<const char *>(payloadTag.data()), payloadTag.size());
            return true;
        }

        template <typename OnPayloadFn, typename OnErrorFn>
        [[nodiscard]] bool decodeChunks(RequestBuffer &wireIn, OnPayloadFn &&onPayload, OnErrorFn &&onError,
                                        bool stopAfterChunkPayload = false)
        {
            while (true)
            {
                if (rxStage == ShadowsocksStage::SALT)
                {
                    if (wireIn.readableBytes() < saltLen)
                    {
                        return true;
                    }
                    const auto *data = reinterpret_cast<const uint8_t *>(wireIn.readableBegin());
                    std::span<const uint8_t> salt(data, saltLen);
                    static constexpr uint8_t kInfo[] = {'s', 's', '-', 's', 'u', 'b', 'k', 'e', 'y'};
                    rxSubkey.resize(keyLen);
                    if (!kdf::hkdfSha1(masterKey, salt, kInfo, rxSubkey) ||
                        !rxCtx.init(evpCipher(), rxSubkey, false, rxNonce.size()))
                    {
                        onError("Shadowsocks: HKDF subkey derivation failed");
                        return false;
                    }
                    std::memset(rxNonce.data(), 0, rxNonce.size());
                    wireIn.retrieve(saltLen);
                    rxStage = ShadowsocksStage::CHUNK_LEN;
                }

                if (rxStage == ShadowsocksStage::CHUNK_LEN || rxStage == ShadowsocksStage::STREAMING)
                {
                    constexpr size_t kLenPacketSize = 2 + 16;
                    if (wireIn.readableBytes() < kLenPacketSize)
                    {
                        return true;
                    }
                    const auto *data = reinterpret_cast<const uint8_t *>(wireIn.readableBegin());
                    std::span<const uint8_t> cipherLen(data, 2);
                    std::array<uint8_t, 16> tag{};
                    std::memcpy(tag.data(), data + 2, 16);

                    std::vector<uint8_t> plainLen;
                    if (!rxCtx.decrypt(rxNonce, {}, cipherLen, tag, plainLen))
                    {
                        onError("Shadowsocks: Decrypt chunk length failed");
                        return false;
                    }
                    cipher::incrementLittleEndianNonce(rxNonce);
                    if (plainLen.size() < 2)
                    {
                        onError("Shadowsocks: Invalid decrypted chunk length");
                        return false;
                    }
                    rxChunkLen = (static_cast<size_t>(plainLen[0]) << 8) | static_cast<size_t>(plainLen[1]);
                    if (rxChunkLen > 0x3FFF)
                    {
                        onError("Shadowsocks: Chunk length exceeds 0x3FFF");
                        return false;
                    }
                    wireIn.retrieve(kLenPacketSize);
                    rxStage = ShadowsocksStage::CHUNK_PAYLOAD;
                }

                if (rxStage == ShadowsocksStage::CHUNK_PAYLOAD)
                {
                    const size_t totalExpected = rxChunkLen + 16;
                    if (wireIn.readableBytes() < totalExpected)
                    {
                        return true;
                    }
                    const auto *data = reinterpret_cast<const uint8_t *>(wireIn.readableBegin());
                    std::span<const uint8_t> cipherPayload(data, rxChunkLen);
                    std::array<uint8_t, 16> tag{};
                    std::memcpy(tag.data(), data + rxChunkLen, 16);

                    std::vector<uint8_t> plainPayload;
                    if (!rxCtx.decrypt(rxNonce, {}, cipherPayload, tag, plainPayload))
                    {
                        onError("Shadowsocks: Decrypt chunk payload failed");
                        return false;
                    }
                    cipher::incrementLittleEndianNonce(rxNonce);
                    wireIn.retrieve(totalExpected);
                    rxStage = ShadowsocksStage::CHUNK_LEN;

                    if (!onPayload(plainPayload))
                    {
                        return false;
                    }
                    if (stopAfterChunkPayload)
                    {
                        return true;
                    }
                }

                if (rxStage == ShadowsocksStage::ERROR)
                {
                    return false;
                }
            }
        }
    };

    /**
     * @brief Shadowsocks AEAD 协议入站状态机处理器
     */
    class HandlerInboundShadowsocks : public HandlerInboundConnectionBase
    {
    public:
        [[nodiscard]] bool canSplice() const noexcept override { return false; }

    private:
        ShadowsocksCodecCore codec_{};
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
            codec_.setMethod(method, password);
            codec_.reset();
            setCodecMode(codec_.cipherType != ShadowsocksCipher::NONE);
        }

        void setOnRequest(RequestCallback cb) noexcept { requestCallback_ = std::move(cb); }

        [[nodiscard]] ShadowsocksStage stage() const noexcept { return codec_.rxStage; }
        [[nodiscard]] bool isEstablished() const noexcept override { return targetResolved_; }

        void reset() noexcept override
        {
            HandlerInboundConnectionBase::reset();
            codec_.reset();
            setCodecMode(codec_.cipherType != ShadowsocksCipher::NONE);
            targetResolved_ = false;
        }

        void onParseError(const char *reason) noexcept override
        {
            (void)reason;
            codec_.rxStage = ShadowsocksStage::ERROR;
            setStage(InboundStage::ERROR);
            setCloseAfterResponse(true);
        }

        [[nodiscard]] Result<> onWireDecode(RequestBuffer &wireIn, RequestBuffer &appOut) noexcept override
        {
            if (codec_.cipherType == ShadowsocksCipher::NONE)
            {
                return decodeNoneFrom(wireIn, appOut);
            }

            const bool ok = codec_.decodeChunks(
                wireIn,
                [&](const std::vector<uint8_t> &plainPayload) -> bool
                {
                    if (!targetResolved_)
                    {
                        size_t addrConsumed = 0;
                        auto target = ProxyAddress::decodeSocks5(plainPayload, addrConsumed);
                        if (!target.has_value())
                        {
                            onParseError("Shadowsocks: Failed to decode initial destination address");
                            return false;
                        }
                        targetAddress_ = std::move(target);
                        targetResolved_ = true;
                        codec_.rxStage = ShadowsocksStage::STREAMING;
                        setStage(InboundStage::STREAMING);
                        onMessageComplete();

                        if (plainPayload.size() > addrConsumed)
                        {
                            const char *extra = reinterpret_cast<const char *>(plainPayload.data() + addrConsumed);
                            [[maybe_unused]] auto _ = appOut.append(extra, plainPayload.size() - addrConsumed);
                        }
                        if (requestCallback_)
                        {
                            requestCallback_(0x01, *targetAddress_);
                        }
                        return true;
                    }
                    if (!plainPayload.empty())
                    {
                        const char *p = reinterpret_cast<const char *>(plainPayload.data());
                        [[maybe_unused]] auto _ = appOut.append(p, plainPayload.size());
                    }
                    codec_.rxStage = ShadowsocksStage::STREAMING;
                    return true;
                },
                [&](const char *err) { onParseError(err); });

            return ok ? Result<>{} : std::unexpected(ERR::CONNECT_FAILED);
        }

        [[nodiscard]] Result<> onEncodePayload(std::string_view plain, ResponseQueue &encodedOut) noexcept override
        {
            if (plain.empty())
            {
                return {};
            }
            if (codec_.cipherType == ShadowsocksCipher::NONE)
            {
                return encodedOut.emplace(plain);
            }
            std::string packet;
            if (!codec_.txInitialized)
            {
                if (!codec_.initTxHeader(packet))
                {
                    return std::unexpected(ERR::CONNECT_FAILED);
                }
            }
            while (!plain.empty())
            {
                const size_t chunkLen = std::min(plain.size(), static_cast<size_t>(0x3FFF));
                std::span<const uint8_t> chunkSpan(reinterpret_cast<const uint8_t *>(plain.data()), chunkLen);
                if (!codec_.encryptChunk(chunkSpan, packet))
                {
                    return std::unexpected(ERR::CONNECT_FAILED);
                }
                plain.remove_prefix(chunkLen);
            }
            return encodedOut.push(std::move(packet));
        }

        void handle() override
        {
            if (codec_.cipherType == ShadowsocksCipher::NONE && !targetResolved_)
            {
                [[maybe_unused]] auto _ = decodeNoneFrom(requestBuffer_, requestBuffer_);
            }
        }

    private:
        Result<> decodeNoneFrom(RequestBuffer &src, RequestBuffer &dst) noexcept
        {
            if (!targetResolved_)
            {
                const size_t avail = src.readableBytes();
                if (avail < 7)
                {
                    return {};
                }
                const auto *data = reinterpret_cast<const uint8_t *>(src.readableBegin());
                size_t consumed = 0;
                auto target = ProxyAddress::decodeSocks5(std::span<const uint8_t>(data, avail), consumed);
                if (!target.has_value())
                {
                    return {};
                }
                targetAddress_ = std::move(target);
                targetResolved_ = true;
                src.retrieve(consumed);
                codec_.rxStage = ShadowsocksStage::STREAMING;
                setStage(InboundStage::STREAMING);
                onMessageComplete();
                if (requestCallback_)
                {
                    requestCallback_(0x01, *targetAddress_);
                }
            }
            if (&src != &dst && src.readableBytes() > 0)
            {
                auto r = dst.append(src.readableBegin(), src.readableBytes());
                src.retrieve(src.readableBytes());
                return r;
            }
            return {};
        }
    };

    /**
     * @brief Shadowsocks AEAD 客户端出站状态机处理器
     */
    class HandlerOutboundShadowsocks : public HandlerOutboundConnectionBase
    {
    public:
        [[nodiscard]] bool canSplice() const noexcept override { return false; }

    private:
        ShadowsocksCodecCore codec_{};
        bool handshakeSent_{false};

    public:
        HandlerOutboundShadowsocks() noexcept { setMethod("aes-128-gcm", "password"); }
        HandlerOutboundShadowsocks(std::string_view method, std::string_view password, const ProxyAddress &target)
            : HandlerOutboundConnectionBase(target)
        {
            setMethod(method, password);
        }

        void setMethod(std::string_view method, std::string_view password)
        {
            codec_.setMethod(method, password);
            codec_.reset();
            setCodecMode(codec_.cipherType != ShadowsocksCipher::NONE);
        }

        [[nodiscard]] bool isEstablished() const noexcept override { return handshakeSent_; }

        void reset() noexcept override
        {
            HandlerOutboundConnectionBase::reset();
            handshakeSent_ = false;
            codec_.reset();
            setCodecMode(codec_.cipherType != ShadowsocksCipher::NONE);
        }

        void onParseError(const char *reason) noexcept override
        {
            (void)reason;
            setStage(OutboundStage::ERROR);
            codec_.rxStage = ShadowsocksStage::ERROR;
        }

        void handle() override
        {
            if (!handshakeSent_)
            {
                sendHandshake();
            }
        }

        [[nodiscard]] Result<> onWireDecode(RequestBuffer &wireIn, RequestBuffer &appOut) noexcept override
        {
            if (codec_.cipherType == ShadowsocksCipher::NONE)
            {
                if (wireIn.readableBytes() > 0)
                {
                    auto r = appOut.append(wireIn.readableBegin(), wireIn.readableBytes());
                    wireIn.retrieve(wireIn.readableBytes());
                    return r;
                }
                return {};
            }

            const bool ok = codec_.decodeChunks(
                wireIn,
                [&](const std::vector<uint8_t> &plainPayload) -> bool
                {
                    if (!plainPayload.empty())
                    {
                        const char *p = reinterpret_cast<const char *>(plainPayload.data());
                        [[maybe_unused]] auto _ = appOut.append(p, plainPayload.size());
                    }
                    return true;
                },
                [&](const char *err) { onParseError(err); });
            return ok ? Result<>{} : std::unexpected(ERR::CONNECT_FAILED);
        }

        [[nodiscard]] Result<> onEncodePayload(std::string_view plain, ResponseQueue &encodedOut) noexcept override
        {
            if (plain.empty())
            {
                return {};
            }
            if (!handshakeSent_)
            {
                sendHandshake();
            }
            if (codec_.cipherType == ShadowsocksCipher::NONE)
            {
                return encodedOut.emplace(plain);
            }
            std::string packet;
            while (!plain.empty())
            {
                const size_t chunkLen = std::min(plain.size(), static_cast<size_t>(0x3FFF));
                std::span<const uint8_t> chunkSpan(reinterpret_cast<const uint8_t *>(plain.data()), chunkLen);
                if (!codec_.encryptChunk(chunkSpan, packet))
                {
                    return std::unexpected(ERR::CONNECT_FAILED);
                }
                plain.remove_prefix(chunkLen);
            }
            return encodedOut.push(std::move(packet));
        }

    private:
        void sendHandshake()
        {
            if (handshakeSent_)
            {
                return;
            }
            handshakeSent_ = true;
            std::vector<uint8_t> encodedTarget;
            target().encodeSocks5(encodedTarget);
            if (encodedTarget.empty())
            {
                onParseError("HandlerOutboundShadowsocks: Failed to encode target address");
                return;
            }

            if (codec_.cipherType == ShadowsocksCipher::NONE)
            {
                [[maybe_unused]] auto _ = emitEncodedToWire(
                    std::string_view(reinterpret_cast<const char *>(encodedTarget.data()), encodedTarget.size()));
                setStage(OutboundStage::STREAMING);
                return;
            }

            std::string packet;
            if (!codec_.initTxHeader(packet))
            {
                onParseError("HandlerOutboundShadowsocks: Failed to init TX cipher");
                return;
            }
            if (!codec_.encryptChunk(encodedTarget, packet))
            {
                onParseError("HandlerOutboundShadowsocks: Encrypt target payload failed");
                return;
            }

            [[maybe_unused]] auto _ = emitEncodedToWire(packet);
            setStage(OutboundStage::STREAMING);
        }
    };

} // namespace mynet::handler
