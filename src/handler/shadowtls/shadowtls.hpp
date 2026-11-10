#pragma once

/**
 * @file proxy/shadowtls/shadowtls.hpp
 * @brief ShadowTLS (v1/v2/v3) 协议服务端状态机处理器。
 */

#include "../../connection.hpp"
#include "../address.hpp"
#include "../crypto.hpp"
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mynet::handler
{

    enum class ShadowTlsVersion : uint8_t
    {
        V1 = 1,
        V2 = 2,
        V3 = 3
    };

    enum class ShadowTlsStage : uint8_t
    {
        INSPECT_CLIENT_HELLO, ///< 嗅探 TLS 握手 ClientHello 并校验 HMAC
        STREAMING,            ///< 判定完成，已进入 detour 或 fallback 零拷贝隧道
        ERROR                 ///< 协议格式畸变
    };

    /**
     * @brief ShadowTLS 服务端处理器
     */
    class HandlerShadowTls : public HandlerConnection
    {
    public:
        using RequestCallback = std::function<void(bool authenticated, const ProxyAddress &target)>;

        static constexpr bool kEnableSplice = true;

        inline void enableSpliceForward(int targetFd) noexcept { setSpliceTarget(targetFd); }
        inline void enableSpliceForward(SPLICE_CONTROL ctrl) noexcept { setSpliceTarget(ctrl); }
        inline void disableSpliceForward() noexcept { disableSplice(); }
        [[nodiscard]] inline bool isSpliceForwardActive() const noexcept { return isSpliceActive(); }

    private:
        ShadowTlsStage stage_{ShadowTlsStage::INSPECT_CLIENT_HELLO};
        ShadowTlsVersion version_{ShadowTlsVersion::V3};
        std::string password_{};
        ProxyAddress detourTarget_{};   ///< 鉴权成功时的内部代理目标
        ProxyAddress fallbackTarget_{}; ///< 鉴权失败/普通探测时的回落目标 (如 google.com:443)
        RequestCallback requestCallback_{nullptr};

        bool clientAuthenticated_{false};
        std::string sni_{};
        std::optional<ProxyAddress> targetAddress_{std::nullopt};

    public:
        HandlerShadowTls() noexcept
        {
            detourTarget_ = ProxyAddress::fromHostPort("127.0.0.1", 1080);
            fallbackTarget_ = ProxyAddress::fromHostPort("google.com", 443);
        }

        HandlerShadowTls(ShadowTlsVersion ver, std::string_view password, const ProxyAddress &detour,
                         const ProxyAddress &fallback)
            : version_(ver),
              password_(password),
              detourTarget_(detour),
              fallbackTarget_(fallback)
        {
        }

        ~HandlerShadowTls() noexcept override = default;

        HandlerShadowTls(const HandlerShadowTls &) = delete;
        HandlerShadowTls &operator=(const HandlerShadowTls &) = delete;
        HandlerShadowTls(HandlerShadowTls &&) = delete;
        HandlerShadowTls &operator=(HandlerShadowTls &&) = delete;

        void setVersion(ShadowTlsVersion ver) noexcept { version_ = ver; }
        void setPassword(std::string_view pass) { password_ = std::string(pass); }
        void setDetourTarget(const ProxyAddress &addr) { detourTarget_ = addr; }
        void setFallbackTarget(const ProxyAddress &addr) { fallbackTarget_ = addr; }
        void setOnRequest(RequestCallback cb) noexcept { requestCallback_ = std::move(cb); }

        [[nodiscard]] ShadowTlsStage stage() const noexcept { return stage_; }
        [[nodiscard]] bool isEstablished() const noexcept { return stage_ == ShadowTlsStage::STREAMING; }
        [[nodiscard]] bool isClientAuthenticated() const noexcept { return clientAuthenticated_; }
        [[nodiscard]] std::string_view sni() const noexcept { return sni_; }
        [[nodiscard]] const std::optional<ProxyAddress> &targetAddress() const noexcept { return targetAddress_; }

        void reset() noexcept override
        {
            HandlerConnection::reset();
            stage_ = ShadowTlsStage::INSPECT_CLIENT_HELLO;
            clientAuthenticated_ = false;
            sni_.clear();
            targetAddress_.reset();
            disableSpliceForward();
        }

        void onMessageComplete() noexcept {}
        void onParseError(const char *reason) noexcept
        {
            (void)reason;
            stage_ = ShadowTlsStage::ERROR;
        }

        void process()
        {
            if (stage_ == ShadowTlsStage::INSPECT_CLIENT_HELLO)
            {
                if (!inspectClientHello())
                {
                    return;
                }
            }
        }

    private:
        bool inspectClientHello()
        {
            // TLS Record Header: [Type 0x16 (1B)][Version (2B)][Length (2B BE)] -> 5 字节
            const size_t avail = requestBytes();
            if (avail < 5)
            {
                return false;
            }

            const auto *data = reinterpret_cast<const uint8_t *>(requestBegin());
            if (data[0] != 0x16) // 不是 TLS Handshake
            {
                // 非 TLS 请求，直接回落
                clientAuthenticated_ = false;
                targetAddress_ = fallbackTarget_;
                stage_ = ShadowTlsStage::STREAMING;
                onMessageComplete();
                if (requestCallback_)
                {
                    requestCallback_(false, *targetAddress_);
                }
                return true;
            }

            const size_t recordLen = (static_cast<size_t>(data[3]) << 8) | static_cast<size_t>(data[4]);
            if (avail < 5 + recordLen)
            {
                // 等待完整 ClientHello 记录
                return false;
            }

            const uint8_t *handshake = data + 5;
            if (recordLen < 4 || handshake[0] != 0x01) // 0x01 = ClientHello
            {
                clientAuthenticated_ = false;
                targetAddress_ = fallbackTarget_;
                stage_ = ShadowTlsStage::STREAMING;
                onMessageComplete();
                if (requestCallback_)
                {
                    requestCallback_(false, *targetAddress_);
                }
                return true;
            }

            // ClientHello 结构解析
            // [HandshakeType 1B][HandshakeLen 3B][TlsVer 2B][Random 32B][SessionIdLen 1B][SessionId N B]...
            if (recordLen < 4 + 2 + 32 + 1)
            {
                return false;
            }

            const uint8_t *random = handshake + 4 + 2;
            const uint8_t sessionIdLen = handshake[4 + 2 + 32];
            const uint8_t *sessionId = handshake + 4 + 2 + 32 + 1;

            if (recordLen < 4 + 2 + 32 + 1 + static_cast<size_t>(sessionIdLen))
            {
                return false;
            }

            // 提取 SNI 扩展
            parseSni(handshake, recordLen);

            // 校验 ShadowTLS 认证令牌 (SessionID 或 Random 中的 HMAC)
            bool ok = false;
            if (!password_.empty())
            {
                if (version_ == ShadowTlsVersion::V3)
                {
                    // v3 使用 SessionID (至少包含 HMAC-SHA256 签名)
                    if (sessionIdLen >= 8)
                    {
                        std::vector<uint8_t> hmacKey(password_.begin(), password_.end());
                        std::span<const uint8_t> challenge(random, 32);
                        auto expected = crypto::hmacSha256(hmacKey, challenge);
                        if (expected.has_value())
                        {
                            const size_t checkLen = std::min<size_t>(sessionIdLen, 8);
                            ok = (CRYPTO_memcmp(sessionId, expected->data(), checkLen) == 0);
                        }
                    }
                }
                else if (version_ == ShadowTlsVersion::V2)
                {
                    if (sessionIdLen == 32)
                    {
                        std::vector<uint8_t> hmacKey(password_.begin(), password_.end());
                        std::span<const uint8_t> challenge(sessionId, 4);
                        auto expected = crypto::hmacSha256(hmacKey, challenge);
                        if (expected.has_value())
                        {
                            ok = (CRYPTO_memcmp(sessionId + 4, expected->data(), 28) == 0);
                        }
                    }
                }
                else
                {
                    // v1 简易标记校验
                    ok = true;
                }
            }
            else
            {
                ok = true;
            }

            clientAuthenticated_ = ok;
            if (ok)
            {
                targetAddress_ = detourTarget_;
            }
            else
            {
                // 回落到真实 SNI 服务器或配置的 fallbackTarget
                if (!sni_.empty())
                {
                    targetAddress_ = ProxyAddress::fromDomain(sni_, 443);
                }
                else
                {
                    targetAddress_ = fallbackTarget_;
                }
            }

            stage_ = ShadowTlsStage::STREAMING;
            onMessageComplete();

            if (requestCallback_)
            {
                requestCallback_(clientAuthenticated_, *targetAddress_);
            }
            return true;
        }

        void parseSni(const uint8_t *handshake, size_t len)
        {
            // 找到 Extensions 偏移
            // [Type 1B][Len 3B][Ver 2B][Random 32B][SessionId 1B + N]
            size_t offset = 4 + 2 + 32;
            if (offset >= len)
            {
                return;
            }
            const uint8_t sidLen = handshake[offset++];
            offset += sidLen;
            if (offset + 2 > len)
            {
                return;
            }

            // Cipher Suites
            const uint16_t cipherLen = (static_cast<uint16_t>(handshake[offset]) << 8) | handshake[offset + 1];
            offset += 2 + cipherLen;
            if (offset + 1 > len)
            {
                return;
            }

            // Compression Methods
            const uint8_t compLen = handshake[offset++];
            offset += compLen;
            if (offset + 2 > len)
            {
                return;
            }

            // Extensions Length
            const uint16_t extTotalLen = (static_cast<uint16_t>(handshake[offset]) << 8) | handshake[offset + 1];
            offset += 2;
            const size_t extEnd = offset + extTotalLen;
            if (extEnd > len)
            {
                return;
            }

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
                        // [ServerNameListLen 2B][ServerNameType 1B][NameLen 2B][Name String]
                        const uint16_t nameLen =
                            (static_cast<uint16_t>(handshake[offset + 3]) << 8) | handshake[offset + 4];
                        if (offset + 5 + nameLen <= extEnd)
                        {
                            sni_ = std::string(reinterpret_cast<const char *>(handshake + offset + 5), nameLen);
                        }
                    }
                    break;
                }
                offset += extLen;
            }
        }
    };

} // namespace mynet::handler
