#pragma once

/**
 * @file handler/proxy/shadowtls.hpp
 * @brief ShadowTLS (v1/v2/v3) 协议服务端状态机处理器。
 */

#include "../address.hpp"
#include "../connection.hpp"
#include "../digest.hpp"
#include "../tls/fragmenter.hpp"
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
     * @brief ShadowTLS 服务端入站处理器
     */
    class HandlerInboundShadowTls : public HandlerInbound
    {
    public:
        using ShadowTlsRequestCallback = std::function<void(bool authenticated, const Address &target)>;

    private:
        ShadowTlsStage shadowTlsStage_{ShadowTlsStage::INSPECT_CLIENT_HELLO};
        ShadowTlsVersion version_{ShadowTlsVersion::V3};
        std::string password_{};
        Address detourTarget_{};   ///< 鉴权成功时的内部代理目标
        Address fallbackTarget_{}; ///< 鉴权失败/普通探测时的回落目标 (如 google.com:443)
        ShadowTlsRequestCallback shadowTlsCallback_{nullptr};

        bool clientAuthenticated_{false};
        std::string sni_{};

    public:
        HandlerInboundShadowTls() noexcept
        {
            detourTarget_ = Address::fromHostPort("127.0.0.1", 1080);
            fallbackTarget_ = Address::fromHostPort("google.com", 443);
        }

        HandlerInboundShadowTls(ShadowTlsVersion ver, std::string_view password, const Address &detour,
                                const Address &fallback)
            : version_(ver),
              password_(password),
              detourTarget_(detour),
              fallbackTarget_(fallback)
        {
        }

        ~HandlerInboundShadowTls() noexcept override = default;

        HandlerInboundShadowTls(const HandlerInboundShadowTls &) = delete;
        HandlerInboundShadowTls &operator=(const HandlerInboundShadowTls &) = delete;
        HandlerInboundShadowTls(HandlerInboundShadowTls &&) = delete;
        HandlerInboundShadowTls &operator=(HandlerInboundShadowTls &&) = delete;

        void setVersion(ShadowTlsVersion ver) noexcept { version_ = ver; }
        void setPassword(std::string_view pass) { password_ = std::string(pass); }
        void setDetourTarget(const Address &addr) { detourTarget_ = addr; }
        void setFallbackTarget(const Address &addr) { fallbackTarget_ = addr; }
        void setOnShadowTlsRequest(ShadowTlsRequestCallback cb) noexcept { shadowTlsCallback_ = std::move(cb); }

        [[nodiscard]] ShadowTlsStage stage() const noexcept { return shadowTlsStage_; }
        [[nodiscard]] bool isClientAuthenticated() const noexcept { return clientAuthenticated_; }
        [[nodiscard]] std::string_view sni() const noexcept { return sni_; }

        void reset() noexcept override
        {
            HandlerInbound::reset();
            shadowTlsStage_ = ShadowTlsStage::INSPECT_CLIENT_HELLO;
            clientAuthenticated_ = false;
            sni_.clear();
        }

        void onMessageComplete() noexcept {}
        void onParseError(const char *reason) noexcept
        {
            (void)reason;
            shadowTlsStage_ = ShadowTlsStage::ERROR;
            setStage(InboundStage::ERROR);
        }

        void handle()
        {
            if (shadowTlsStage_ == ShadowTlsStage::INSPECT_CLIENT_HELLO)
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
                shadowTlsStage_ = ShadowTlsStage::STREAMING;
                setStage(InboundStage::STREAMING);
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
                shadowTlsStage_ = ShadowTlsStage::STREAMING;
                setStage(InboundStage::STREAMING);
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
                        auto expected = digest::hmacSha256(hmacKey, challenge);
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
                        auto expected = digest::hmacSha256(hmacKey, challenge);
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
                    targetAddress_ = Address::fromDomain(sni_, 443);
                }
                else
                {
                    targetAddress_ = fallbackTarget_;
                }
            }

            shadowTlsStage_ = ShadowTlsStage::STREAMING;
            setStage(InboundStage::STREAMING);
            onMessageComplete();

            if (shadowTlsCallback_)
            {
                shadowTlsCallback_(clientAuthenticated_, *targetAddress_);
            }
            else if (requestCallback_)
            {
                requestCallback_(clientAuthenticated_ ? 0x01 : 0x00, *targetAddress_);
            }
            return true;
        }

        void parseSni(const uint8_t *handshake, size_t len)
        {
            if (handshake == nullptr || len == 0)
            {
                return;
            }
            if (auto info = tls::TlsFragmenter::findSni(std::span<const uint8_t>(handshake, len)); info.has_value())
            {
                sni_ = std::string(info->serverName);
            }
        }
    };

} // namespace mynet::handler
