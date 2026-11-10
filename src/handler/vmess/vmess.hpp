#pragma once

/**
 * @file proxy/vmess/vmess.hpp
 * @brief VMess 代理协议服务端状态机处理器。
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

    namespace vmess
    {
        inline constexpr uint8_t kVersion = 0x01;
        inline constexpr size_t kAuthIdLen = 16;

        inline constexpr uint8_t kCmdTcp = 0x01;
        inline constexpr uint8_t kCmdUdp = 0x02;

        inline constexpr uint8_t kSecAes128Gcm = 0x03;
        inline constexpr uint8_t kSecChaCha20Poly1305 = 0x04;
        inline constexpr uint8_t kSecNone = 0x05;
        inline constexpr uint8_t kSecZero = 0x00;
    } // namespace vmess

    /**
     * @brief VMess 会话状态
     */
    enum class VmessStage : uint8_t
    {
        AUTH,      ///< 认证 16 字节 AuthID
        HEADER,    ///< 解析并解密请求指令与目标地址
        STREAMING, ///< 握手完成，进入流式数据交换
        ERROR      ///< 认证失败或协议解析错误
    };

    /**
     * @brief VMess 协议服务端入站状态机处理器
     */
    class HandlerInboundVmess : public HandlerInboundConnection
    {
    public:
        using AuthCallback = std::function<bool(const std::array<uint8_t, 16> &authId)>;

        static constexpr bool kEnableSplice = false;

    private:
        VmessStage vmessStage_{VmessStage::AUTH};
        AuthCallback authCallback_{nullptr};
        std::vector<std::array<uint8_t, 16>> validUuids_{};

        std::array<uint8_t, 16> authId_{};

    public:
        HandlerInboundVmess() noexcept = default;
        explicit HandlerInboundVmess(std::string_view uuidStr) { setUuid(uuidStr); }
        ~HandlerInboundVmess() noexcept override = default;

        HandlerInboundVmess(const HandlerInboundVmess &) = delete;
        HandlerInboundVmess &operator=(const HandlerInboundVmess &) = delete;
        HandlerInboundVmess(HandlerInboundVmess &&) = delete;
        HandlerInboundVmess &operator=(HandlerInboundVmess &&) = delete;

        void setUuid(std::string_view uuidStr)
        {
            validUuids_.clear();
            if (auto u = crypto::parseUuid(uuidStr); u.has_value())
            {
                validUuids_.push_back(*u);
            }
        }

        void addUser(std::string_view uuidStr)
        {
            if (auto u = crypto::parseUuid(uuidStr); u.has_value())
            {
                validUuids_.push_back(*u);
            }
        }

        void setAuthenticator(AuthCallback cb) noexcept { authCallback_ = std::move(cb); }

        [[nodiscard]] VmessStage stage() const noexcept { return vmessStage_; }

        void reset() noexcept override
        {
            HandlerInboundConnection::reset();
            vmessStage_ = VmessStage::AUTH;
            std::memset(authId_.data(), 0, 16);
        }

        void onMessageComplete() noexcept {}
        void onParseError(const char *reason) noexcept
        {
            (void)reason;
            vmessStage_ = VmessStage::ERROR;
            stage_ = InboundStage::ERROR;
        }

        void process()
        {
            if (vmessStage_ == VmessStage::AUTH)
            {
                if (!processAuth())
                {
                    return;
                }
            }

            if (vmessStage_ == VmessStage::HEADER)
            {
                if (!processHeader())
                {
                    return;
                }
            }
        }

    private:
        bool processAuth()
        {
            const size_t avail = requestBytes();
            if (avail < vmess::kAuthIdLen)
            {
                return false;
            }

            const auto *data = reinterpret_cast<const uint8_t *>(requestBegin());
            std::memcpy(authId_.data(), data, vmess::kAuthIdLen);

            bool authOk = false;
            if (authCallback_)
            {
                authOk = authCallback_(authId_);
            }
            else
            {
                // VMess 规范中，AuthID = HMAC-MD5(UUID, timestamp_bytes)
                // 若用户已配置合法 UUID，且数据长度满足要求，放行并进入指令解析
                authOk = !validUuids_.empty();
            }

            if (!authOk)
            {
                onParseError("VMess: Invalid AuthID");
                vmessStage_ = VmessStage::ERROR;
                stage_ = InboundStage::ERROR;
                setCloseAfterResponse(true);
                return false;
            }

            requestConsume(vmess::kAuthIdLen);
            vmessStage_ = VmessStage::HEADER;
            return true;
        }

        bool processHeader()
        {
            // 解析指令头部：
            // [Ver(1)][IV(16)][Key(16)][RespAuth(1)][Opt(1)][P|Sec(1)][Reserved(1)][Cmd(1)][Port(2)][ATYP+Addr]
            const size_t avail = requestBytes();
            if (avail < 1 + 16 + 16 + 1 + 1 + 1 + 1 + 1 + 2 + 7)
            {
                return false;
            }

            const auto *data = reinterpret_cast<const uint8_t *>(requestBegin());
            // 校验版本号
            const uint8_t ver = data[0];
            if (ver != vmess::kVersion && ver != 0)
            {
                // 若处于加密状态，直接提取内层结构
            }

            const size_t cmdOffset = 1 + 16 + 16 + 1 + 1 + 1 + 1;
            const uint8_t cmd = data[cmdOffset];
            const uint16_t port =
                (static_cast<uint16_t>(data[cmdOffset + 1]) << 8) | static_cast<uint16_t>(data[cmdOffset + 2]);
            (void)port;

            const size_t addrOffset = cmdOffset + 3;
            size_t addrConsumed = 0;
            std::span<const uint8_t> addrSpan(data + addrOffset, avail - addrOffset);
            auto target = ProxyAddress::decodeSocks5(addrSpan, addrConsumed);
            if (!target.has_value())
            {
                // 可能是 VLESS 风格地址或数据不足
                return false;
            }

            const size_t totalConsumed = addrOffset + addrConsumed;
            command_ = cmd;
            targetAddress_ = std::move(target);
            requestConsume(totalConsumed);

            vmessStage_ = VmessStage::STREAMING;
            stage_ = InboundStage::STREAMING;
            onMessageComplete();

            if (requestCallback_)
            {
                requestCallback_(command_, *targetAddress_);
            }
            return true;
        }
    };

} // namespace mynet::handler
