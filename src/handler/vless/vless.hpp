#pragma once

/**
 * @file proxy/vless/vless.hpp
 * @brief VLESS (v0) 代理协议服务端状态机处理器。
 */

#include "../../connection.hpp"
#include "../address.hpp"
#include "../crypto.hpp"
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

    namespace vless
    {
        inline constexpr uint8_t kVersion = 0x00;

        inline constexpr uint8_t kCmdTcp = 0x01;
        inline constexpr uint8_t kCmdUdp = 0x02;
        inline constexpr uint8_t kCmdMux = 0x03;
    } // namespace vless

    /**
     * @brief VLESS 会话状态
     */
    enum class VlessStage : uint8_t
    {
        HEADER,    ///< 等待解析 VLESS 请求头部
        STREAMING, ///< 握手成功并回送响应，进入数据流式透传
        ERROR      ///< UUID 鉴权失败或协议畸变
    };

    /**
     * @brief VLESS (v0) 协议状态机处理器
     */
    class HandlerVless : public HandlerConnection
    {
    public:
        using AuthCallback = std::function<bool(const std::array<uint8_t, 16> &uuid)>;
        using RequestCallback = std::function<void(uint8_t cmd, const ProxyAddress &target)>;

        static constexpr bool kEnableSplice = true;

        inline void enableSpliceForward(int targetFd) noexcept { setSpliceTarget(targetFd); }
        inline void enableSpliceForward(SPLICE_CONTROL ctrl) noexcept { setSpliceTarget(ctrl); }
        inline void disableSpliceForward() noexcept { disableSplice(); }
        [[nodiscard]] inline bool isSpliceForwardActive() const noexcept { return isSpliceActive(); }

    private:
        VlessStage stage_{VlessStage::HEADER};
        AuthCallback authCallback_{nullptr};
        RequestCallback requestCallback_{nullptr};
        std::vector<std::array<uint8_t, 16>> validUuids_{};

        uint8_t command_{0};
        std::array<uint8_t, 16> clientUuid_{};
        std::optional<ProxyAddress> targetAddress_{std::nullopt};
        bool autoReplySuccess_{true};

    public:
        HandlerVless() noexcept = default;
        explicit HandlerVless(std::string_view uuidStr) { setUuid(uuidStr); }
        ~HandlerVless() noexcept override = default;

        HandlerVless(const HandlerVless &) = delete;
        HandlerVless &operator=(const HandlerVless &) = delete;
        HandlerVless(HandlerVless &&) = delete;
        HandlerVless &operator=(HandlerVless &&) = delete;

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
        void setOnRequest(RequestCallback cb) noexcept { requestCallback_ = std::move(cb); }
        void setAutoReply(bool autoReply) noexcept { autoReplySuccess_ = autoReply; }

        [[nodiscard]] VlessStage stage() const noexcept { return stage_; }
        [[nodiscard]] bool isEstablished() const noexcept { return stage_ == VlessStage::STREAMING; }
        [[nodiscard]] uint8_t command() const noexcept { return command_; }
        [[nodiscard]] const std::array<uint8_t, 16> &clientUuid() const noexcept { return clientUuid_; }
        [[nodiscard]] const std::optional<ProxyAddress> &targetAddress() const noexcept { return targetAddress_; }

        void reset() noexcept override
        {
            HandlerConnection::reset();
            stage_ = VlessStage::HEADER;
            command_ = 0;
            std::memset(clientUuid_.data(), 0, 16);
            targetAddress_.reset();
            disableSpliceForward();
        }

        void onMessageComplete() noexcept {}
        void onParseError(const char *reason) noexcept
        {
            (void)reason;
            stage_ = VlessStage::ERROR;
        }

        void process()
        {
            if (stage_ == VlessStage::HEADER)
            {
                if (!processHeader())
                {
                    return;
                }
            }
        }

        /**
         * @brief 向客户端发送 VLESS 响应头 (Version 0x00 + Addon Length 0x00)
         */
        void sendReply()
        {
            static constexpr char kReply[2] = {static_cast<char>(vless::kVersion), 0x00};
            [[maybe_unused]] auto _ = pushResponse(std::string_view(kReply, 2));
        }

    private:
        bool processHeader()
        {
            // VLESS 规范格式：
            // [Ver(1B)][UUID(16B)][AddonLen(1B)][Addons(M B)][CMD(1B)][Port(2B BE)][ATYP(1B)][Address(Var B)]
            const size_t avail = requestBytes();
            if (avail < 1 + 16 + 1)
            {
                return false;
            }

            const auto *data = reinterpret_cast<const uint8_t *>(requestBegin());
            if (data[0] != vless::kVersion)
            {
                onParseError("VLESS: Unsupported version");
                stage_ = VlessStage::ERROR;
                setCloseAfterResponse(true);
                return false;
            }

            std::array<uint8_t, 16> uuid{};
            std::memcpy(uuid.data(), data + 1, 16);

            const uint8_t addonLen = data[17];
            const size_t minHeaderBeforeAddr = 1 + 16 + 1 + addonLen + 1 + 2 + 1;
            if (avail < minHeaderBeforeAddr)
            {
                return false;
            }

            // 认证 UUID
            bool authOk = false;
            if (authCallback_)
            {
                authOk = authCallback_(uuid);
            }
            else
            {
                for (const auto &v : validUuids_)
                {
                    if (crypto::constantTimeEqual(uuid, v))
                    {
                        authOk = true;
                        break;
                    }
                }
            }

            if (!authOk)
            {
                onParseError("VLESS: Unauthorized UUID");
                stage_ = VlessStage::ERROR;
                setCloseAfterResponse(true);
                return false;
            }

            const size_t cmdOffset = 1 + 16 + 1 + addonLen;
            const uint8_t cmd = data[cmdOffset];
            const uint16_t port =
                (static_cast<uint16_t>(data[cmdOffset + 1]) << 8) | static_cast<uint16_t>(data[cmdOffset + 2]);
            const uint8_t atyp = data[cmdOffset + 3];
            const size_t addrOffset = cmdOffset + 4;

            size_t addrConsumed = 0;
            std::span<const uint8_t> addrSpan(data + addrOffset, avail - addrOffset);
            auto target = ProxyAddress::decodeVlessAddress(atyp, addrSpan, port, addrConsumed);
            if (!target.has_value())
            {
                return false; // 地址尚未完整
            }

            const size_t totalHeaderSize = addrOffset + addrConsumed;
            command_ = cmd;
            clientUuid_ = uuid;
            targetAddress_ = std::move(target);
            requestConsume(totalHeaderSize);

            if (autoReplySuccess_)
            {
                sendReply();
            }

            stage_ = VlessStage::STREAMING;
            onMessageComplete();

            if (requestCallback_)
            {
                requestCallback_(command_, *targetAddress_);
            }
            return true;
        }
    };

} // namespace mynet::handler
