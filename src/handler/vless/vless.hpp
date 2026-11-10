#pragma once

/**
 * @file handler/vless/vless.hpp
 * @brief VLESS (v0) 代理协议入站状态机处理器 (HandlerInboundVless) 与出站协议处理器 (HandlerOutboundVless)。
 */

#include "../address.hpp"
#include "../crypto.hpp"
#include "../inbound.hpp"
#include "../outbound.hpp"
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
     * @brief VLESS (v0) 入站协议状态机处理器
     */
    class HandlerInboundVless : public HandlerInboundConnection
    {
    public:
        using AuthCallback = std::function<bool(const std::array<uint8_t, 16> &uuid)>;

    private:
        AuthCallback authCallback_{nullptr};
        std::vector<std::array<uint8_t, 16>> validUuids_{};

        std::array<uint8_t, 16> clientUuid_{};
        bool autoReplySuccess_{true};

    public:
        HandlerInboundVless() noexcept = default;
        explicit HandlerInboundVless(std::string_view uuidStr) { setUuid(uuidStr); }
        ~HandlerInboundVless() noexcept override = default;

        HandlerInboundVless(const HandlerInboundVless &) = delete;
        HandlerInboundVless &operator=(const HandlerInboundVless &) = delete;
        HandlerInboundVless(HandlerInboundVless &&) = delete;
        HandlerInboundVless &operator=(HandlerInboundVless &&) = delete;

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
        void setAutoReply(bool autoReply) noexcept { autoReplySuccess_ = autoReply; }

        [[nodiscard]] const std::array<uint8_t, 16> &clientUuid() const noexcept { return clientUuid_; }

        void reset() noexcept override
        {
            HandlerInboundConnection::reset();
            std::memset(clientUuid_.data(), 0, 16);
        }

        void process() override
        {
            if (stage_ == InboundStage::HANDSHAKE)
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
                stage_ = InboundStage::ERROR;
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
                stage_ = InboundStage::ERROR;
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

            stage_ = InboundStage::STREAMING;
            onMessageComplete();

            if (requestCallback_)
            {
                requestCallback_(command_, *targetAddress_);
            }
            return true;
        }
    };

    /**
     * @brief VLESS (v0) 出站协议处理器 (VLESS Outbound)
     *
     * 建立四元组后发送 VLESS 首包：
     * [Version 0x00][UUID 16B][AddonLen 0x00][CMD 0x01][Port 2B BE][Address ATYP + Body]
     * 接收 2 字节回执 [0x00, 0x00] 后进入 STREAMING 阶段。
     */
    class HandlerOutboundVless : public HandlerOutboundConnection
    {
    private:
        std::array<uint8_t, 16> uuid_{};
        bool headerSent_{false};

    public:
        HandlerOutboundVless() noexcept = default;
        HandlerOutboundVless(const std::array<uint8_t, 16> &uuid, const ProxyAddress &target)
            : HandlerOutboundConnection(target),
              uuid_(uuid)
        {
        }

        void setUuid(const std::array<uint8_t, 16> &uuid) noexcept { uuid_ = uuid; }

        bool setUuidString(std::string_view uuidStr) noexcept
        {
            auto parsed = crypto::parseUuid(uuidStr);
            if (!parsed.has_value())
            {
                return false;
            }
            uuid_ = *parsed;
            return true;
        }

        void reset() noexcept override
        {
            HandlerOutboundConnection::reset();
            headerSent_ = false;
        }

        void process() override
        {
            if (!headerSent_)
            {
                sendVlessHeader();
            }

            if (stage_ == OutboundStage::CONNECTING)
            {
                // 等待服务端 2 字节握手回执 [0x00, 0x00]
                if (requestBytes() >= 2)
                {
                    const auto *resp = reinterpret_cast<const uint8_t *>(requestBegin());
                    if (resp[0] != 0x00) // Version
                    {
                        onParseError("HandlerOutboundVless: Invalid version in server response");
                        return;
                    }
                    const uint8_t addonLen = resp[1];
                    if (requestBytes() >= static_cast<size_t>(2 + addonLen))
                    {
                        requestConsume(2 + addonLen);
                        stage_ = OutboundStage::STREAMING;
                    }
                }
            }
        }

    private:
        void sendVlessHeader()
        {
            std::vector<uint8_t> header;
            header.reserve(1 + 16 + 1 + 1 + 2 + 64);

            header.push_back(0x00); // Version 0
            header.insert(header.end(), uuid_.begin(), uuid_.end()); // 16 字节 UUID
            header.push_back(0x00); // Addon length 0

            header.push_back(0x01); // CMD: 0x01 (TCP)
            header.push_back(static_cast<uint8_t>(target_.port >> 8));
            header.push_back(static_cast<uint8_t>(target_.port & 0xFF));

            // ATYP + Address
            header.push_back(static_cast<uint8_t>(target_.type));
            if (target_.type == AddressType::IPV4)
            {
                const auto *p = reinterpret_cast<const uint8_t *>(&target_.ipv4_.s_addr);
                header.insert(header.end(), p, p + 4);
            }
            else if (target_.type == AddressType::DOMAIN)
            {
                header.push_back(static_cast<uint8_t>(target_.host.size()));
                header.insert(header.end(), target_.host.begin(), target_.host.end());
            }
            else if (target_.type == AddressType::IPV6)
            {
                const auto *p = reinterpret_cast<const uint8_t *>(&target_.ipv6_);
                header.insert(header.end(), p, p + 16);
            }

            [[maybe_unused]] auto _ =
                pushResponse(std::string_view(reinterpret_cast<const char *>(header.data()), header.size()));
            headerSent_ = true;
            stage_ = OutboundStage::CONNECTING;
        }
    };

} // namespace mynet::handler
