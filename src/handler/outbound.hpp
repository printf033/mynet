#pragma once

/**
 * @file handler/outbound.hpp
 * @brief 出站协议状态机处理器族（对齐 HandlerOutbound... 命名风格）。
 */

#include "../connection.hpp"
#include "address.hpp"
#include "crypto.hpp"
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

    enum class OutboundStage : uint8_t
    {
        INITIAL,    ///< 初始未握手状态
        CONNECTING, ///< 正在发送出站协议头部或等待对端认证回执
        STREAMING,  ///< 握手完成，进入流式数据透传/内核零拷贝转发
        ERROR       ///< 出站协议握手失败或对端报错
    };

    /**
     * @brief 客户端出站协议处理器基类
     *
     * 派生自 HandlerConnection，满足 HandlerConstraint 与 MandatoryMethodConnection。
     */
    class HandlerOutbound : public HandlerConnection
    {
    public:
        static constexpr bool kEnableSplice = true;

        inline void enableSpliceForward(int targetFd) noexcept { setSpliceTarget(targetFd); }
        inline void enableSpliceForward(SPLICE_CONTROL ctrl) noexcept { setSpliceTarget(ctrl); }
        inline void disableSpliceForward() noexcept { disableSplice(); }
        [[nodiscard]] inline bool isSpliceForwardActive() const noexcept { return isSpliceActive(); }

    protected:
        OutboundStage stage_{OutboundStage::INITIAL};
        ProxyAddress target_{};

    public:
        HandlerOutbound() noexcept = default;
        explicit HandlerOutbound(const ProxyAddress &target) noexcept
            : target_(target)
        {
        }
        ~HandlerOutbound() noexcept override = default;

        HandlerOutbound(const HandlerOutbound &) = delete;
        HandlerOutbound &operator=(const HandlerOutbound &) = delete;
        HandlerOutbound(HandlerOutbound &&) = delete;
        HandlerOutbound &operator=(HandlerOutbound &&) = delete;

        void setTarget(const ProxyAddress &target) noexcept { target_ = target; }
        [[nodiscard]] const ProxyAddress &target() const noexcept { return target_; }
        [[nodiscard]] OutboundStage stage() const noexcept { return stage_; }
        [[nodiscard]] bool isEstablished() const noexcept { return stage_ == OutboundStage::STREAMING; }

        void reset() noexcept override
        {
            HandlerConnection::reset();
            stage_ = OutboundStage::INITIAL;
            target_ = {};
            disableSpliceForward();
        }

        void onMessageComplete() noexcept override {}
        void onParseError(const char *reason) noexcept override
        {
            (void)reason;
            stage_ = OutboundStage::ERROR;
        }

        virtual void process() {}
    };

    /**
     * @brief 直连出站处理器 (Direct Outbound)
     *
     * 初始即处于 STREAMING 状态，建连后可直接通过 splice 桥接入站。
     */
    class HandlerOutboundDirect : public HandlerOutbound
    {
    public:
        HandlerOutboundDirect() noexcept
        {
            stage_ = OutboundStage::STREAMING;
        }

        explicit HandlerOutboundDirect(const ProxyAddress &target) noexcept
            : HandlerOutbound(target)
        {
            stage_ = OutboundStage::STREAMING;
        }

        void reset() noexcept override
        {
            HandlerOutbound::reset();
            stage_ = OutboundStage::STREAMING;
        }

        void process() override {}
    };

    /**
     * @brief Trojan 出站协议处理器 (Trojan Outbound)
     *
     * 建立四元组连接后，在流首部自动填充并推送 Trojan 鉴权报文头：
     * [SHA-224 Hex Key (56B)][CRLF][CMD (0x01)][SOCKS5 Target Address][CRLF]
     */
    class HandlerOutboundTrojan : public HandlerOutbound
    {
    private:
        std::string hexKey_{};
        bool headerSent_{false};

    public:
        HandlerOutboundTrojan() noexcept = default;
        HandlerOutboundTrojan(std::string_view password, const ProxyAddress &target)
            : HandlerOutbound(target),
              hexKey_(crypto::sha224Hex(password))
        {
        }

        void setPassword(std::string_view password)
        {
            hexKey_ = crypto::sha224Hex(password);
        }

        void reset() noexcept override
        {
            HandlerOutbound::reset();
            headerSent_ = false;
        }

        void process() override
        {
            if (!headerSent_)
            {
                sendHandshakeHeader();
            }
        }

    private:
        void sendHandshakeHeader()
        {
            if (hexKey_.empty())
            {
                onParseError("HandlerOutboundTrojan: Missing password");
                return;
            }

            std::string header;
            header.reserve(56 + 2 + 1 + 64 + 2);

            // 1. 56 字节 SHA-224 十六进制密钥 + CRLF
            header.append(hexKey_);
            header.append("\r\n");

            // 2. CMD (0x01 TCP CONNECT)
            header.push_back(0x01);

            // 3. SOCKS5 目标网络地址
            std::vector<uint8_t> encodedAddr;
            target_.encodeSocks5(encodedAddr);
            header.append(reinterpret_cast<const char *>(encodedAddr.data()), encodedAddr.size());

            // 4. 结尾 CRLF
            header.append("\r\n");

            [[maybe_unused]] auto _ = pushResponse(std::move(header));
            headerSent_ = true;
            stage_ = OutboundStage::STREAMING;
        }
    };

    /**
     * @brief VLESS (v0) 出站协议处理器 (VLESS Outbound)
     *
     * 建立四元组后发送 VLESS 首包：
     * [Version 0x00][UUID 16B][AddonLen 0x00][CMD 0x01][Port 2B BE][Address ATYP + Body]
     * 接收 2 字节回执 [0x00, 0x00] 后进入 STREAMING 阶段。
     */
    class HandlerOutboundVless : public HandlerOutbound
    {
    private:
        std::array<uint8_t, 16> uuid_{};
        bool headerSent_{false};

    public:
        HandlerOutboundVless() noexcept = default;
        HandlerOutboundVless(const std::array<uint8_t, 16> &uuid, const ProxyAddress &target)
            : HandlerOutbound(target),
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
            HandlerOutbound::reset();
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

    /**
     * @brief SOCKS5 出站协议客户端处理器 (SOCKS5 Outbound)
     *
     * 自动处理与上游 SOCKS5 代理服务器的握手与 CONNECT 建连指令。
     */
    class HandlerOutboundSocks5 : public HandlerOutbound
    {
    private:
        enum class Step : uint8_t
        {
            SEND_GREETING,
            RECV_GREETING,
            RECV_CONNECT,
            DONE
        };
        Step step_{Step::SEND_GREETING};

    public:
        HandlerOutboundSocks5() noexcept = default;
        explicit HandlerOutboundSocks5(const ProxyAddress &target) noexcept
            : HandlerOutbound(target)
        {
        }

        void reset() noexcept override
        {
            HandlerOutbound::reset();
            step_ = Step::SEND_GREETING;
        }

        void process() override
        {
            switch (step_)
            {
            case Step::SEND_GREETING:
            {
                // 发送 [VER 0x05, NMETHODS 0x01, METHOD 0x00 (NO AUTH)]
                static constexpr char kGreeting[] = {0x05, 0x01, 0x00};
                [[maybe_unused]] auto _ = pushResponse(std::string_view(kGreeting, 3));
                step_ = Step::RECV_GREETING;
                stage_ = OutboundStage::CONNECTING;
                break;
            }
            case Step::RECV_GREETING:
            {
                if (requestBytes() < 2)
                {
                    return;
                }
                const auto *data = reinterpret_cast<const uint8_t *>(requestBegin());
                if (data[0] != 0x05 || data[1] != 0x00)
                {
                    onParseError("HandlerOutboundSocks5: Server rejected authentication");
                    return;
                }
                requestConsume(2);

                // 发送 CONNECT 请求
                std::vector<uint8_t> req = {0x05, 0x01, 0x00};
                target_.encodeSocks5(req);
                [[maybe_unused]] auto _ =
                    pushResponse(std::string_view(reinterpret_cast<const char *>(req.data()), req.size()));

                step_ = Step::RECV_CONNECT;
                break;
            }
            case Step::RECV_CONNECT:
            {
                // SOCKS5 响应头部至少 4 字节: VER, REP, RSV, ATYP
                if (requestBytes() < 4)
                {
                    return;
                }
                const auto *data = reinterpret_cast<const uint8_t *>(requestBegin());
                if (data[1] != 0x00) // REP != 0x00
                {
                    onParseError("HandlerOutboundSocks5: CONNECT failed");
                    return;
                }

                size_t consumed = 0;
                auto boundAddr = ProxyAddress::decodeSocks5(
                    std::span<const uint8_t>(data + 3, requestBytes() - 3), consumed);
                if (!boundAddr.has_value())
                {
                    return; // 数据尚不足
                }
                requestConsume(3 + consumed);
                step_ = Step::DONE;
                stage_ = OutboundStage::STREAMING;
                break;
            }
            case Step::DONE:
                break;
            }
        }
    };

    /**
     * @brief 黑洞阻断出站处理器 (Block Outbound)
     */
    class HandlerOutboundBlock : public HandlerOutbound
    {
    public:
        HandlerOutboundBlock() noexcept
        {
            setCloseAfterResponse(true);
            stage_ = OutboundStage::ERROR;
        }

        void reset() noexcept override
        {
            HandlerOutbound::reset();
            setCloseAfterResponse(true);
            stage_ = OutboundStage::ERROR;
        }

        void process() override
        {
            if (requestBytes() > 0)
            {
                requestConsume(requestBytes());
            }
            setCloseAfterResponse(true);
        }
    };

} // namespace mynet::handler

namespace mynet
{
    // 全局命名空间导出
    using handler::HandlerOutbound;
    using handler::HandlerOutboundBlock;
    using handler::HandlerOutboundDirect;
    using handler::HandlerOutboundSocks5;
    using handler::HandlerOutboundTrojan;
    using handler::HandlerOutboundVless;
} // namespace mynet
