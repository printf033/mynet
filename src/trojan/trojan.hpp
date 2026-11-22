#pragma once

/**
 * @file handler/proxy/trojan.hpp
 * @brief Trojan 代理协议入站状态机处理器 (HandlerInboundTrojan) 与出站协议处理器 (HandlerOutboundTrojan)。
 */

#include "../address.hpp"
#include "../connection.hpp"
#include "../digest.hpp"
#include "../encoding.hpp"
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mynet::handler
{

    namespace trojan
    {
        inline constexpr size_t kKeyLength = 56; ///< SHA-224 十六进制文本长度
        inline constexpr uint8_t kCmdConnect = 0x01;
        inline constexpr uint8_t kCmdUdp = 0x03;
        inline constexpr uint8_t kCmdMux = 0x7F;
    } // namespace trojan

    /**
     * @brief Trojan 协议入站状态机处理器
     */
    class HandlerInboundTrojan : public HandlerInboundConnectionBase
    {
    public:
        using AuthCallback = std::function<bool(std::string_view hexHash)>;

    private:
        AuthCallback authCallback_{nullptr};
        std::vector<std::string> validHexKeys_{};

    public:
        HandlerInboundTrojan() noexcept = default;
        explicit HandlerInboundTrojan(std::string_view password) { setPassword(password); }
        ~HandlerInboundTrojan() noexcept override = default;

        HandlerInboundTrojan(const HandlerInboundTrojan &) = delete;
        HandlerInboundTrojan &operator=(const HandlerInboundTrojan &) = delete;
        HandlerInboundTrojan(HandlerInboundTrojan &&) = delete;
        HandlerInboundTrojan &operator=(HandlerInboundTrojan &&) = delete;

        /**
         * @brief 设置单一合法密码
         */
        void setPassword(std::string_view password)
        {
            validHexKeys_.clear();
            validHexKeys_.push_back(digest::sha224Hex(password));
        }

        /**
         * @brief 添加一个合法用户密码
         */
        void addUser(std::string_view password) { validHexKeys_.push_back(digest::sha224Hex(password)); }

        /**
         * @brief 自定义鉴权回调（供复杂数据库/鉴权系统使用）
         */
        void setAuthenticator(AuthCallback cb) noexcept { authCallback_ = std::move(cb); }

        void reset() noexcept override { HandlerInboundConnectionBase::reset(); }

        void handle() override
        {
            if (inboundStage() == InboundStage::HANDSHAKE)
            {
                if (!processHeader())
                {
                    return;
                }
            }
        }

    private:
        bool processHeader()
        {
            // 协议头部结构：
            // [Key (56 B)][CRLF (2 B)][CMD (1 B)][Address (SOCKS5 format)][CRLF (2 B)]
            const size_t avail = requestBytes();
            if (avail < trojan::kKeyLength + 2 + 1 + 7 + 2)
            {
                return false;
            }

            const auto *data = reinterpret_cast<const uint8_t *>(requestBegin());

            // 1. 验证 56 字节 hex key 与第一个 CRLF
            std::string_view keySpan(reinterpret_cast<const char *>(data), trojan::kKeyLength);
            if (data[trojan::kKeyLength] != '\r' || data[trojan::kKeyLength + 1] != '\n')
            {
                onParseError("Trojan: Missing CRLF after auth key");
                setStage(InboundStage::ERROR);
                setCloseAfterResponse(true);
                return false;
            }

            bool authOk = false;
            if (authCallback_)
            {
                authOk = authCallback_(keySpan);
            }
            else
            {
                for (const auto &v : validHexKeys_)
                {
                    if (encoding::constantTimeEqual(keySpan, v))
                    {
                        authOk = true;
                        break;
                    }
                }
            }

            if (!authOk)
            {
                onParseError("Trojan: Unauthorized user hex key");
                setStage(InboundStage::ERROR);
                setCloseAfterResponse(true);
                return false;
            }

            // 2. 命令字 CMD
            const uint8_t cmd = data[trojan::kKeyLength + 2];

            // 3. 目标地址解析 (SOCKS5 格式)
            const size_t addrOffset = trojan::kKeyLength + 2 + 1;
            size_t addrConsumed = 0;
            std::span<const uint8_t> addrSpan(data + addrOffset, avail - addrOffset);
            auto target = ProxyAddress::decodeSocks5(addrSpan, addrConsumed);
            if (!target.has_value())
            {
                return false; // 地址不完整
            }

            const size_t afterAddr = addrOffset + addrConsumed;
            if (avail < afterAddr + 2)
            {
                return false; // 等待结尾 CRLF
            }

            if (data[afterAddr] != '\r' || data[afterAddr + 1] != '\n')
            {
                onParseError("Trojan: Missing CRLF after target address");
                setStage(InboundStage::ERROR);
                setCloseAfterResponse(true);
                return false;
            }

            const size_t totalHeaderSize = afterAddr + 2;
            command_ = cmd;
            targetAddress_ = std::move(target);
            requestConsume(totalHeaderSize);

            setStage(InboundStage::STREAMING);
            onMessageComplete();

            if (requestCallback_)
            {
                requestCallback_(command_, *targetAddress_);
            }
            return true;
        }
    };

    /**
     * @brief Trojan 出站协议处理器 (Trojan Outbound)
     *
     * 建立四元组连接后，在流首部自动填充并推送 Trojan 鉴权报文头：
     * [SHA-224 Hex Key (56B)][CRLF][CMD (0x01)][SOCKS5 Target Address][CRLF]
     */
    class HandlerOutboundTrojan : public HandlerOutboundConnectionBase
    {
    private:
        std::string hexKey_{};
        bool headerSent_{false};

    public:
        HandlerOutboundTrojan() noexcept = default;
        HandlerOutboundTrojan(std::string_view password, const ProxyAddress &target)
            : HandlerOutboundConnectionBase(target),
              hexKey_(digest::sha224Hex(password))
        {
        }

        void setPassword(std::string_view password) { hexKey_ = digest::sha224Hex(password); }

        void reset() noexcept override
        {
            HandlerOutboundConnectionBase::reset();
            headerSent_ = false;
        }

        void handle() override
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
            target().encodeSocks5(encodedAddr);
            header.append(reinterpret_cast<const char *>(encodedAddr.data()), encodedAddr.size());

            // 4. 结尾 CRLF
            header.append("\r\n");

            [[maybe_unused]] auto _ = pushResponse(std::move(header));
            headerSent_ = true;
            setStage(OutboundStage::STREAMING);
        }
    };

} // namespace mynet::handler
