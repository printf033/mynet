#pragma once

/**
 * @file proxy/trojan/trojan.hpp
 * @brief Trojan 代理协议服务端状态机处理器。
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

    namespace trojan
    {
        inline constexpr size_t kKeyLength = 56; ///< SHA-224 十六进制文本长度
        inline constexpr uint8_t kCmdConnect = 0x01;
        inline constexpr uint8_t kCmdUdp = 0x03;
        inline constexpr uint8_t kCmdMux = 0x7F;
    } // namespace trojan

    /**
     * @brief Trojan 会话状态
     */
    enum class TrojanStage : uint8_t
    {
        HEADER,    ///< 等待解析 Trojan 鉴权头部与目标地址
        STREAMING, ///< 握手成功，处于数据隧道/零拷贝透传阶段
        ERROR      ///< 鉴权失败或协议畸变
    };

    /**
     * @brief Trojan 协议状态机处理器
     */
    class HandlerTrojan : public HandlerConnection
    {
    public:
        using AuthCallback = std::function<bool(std::string_view hexHash)>;
        using RequestCallback = std::function<void(uint8_t cmd, const ProxyAddress &target)>;

        static constexpr bool kEnableSplice = true;

        inline void enableSpliceForward(int targetFd) noexcept { setSpliceTarget(targetFd); }
        inline void enableSpliceForward(SPLICE_CONTROL ctrl) noexcept { setSpliceTarget(ctrl); }
        inline void disableSpliceForward() noexcept { disableSplice(); }
        [[nodiscard]] inline bool isSpliceForwardActive() const noexcept { return isSpliceActive(); }

    private:
        TrojanStage stage_{TrojanStage::HEADER};
        AuthCallback authCallback_{nullptr};
        RequestCallback requestCallback_{nullptr};
        std::vector<std::string> validHexKeys_{};

        uint8_t command_{0};
        std::optional<ProxyAddress> targetAddress_{std::nullopt};

    public:
        HandlerTrojan() noexcept = default;
        explicit HandlerTrojan(std::string_view password) { setPassword(password); }
        ~HandlerTrojan() noexcept override = default;

        HandlerTrojan(const HandlerTrojan &) = delete;
        HandlerTrojan &operator=(const HandlerTrojan &) = delete;
        HandlerTrojan(HandlerTrojan &&) = delete;
        HandlerTrojan &operator=(HandlerTrojan &&) = delete;

        /**
         * @brief 设置单一合法密码
         */
        void setPassword(std::string_view password)
        {
            validHexKeys_.clear();
            validHexKeys_.push_back(crypto::sha224Hex(password));
        }

        /**
         * @brief 添加一个合法用户密码
         */
        void addUser(std::string_view password) { validHexKeys_.push_back(crypto::sha224Hex(password)); }

        /**
         * @brief 自定义鉴权回调（供复杂数据库/鉴权系统使用）
         */
        void setAuthenticator(AuthCallback cb) noexcept { authCallback_ = std::move(cb); }
        void setOnRequest(RequestCallback cb) noexcept { requestCallback_ = std::move(cb); }

        [[nodiscard]] TrojanStage stage() const noexcept { return stage_; }
        [[nodiscard]] bool isEstablished() const noexcept { return stage_ == TrojanStage::STREAMING; }
        [[nodiscard]] uint8_t command() const noexcept { return command_; }
        [[nodiscard]] const std::optional<ProxyAddress> &targetAddress() const noexcept { return targetAddress_; }

        void reset() noexcept override
        {
            HandlerConnection::reset();
            stage_ = TrojanStage::HEADER;
            command_ = 0;
            targetAddress_.reset();
            disableSpliceForward();
        }

        void onMessageComplete() noexcept {}
        void onParseError(const char *reason) noexcept
        {
            (void)reason;
            stage_ = TrojanStage::ERROR;
        }

        void process()
        {
            if (stage_ == TrojanStage::HEADER)
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
                stage_ = TrojanStage::ERROR;
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
                for (const auto &validKey : validHexKeys_)
                {
                    if (crypto::constantTimeEqual(keySpan, validKey))
                    {
                        authOk = true;
                        break;
                    }
                }
            }

            if (!authOk)
            {
                onParseError("Trojan: Authentication failed");
                stage_ = TrojanStage::ERROR;
                setCloseAfterResponse(true);
                return false;
            }

            // 2. 解析命令与目标地址
            const size_t cmdOffset = trojan::kKeyLength + 2;
            const uint8_t cmd = data[cmdOffset];
            const size_t addrOffset = cmdOffset + 1;

            size_t addrConsumed = 0;
            std::span<const uint8_t> addrSpan(data + addrOffset, avail - addrOffset);
            auto target = ProxyAddress::decodeSocks5(addrSpan, addrConsumed);
            if (!target.has_value())
            {
                // 地址部分尚未接收完整
                return false;
            }

            const size_t crlf2Offset = addrOffset + addrConsumed;
            if (avail < crlf2Offset + 2)
            {
                return false; // 等待结尾 CRLF
            }

            if (data[crlf2Offset] != '\r' || data[crlf2Offset + 1] != '\n')
            {
                onParseError("Trojan: Missing closing CRLF after target address");
                stage_ = TrojanStage::ERROR;
                setCloseAfterResponse(true);
                return false;
            }

            const size_t totalHeaderSize = crlf2Offset + 2;
            command_ = cmd;
            targetAddress_ = std::move(target);
            requestConsume(totalHeaderSize);

            stage_ = TrojanStage::STREAMING;
            onMessageComplete();

            if (requestCallback_)
            {
                requestCallback_(command_, *targetAddress_);
            }
            return true;
        }
    };

} // namespace mynet::handler
