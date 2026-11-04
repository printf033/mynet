#pragma once

/**
 * @file proxy/hysteria2.hpp
 * @brief Hysteria 2 代理协议状态机处理器。
 */

#include "../connection.hpp"
#include "address.hpp"
#include "crypto.hpp"
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mynet::proxy
{

    namespace hysteria2
    {
        inline constexpr uint8_t kCmdTcp = 0x01;
        inline constexpr uint8_t kCmdUdp = 0x02;

        inline constexpr uint8_t kStatusOk = 0x00;
        inline constexpr uint8_t kStatusAuthFailed = 0x01;
    } // namespace hysteria2

    enum class Hysteria2Stage : uint8_t
    {
        AUTH,      ///< 鉴权与目标指令解析
        STREAMING, ///< 握手成功，进入双向数据转发
        ERROR      ///< 鉴权失败或协议错误
    };

    /**
     * @brief Hysteria 2 协议状态机处理器
     */
    class HandlerHysteria2 : public HandlerConnection
    {
    public:
        using AuthCallback = std::function<bool(std::string_view authStr)>;
        using RequestCallback = std::function<void(uint8_t cmd, const ProxyAddress &target)>;

        static constexpr bool kEnableSplice = true;

        inline void enableSpliceForward(int targetFd) noexcept { setSpliceTarget(targetFd); }
        inline void enableSpliceForward(SPLICE_CONTROL ctrl) noexcept { setSpliceTarget(ctrl); }
        inline void disableSpliceForward() noexcept { disableSplice(); }
        [[nodiscard]] inline bool isSpliceForwardActive() const noexcept { return isSpliceActive(); }

    private:
        Hysteria2Stage stage_{Hysteria2Stage::AUTH};
        std::string password_{};
        AuthCallback authCallback_{nullptr};
        RequestCallback requestCallback_{nullptr};

        uint8_t command_{0};
        std::optional<ProxyAddress> targetAddress_{std::nullopt};
        bool autoReplyOk_{true};

    public:
        HandlerHysteria2() noexcept = default;
        explicit HandlerHysteria2(std::string_view password)
            : password_(password)
        {
        }
        ~HandlerHysteria2() noexcept override = default;

        HandlerHysteria2(const HandlerHysteria2 &) = delete;
        HandlerHysteria2 &operator=(const HandlerHysteria2 &) = delete;
        HandlerHysteria2(HandlerHysteria2 &&) = delete;
        HandlerHysteria2 &operator=(HandlerHysteria2 &&) = delete;

        void setPassword(std::string_view pass) { password_ = std::string(pass); }
        void setAuthenticator(AuthCallback cb) noexcept { authCallback_ = std::move(cb); }
        void setOnRequest(RequestCallback cb) noexcept { requestCallback_ = std::move(cb); }

        [[nodiscard]] Hysteria2Stage stage() const noexcept { return stage_; }
        [[nodiscard]] bool isEstablished() const noexcept { return stage_ == Hysteria2Stage::STREAMING; }
        [[nodiscard]] uint8_t command() const noexcept { return command_; }
        [[nodiscard]] const std::optional<ProxyAddress> &targetAddress() const noexcept { return targetAddress_; }

        void reset() noexcept override
        {
            HandlerConnection::reset();
            stage_ = Hysteria2Stage::AUTH;
            command_ = 0;
            targetAddress_.reset();
            disableSpliceForward();
        }

        void onMessageComplete() noexcept {}
        void onParseError(const char *reason) noexcept
        {
            (void)reason;
            stage_ = Hysteria2Stage::ERROR;
        }

        void process()
        {
            if (stage_ == Hysteria2Stage::AUTH)
            {
                if (!processAuth())
                {
                    return;
                }
            }
        }

        void sendReply(uint8_t status)
        {
            const char reply[1] = {static_cast<char>(status)};
            [[maybe_unused]] auto _ = pushResponse(std::string_view(reply, 1));
        }

    private:
        bool processAuth()
        {
            // 首部格式：[AuthLen 1B][AuthStr AuthLen B][CMD 1B][Address (SOCKS5)]
            const size_t avail = requestBytes();
            if (avail < 1)
            {
                return false;
            }

            const auto *data = reinterpret_cast<const uint8_t *>(requestBegin());
            const uint8_t authLen = data[0];
            const size_t minHeader = 1 + static_cast<size_t>(authLen) + 1 + 7;
            if (avail < minHeader)
            {
                return false;
            }

            std::string_view authStr(reinterpret_cast<const char *>(data + 1), authLen);

            bool ok = false;
            if (authCallback_)
            {
                ok = authCallback_(authStr);
            }
            else
            {
                ok = (authStr == password_);
            }

            if (!ok)
            {
                sendReply(hysteria2::kStatusAuthFailed);
                onParseError("Hysteria2: Authentication failed");
                stage_ = Hysteria2Stage::ERROR;
                setCloseAfterResponse(true);
                return false;
            }

            const size_t cmdOffset = 1 + authLen;
            const uint8_t cmd = data[cmdOffset];
            const size_t addrOffset = cmdOffset + 1;

            size_t addrConsumed = 0;
            std::span<const uint8_t> addrSpan(data + addrOffset, avail - addrOffset);
            auto target = ProxyAddress::decodeSocks5(addrSpan, addrConsumed);
            if (!target.has_value())
            {
                return false;
            }

            const size_t totalHeader = addrOffset + addrConsumed;
            command_ = cmd;
            targetAddress_ = std::move(target);
            requestConsume(totalHeader);

            if (autoReplyOk_)
            {
                sendReply(hysteria2::kStatusOk);
            }

            stage_ = Hysteria2Stage::STREAMING;
            onMessageComplete();

            if (requestCallback_)
            {
                requestCallback_(command_, *targetAddress_);
            }
            return true;
        }
    };

} // namespace mynet::proxy
