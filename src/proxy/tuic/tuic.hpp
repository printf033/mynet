#pragma once

/**
 * @file proxy/tuic/tuic.hpp
 * @brief TUIC (v5) 代理协议状态机处理器。
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

namespace mynet::proxy
{

    namespace tuic
    {
        inline constexpr uint8_t kCmdConnect = 0x01;
        inline constexpr uint8_t kCmdPacket = 0x02;
        inline constexpr uint8_t kCmdHeartbeat = 0x03;

        inline constexpr uint8_t kRepSuccess = 0x00;
        inline constexpr uint8_t kRepAuthFailure = 0x01;
    } // namespace tuic

    enum class TuicStage : uint8_t
    {
        HEADER,    ///< 鉴权与目标指令解析
        STREAMING, ///< 握手成功，进入双向数据转发
        ERROR      ///< 鉴权失败或协议错误
    };

    /**
     * @brief TUIC 协议状态机处理器
     */
    class HandlerTuic : public HandlerConnection
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
        TuicStage stage_{TuicStage::HEADER};
        std::array<uint8_t, 16> expectedUuid_{};
        AuthCallback authCallback_{nullptr};
        RequestCallback requestCallback_{nullptr};

        uint8_t command_{0};
        std::optional<ProxyAddress> targetAddress_{std::nullopt};
        bool autoReplySuccess_{true};

    public:
        HandlerTuic() noexcept = default;
        explicit HandlerTuic(std::string_view uuidStr) { setUuid(uuidStr); }
        ~HandlerTuic() noexcept override = default;

        HandlerTuic(const HandlerTuic &) = delete;
        HandlerTuic &operator=(const HandlerTuic &) = delete;
        HandlerTuic(HandlerTuic &&) = delete;
        HandlerTuic &operator=(HandlerTuic &&) = delete;

        void setUuid(std::string_view uuidStr)
        {
            if (auto u = crypto::parseUuid(uuidStr); u.has_value())
            {
                expectedUuid_ = *u;
            }
        }

        void setAuthenticator(AuthCallback cb) noexcept { authCallback_ = std::move(cb); }
        void setOnRequest(RequestCallback cb) noexcept { requestCallback_ = std::move(cb); }

        [[nodiscard]] TuicStage stage() const noexcept { return stage_; }
        [[nodiscard]] bool isEstablished() const noexcept { return stage_ == TuicStage::STREAMING; }
        [[nodiscard]] uint8_t command() const noexcept { return command_; }
        [[nodiscard]] const std::optional<ProxyAddress> &targetAddress() const noexcept { return targetAddress_; }

        void reset() noexcept override
        {
            HandlerConnection::reset();
            stage_ = TuicStage::HEADER;
            command_ = 0;
            targetAddress_.reset();
            disableSpliceForward();
        }

        void onMessageComplete() noexcept {}
        void onParseError(const char *reason) noexcept
        {
            (void)reason;
            stage_ = TuicStage::ERROR;
        }

        void process()
        {
            if (stage_ == TuicStage::HEADER)
            {
                if (!processHeader())
                {
                    return;
                }
            }
        }

        void sendReply(uint8_t rep)
        {
            const char reply[1] = {static_cast<char>(rep)};
            [[maybe_unused]] auto _ = pushResponse(std::string_view(reply, 1));
        }

    private:
        bool processHeader()
        {
            // 首部格式：[CMD 1B][UUID 16B][Address (SOCKS5)]
            const size_t avail = requestBytes();
            if (avail < 1 + 16 + 7)
            {
                return false;
            }

            const auto *data = reinterpret_cast<const uint8_t *>(requestBegin());
            const uint8_t cmd = data[0];

            std::array<uint8_t, 16> clientUuid{};
            std::memcpy(clientUuid.data(), data + 1, 16);

            bool ok = false;
            if (authCallback_)
            {
                ok = authCallback_(clientUuid);
            }
            else
            {
                ok = crypto::constantTimeEqual(clientUuid, expectedUuid_);
            }

            if (!ok)
            {
                sendReply(tuic::kRepAuthFailure);
                onParseError("TUIC: Authentication failed");
                stage_ = TuicStage::ERROR;
                setCloseAfterResponse(true);
                return false;
            }

            size_t addrConsumed = 0;
            std::span<const uint8_t> addrSpan(data + 17, avail - 17);
            auto target = ProxyAddress::decodeSocks5(addrSpan, addrConsumed);
            if (!target.has_value())
            {
                return false;
            }

            const size_t totalHeader = 17 + addrConsumed;
            command_ = cmd;
            targetAddress_ = std::move(target);
            requestConsume(totalHeader);

            if (autoReplySuccess_)
            {
                sendReply(tuic::kRepSuccess);
            }

            stage_ = TuicStage::STREAMING;
            onMessageComplete();

            if (requestCallback_)
            {
                requestCallback_(command_, *targetAddress_);
            }
            return true;
        }
    };

} // namespace mynet::proxy
