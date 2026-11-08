#pragma once

/**
 * @file proxy/snell/snell.hpp
 * @brief Snell 代理协议服务端状态机处理器。
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

namespace mynet::proxy
{

    namespace snell
    {
        inline constexpr uint8_t kCmdConnect = 0x01;
        inline constexpr uint8_t kCmdPing = 0x02;
    } // namespace snell

    enum class SnellStage : uint8_t
    {
        HEADER,    ///< 等待解析 Snell 请求首部
        STREAMING, ///< 握手完成，进入流式数据交换
        ERROR      ///< PSK 鉴权失败或协议畸变
    };

    /**
     * @brief Snell 协议状态机处理器
     */
    class HandlerSnell : public HandlerConnection
    {
    public:
        using RequestCallback = std::function<void(uint8_t cmd, const ProxyAddress &target)>;

        static constexpr bool kEnableSplice = true;

        inline void enableSpliceForward(int targetFd) noexcept { setSpliceTarget(targetFd); }
        inline void enableSpliceForward(SPLICE_CONTROL ctrl) noexcept { setSpliceTarget(ctrl); }
        inline void disableSpliceForward() noexcept { disableSplice(); }
        [[nodiscard]] inline bool isSpliceForwardActive() const noexcept { return isSpliceActive(); }

    private:
        SnellStage stage_{SnellStage::HEADER};
        uint8_t version_{2};
        std::string psk_{};
        RequestCallback requestCallback_{nullptr};

        uint8_t command_{0};
        std::optional<ProxyAddress> targetAddress_{std::nullopt};

    public:
        HandlerSnell() noexcept = default;
        HandlerSnell(uint8_t version, std::string_view psk)
            : version_(version),
              psk_(psk)
        {
        }
        ~HandlerSnell() noexcept override = default;

        HandlerSnell(const HandlerSnell &) = delete;
        HandlerSnell &operator=(const HandlerSnell &) = delete;
        HandlerSnell(HandlerSnell &&) = delete;
        HandlerSnell &operator=(HandlerSnell &&) = delete;

        void setVersion(uint8_t ver) noexcept { version_ = ver; }
        void setPsk(std::string_view psk) { psk_ = std::string(psk); }
        void setOnRequest(RequestCallback cb) noexcept { requestCallback_ = std::move(cb); }

        [[nodiscard]] SnellStage stage() const noexcept { return stage_; }
        [[nodiscard]] bool isEstablished() const noexcept { return stage_ == SnellStage::STREAMING; }
        [[nodiscard]] uint8_t command() const noexcept { return command_; }
        [[nodiscard]] const std::optional<ProxyAddress> &targetAddress() const noexcept { return targetAddress_; }

        void reset() noexcept override
        {
            HandlerConnection::reset();
            stage_ = SnellStage::HEADER;
            command_ = 0;
            targetAddress_.reset();
            disableSpliceForward();
        }

        void onMessageComplete() noexcept {}
        void onParseError(const char *reason) noexcept
        {
            (void)reason;
            stage_ = SnellStage::ERROR;
        }

        void process()
        {
            if (stage_ == SnellStage::HEADER)
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
            // 首部格式：[Version 1B][CMD 1B][Address (SOCKS5)]
            const size_t avail = requestBytes();
            if (avail < 2 + 7)
            {
                return false;
            }

            const auto *data = reinterpret_cast<const uint8_t *>(requestBegin());
            const uint8_t ver = data[0];
            const uint8_t cmd = data[1];

            if (ver != version_ && version_ != 0)
            {
                onParseError("Snell: Version mismatch");
                stage_ = SnellStage::ERROR;
                setCloseAfterResponse(true);
                return false;
            }

            if (cmd == snell::kCmdPing)
            {
                // 回复 PING 响应包
                static constexpr char kPong[2] = {0x00, 0x00};
                [[maybe_unused]] auto _ = pushResponse(std::string_view(kPong, 2));
                requestConsume(2);
                return true;
            }

            size_t addrConsumed = 0;
            std::span<const uint8_t> addrSpan(data + 2, avail - 2);
            auto target = ProxyAddress::decodeSocks5(addrSpan, addrConsumed);
            if (!target.has_value())
            {
                return false;
            }

            const size_t totalHeaderSize = 2 + addrConsumed;
            command_ = cmd;
            targetAddress_ = std::move(target);
            requestConsume(totalHeaderSize);

            stage_ = SnellStage::STREAMING;
            onMessageComplete();

            if (requestCallback_)
            {
                requestCallback_(command_, *targetAddress_);
            }
            return true;
        }
    };

} // namespace mynet::proxy
