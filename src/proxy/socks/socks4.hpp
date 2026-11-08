#pragma once

/**
 * @file proxy/socks/socks4.hpp
 * @brief SOCKS4 / SOCKS4a 代理协议服务端状态机处理器。
 */

#include "../../connection.hpp"
#include "../address.hpp"
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mynet::proxy
{

    namespace socks4
    {
        inline constexpr uint8_t kVersion = 0x04;
        inline constexpr uint8_t kReplyVersion = 0x00;

        // 命令代码 (Commands)
        inline constexpr uint8_t kCmdConnect = 0x01;
        inline constexpr uint8_t kCmdBind = 0x02;

        // 响应状态码 (Reply Codes)
        inline constexpr uint8_t kRepSuccess = 0x5A;       ///< 90: 请求已允许
        inline constexpr uint8_t kRepRejected = 0x5B;      ///< 91: 请求被拒绝或失败
        inline constexpr uint8_t kRepIdentdFailed = 0x5C;  ///< 92: 连接 identd 失败
        inline constexpr uint8_t kRepIdentdDiffers = 0x5D; ///< 93: identd 用户名不匹配
    } // namespace socks4

    /**
     * @brief SOCKS4 会话状态
     */
    enum class Socks4Stage : uint8_t
    {
        REQUEST,   ///< 等待解析 SOCKS4/SOCKS4a 连接请求包
        STREAMING, ///< 握手完成，处于数据透传/隧道转发中
        ERROR      ///< 协议解析错误或认证失败
    };

    /**
     * @brief SOCKS4 / SOCKS4a 协议状态机处理器
     */
    class HandlerSocks4 : public HandlerConnection
    {
    public:
        using AuthCallback = std::function<bool(std::string_view userId)>;
        using RequestCallback = std::function<void(uint8_t cmd, const ProxyAddress &target)>;

        static constexpr bool kEnableSplice = true;

        inline void enableSpliceForward(int targetFd) noexcept { setSpliceTarget(targetFd); }
        inline void enableSpliceForward(SPLICE_CONTROL ctrl) noexcept { setSpliceTarget(ctrl); }
        inline void disableSpliceForward() noexcept { disableSplice(); }
        [[nodiscard]] inline bool isSpliceForwardActive() const noexcept { return isSpliceActive(); }

    private:
        Socks4Stage stage_{Socks4Stage::REQUEST};
        AuthCallback authCallback_{nullptr};
        RequestCallback requestCallback_{nullptr};

        uint8_t command_{0};
        std::string userId_{};
        std::optional<ProxyAddress> targetAddress_{std::nullopt};
        bool autoReplyConnectSuccess_{true};

    public:
        HandlerSocks4() noexcept
            : autoReplyConnectSuccess_(getProxyConfig().autoReplyConnectSuccess)
        {
        }
        explicit HandlerSocks4(const ProxyConfig &cfg) noexcept
            : autoReplyConnectSuccess_(cfg.autoReplyConnectSuccess)
        {
        }
        ~HandlerSocks4() noexcept override = default;

        HandlerSocks4(const HandlerSocks4 &) = delete;
        HandlerSocks4 &operator=(const HandlerSocks4 &) = delete;
        HandlerSocks4(HandlerSocks4 &&) = delete;
        HandlerSocks4 &operator=(HandlerSocks4 &&) = delete;

        void setAuthenticator(AuthCallback cb) noexcept { authCallback_ = std::move(cb); }
        void setOnRequest(RequestCallback cb) noexcept { requestCallback_ = std::move(cb); }

        [[nodiscard]] Socks4Stage stage() const noexcept { return stage_; }
        [[nodiscard]] bool isEstablished() const noexcept { return stage_ == Socks4Stage::STREAMING; }
        [[nodiscard]] uint8_t command() const noexcept { return command_; }
        [[nodiscard]] std::string_view userId() const noexcept { return userId_; }
        [[nodiscard]] const std::optional<ProxyAddress> &targetAddress() const noexcept { return targetAddress_; }

        void configure(const ProxyConfig &cfg) noexcept { autoReplyConnectSuccess_ = cfg.autoReplyConnectSuccess; }

        void reset() noexcept override
        {
            HandlerConnection::reset();
            stage_ = Socks4Stage::REQUEST;
            command_ = 0;
            userId_.clear();
            targetAddress_.reset();
            autoReplyConnectSuccess_ = getProxyConfig().autoReplyConnectSuccess;
            disableSpliceForward();
        }

        void onMessageComplete() noexcept {}
        void onParseError(const char *reason) noexcept
        {
            (void)reason;
            stage_ = Socks4Stage::ERROR;
        }

        void process()
        {
            if (stage_ == Socks4Stage::REQUEST)
            {
                if (!processRequest())
                {
                    return;
                }
            }
        }

        /**
         * @brief 向客户端发送 SOCKS4 响应包 (VN=0, CD, Port, IP)
         */
        void sendReply(uint8_t replyCode, uint16_t port = 0, uint32_t ipBe = 0)
        {
            uint8_t resp[8] = {socks4::kReplyVersion,
                               replyCode,
                               static_cast<uint8_t>((port >> 8) & 0xFF),
                               static_cast<uint8_t>(port & 0xFF),
                               static_cast<uint8_t>((ipBe) & 0xFF),
                               static_cast<uint8_t>((ipBe >> 8) & 0xFF),
                               static_cast<uint8_t>((ipBe >> 16) & 0xFF),
                               static_cast<uint8_t>((ipBe >> 24) & 0xFF)};
            [[maybe_unused]] auto _ = pushResponse(std::string_view(reinterpret_cast<const char *>(resp), 8));
        }

    private:
        bool processRequest()
        {
            const size_t avail = requestBytes();
            if (avail < 8)
            {
                return false;
            }

            const auto *data = reinterpret_cast<const uint8_t *>(requestBegin());
            if (data[0] != socks4::kVersion)
            {
                onParseError("SOCKS4: Invalid version");
                stage_ = Socks4Stage::ERROR;
                setCloseAfterResponse(true);
                return false;
            }

            const uint8_t cmd = data[1];
            const uint16_t port = (static_cast<uint16_t>(data[2]) << 8) | static_cast<uint16_t>(data[3]);
            uint32_t ipBe = 0;
            std::memcpy(&ipBe, data + 4, 4);

            // 寻找 USERID 的结尾 '\0'
            size_t userEnd = 8;
            while (userEnd < avail && data[userEnd] != 0)
            {
                ++userEnd;
            }
            if (userEnd >= avail)
            {
                return false; // 还需要等待更多数据
            }

            std::string_view uid(reinterpret_cast<const char *>(data + 8), userEnd - 8);

            // 检查是否为 SOCKS4a 域名形式：前 3 字节为 0，第 4 字节非 0 (0.0.0.x)
            const bool isSocks4a = (data[4] == 0 && data[5] == 0 && data[6] == 0 && data[7] != 0);
            size_t totalExpected = userEnd + 1;
            std::string domain{};

            if (isSocks4a)
            {
                size_t domainEnd = totalExpected;
                while (domainEnd < avail && data[domainEnd] != 0)
                {
                    ++domainEnd;
                }
                if (domainEnd >= avail)
                {
                    return false; // 还需要等待域名结尾
                }
                domain = std::string(reinterpret_cast<const char *>(data + totalExpected), domainEnd - totalExpected);
                totalExpected = domainEnd + 1;
            }

            // 认证校验
            if (authCallback_ && !authCallback_(uid))
            {
                sendReply(socks4::kRepRejected);
                stage_ = Socks4Stage::ERROR;
                setCloseAfterResponse(true);
                requestConsume(totalExpected);
                return false;
            }

            // 构造地址
            if (isSocks4a)
            {
                targetAddress_ = ProxyAddress::fromDomain(domain, port);
            }
            else
            {
                targetAddress_ = ProxyAddress::fromIPv4(ipBe, port);
            }

            command_ = cmd;
            userId_ = std::string(uid);
            requestConsume(totalExpected);

            if (cmd != socks4::kCmdConnect)
            {
                sendReply(socks4::kRepRejected);
                stage_ = Socks4Stage::ERROR;
                setCloseAfterResponse(true);
                return false;
            }

            if (autoReplyConnectSuccess_)
            {
                sendReply(socks4::kRepSuccess, port, ipBe);
            }

            stage_ = Socks4Stage::STREAMING;
            onMessageComplete();

            if (requestCallback_)
            {
                requestCallback_(command_, *targetAddress_);
            }
            return true;
        }
    };

} // namespace mynet::proxy
