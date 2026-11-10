#pragma once

/**
 * @file handler/socks/socks5.hpp
 * @brief SOCKS5 代理协议入站状态机处理器 (HandlerInboundSocks5) 与出站协议处理器 (HandlerOutboundSocks5)（RFC 1928 / RFC 1929）。
 */

#include "../address.hpp"
#include "../inbound.hpp"
#include "../outbound.hpp"
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mynet::handler
{

    /**
     * @brief SOCKS5 协议常量定义（RFC 1928 / RFC 1929）
     */
    namespace socks5
    {
        inline constexpr uint8_t kVersion = 0x05;
        inline constexpr uint8_t kSubnegotiationVersion = 0x01;

        // 认证方式 (Methods)
        inline constexpr uint8_t kMethodNoAuth = 0x00;
        inline constexpr uint8_t kMethodGssApi = 0x01;
        inline constexpr uint8_t kMethodUserPass = 0x02;
        inline constexpr uint8_t kMethodNoAcceptable = 0xFF;

        // 命令代码 (Commands)
        inline constexpr uint8_t kCmdConnect = 0x01;
        inline constexpr uint8_t kCmdBind = 0x02;
        inline constexpr uint8_t kCmdUdpAssociate = 0x03;

        // 响应状态码 (Reply Codes)
        inline constexpr uint8_t kRepSuccess = 0x00;
        inline constexpr uint8_t kRepGeneralFailure = 0x01;
        inline constexpr uint8_t kRepConnectionNotAllowed = 0x02;
        inline constexpr uint8_t kRepNetworkUnreachable = 0x03;
        inline constexpr uint8_t kRepHostUnreachable = 0x04;
        inline constexpr uint8_t kRepConnectionRefused = 0x05;
        inline constexpr uint8_t kRepTtlExpired = 0x06;
        inline constexpr uint8_t kRepCommandNotSupported = 0x07;
        inline constexpr uint8_t kRepAddressTypeNotSupported = 0x08;
    } // namespace socks5

    using ProxyConfig = mynet::ProxyConfig;

    /**
     * @brief SOCKS5 会话状态
     */
    enum class Socks5Stage : uint8_t
    {
        METHOD_SELECT, ///< 等待客户端初始协商（方法列表）
        AUTH,          ///< 等待用户名密码认证 (RFC 1929)
        REQUEST,       ///< 等待客户端请求（目标地址与命令）
        STREAMING,     ///< 握手完成，处于数据透传/隧道转发中
        ERROR          ///< 协议解析错误或认证失败
    };

    /**
     * @brief SOCKS5 协议入站状态机处理器
     *
     * 派生自 HandlerInboundConnection，满足 HandlerConstraint 与 MandatoryMethodConnection。
     */
    class HandlerInboundSocks5 : public HandlerInboundConnection
    {
    public:
        using AuthCallback = std::function<bool(std::string_view username, std::string_view password)>;

    private:
        Socks5Stage socks5Stage_{Socks5Stage::METHOD_SELECT};
        AuthCallback authCallback_{nullptr};

        uint8_t selectedMethod_{socks5::kMethodNoAcceptable};
        bool autoReplyConnectSuccess_{true};

    public:
        HandlerInboundSocks5() noexcept
            : autoReplyConnectSuccess_(getProxyConfig().autoReplyConnectSuccess)
        {
        }
        explicit HandlerInboundSocks5(const ProxyConfig &cfg) noexcept
            : autoReplyConnectSuccess_(cfg.autoReplyConnectSuccess)
        {
        }
        ~HandlerInboundSocks5() noexcept override = default;

        HandlerInboundSocks5(const HandlerInboundSocks5 &) = delete;
        HandlerInboundSocks5 &operator=(const HandlerInboundSocks5 &) = delete;
        HandlerInboundSocks5(HandlerInboundSocks5 &&) = delete;
        HandlerInboundSocks5 &operator=(HandlerInboundSocks5 &&) = delete;

        void setAuthenticator(AuthCallback cb) noexcept { authCallback_ = std::move(cb); }
        void setAutoReply(bool autoReply) noexcept { autoReplyConnectSuccess_ = autoReply; }
        void configure(const ProxyConfig &cfg) noexcept { autoReplyConnectSuccess_ = cfg.autoReplyConnectSuccess; }

        [[nodiscard]] Socks5Stage stage() const noexcept { return socks5Stage_; }
        [[nodiscard]] uint8_t selectedMethod() const noexcept { return selectedMethod_; }

        void reset() noexcept override
        {
            HandlerInboundConnection::reset();
            socks5Stage_ = Socks5Stage::METHOD_SELECT;
            selectedMethod_ = socks5::kMethodNoAcceptable;
        }

        void process() override
        {
            while (requestBytes() > 0)
            {
                switch (socks5Stage_)
                {
                case Socks5Stage::METHOD_SELECT:
                    if (!processMethodSelect())
                    {
                        return;
                    }
                    break;
                case Socks5Stage::AUTH:
                    if (!processAuth())
                    {
                        return;
                    }
                    break;
                case Socks5Stage::REQUEST:
                    if (!processRequest())
                    {
                        return;
                    }
                    break;
                case Socks5Stage::STREAMING:
                    return;
                case Socks5Stage::ERROR:
                    return;
                }
            }
        }

        /**
         * @brief 发送标准的 SOCKS5 握手回复包（默认 0x00 表示成功）
         *
         * 格式：VER(0x05) | REP | RSV(0x00) | ATYP(0x01) | BND.ADDR(0.0.0.0) | BND.PORT(0)
         */
        void sendReply(uint8_t replyCode, const ProxyAddress *bindAddr = nullptr)
        {
            std::vector<uint8_t> frame;
            frame.reserve(32);
            frame.push_back(socks5::kVersion);
            frame.push_back(replyCode);
            frame.push_back(0x00); // RSV

            if (bindAddr != nullptr)
            {
                bindAddr->encodeSocks5(frame);
            }
            else
            {
                // 默认返回 0.0.0.0:0 (IPv4)
                frame.push_back(static_cast<uint8_t>(AddressType::IPV4));
                frame.push_back(0);
                frame.push_back(0);
                frame.push_back(0);
                frame.push_back(0);
                frame.push_back(0);
                frame.push_back(0);
            }

            [[maybe_unused]] auto _ =
                pushResponse(std::string_view(reinterpret_cast<const char *>(frame.data()), frame.size()));
        }

    private:
        /**
         * @brief 解析方法协商包
         * 格式：VER(1) | NMETHODS(1) | METHODS(NMETHODS)
         */
        bool processMethodSelect()
        {
            const size_t avail = requestBytes();
            if (avail < 2)
            {
                return false;
            }

            const auto *data = reinterpret_cast<const uint8_t *>(requestBegin());
            if (data[0] != socks5::kVersion)
            {
                onParseError("SOCKS5: Unsupported version");
                socks5Stage_ = Socks5Stage::ERROR;
                stage_ = InboundStage::ERROR;
                setCloseAfterResponse(true);
                return false;
            }

            const uint8_t nmethods = data[1];
            if (avail < static_cast<size_t>(2 + nmethods))
            {
                return false;
            }

            // 检查客户端支持的方法列表
            bool hasNoAuth = false;
            bool hasUserPass = false;
            for (size_t i = 0; i < nmethods; ++i)
            {
                uint8_t m = data[2 + i];
                if (m == socks5::kMethodNoAuth)
                {
                    hasNoAuth = true;
                }
                else if (m == socks5::kMethodUserPass)
                {
                    hasUserPass = true;
                }
            }

            requestConsume(2 + nmethods);

            // 服务端决策：若设置了 authenticator，必须走用户名密码认证；否则免密
            uint8_t chosen = socks5::kMethodNoAcceptable;
            if (authCallback_)
            {
                if (hasUserPass)
                {
                    chosen = socks5::kMethodUserPass;
                    socks5Stage_ = Socks5Stage::AUTH;
                }
                else
                {
                    chosen = socks5::kMethodNoAcceptable;
                    socks5Stage_ = Socks5Stage::ERROR;
                    stage_ = InboundStage::ERROR;
                    setCloseAfterResponse(true);
                }
            }
            else
            {
                if (hasNoAuth)
                {
                    chosen = socks5::kMethodNoAuth;
                    socks5Stage_ = Socks5Stage::REQUEST;
                }
                else
                {
                    chosen = socks5::kMethodNoAcceptable;
                    socks5Stage_ = Socks5Stage::ERROR;
                    stage_ = InboundStage::ERROR;
                    setCloseAfterResponse(true);
                }
            }

            selectedMethod_ = chosen;

            // 回复客户端协商结果：VER(0x05) | METHOD(1B)
            char reply[2] = {static_cast<char>(socks5::kVersion), static_cast<char>(chosen)};
            [[maybe_unused]] auto _ = pushResponse(std::string_view(reply, 2));

            return socks5Stage_ != Socks5Stage::ERROR;
        }

        /**
         * @brief 解析用户名/密码认证包 (RFC 1929)
         * 格式：VER(1=0x01) | ULEN(1) | UNAME(ULEN) | PLEN(1) | PASSWD(PLEN)
         */
        bool processAuth()
        {
            const size_t avail = requestBytes();
            if (avail < 2)
            {
                return false;
            }

            const auto *data = reinterpret_cast<const uint8_t *>(requestBegin());
            if (data[0] != socks5::kSubnegotiationVersion)
            {
                onParseError("SOCKS5 Auth: Invalid subnegotiation version");
                socks5Stage_ = Socks5Stage::ERROR;
                stage_ = InboundStage::ERROR;
                setCloseAfterResponse(true);
                return false;
            }

            const uint8_t ulen = data[1];
            if (avail < static_cast<size_t>(2 + ulen + 1))
            {
                return false;
            }

            const uint8_t plen = data[2 + ulen];
            const size_t totalExpected = 2 + ulen + 1 + plen;
            if (avail < totalExpected)
            {
                return false;
            }

            std::string_view uname(reinterpret_cast<const char *>(data + 2), ulen);
            std::string_view passwd(reinterpret_cast<const char *>(data + 2 + ulen + 1), plen);

            bool ok = false;
            if (authCallback_)
            {
                ok = authCallback_(uname, passwd);
            }

            requestConsume(totalExpected);

            // 回复认证状态包：VER(0x01) | STATUS(0x00=成功, 其余=失败)
            char reply[2] = {static_cast<char>(socks5::kSubnegotiationVersion), static_cast<char>(ok ? 0x00 : 0xFF)};
            [[maybe_unused]] auto _ = pushResponse(std::string_view(reply, 2));

            if (ok)
            {
                socks5Stage_ = Socks5Stage::REQUEST;
                return true;
            }
            else
            {
                socks5Stage_ = Socks5Stage::ERROR;
                stage_ = InboundStage::ERROR;
                setCloseAfterResponse(true);
                return false;
            }
        }

        /**
         * @brief 解析目标命令请求包
         * 格式：VER(1=0x05) | CMD(1) | RSV(1=0x00) | ATYP + ADDR + PORT
         */
        bool processRequest()
        {
            const size_t avail = requestBytes();
            if (avail < 4)
            {
                return false;
            }

            const auto *data = reinterpret_cast<const uint8_t *>(requestBegin());
            if (data[0] != socks5::kVersion)
            {
                onParseError("SOCKS5: Invalid request version");
                socks5Stage_ = Socks5Stage::ERROR;
                stage_ = InboundStage::ERROR;
                setCloseAfterResponse(true);
                return false;
            }

            const uint8_t cmd = data[1];
            // data[2] 为 RSV (0x00)

            size_t addrConsumed = 0;
            std::span<const uint8_t> addrSpan(data + 3, avail - 3);
            auto target = ProxyAddress::decodeSocks5(addrSpan, addrConsumed);
            if (!target.has_value())
            {
                return false;
            }

            const size_t totalConsumed = 3 + addrConsumed;
            command_ = cmd;
            targetAddress_ = std::move(target);
            requestConsume(totalConsumed);

            if (cmd != socks5::kCmdConnect)
            {
                sendReply(socks5::kRepCommandNotSupported);
                socks5Stage_ = Socks5Stage::ERROR;
                stage_ = InboundStage::ERROR;
                setCloseAfterResponse(true);
                return false;
            }

            if (autoReplyConnectSuccess_)
            {
                sendReply(socks5::kRepSuccess);
            }

            socks5Stage_ = Socks5Stage::STREAMING;
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
     * @brief SOCKS5 出站协议客户端处理器 (SOCKS5 Outbound)
     *
     * 自动处理与上游 SOCKS5 代理服务器的握手与 CONNECT 建连指令。
     */
    class HandlerOutboundSocks5 : public HandlerOutboundConnection
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
            : HandlerOutboundConnection(target)
        {
        }

        void reset() noexcept override
        {
            HandlerOutboundConnection::reset();
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

} // namespace mynet::handler
