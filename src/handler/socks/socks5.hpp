#pragma once

/**
 * @file proxy/socks/socks5.hpp
 * @brief SOCKS5 代理协议服务端状态机处理器（RFC 1928 / RFC 1929）。
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
     * @brief SOCKS5 协议状态机处理器
     *
     * 派生自 HandlerConnection，满足 HandlerConstraint，可直接供 Reactor / Proactor 引擎驱动，
     * 并完美兼容 ObjectPool 进行零分配重用。
     */
    class HandlerSocks5 : public HandlerConnection
    {
    public:
        using AuthCallback = std::function<bool(std::string_view username, std::string_view password)>;
        using RequestCallback = std::function<void(uint8_t cmd, const ProxyAddress &target)>;

        /// 是否允许该处理器使用 Linux splice(2) 内核零拷贝（SOCKS5 转发管道）
        static constexpr bool kEnableSplice = true;

        /**
         * @brief 开启零拷贝 SOCKS5 转发管道（直接复用 Connection 零拷贝管道）
         *
         * 在 CONNECT 握手完成进入 STREAMING 状态后调用，将客户端与目标套接字直连，
         * 避免在用户态搬运数据载荷。
         *
         * @param targetFd 目标远端套接字描述符
         */
        inline void enableSpliceForward(int targetFd) noexcept { setSpliceTarget(targetFd); }
        inline void enableSpliceForward(SPLICE_CONTROL ctrl) noexcept { setSpliceTarget(ctrl); }
        inline void disableSpliceForward() noexcept { disableSplice(); }
        [[nodiscard]] inline bool isSpliceForwardActive() const noexcept { return isSpliceActive(); }

    private:
        Socks5Stage stage_{Socks5Stage::METHOD_SELECT};
        AuthCallback authCallback_{nullptr};
        RequestCallback requestCallback_{nullptr};

        uint8_t selectedMethod_{socks5::kMethodNoAcceptable};
        uint8_t command_{0};
        std::optional<ProxyAddress> targetAddress_{std::nullopt};
        bool autoReplyConnectSuccess_{true};

    public:
        HandlerSocks5() noexcept
            : autoReplyConnectSuccess_(getProxyConfig().autoReplyConnectSuccess)
        {
        }
        explicit HandlerSocks5(const ProxyConfig &cfg) noexcept
            : autoReplyConnectSuccess_(cfg.autoReplyConnectSuccess)
        {
        }
        ~HandlerSocks5() noexcept override = default;

        HandlerSocks5(const HandlerSocks5 &) = delete;
        HandlerSocks5 &operator=(const HandlerSocks5 &) = delete;
        HandlerSocks5(HandlerSocks5 &&) = delete;
        HandlerSocks5 &operator=(HandlerSocks5 &&) = delete;

        /**
         * @brief 设置用户认证回调函数（为空表示仅接受无认证 NO_AUTH）
         */
        void setAuthenticator(AuthCallback cb) noexcept { authCallback_ = std::move(cb); }

        /**
         * @brief 设置收到目标连接请求时的业务回调
         */
        void setOnRequest(RequestCallback cb) noexcept { requestCallback_ = std::move(cb); }

        /**
         * @brief 设置是否在解析出 CONNECT 成功时自动向客户端回送 0x00 Success 响应包
         * 默认为 true。若业务层需要异步连接目标后再回送实际绑定地址，可设为 false。
         */
        void setAutoReplyConnectSuccess(bool autoReply) noexcept { autoReplyConnectSuccess_ = autoReply; }

        /**
         * @brief 应用 SOCKS5 代理配置
         */
        void configure(const ProxyConfig &cfg) noexcept { autoReplyConnectSuccess_ = cfg.autoReplyConnectSuccess; }

        [[nodiscard]] Socks5Stage stage() const noexcept { return stage_; }
        [[nodiscard]] uint8_t command() const noexcept { return command_; }
        [[nodiscard]] const std::optional<ProxyAddress> &targetAddress() const noexcept { return targetAddress_; }
        [[nodiscard]] bool isEstablished() const noexcept { return stage_ == Socks5Stage::STREAMING; }

        /**
         * @brief 重置协议状态（供对象池重用）
         */
        void reset() noexcept override
        {
            stage_ = Socks5Stage::METHOD_SELECT;
            selectedMethod_ = socks5::kMethodNoAcceptable;
            command_ = 0;
            targetAddress_.reset();
            autoReplyConnectSuccess_ = getProxyConfig().autoReplyConnectSuccess;
            HandlerConnection::reset();
        }

        /**
         * @brief 发送 SOCKS5 应答包（RFC 1928 规范）
         *
         * @param rep 应答状态码（如 kRepSuccess）
         * @param bindAddr 服务端分配/绑定的地址（通常可为 0.0.0.0:0）
         */
        void sendReply(uint8_t rep, const ProxyAddress &bindAddr = ProxyAddress::fromIPv4(0, 0))
        {
            std::vector<uint8_t> packet;
            packet.reserve(32);
            packet.push_back(socks5::kVersion);
            packet.push_back(rep);
            packet.push_back(0x00); // RSV
            bindAddr.encodeSocks5(packet);
            [[maybe_unused]] auto _ =
                pushResponse(std::string_view(reinterpret_cast<const char *>(packet.data()), packet.size()));
        }

        /**
         * @brief 驱动协议解析状态机
         */
        void process()
        {
            while (true)
            {
                const size_t avail = requestBytes();
                if (avail == 0 || stage_ == Socks5Stage::ERROR)
                {
                    return;
                }

                switch (stage_)
                {
                case Socks5Stage::METHOD_SELECT:
                {
                    if (!processMethodSelect())
                    {
                        return; // 数据不足或出错退出循环
                    }
                    break;
                }
                case Socks5Stage::AUTH:
                {
                    if (!processAuth())
                    {
                        return;
                    }
                    break;
                }
                case Socks5Stage::REQUEST:
                {
                    if (!processRequest())
                    {
                        return;
                    }
                    break;
                }
                case Socks5Stage::STREAMING:
                {
                    // 已建立隧道，后续数据由具体流转业务处理（保留在缓冲区中供上层读取转发）
                    return;
                }
                case Socks5Stage::ERROR:
                    return;
                }
            }
        }

    private:
        /**
         * @brief 解析方法协商包：VER(1) | NMETHODS(1) | METHODS(N)
         */
        bool processMethodSelect()
        {
            const size_t avail = requestBytes();
            if (avail < 2)
            {
                return false; // 数据不足 2 字节
            }

            const auto *data = reinterpret_cast<const uint8_t *>(requestBegin());
            if (data[0] != socks5::kVersion)
            {
                onParseError("SOCKS5: Unsupported protocol version");
                stage_ = Socks5Stage::ERROR;
                setCloseAfterResponse(true);
                return false;
            }

            const uint8_t nmethods = data[1];
            const size_t totalExpected = 2 + nmethods;
            if (avail < totalExpected)
            {
                return false; // 等待完整的方法列表
            }

            std::span<const uint8_t> methods(data + 2, nmethods);
            uint8_t chosenMethod = socks5::kMethodNoAcceptable;

            if (authCallback_ != nullptr)
            {
                // 需要用户密码认证
                for (uint8_t m : methods)
                {
                    if (m == socks5::kMethodUserPass)
                    {
                        chosenMethod = socks5::kMethodUserPass;
                        break;
                    }
                }
            }
            else
            {
                // 无需认证
                for (uint8_t m : methods)
                {
                    if (m == socks5::kMethodNoAuth)
                    {
                        chosenMethod = socks5::kMethodNoAuth;
                        break;
                    }
                }
            }

            selectedMethod_ = chosenMethod;
            requestConsume(totalExpected);

            // 回复协商结果：VER(1) | METHOD(1)
            char reply[2] = {static_cast<char>(socks5::kVersion), static_cast<char>(chosenMethod)};
            [[maybe_unused]] auto _ = pushResponse(std::string_view(reply, 2));

            if (chosenMethod == socks5::kMethodNoAcceptable)
            {
                stage_ = Socks5Stage::ERROR;
                setCloseAfterResponse(true);
                return false;
            }
            else if (chosenMethod == socks5::kMethodUserPass)
            {
                stage_ = Socks5Stage::AUTH;
            }
            else
            {
                stage_ = Socks5Stage::REQUEST;
            }
            return true;
        }

        /**
         * @brief 解析 RFC 1929 用户名密码认证包
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
                onParseError("SOCKS5: Unsupported subnegotiation auth version");
                stage_ = Socks5Stage::ERROR;
                setCloseAfterResponse(true);
                return false;
            }

            const uint8_t ulen = data[1];
            if (avail < 2 + static_cast<size_t>(ulen) + 1)
            {
                return false;
            }

            const uint8_t plen = data[2 + ulen];
            const size_t totalExpected = 2 + static_cast<size_t>(ulen) + 1 + static_cast<size_t>(plen);
            if (avail < totalExpected)
            {
                return false;
            }

            std::string_view username(reinterpret_cast<const char *>(data + 2), ulen);
            std::string_view password(reinterpret_cast<const char *>(data + 2 + ulen + 1), plen);

            bool ok = false;
            if (authCallback_)
            {
                ok = authCallback_(username, password);
            }

            requestConsume(totalExpected);

            // 回复认证状态包：VER(0x01) | STATUS(0x00=成功, 其余=失败)
            char reply[2] = {static_cast<char>(socks5::kSubnegotiationVersion), static_cast<char>(ok ? 0x00 : 0xFF)};
            [[maybe_unused]] auto _ = pushResponse(std::string_view(reply, 2));

            if (ok)
            {
                stage_ = Socks5Stage::REQUEST;
                return true;
            }
            else
            {
                stage_ = Socks5Stage::ERROR;
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
                stage_ = Socks5Stage::ERROR;
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
                // 数据不足以构成完整地址
                return false;
            }

            const size_t totalConsumed = 3 + addrConsumed;
            command_ = cmd;
            targetAddress_ = std::move(target);
            requestConsume(totalConsumed);

            if (cmd != socks5::kCmdConnect)
            {
                // 目前仅默认放行 CONNECT 命令，其余返回 Command Not Supported
                sendReply(socks5::kRepCommandNotSupported);
                stage_ = Socks5Stage::ERROR;
                setCloseAfterResponse(true);
                return false;
            }

            if (autoReplyConnectSuccess_)
            {
                sendReply(socks5::kRepSuccess);
            }

            stage_ = Socks5Stage::STREAMING;
            onMessageComplete();

            if (requestCallback_)
            {
                requestCallback_(command_, *targetAddress_);
            }
            return true;
        }
    };

} // namespace mynet::handler
