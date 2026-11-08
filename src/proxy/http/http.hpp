#pragma once

/**
 * @file proxy/http/http.hpp
 * @brief HTTP 代理协议服务端状态机处理器（支持 HTTP CONNECT 隧道与透明转发，带 Basic 认证）。
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

    namespace http_proxy
    {
        inline constexpr uint8_t kCmdConnect = 0x01; ///< HTTP CONNECT 隧道
        inline constexpr uint8_t kCmdPlain = 0x02;   ///< 普通 HTTP 明文转发代理
    } // namespace http_proxy

    /**
     * @brief HTTP 代理会话阶段
     */
    enum class HttpProxyStage : uint8_t
    {
        REQUEST,   ///< 等待解析 HTTP 请求行与头部
        STREAMING, ///< 握手完成，处于数据透传/隧道转发中
        ERROR      ///< 认证失败或协议格式错误
    };

    /**
     * @brief HTTP 代理协议服务端状态机处理器
     */
    class HandlerHttpProxy : public HandlerConnection
    {
    public:
        using AuthCallback = std::function<bool(std::string_view user, std::string_view pass)>;
        using RequestCallback = std::function<void(uint8_t cmd, const ProxyAddress &target)>;

        static constexpr bool kEnableSplice = true;

        inline void enableSpliceForward(int targetFd) noexcept { setSpliceTarget(targetFd); }
        inline void enableSpliceForward(SPLICE_CONTROL ctrl) noexcept { setSpliceTarget(ctrl); }
        inline void disableSpliceForward() noexcept { disableSplice(); }
        [[nodiscard]] inline bool isSpliceForwardActive() const noexcept { return isSpliceActive(); }

    private:
        HttpProxyStage stage_{HttpProxyStage::REQUEST};
        AuthCallback authCallback_{nullptr};
        RequestCallback requestCallback_{nullptr};

        uint8_t command_{0};
        std::optional<ProxyAddress> targetAddress_{std::nullopt};
        bool isConnectMethod_{false};
        std::string method_{};
        std::string uri_{};

    public:
        HandlerHttpProxy() noexcept = default;
        ~HandlerHttpProxy() noexcept override = default;

        HandlerHttpProxy(const HandlerHttpProxy &) = delete;
        HandlerHttpProxy &operator=(const HandlerHttpProxy &) = delete;
        HandlerHttpProxy(HandlerHttpProxy &&) = delete;
        HandlerHttpProxy &operator=(HandlerHttpProxy &&) = delete;

        void setAuthenticator(AuthCallback cb) noexcept { authCallback_ = std::move(cb); }
        void setOnRequest(RequestCallback cb) noexcept { requestCallback_ = std::move(cb); }

        [[nodiscard]] HttpProxyStage stage() const noexcept { return stage_; }
        [[nodiscard]] bool isEstablished() const noexcept { return stage_ == HttpProxyStage::STREAMING; }
        [[nodiscard]] uint8_t command() const noexcept { return command_; }
        [[nodiscard]] const std::optional<ProxyAddress> &targetAddress() const noexcept { return targetAddress_; }
        [[nodiscard]] bool isConnectMethod() const noexcept { return isConnectMethod_; }

        void reset() noexcept override
        {
            HandlerConnection::reset();
            stage_ = HttpProxyStage::REQUEST;
            command_ = 0;
            targetAddress_.reset();
            isConnectMethod_ = false;
            method_.clear();
            uri_.clear();
            disableSpliceForward();
        }

        void onMessageComplete() noexcept {}
        void onParseError(const char *reason) noexcept
        {
            (void)reason;
            stage_ = HttpProxyStage::ERROR;
        }

        void process()
        {
            if (stage_ == HttpProxyStage::REQUEST)
            {
                if (!processRequest())
                {
                    return;
                }
            }
        }

    private:
        bool processRequest()
        {
            const size_t avail = requestBytes();
            if (avail < 10)
            {
                return false;
            }

            std::string_view req(requestBegin(), avail);
            const size_t headerEnd = req.find("\r\n\r\n");
            if (headerEnd == std::string_view::npos)
            {
                // 首部尚未完整
                return false;
            }

            const size_t totalHeaderSize = headerEnd + 4;
            std::string_view headerBlock = req.substr(0, headerEnd);

            // 解析首行 Request-Line: METHOD URI HTTP/1.x
            const size_t firstLineEnd = headerBlock.find("\r\n");
            std::string_view firstLine =
                (firstLineEnd != std::string_view::npos) ? headerBlock.substr(0, firstLineEnd) : headerBlock;

            const size_t space1 = firstLine.find(' ');
            if (space1 == std::string_view::npos)
            {
                onParseError("HTTP Proxy: Invalid request line");
                stage_ = HttpProxyStage::ERROR;
                setCloseAfterResponse(true);
                return false;
            }

            std::string_view method = firstLine.substr(0, space1);
            const size_t space2 = firstLine.find(' ', space1 + 1);
            if (space2 == std::string_view::npos)
            {
                onParseError("HTTP Proxy: Invalid request line format");
                stage_ = HttpProxyStage::ERROR;
                setCloseAfterResponse(true);
                return false;
            }

            std::string_view uri = firstLine.substr(space1 + 1, space2 - (space1 + 1));
            method_ = std::string(method);
            uri_ = std::string(uri);

            // 认证校验 (Proxy-Authorization: Basic ...)
            if (authCallback_)
            {
                if (!checkAuth(headerBlock))
                {
                    static constexpr std::string_view kAuthRequired = "HTTP/1.1 407 Proxy Authentication Required\r\n"
                                                                      "Proxy-Authenticate: Basic realm=\"Proxy\"\r\n"
                                                                      "Content-Length: 0\r\n"
                                                                      "Connection: close\r\n\r\n";
                    [[maybe_unused]] auto _ = pushResponse(kAuthRequired);
                    stage_ = HttpProxyStage::ERROR;
                    setCloseAfterResponse(true);
                    requestConsume(totalHeaderSize);
                    return false;
                }
            }

            // 解析目标地址
            if (method == "CONNECT")
            {
                isConnectMethod_ = true;
                command_ = http_proxy::kCmdConnect;

                // CONNECT 的 URI 格式为 "host:port"
                auto addr = parseHostPort(uri, 443);
                if (!addr.has_value())
                {
                    onParseError("HTTP Proxy: Invalid CONNECT target address");
                    stage_ = HttpProxyStage::ERROR;
                    setCloseAfterResponse(true);
                    return false;
                }
                targetAddress_ = std::move(addr);

                // 消耗握手首部
                requestConsume(totalHeaderSize);

                // 回送 200 Connection Established 建立隧道
                static constexpr std::string_view kEstablished = "HTTP/1.1 200 Connection Established\r\n\r\n";
                [[maybe_unused]] auto _ = pushResponse(kEstablished);

                stage_ = HttpProxyStage::STREAMING;
                onMessageComplete();

                if (requestCallback_)
                {
                    requestCallback_(command_, *targetAddress_);
                }
                return true;
            }
            else
            {
                // 普通 HTTP 代理明文转发，如 "GET http://example.com/path HTTP/1.1"
                isConnectMethod_ = false;
                command_ = http_proxy::kCmdPlain;

                auto addr = parseUriAddress(uri);
                if (!addr.has_value())
                {
                    // 尝试从 Host 首部提取
                    addr = extractHostHeader(headerBlock);
                }

                if (!addr.has_value())
                {
                    onParseError("HTTP Proxy: Missing target host in plain proxy request");
                    stage_ = HttpProxyStage::ERROR;
                    setCloseAfterResponse(true);
                    return false;
                }
                targetAddress_ = std::move(addr);

                stage_ = HttpProxyStage::STREAMING;
                onMessageComplete();

                if (requestCallback_)
                {
                    requestCallback_(command_, *targetAddress_);
                }
                return true;
            }
        }

        bool checkAuth(std::string_view headers)
        {
            static constexpr std::string_view kAuthHeader = "proxy-authorization:";
            size_t pos = 0;
            while (pos < headers.size())
            {
                size_t lineEnd = headers.find("\r\n", pos);
                if (lineEnd == std::string_view::npos)
                {
                    lineEnd = headers.size();
                }
                std::string_view line = headers.substr(pos, lineEnd - pos);
                pos = lineEnd + 2;

                // 统一大小写比对
                if (line.size() > kAuthHeader.size())
                {
                    bool match = true;
                    for (size_t i = 0; i < kAuthHeader.size(); ++i)
                    {
                        if (std::tolower(static_cast<unsigned char>(line[i])) != kAuthHeader[i])
                        {
                            match = false;
                            break;
                        }
                    }
                    if (match)
                    {
                        std::string_view val = line.substr(kAuthHeader.size());
                        while (!val.empty() && val.front() == ' ')
                        {
                            val.remove_prefix(1);
                        }
                        if (val.starts_with("Basic ") || val.starts_with("basic "))
                        {
                            std::string_view b64 = val.substr(6);
                            std::string decoded;
                            if (crypto::base64Decode(b64, decoded))
                            {
                                size_t colon = decoded.find(':');
                                if (colon != std::string::npos)
                                {
                                    std::string_view u = std::string_view(decoded).substr(0, colon);
                                    std::string_view p = std::string_view(decoded).substr(colon + 1);
                                    return authCallback_(u, p);
                                }
                            }
                        }
                    }
                }
            }
            return false;
        }

        static std::optional<ProxyAddress> parseHostPort(std::string_view hostPortStr, uint16_t defaultPort)
        {
            if (hostPortStr.empty())
            {
                return std::nullopt;
            }

            if (hostPortStr.front() == '[')
            {
                // IPv6 [::1]:port
                size_t closeBracket = hostPortStr.find(']');
                if (closeBracket == std::string_view::npos)
                {
                    return std::nullopt;
                }
                std::string_view ip = hostPortStr.substr(1, closeBracket - 1);
                uint16_t port = defaultPort;
                if (closeBracket + 1 < hostPortStr.size() && hostPortStr[closeBracket + 1] == ':')
                {
                    std::string pStr(hostPortStr.substr(closeBracket + 2));
                    port = static_cast<uint16_t>(std::atoi(pStr.c_str()));
                }
                return ProxyAddress::fromHostPort(ip, port);
            }

            size_t colon = hostPortStr.rfind(':');
            if (colon != std::string_view::npos)
            {
                std::string_view host = hostPortStr.substr(0, colon);
                std::string pStr(hostPortStr.substr(colon + 1));
                uint16_t port = static_cast<uint16_t>(std::atoi(pStr.c_str()));
                return ProxyAddress::fromHostPort(host, port);
            }

            return ProxyAddress::fromHostPort(hostPortStr, defaultPort);
        }

        static std::optional<ProxyAddress> parseUriAddress(std::string_view uri)
        {
            // 例如 "http://example.com:8080/foo" 或 "http://127.0.0.1/bar"
            static constexpr std::string_view kHttp = "http://";
            static constexpr std::string_view kHttps = "https://";
            uint16_t defPort = 80;
            if (uri.starts_with(kHttp))
            {
                uri.remove_prefix(kHttp.size());
                defPort = 80;
            }
            else if (uri.starts_with(kHttps))
            {
                uri.remove_prefix(kHttps.size());
                defPort = 443;
            }
            else
            {
                return std::nullopt;
            }

            size_t slash = uri.find('/');
            std::string_view authority = (slash != std::string_view::npos) ? uri.substr(0, slash) : uri;
            return parseHostPort(authority, defPort);
        }

        static std::optional<ProxyAddress> extractHostHeader(std::string_view headers)
        {
            static constexpr std::string_view kHost = "host:";
            size_t pos = 0;
            while (pos < headers.size())
            {
                size_t lineEnd = headers.find("\r\n", pos);
                if (lineEnd == std::string_view::npos)
                {
                    lineEnd = headers.size();
                }
                std::string_view line = headers.substr(pos, lineEnd - pos);
                pos = lineEnd + 2;

                if (line.size() > kHost.size())
                {
                    bool match = true;
                    for (size_t i = 0; i < kHost.size(); ++i)
                    {
                        if (std::tolower(static_cast<unsigned char>(line[i])) != kHost[i])
                        {
                            match = false;
                            break;
                        }
                    }
                    if (match)
                    {
                        std::string_view val = line.substr(kHost.size());
                        while (!val.empty() && val.front() == ' ')
                        {
                            val.remove_prefix(1);
                        }
                        return parseHostPort(val, 80);
                    }
                }
            }
            return std::nullopt;
        }
    };

} // namespace mynet::proxy
