#pragma once

/**
 * @file handler/http/http.hpp
 * @brief HTTP 代理协议服务端状态机处理器（支持 HTTP CONNECT 隧道与透明转发，带 Basic 认证）。
 */

#include "../address.hpp"
#include "../connection.hpp"
#include "../encoding.hpp"
#include "common.hpp"
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mynet::handler
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
     * @brief HTTP 代理协议服务端入站状态机处理器
     */
    class HandlerInboundHttpProxy : public HandlerInboundConnectionBase
    {
    public:
        using AuthCallback = std::function<bool(std::string_view user, std::string_view pass)>;

    private:
        HttpProxyStage httpStage_{HttpProxyStage::REQUEST};
        AuthCallback authCallback_{nullptr};

        bool isConnectMethod_{false};
        std::string method_{};
        std::string uri_{};

    public:
        HandlerInboundHttpProxy() noexcept = default;
        ~HandlerInboundHttpProxy() noexcept override = default;

        HandlerInboundHttpProxy(const HandlerInboundHttpProxy &) = delete;
        HandlerInboundHttpProxy &operator=(const HandlerInboundHttpProxy &) = delete;
        HandlerInboundHttpProxy(HandlerInboundHttpProxy &&) = delete;
        HandlerInboundHttpProxy &operator=(HandlerInboundHttpProxy &&) = delete;

        void setAuthenticator(AuthCallback cb) noexcept { authCallback_ = std::move(cb); }

        [[nodiscard]] HttpProxyStage stage() const noexcept { return httpStage_; }
        [[nodiscard]] bool isConnectMethod() const noexcept { return isConnectMethod_; }

        void reset() noexcept override
        {
            HandlerInboundConnectionBase::reset();
            httpStage_ = HttpProxyStage::REQUEST;
            isConnectMethod_ = false;
            method_.clear();
            uri_.clear();
        }

        void onMessageComplete() noexcept {}
        void onParseError(const char *reason) noexcept
        {
            (void)reason;
            httpStage_ = HttpProxyStage::ERROR;
            stage_ = InboundStage::ERROR;
        }

        void handle()
        {
            if (httpStage_ == HttpProxyStage::REQUEST)
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
                httpStage_ = HttpProxyStage::ERROR;
                stage_ = InboundStage::ERROR;
                setCloseAfterResponse(true);
                return false;
            }

            std::string_view method = firstLine.substr(0, space1);
            const size_t space2 = firstLine.find(' ', space1 + 1);
            if (space2 == std::string_view::npos)
            {
                onParseError("HTTP Proxy: Invalid request line format");
                httpStage_ = HttpProxyStage::ERROR;
                stage_ = InboundStage::ERROR;
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
                    httpStage_ = HttpProxyStage::ERROR;
                    stage_ = InboundStage::ERROR;
                    setCloseAfterResponse(true);
                    requestConsume(totalHeaderSize);
                    return false;
                }
            }

            // 解析目标地址
            if (method == http::method::kConnect)
            {
                isConnectMethod_ = true;
                command_ = http_proxy::kCmdConnect;

                // CONNECT 的 URI 格式为 "host:port"
                auto addr = parseHostPort(uri, 443);
                if (!addr.has_value())
                {
                    onParseError("HTTP Proxy: Invalid CONNECT target address");
                    httpStage_ = HttpProxyStage::ERROR;
                    stage_ = InboundStage::ERROR;
                    setCloseAfterResponse(true);
                    return false;
                }
                targetAddress_ = std::move(addr);

                // 消耗握手首部
                requestConsume(totalHeaderSize);

                // 回送 200 Connection Established 建立隧道
                static constexpr std::string_view kEstablished = "HTTP/1.1 200 Connection Established\r\n\r\n";
                [[maybe_unused]] auto _ = pushResponse(kEstablished);

                httpStage_ = HttpProxyStage::STREAMING;
                stage_ = InboundStage::STREAMING;
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
                    httpStage_ = HttpProxyStage::ERROR;
                    stage_ = InboundStage::ERROR;
                    setCloseAfterResponse(true);
                    return false;
                }
                targetAddress_ = std::move(addr);

                httpStage_ = HttpProxyStage::STREAMING;
                stage_ = InboundStage::STREAMING;
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

                if (http::istartsWith(line, kAuthHeader))
                {
                    std::string_view val = line.substr(kAuthHeader.size());
                    while (!val.empty() && val.front() == ' ')
                    {
                        val.remove_prefix(1);
                    }
                    if (http::istartsWith(val, "Basic ") || http::istartsWith(val, "basic "))
                    {
                        std::string_view b64 = val.substr(6);
                        std::string decoded;
                        if (encoding::base64Decode(b64, decoded))
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

                if (http::istartsWith(line, kHost))
                {
                    std::string_view val = line.substr(kHost.size());
                    while (!val.empty() && val.front() == ' ')
                    {
                        val.remove_prefix(1);
                    }
                    return parseHostPort(val, 80);
                }
            }
            return std::nullopt;
        }
    };

    /**
     * @brief HTTP 代理出站客户端协议处理器 (HTTP Proxy Outbound)
     *
     * 自动向上游 HTTP 代理服务器发送 CONNECT 隧道建连指令，并等待 HTTP/1.x 200 响应。
     */
    class HandlerOutboundHttp : public HandlerOutboundConnectionBase
    {
    public:
        static constexpr bool kEnableSplice = true;

    private:
        enum class Step : uint8_t
        {
            SEND_CONNECT,
            RECV_CONNECT,
            DONE
        };
        Step step_{Step::SEND_CONNECT};
        std::string username_{};
        std::string password_{};

    public:
        HandlerOutboundHttp() noexcept = default;
        HandlerOutboundHttp(std::string_view username, std::string_view password, const ProxyAddress &target)
            : HandlerOutboundConnectionBase(target),
              username_(username),
              password_(password)
        {
        }
        explicit HandlerOutboundHttp(const ProxyAddress &target)
            : HandlerOutboundConnectionBase(target)
        {
        }

        void reset() noexcept override
        {
            HandlerOutboundConnectionBase::reset();
            step_ = Step::SEND_CONNECT;
        }

        void handle() override
        {
            switch (step_)
            {
            case Step::SEND_CONNECT:
            {
                std::string req;
                std::string endpoint = target().toString();
                req.reserve(128 + endpoint.size() * 2);
                req.append("CONNECT ").append(endpoint).append(" HTTP/1.1\r\n");
                req.append("Host: ").append(endpoint).append("\r\n");
                req.append("User-Agent: mynet/1.0\r\n");
                req.append("Proxy-Connection: Keep-Alive\r\n");
                if (!username_.empty())
                {
                    std::string cred = username_ + ":" + password_;
                    std::span<const uint8_t> credSpan(reinterpret_cast<const uint8_t *>(cred.data()), cred.size());
                    req.append("Proxy-Authorization: Basic ").append(encoding::base64Encode(credSpan)).append("\r\n");
                }
                req.append("\r\n");
                [[maybe_unused]] auto _ = pushResponse(std::move(req));
                step_ = Step::RECV_CONNECT;
                stage_ = OutboundStage::CONNECTING;
                break;
            }
            case Step::RECV_CONNECT:
            {
                const size_t avail = requestBytes();
                if (avail < 12)
                {
                    return;
                }
                std::string_view resp(requestBegin(), avail);
                size_t headerEnd = resp.find("\r\n\r\n");
                if (headerEnd == std::string_view::npos)
                {
                    return;
                }
                size_t firstLineEnd = resp.find("\r\n");
                std::string_view statusLine = resp.substr(0, firstLineEnd);
                if (statusLine.find(" 200") == std::string_view::npos)
                {
                    onParseError("HandlerOutboundHttp: CONNECT rejected by upstream HTTP proxy");
                    return;
                }
                requestConsume(headerEnd + 4);
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
