#pragma once

/**
 * @file http/common.hpp
 * @brief HTTP 跨版本 (HTTP/1.x, HTTP/2, HTTP/3) 统一通用基础设施与协议常量定义。
 */

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace mynet::http
{
    /**
     * @brief HTTP 统一首部字段键值对结构体 (Single Source of Truth)
     */
    struct Header
    {
        std::string name{};
        std::string value{};

        bool operator==(const Header &o) const noexcept = default;
    };

    /**
     * @brief ASCII 大小写不敏感字符比对
     */
    [[nodiscard]] constexpr bool icharEquals(char a, char b) noexcept
    {
        if (a >= 'A' && a <= 'Z')
        {
            a = static_cast<char>(a - 'A' + 'a');
        }
        if (b >= 'A' && b <= 'Z')
        {
            b = static_cast<char>(b - 'A' + 'a');
        }
        return a == b;
    }

    /**
     * @brief ASCII 大小写不敏感字符串相等比对
     */
    [[nodiscard]] constexpr bool iequals(std::string_view a, std::string_view b) noexcept
    {
        if (a.size() != b.size())
        {
            return false;
        }
        for (size_t i = 0; i < a.size(); ++i)
        {
            if (!icharEquals(a[i], b[i]))
            {
                return false;
            }
        }
        return true;
    }

    /**
     * @brief ASCII 大小写不敏感前缀比对
     */
    [[nodiscard]] constexpr bool istartsWith(std::string_view str, std::string_view prefix) noexcept
    {
        if (str.size() < prefix.size())
        {
            return false;
        }
        return iequals(str.substr(0, prefix.size()), prefix);
    }

    /**
     * @brief 在首部列表中大小写不敏感查找指定字段值
     */
    [[nodiscard]] inline std::optional<std::string_view> findHeader(std::span<const Header> headers,
                                                                    std::string_view name) noexcept
    {
        for (const auto &h : headers)
        {
            if (iequals(h.name, name))
            {
                return h.value;
            }
        }
        return std::nullopt;
    }

    /**
     * @brief HTTP/2 与 HTTP/3 标准伪首部字段定义 (RFC 7540 / RFC 9114)
     */
    namespace pseudo
    {
        inline constexpr std::string_view kMethod = ":method";
        inline constexpr std::string_view kScheme = ":scheme";
        inline constexpr std::string_view kAuthority = ":authority";
        inline constexpr std::string_view kPath = ":path";
        inline constexpr std::string_view kStatus = ":status";
        inline constexpr std::string_view kProtocol = ":protocol";
    } // namespace pseudo

    /**
     * @brief HTTP 标准请求方法字符串
     */
    namespace method
    {
        inline constexpr std::string_view kGet = "GET";
        inline constexpr std::string_view kHead = "HEAD";
        inline constexpr std::string_view kPost = "POST";
        inline constexpr std::string_view kPut = "PUT";
        inline constexpr std::string_view kDelete = "DELETE";
        inline constexpr std::string_view kConnect = "CONNECT";
        inline constexpr std::string_view kOptions = "OPTIONS";
        inline constexpr std::string_view kTrace = "TRACE";
        inline constexpr std::string_view kPatch = "PATCH";
    } // namespace method

    /**
     * @brief 常见 HTTP 状态码枚举
     */
    enum class StatusCode : uint16_t
    {
        Continue = 100,
        SwitchingProtocols = 101,
        EarlyHints = 103,
        OK = 200,
        Created = 201,
        Accepted = 202,
        NoContent = 204,
        PartialContent = 206,
        MultipleChoices = 300,
        MovedPermanently = 301,
        Found = 302,
        SeeOther = 303,
        NotModified = 304,
        TemporaryRedirect = 307,
        PermanentRedirect = 308,
        BadRequest = 400,
        Unauthorized = 401,
        Forbidden = 403,
        NotFound = 404,
        MethodNotAllowed = 405,
        ProxyAuthenticationRequired = 407,
        RequestTimeout = 408,
        PayloadTooLarge = 413,
        UriTooLong = 414,
        MisdirectedRequest = 421,
        TooEarly = 425,
        UpgradeRequired = 426,
        InternalServerError = 500,
        NotImplemented = 501,
        BadGateway = 502,
        ServiceUnavailable = 503,
        GatewayTimeout = 504,
        HttpVersionNotSupported = 505
    };

    /**
     * @brief 获取 HTTP 状态码对应的标准原因短语 (Reason Phrase)
     */
    [[nodiscard]] constexpr std::string_view statusReason(uint16_t code) noexcept
    {
        switch (code)
        {
        case 100:
            return "Continue";
        case 101:
            return "Switching Protocols";
        case 103:
            return "Early Hints";
        case 200:
            return "OK";
        case 201:
            return "Created";
        case 202:
            return "Accepted";
        case 204:
            return "No Content";
        case 206:
            return "Partial Content";
        case 300:
            return "Multiple Choices";
        case 301:
            return "Moved Permanently";
        case 302:
            return "Found";
        case 303:
            return "See Other";
        case 304:
            return "Not Modified";
        case 307:
            return "Temporary Redirect";
        case 308:
            return "Permanent Redirect";
        case 400:
            return "Bad Request";
        case 401:
            return "Unauthorized";
        case 403:
            return "Forbidden";
        case 404:
            return "Not Found";
        case 405:
            return "Method Not Allowed";
        case 407:
            return "Proxy Authentication Required";
        case 408:
            return "Request Timeout";
        case 413:
            return "Payload Too Large";
        case 414:
            return "URI Too Long";
        case 421:
            return "Misdirected Request";
        case 425:
            return "Too Early";
        case 426:
            return "Upgrade Required";
        case 500:
            return "Internal Server Error";
        case 501:
            return "Not Implemented";
        case 502:
            return "Bad Gateway";
        case 503:
            return "Service Unavailable";
        case 504:
            return "Gateway Timeout";
        case 505:
            return "HTTP Version Not Supported";
        default:
            return "Unknown";
        }
    }

    [[nodiscard]] constexpr std::string_view statusReason(StatusCode code) noexcept
    {
        return statusReason(std::to_underlying(code));
    }

} // namespace mynet::http
