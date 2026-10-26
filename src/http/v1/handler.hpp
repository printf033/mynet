#pragma once

/**
 * @file http/v1/handler.hpp
 * @brief HTTP/1.x 协议处理器实现，基于 llhttp 状态机进行文本报文流解析。
 */

#include "../../handler.hpp"
#include "log.hpp"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <llhttp.h>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace mynet
{
    namespace http::v1
    {
        /**
         * @brief HTTP 编解码模式枚举
         */
        enum class HTTP_MODE : uint8_t
        {
            REQUEST = 0,
            RESPONSE = 1
        };

        /**
         * @brief 基于 llhttp 的极速 HTTP/1.x 编解码协议处理器
         *
         * 支持完整的 HTTP 请求与响应解析、Keep-Alive 自动推断、流水线边界识别与自动 400 Bad Request 错误自愈。
         */
        template <HTTP_MODE Mode>
        class HandlerHttp : public HandlerBase
        {
        public:
            HandlerHttp() noexcept { init(); }

            ~HandlerHttp() noexcept override = default;

            HandlerHttp(const HandlerHttp &) = delete("a handler holds parser state bound to one connection");
            HandlerHttp &
            operator=(const HandlerHttp &) = delete("a handler holds parser state bound to one connection");
            HandlerHttp(HandlerHttp &&) = delete("a handler holds parser state bound to one connection");
            HandlerHttp &operator=(HandlerHttp &&) = delete("a handler holds parser state bound to one connection");

            inline void init() noexcept
            {
                llhttp_settings_init(&settings_);
                settings_.on_message_begin = &HandlerHttp::cbMessageBegin;
                settings_.on_url = &HandlerHttp::cbUrl;
                settings_.on_header_field = &HandlerHttp::cbHeaderField;
                settings_.on_header_value = &HandlerHttp::cbHeaderValue;
                settings_.on_header_value_complete = &HandlerHttp::cbHeaderValueComplete;
                settings_.on_headers_complete = &HandlerHttp::cbHeadersComplete;
                settings_.on_body = &HandlerHttp::cbBody;
                settings_.on_message_complete = &HandlerHttp::cbMessageComplete;
                llhttp_init(&parser_, parserType(), &settings_);
                parser_.data = this;
            }

            void reset() noexcept override
            {
                init();
                url_.clear();
                headers_.clear();
                body_.clear();
                currentField_.clear();
                currentValue_.clear();
                totalHeaderBytes_ = 0;
                HandlerBase::reset();
            }

            // ---- 解析元数据快速提取 ----

            [[nodiscard]] inline const std::string &url() const noexcept { return url_; }
            [[nodiscard]] inline const std::string &body() const noexcept { return body_; }
            [[nodiscard]] inline const std::vector<std::pair<std::string, std::string>> &headers() const noexcept
            {
                return headers_;
            }
            [[nodiscard]] inline int httpMajor() const noexcept { return parser_.http_major; }
            [[nodiscard]] inline int httpMinor() const noexcept { return parser_.http_minor; }
            [[nodiscard]] inline bool keepAlive() const noexcept { return llhttp_should_keep_alive(&parser_) != 0; }
            [[nodiscard]] inline uint8_t method() const noexcept { return parser_.method; }
            [[nodiscard]] inline const char *methodName() const noexcept
            {
                return llhttp_method_name(static_cast<llhttp_method_t>(parser_.method));
            }

            [[nodiscard]] inline std::string_view headerValue(const char *name) const noexcept
            {
                if (name == nullptr) [[unlikely]]
                {
                    return {};
                }
                const size_t targetLen = std::strlen(name);
                for (const auto &kv : headers_)
                {
                    if (kv.first.size() != targetLen)
                    {
                        continue;
                    }
                    bool equal = true;
                    for (size_t i = 0; i < kv.first.size(); ++i)
                    {
                        char a = kv.first[i];
                        char b = name[i];
                        if (a >= 'A' && a <= 'Z')
                        {
                            a = static_cast<char>(a - 'A' + 'a');
                        }
                        if (b >= 'A' && b <= 'Z')
                        {
                            b = static_cast<char>(b - 'A' + 'a');
                        }
                        if (a != b)
                        {
                            equal = false;
                            break;
                        }
                    }
                    if (equal)
                    {
                        return kv.second;
                    }
                }
                return {};
            }

            void onMessageComplete() noexcept override
            {
                if constexpr (Mode == HTTP_MODE::REQUEST)
                {
                    std::string resp;
                    resp.reserve(128 + body_.size());
                    resp.append("HTTP/1.1 200 OK\r\nContent-Length: ");
                    resp.append(std::to_string(body_.size()));
                    resp.append("\r\nContent-Type: application/octet-stream\r\nConnection: ");
                    // 按 llhttp 解析结论回写连接语义，避免对 Connection: close 的请求错误地续连
                    resp.append(keepAlive() ? "keep-alive" : "close");
                    resp.append("\r\n\r\n");
                    resp.append(body_);
                    if (!pushResponse(std::move(resp))) [[unlikely]]
                    {
                        LOG_WARN("HandlerHttp: response queue full, response dropped");
                    }
                    if (!keepAlive())
                    {
                        closeAfterResponse_ = true;
                    }
                }
            }

            void onParseError([[maybe_unused]] const char *reason) noexcept override
            {
                if constexpr (Mode == HTTP_MODE::REQUEST)
                {
                    static constexpr std::string_view kBadResponse = "HTTP/1.1 400 Bad Request\r\n"
                                                                     "Content-Length: 0\r\n"
                                                                     "Connection: close\r\n\r\n";
                    if (!pushResponse(kBadResponse)) [[unlikely]]
                    {
                        LOG_WARN("HandlerHttp: response queue full, 400 dropped");
                    }
                }
                closeAfterResponse_ = true;
            }

            void process()
            {
                while (true)
                {
                    const size_t avail = requestBuffer_.readableBytes();
                    if (avail == 0)
                    {
                        return;
                    }
                    const char *data = requestBuffer_.readableBegin();
                    const auto err = static_cast<llhttp_errno_t>(llhttp_execute(&parser_, data, avail));
                    const char *pos = llhttp_get_error_pos(&parser_);
                    const size_t consumed =
                        (pos != nullptr && pos >= data && pos <= data + avail) ? static_cast<size_t>(pos - data) : 0;
                    if (consumed > 0)
                    {
                        requestBuffer_.retrieve(consumed);
                    }

                    switch (err)
                    {
                    case HPE_OK:
                        requestBuffer_.retrieveAll();
                        return;
                    case HPE_PAUSED:
                        llhttp_resume(&parser_);
                        if (consumed == 0)
                        {
                            return;
                        }
                        break;
                    case HPE_PAUSED_UPGRADE:
                        llhttp_resume_after_upgrade(&parser_);
                        onUpgrade();
                        return;
                    default:
                    {
                        const char *reason = llhttp_get_error_reason(&parser_);
                        LOG_WARN("Handler: HTTP message parse error: {}", reason != nullptr ? reason : "unknown");
                        onParseError(reason);
                        requestBuffer_.retrieveAll();
                        return;
                    }
                    }
                }
            }

        private:
            static constexpr size_t kMaxUrlLength = 8192;
            static constexpr size_t kMaxHeadersCount = 100;
            static constexpr size_t kMaxHeaderFieldLength = 4096;
            static constexpr size_t kMaxHeaderValueLength = 16384;
            static constexpr size_t kMaxTotalHeadersLength = 65536;    // 64 KiB
            static constexpr size_t kMaxBodyLength = 16 * 1024 * 1024; // 16 MiB

            llhttp_t parser_{};
            llhttp_settings_t settings_{};

            std::string url_;
            std::vector<std::pair<std::string, std::string>> headers_;
            std::string body_;
            std::string currentField_;
            std::string currentValue_;
            size_t totalHeaderBytes_ = 0;

            static constexpr llhttp_type_t parserType() noexcept
            {
                return Mode == HTTP_MODE::REQUEST ? HTTP_REQUEST : HTTP_RESPONSE;
            }

            // ---- llhttp 回调跳板 ----

            static int cbMessageBegin(llhttp_t *p)
            {
                auto *self = static_cast<HandlerHttp *>(p->data);
                if (self == nullptr) [[unlikely]]
                {
                    return HPE_OK;
                }
                self->url_.clear();
                self->headers_.clear();
                self->body_.clear();
                self->currentField_.clear();
                self->currentValue_.clear();
                self->totalHeaderBytes_ = 0;
                return HPE_OK;
            }

            static int cbUrl(llhttp_t *p, const char *at, size_t len)
            {
                auto *self = static_cast<HandlerHttp *>(p->data);
                if (self != nullptr) [[likely]]
                {
                    if (self->url_.size() + len > kMaxUrlLength) [[unlikely]]
                    {
                        return HPE_USER;
                    }
                    self->url_.append(at, len);
                }
                return HPE_OK;
            }

            static int cbHeaderField(llhttp_t *p, const char *at, size_t len)
            {
                auto *self = static_cast<HandlerHttp *>(p->data);
                if (self == nullptr) [[unlikely]]
                {
                    return HPE_OK;
                }
                if (self->currentField_.size() + len > kMaxHeaderFieldLength) [[unlikely]]
                {
                    return HPE_USER;
                }
                self->currentField_.append(at, len);
                return HPE_OK;
            }

            static int cbHeaderValue(llhttp_t *p, const char *at, size_t len)
            {
                auto *self = static_cast<HandlerHttp *>(p->data);
                if (self == nullptr) [[unlikely]]
                {
                    return HPE_OK;
                }
                if (self->currentValue_.size() + len > kMaxHeaderValueLength) [[unlikely]]
                {
                    return HPE_USER;
                }
                self->currentValue_.append(at, len);
                return HPE_OK;
            }

            static int cbHeaderValueComplete(llhttp_t *p)
            {
                auto *self = static_cast<HandlerHttp *>(p->data);
                if (self == nullptr) [[unlikely]]
                {
                    return HPE_OK;
                }
                if (self->headers_.size() >= kMaxHeadersCount) [[unlikely]]
                {
                    return HPE_USER;
                }
                self->totalHeaderBytes_ += self->currentField_.size() + self->currentValue_.size();
                if (self->totalHeaderBytes_ > kMaxTotalHeadersLength) [[unlikely]]
                {
                    return HPE_USER;
                }
                self->headers_.emplace_back(std::move(self->currentField_), std::move(self->currentValue_));
                self->currentField_.clear();
                self->currentValue_.clear();
                return HPE_OK;
            }

            static int cbHeadersComplete(llhttp_t *p)
            {
                auto *self = static_cast<HandlerHttp *>(p->data);
                if (self == nullptr) [[unlikely]]
                {
                    return HPE_OK;
                }
                if (!self->currentField_.empty())
                {
                    if (self->headers_.size() >= kMaxHeadersCount) [[unlikely]]
                    {
                        return HPE_USER;
                    }
                    self->totalHeaderBytes_ += self->currentField_.size() + self->currentValue_.size();
                    if (self->totalHeaderBytes_ > kMaxTotalHeadersLength) [[unlikely]]
                    {
                        return HPE_USER;
                    }
                    self->headers_.emplace_back(std::move(self->currentField_), std::move(self->currentValue_));
                    self->currentField_.clear();
                    self->currentValue_.clear();
                }
                return HPE_OK;
            }

            static int cbBody(llhttp_t *p, const char *at, size_t len)
            {
                auto *self = static_cast<HandlerHttp *>(p->data);
                if (self != nullptr) [[likely]]
                {
                    if (self->body_.size() + len > kMaxBodyLength) [[unlikely]]
                    {
                        return HPE_USER;
                    }
                    self->body_.append(at, len);
                }
                return HPE_OK;
            }

            static int cbMessageComplete(llhttp_t *p)
            {
                auto *self = static_cast<HandlerHttp *>(p->data);
                if (self != nullptr) [[likely]]
                {
                    self->onMessageComplete();
                }
                return HPE_PAUSED;
            }
        };
    } // namespace http::v1

    using http::v1::HandlerHttp;
    using http::v1::HTTP_MODE;

} // namespace mynet
