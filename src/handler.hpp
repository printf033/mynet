#pragma once

#include "buffer.hpp"
#include "concepts.hpp"
#include "log.hpp"
#include "ringQueue.hpp"
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

    /**
     * @brief 业务协议处理器基类
     *
     * 架构分层职责：
     * - 处理器（Handler）专精于协议流解析（Parsing）与应答生成（Response Production）；
     * - 传输层（Connection）掌管套接字收发进度、Keep-Alive 超时与底层 TLS 加密。
     * 这种解耦使得单次网络数据读取能够连续生成多条管道化应答，同时通过 readCredit() 提供自然的流控背压。
     */
    class HandlerBase
    {
    public:
        /**
         * @brief 构造时一次性定容响应队列
         *
         * 默认 64 槽对齐流水线深度：开箱即可用，后续连接层可在建连时调用
         * reserveResponses() 按协议需求重新定容（init 幂等）。
         */
        explicit HandlerBase(size_t responseCapacity = 64) noexcept
        {
            (void)responseQueue_.init(responseCapacity); // 槽位分配失败降级为容量 0 拒收，不折损零异常构造
        }

        virtual ~HandlerBase() noexcept = default;

        HandlerBase(const HandlerBase &) = delete ("a handler holds parser state bound to one connection");
        HandlerBase &operator=(const HandlerBase &) = delete ("a handler holds parser state bound to one connection");
        HandlerBase(HandlerBase &&) = delete ("a handler holds parser state bound to one connection");
        HandlerBase &operator=(HandlerBase &&) = delete ("a handler holds parser state bound to one connection");

        /**
         * @brief 重置处理器状态（虚函数，以便派生类重置专属解析器）
         */
        virtual void reset() noexcept
        {
            requestBuffer_.reset();
            responseQueue_.clear();
            closeAfterResponse_ = false;
        }

        // ---- 读取侧控制 (Read Side) ----

        /**
         * @brief 追加一段对端请求字节到解析缓冲（零异常，失败显式错误码）
         *
         * Buffer::append() 为 nothrow 接口：堆扩容失败以 ERR::BUF_ALLOC_FAILED
         * 交付，缓冲区保持原样，调用方据此可安全丢弃本次读到的字节（对端重传
         * 或连接关闭兜底）。
         *
         * @param buf 对端字节首地址（允许为 nullptr，此时为无操作）
         * @param rn 本次读取的字节数（须非负）
         * @return 成功 {}；解析缓冲扩容失败 std::unexpected(ERR::BUF_ALLOC_FAILED)
         */
        [[nodiscard]] inline Result<> appendRequest(const char *buf, ssize_t rn) noexcept
        {
            if (buf != nullptr && rn > 0) [[likely]]
            {
                return requestBuffer_.append(buf, static_cast<size_t>(rn));
            }
            return {};
        }

        [[nodiscard]] inline bool requestOverLimit() const noexcept
        {
            return requestBuffer_.readableBytes() > maxRequestBytes_;
        }

        [[nodiscard]] inline size_t requestBytes() const noexcept { return requestBuffer_.readableBytes(); }

        [[nodiscard]] inline const char *requestBegin() const noexcept { return requestBuffer_.readableBegin(); }

        inline void requestConsume(size_t n) noexcept { requestBuffer_.retrieve(n); }

        inline void requestClear() noexcept { requestBuffer_.retrieveAll(); }

        /**
         * @brief 剩余信用窗口（为 0 时事件循环将暂停接收读取，实施背压保护）
         */
        [[nodiscard]] inline size_t readCredit() const noexcept
        {
            const size_t used = requestBuffer_.readableBytes();
            return used >= maxRequestBytes_ ? 0 : maxRequestBytes_ - used;
        }

        inline void setMaxRequestBytes(size_t n) noexcept { maxRequestBytes_ = n; }

        // ---- 发送响应侧控制 (Write Side) ----

        [[nodiscard]] inline bool hasResponse() const noexcept { return !responseQueue_.empty(); }

        [[nodiscard]] inline size_t responseCount() const noexcept { return responseQueue_.size(); }

        [[nodiscard]] inline std::string takeResponse()
        {
            if (responseQueue_.empty()) [[unlikely]]
            {
                return std::string();
            }
            std::string out = std::move(responseQueue_.front());
            responseQueue_.pop();
            return out;
        }

        /**
         * @brief 推入一条完整响应（定容队列，满队显式拒绝）
         */
        [[nodiscard]] inline Result<> pushResponse(std::string s) noexcept
        {
            return responseQueue_.push(std::move(s));
        }

        /**
         * @brief 推入一段视图响应（零拷贝适配 string_view 与连续字节）
         */
        [[nodiscard]] inline Result<> pushResponse(std::string_view sv) noexcept
        {
            if (sv.data() == nullptr || sv.empty())
            {
                return {};
            }
            return responseQueue_.emplace(sv);
        }

        /**
         * @brief 推入以空终止的字符串字面量（重载消歧义，内部转为 string_view）
         */
        [[nodiscard]] inline Result<> pushResponse(const char *s) noexcept
        {
            if (s == nullptr) [[unlikely]]
            {
                return {};
            }
            return pushResponse(std::string_view(s));
        }

        /**
         * @brief 预分配响应队列槽位（连接建立时调用一次）
         *
         * @param capacity 槽位数量（允许流水线化的最大响应条数）
         * @return 成功 {}；槽位分配失败 std::unexpected(ERR::POOL_ALLOC_FAILED)
         */
        [[nodiscard]] inline Result<> reserveResponses(size_t capacity) noexcept
        {
            return responseQueue_.init(capacity);
        }

        // ---- 生命周期管理 (Lifecycle) ----

        [[nodiscard]] inline bool closeAfterResponse() const noexcept { return closeAfterResponse_; }

        inline void setCloseAfterResponse(bool v) noexcept { closeAfterResponse_ = v; }

        // ---- 业务扩展虚钩子 (Business Hooks) ----

        virtual void onMessageComplete() noexcept {}
        virtual void onParseError([[maybe_unused]] const char *reason) noexcept {}
        virtual void onUpgrade() noexcept {}

        /**
         * @brief 默认执行逻辑：标准 Echo 协议回显
         */
        void process()
        {
            if (requestBuffer_.empty()) [[unlikely]]
            {
                return;
            }
            if (!pushResponse(requestBuffer_.readableView())) [[unlikely]]
            {
                LOG_WARN("Handler::process: response queue full, echoing dropped");
            }
            requestBuffer_.retrieveAll();
        }

    protected:
        Buffer requestBuffer_;
        RingQueue responseQueue_;
        size_t maxRequestBytes_ = 4 << 20;
        bool closeAfterResponse_ = false;
    };

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

        HandlerHttp(const HandlerHttp &) = delete ("a handler holds parser state bound to one connection");
        HandlerHttp &operator=(const HandlerHttp &) = delete ("a handler holds parser state bound to one connection");
        HandlerHttp(HandlerHttp &&) = delete ("a handler holds parser state bound to one connection");
        HandlerHttp &operator=(HandlerHttp &&) = delete ("a handler holds parser state bound to one connection");

        inline void init() noexcept
        {
            llhttp_settings_init(&settings_);
            settings_.on_message_begin = &HandlerHttp::cbMessageBegin;
            settings_.on_url = &HandlerHttp::cbUrl;
            settings_.on_header_field = &HandlerHttp::cbHeaderField;
            settings_.on_header_value = &HandlerHttp::cbHeaderValue;
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
            inValue_ = false;
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

        void onParseError(const char *reason) noexcept override
        {
            (void)reason;
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
        llhttp_t parser_{};
        llhttp_settings_t settings_{};

        std::string url_;
        std::vector<std::pair<std::string, std::string>> headers_;
        std::string body_;
        std::string currentField_;
        std::string currentValue_;
        bool inValue_ = false;

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
            self->inValue_ = false;
            return HPE_OK;
        }

        static int cbUrl(llhttp_t *p, const char *at, size_t len)
        {
            auto *self = static_cast<HandlerHttp *>(p->data);
            if (self != nullptr) [[likely]]
            {
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
            if (self->inValue_)
            {
                self->headers_.emplace_back(std::move(self->currentField_), std::move(self->currentValue_));
                self->currentField_.clear();
                self->currentValue_.clear();
                self->inValue_ = false;
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
            self->inValue_ = true;
            self->currentValue_.append(at, len);
            return HPE_OK;
        }

        static int cbHeadersComplete(llhttp_t *p)
        {
            auto *self = static_cast<HandlerHttp *>(p->data);
            if (self == nullptr) [[unlikely]]
            {
                return HPE_OK;
            }
            if (self->inValue_ || !self->currentField_.empty())
            {
                self->headers_.emplace_back(std::move(self->currentField_), std::move(self->currentValue_));
                self->currentField_.clear();
                self->currentValue_.clear();
                self->inValue_ = false;
            }
            return HPE_OK;
        }

        static int cbBody(llhttp_t *p, const char *at, size_t len)
        {
            auto *self = static_cast<HandlerHttp *>(p->data);
            if (self != nullptr) [[likely]]
            {
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

} // namespace mynet
