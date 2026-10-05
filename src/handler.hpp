#pragma once

#include "buffer.hpp"
#include "hexdump.hpp"
#include "log.hpp"
#include "myconcepts.hpp"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <llhttp.h>
#include <string>
#include <utility>
#include <vector>

// Protocol front end for one connection.
//
// The split this type follows: a handler owns *parsing* and *response
// production*. It does not own socket send progress, keep-alive timing or
// the transport. Those belong to Connection (see connection.hpp), which is
// what lets one read event yield several responses without trampling a
// single shared buffer, and lets the loop apply back pressure by asking
// readCredit().
class HandlerBase
{
protected:
    Buffer requestBuffer_;
    std::deque<std::string> responseQueue_;
    size_t maxRequestBytes_ = 4 * 1024 * 1024;
    bool closeAfterResponse_ = false;

public:
    HandlerBase() noexcept = default;
    virtual ~HandlerBase() noexcept = default;
    HandlerBase(const HandlerBase &) = delete("a handler holds parser state bound to one connection");
    HandlerBase &operator=(const HandlerBase &) = delete("a handler holds parser state bound to one connection");
    HandlerBase(HandlerBase &&) = delete("a handler holds parser state bound to one connection");
    HandlerBase &operator=(HandlerBase &&) = delete("a handler holds parser state bound to one connection");

    // 0 success. Virtual so a recycled derived handler rebuilds its own
    // parser state and not only this base's buffers.
    virtual void reset() noexcept
    {
        requestBuffer_.reset();
        responseQueue_.clear();
        closeAfterResponse_ = false;
    }

    // ---- read side ----
    inline void appendRequest(const char *buf, ssize_t rn) noexcept
    {
        requestBuffer_.append(buf, rn);
    }
    inline bool requestOverLimit() const noexcept
    {
        return requestBuffer_.readableBytes() > maxRequestBytes_;
    }
    inline size_t requestBytes() const noexcept { return requestBuffer_.readableBytes(); }
    inline const char *requestBegin() const noexcept { return requestBuffer_.readableBegin(); }
    inline void requestConsume(size_t n) noexcept { requestBuffer_.retrieve(n); }
    inline void requestClear() noexcept { requestBuffer_.retrieveAll(); }
    // Back pressure: the loop stops reading this socket while the credit is 0.
    inline size_t readCredit() const noexcept
    {
        size_t used = requestBuffer_.readableBytes();
        return used >= maxRequestBytes_ ? 0 : maxRequestBytes_ - used;
    }
    inline void setMaxRequestBytes(size_t n) noexcept { maxRequestBytes_ = n; }

    // ---- write side ----
    inline bool hasResponse() const noexcept { return !responseQueue_.empty(); }
    inline size_t responseCount() const noexcept { return responseQueue_.size(); }
    inline std::string takeResponse()
    {
        if (responseQueue_.empty())
            return std::string();
        std::string out = std::move(responseQueue_.front());
        responseQueue_.pop_front();
        return out;
    }
    inline void pushResponse(std::string s)
    {
        responseQueue_.push_back(std::move(s));
    }
    inline void pushResponse(const char *buf, size_t n)
    {
        responseQueue_.emplace_back(buf, n);
    }

    // ---- lifecycle ----
    inline bool closeAfterResponse() const noexcept { return closeAfterResponse_; }
    inline void setCloseAfterResponse(bool v) noexcept { closeAfterResponse_ = v; }

    // ---- hooks a business handler may override ----
    virtual void onMessageComplete() noexcept {}
    virtual void onParseError(const char *reason) noexcept { (void)reason; }
    virtual void onUpgrade() noexcept {}

    // HandlerBase itself speaks a trivial echo protocol, which keeps the
    // samples runnable without an application on top.
    void process()
    {
        if (requestBuffer_.readableBytes() == 0)
            return;
        pushResponse(requestBuffer_.readableBegin(), requestBuffer_.readableBytes());
        requestBuffer_.retrieveAll();
    }
};

// HTTP/1.x codec. Parses one message at a time: on_message_complete pauses
// the parser so the loop can drain the produced response before the next
// message on the same connection is touched.
template <HttpMode Mode>
class HandlerHttp : public HandlerBase
{
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
        return Mode == HttpMode::request ? HTTP_REQUEST : HTTP_RESPONSE;
    }

    // ---- llhttp trampolines ----
    static int cbMessageBegin(llhttp_t *p)
    {
        auto *self = static_cast<HandlerHttp *>(p->data);
        if (self == nullptr)
            return HPE_OK;
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
        if (self != nullptr)
            self->url_.append(at, len);
        return HPE_OK;
    }
    static int cbHeaderField(llhttp_t *p, const char *at, size_t len)
    {
        auto *self = static_cast<HandlerHttp *>(p->data);
        if (self == nullptr)
            return HPE_OK;
        // A new field starts here, which means the previous pair is done.
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
        if (self == nullptr)
            return HPE_OK;
        self->inValue_ = true;
        self->currentValue_.append(at, len);
        return HPE_OK;
    }
    static int cbHeadersComplete(llhttp_t *p)
    {
        auto *self = static_cast<HandlerHttp *>(p->data);
        if (self == nullptr)
            return HPE_OK;
        if (self->inValue_)
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
        if (self != nullptr)
            self->body_.append(at, len);
        return HPE_OK;
    }
    static int cbMessageComplete(llhttp_t *p)
    {
        auto *self = static_cast<HandlerHttp *>(p->data);
        if (self != nullptr)
            self->onMessageComplete();
        // Stop exactly at the message boundary; process() resumes and picks
        // up whatever pipelined bytes follow.
        return HPE_PAUSED;
    }

public:
    HandlerHttp() noexcept { init(); }
    ~HandlerHttp() noexcept override = default;
    HandlerHttp(const HandlerHttp &) = delete("a handler holds parser state bound to one connection");
    HandlerHttp &operator=(const HandlerHttp &) = delete("a handler holds parser state bound to one connection");
    HandlerHttp(HandlerHttp &&) = delete("a handler holds parser state bound to one connection");
    HandlerHttp &operator=(HandlerHttp &&) = delete("a handler holds parser state bound to one connection");

    // 0 success. Rebuilds both the parser state and the callback table; the
    // two must never be torn apart, which is what reset() below relies on.
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

    // 0 success
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

    // ---- parsed message accessors ----
    inline const std::string &url() const noexcept { return url_; }
    inline const std::string &body() const noexcept { return body_; }
    inline const std::vector<std::pair<std::string, std::string>> &headers() const noexcept { return headers_; }
    inline int httpMajor() const noexcept { return parser_.http_major; }
    inline int httpMinor() const noexcept { return parser_.http_minor; }
    inline bool keepAlive() const noexcept { return llhttp_should_keep_alive(&parser_) != 0; }
    inline uint8_t method() const noexcept { return parser_.method; }
    inline const char *methodName() const noexcept { return llhttp_method_name(static_cast<llhttp_method_t>(parser_.method)); }
    inline std::string headerValue(const char *name) const
    {
        for (const auto &kv : headers_)
        {
            if (kv.first.size() != std::strlen(name))
                continue;
            bool equal = true;
            for (size_t i = 0; i < kv.first.size(); ++i)
            {
                char a = kv.first[i];
                char b = name[i];
                if (a >= 'A' && a <= 'Z')
                    a = static_cast<char>(a - 'A' + 'a');
                if (b >= 'A' && b <= 'Z')
                    b = static_cast<char>(b - 'A' + 'a');
                if (a != b)
                {
                    equal = false;
                    break;
                }
            }
            if (equal)
                return kv.second;
        }
        return std::string();
    }

    // Default behaviour: answer a request with a minimal keep-alive echo.
    // A real application derives from this and overrides.
    void onMessageComplete() noexcept override
    {
        if constexpr (Mode == HttpMode::request)
        {
            std::string resp;
            resp.reserve(128 + body_.size());
            resp += "HTTP/1.1 200 OK\r\n";
            resp += "Content-Length: ";
            resp += std::to_string(body_.size());
            resp += "\r\n";
            resp += "Content-Type: application/octet-stream\r\n";
            resp += "Connection: keep-alive\r\n\r\n";
            resp += body_;
            pushResponse(std::move(resp));
        }
    }

    void onParseError(const char *reason) noexcept override
    {
        (void)reason;
        if constexpr (Mode == HttpMode::request)
        {
            static const char bad[] =
                "HTTP/1.1 400 Bad Request\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n\r\n";
            pushResponse(std::string(bad, sizeof(bad) - 1));
        }
        // A framing error is unrecoverable for the rest of the connection.
        closeAfterResponse_ = true;
    }

    void process()
    {
        while (true)
        {
            size_t avail = requestBuffer_.readableBytes();
            if (avail == 0)
                return;
            const char *data = requestBuffer_.readableBegin();
            llhttp_errno_t err = static_cast<llhttp_errno_t>(llhttp_execute(&parser_, data, avail));
            const char *pos = llhttp_get_error_pos(&parser_);
            size_t consumed = (pos != nullptr && pos >= data && pos <= data + avail)
                                  ? static_cast<size_t>(pos - data)
                                  : 0;
            if (consumed > 0)
                requestBuffer_.retrieve(consumed);

            switch (err)
            {
            case HPE_OK:
                // llhttp consumed every byte handed in and wants more. The
                // parser keeps its partial-message state, so the buffer must
                // be drained here or process() would re-feed those bytes and
                // pad the header list with duplicates.
                requestBuffer_.retrieveAll();
                return;
            case HPE_PAUSED:
                // on_message_complete stopped us exactly on a message
                // boundary, so err_pos marks where the next pipelined message
                // starts. Resume and let the loop take the rest.
                llhttp_resume(&parser_);
                if (consumed == 0)
                    return;
                break;
            case HPE_PAUSED_UPGRADE:
                llhttp_resume_after_upgrade(&parser_);
                onUpgrade();
                return;
            default:
            {
                // The library owns the observation point rather than the virtual
                // onParseError(): a subclass that overrides the hook to write its
                // own 400 still gets the wire-level reason recorded here.
                const char *reason = llhttp_get_error_reason(&parser_);
                LOG_WARN("Handler: HTTP message parse error: {}", reason != nullptr ? reason : "unknown");
                onParseError(reason);
                requestBuffer_.retrieveAll();
                return;
            }
            }
        }
    }
};

// A front end that writes down whatever arrives, understood or not.
//
// HandlerBase already echoes the bytes it is handed. This one echoes them and
// also records them, which is what a listener needs when the traffic cannot be
// understood *at all*. The case it exists for is a TLS client that reached a
// plain port: finishing that handshake takes a listener holding the matching
// private key, but the ClientHello is still bytes on the wire, and seeing
// those bytes is the difference between "the client got nothing" and "the
// client sent a ClientHello, and here it is".
//
// The echo half stays exactly as inherited -- a client that speaks something
// this listener does understand sees no behavioural difference, only extra
// log lines.
//
// Nothing is truncated: every byte that reaches this front end is written
// down, in full. That is a deliberate trade for a listener under inspection --
// a large body costs a large log -- and the reason this front end belongs on
// a port someone is watching, not in front of real traffic.
class HandlerTrace : public HandlerBase
{
public:
    void process()
    {
        const size_t n = requestBuffer_.readableBytes();
        if (n == 0)
            return;
        mynetdump::writeDown("HandlerTrace", reinterpret_cast<const unsigned char *>(requestBuffer_.readableBegin()), n);
        // Unchanged echo semantics: what arrived goes back out.
        pushResponse(requestBuffer_.readableBegin(), n);
        requestBuffer_.retrieveAll();
    }
};
