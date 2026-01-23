#pragma once

#include <string>
#include <iostream>

class Handler_base
{
protected:
    std::string requestBuffer_;
    std::string responseBuffer_;
    size_t responseOffset_ = 0;
    bool isResponding_ = false;

public:
    Handler_base() noexcept = default;
    ~Handler_base() noexcept { reset(); }
    Handler_base(const Handler_base &other)
    {
        if (this != &other)
        {
            requestBuffer_ = other.requestBuffer_;
            responseBuffer_ = other.responseBuffer_;
            responseOffset_ = other.responseOffset_;
            isResponding_ = other.isResponding_;
        }
    }
    Handler_base &operator=(const Handler_base &other)
    {
        if (&other != this)
            Handler_base(other).swap(*this);
        return *this;
    }
    Handler_base(Handler_base &&other) noexcept
    {
        if (this != &other)
        {
            requestBuffer_ = std::move(other.requestBuffer_);
            responseBuffer_ = std::move(other.responseBuffer_);
            responseOffset_ = other.responseOffset_;
            other.responseOffset_ = 0;
            isResponding_ = other.isResponding_;
            other.isResponding_ = false;
        }
    }
    Handler_base &operator=(Handler_base &&other) noexcept
    {
        if (&other != this)
            Handler_base(std::move(other)).swap(*this);
        return *this;
    }
    inline void swap(Handler_base &other) noexcept
    {
        std::swap(requestBuffer_, other.requestBuffer_);
        std::swap(responseBuffer_, other.responseBuffer_);
        std::swap(responseOffset_, other.responseOffset_);
        std::swap(isResponding_, other.isResponding_);
    }
    inline void reset() noexcept
    {
        requestBuffer_.clear();
        responseBuffer_.clear();
        responseOffset_ = 0;
        isResponding_ = false;
    }
    inline void appendRequest(const char *buf, ssize_t rn)
    {
        if (rn <= 0)
            return;
        requestBuffer_.append(buf, rn);
    }
    inline const char *responseBegin() const noexcept { return responseBuffer_.data() + responseOffset_; }
    inline size_t responseLength() const noexcept { return responseBuffer_.size() - responseOffset_; }
    inline bool isResponse(ssize_t offset = 0) noexcept
    {
        if (isResponding_)
            return false;
        if (offset < 0)
            offset = 0;
        responseOffset_ = offset;
        if (responseBuffer_.empty())
            return false;
        if (responseOffset_ < responseBuffer_.size())
            isResponding_ = true;
        return true;
    }
    inline bool isResponding(ssize_t sn) noexcept
    {
        if (sn < 0)
            sn = 0;
        if (!isResponding_)
        {
            responseOffset_ = 0;
            isResponding_ = false;
            return false;
        }
        responseOffset_ += sn;
        if (responseOffset_ >= responseBuffer_.size())
        {
            responseBuffer_.clear();
            responseOffset_ = 0;
            isResponding_ = false;
            return false;
        }
        return true;
    }
    void stdin2response()
    {
        responseBuffer_.clear();
        std::cout << "(tap 'Enter' again to response)" << std::endl;
        std::string line;
        while (std::getline(std::cin, line))
        {
            if (!responseBuffer_.empty() && (line.empty() || line == "\r"))
                break;
            responseBuffer_ += line + "\n";
        }
    }
    void request2stdout()
    {
        std::cout << requestBuffer_ << std::endl;
    }
    void process()
    {
        request2stdout();
        // responseBuffer_ = requestBuffer_;
    }
};

#include "myconcepts.hpp"
#include <llhttp.h>

template <MODE_http Mode>
class Handler_http : public Handler_base
{
    llhttp_t parser_;
    llhttp_settings_t settings_;
    size_t requestOffset_ = 0;

public:
    Handler_http() noexcept { init(); }
    ~Handler_http() noexcept { reset(); }
    Handler_http(const Handler_http &other)
        : Handler_base(other)
    {
        if (this != &other)
        {
            parser_ = other.parser_;
            settings_ = other.settings_;
            requestOffset_ = other.requestOffset_;
        }
    }
    Handler_http &operator=(const Handler_http &other)
    {
        if (&other != this)
            Handler_http(other).swap(*this);
        return *this;
    }
    Handler_http(Handler_http &&other) noexcept
        : Handler_base(std::move(other))
    {
        if (this != &other)
        {
            parser_ = std::move(other.parser_);
            settings_ = std::move(other.settings_);
            requestOffset_ = std::move(other.requestOffset_);
        }
    }
    Handler_http &operator=(Handler_http &&other) noexcept
    {
        if (&other != this)
            Handler_http(std::move(other)).swap(*this);
        return *this;
    }
    inline void swap(Handler_http &other) noexcept
    {
        Handler_base::swap(other);
        std::swap(parser_, other.parser_);
        std::swap(settings_, other.settings_);
        std::swap(requestOffset_, other.requestOffset_);
    }
    inline void reset() noexcept
    {
        if constexpr (Mode == MODE_http::REQUEST)
            llhttp_init(&parser_, HTTP_REQUEST, &settings_);
        else
            llhttp_init(&parser_, HTTP_RESPONSE, &settings_);
        parser_ = {};
        settings_ = {};
        requestOffset_ = 0;
        Handler_base::reset();
    }
    inline void init() noexcept
    {
        llhttp_settings_init(&settings_);
        settings_.on_message_begin = [](llhttp_t *p) -> int
        {
            auto *self = reinterpret_cast<Handler_http *>(p->data);
            // cleaning
            return 0;
        };
        settings_.on_header_field = [](llhttp_t *p, const char *at, size_t len) -> int
        {
            auto *self = reinterpret_cast<Handler_http *>(p->data);
            std::cout.write(at, len);
            std::cout << std::endl;
            return 0;
        };
        settings_.on_header_value = [](llhttp_t *p, const char *at, size_t len) -> int
        {
            auto *self = reinterpret_cast<Handler_http *>(p->data);
            std::cout.write(at, len);
            std::cout << std::endl;
            return 0;
        };
        settings_.on_url = [](llhttp_t *p, const char *at, size_t len) -> int
        {
            auto *self = reinterpret_cast<Handler_http *>(p->data);
            std::cout.write(at, len);
            std::cout << std::endl;
            return 0;
        };
        settings_.on_headers_complete = [](llhttp_t *p) -> int
        {
            auto *self = reinterpret_cast<Handler_http *>(p->data);
            // check headers
            return 0;
        };
        settings_.on_body = [](llhttp_t *p, const char *at, size_t len) -> int
        {
            auto *self = reinterpret_cast<Handler_http *>(p->data);
            std::cout.write(at, len);
            std::cout << std::endl;
            return 0;
        };
        settings_.on_message_complete = [](llhttp_t *p) -> int
        {
            auto *self = reinterpret_cast<Handler_http *>(p->data);
            // do business
            return 0;
        };
        if constexpr (Mode == MODE_http::REQUEST)
            llhttp_init(&parser_, HTTP_REQUEST, &settings_);
        else
            llhttp_init(&parser_, HTTP_RESPONSE, &settings_);
        parser_.data = this;
    }
    void process()
    {
        const char *data = requestBuffer_.data();
        size_t len = requestBuffer_.size();
        if (len > requestOffset_)
            switch (llhttp_execute(&parser_, data + requestOffset_, len - requestOffset_))
            {
            case HPE_OK:
                requestOffset_ = len;
                break;
            case HPE_PAUSED_UPGRADE:
                llhttp_resume_after_upgrade(&parser_);
                break;
            case HPE_PAUSED:
                llhttp_resume(&parser_);
                break;
            default:
                std::cerr << "Parse Error: " << llhttp_get_error_reason(&parser_) << std::endl;
                llhttp_init(&parser_, HTTP_REQUEST, &settings_);
                break;
            }
    }
};
