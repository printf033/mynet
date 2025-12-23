#pragma once

#include <string>
#include <iostream>

class Handler
{
    std::string recvBuffer_;
    std::string sendBuffer_;
    size_t sendOffset_ = 0;
    bool isSending_ = false;

public:
    Handler() noexcept = default;
    ~Handler() noexcept { reset(); }
    Handler(const Handler &other)
    {
        if (this != &other)
        {
            recvBuffer_ = other.recvBuffer_;
            sendBuffer_ = other.sendBuffer_;
            sendOffset_ = other.sendOffset_;
            isSending_ = other.isSending_;
        }
    }
    Handler &operator=(const Handler &other)
    {
        if (&other != this)
            Handler(other).swap(*this);
        return *this;
    }
    Handler(Handler &&other) noexcept
    {
        if (this != &other)
        {
            recvBuffer_ = std::move(other.recvBuffer_);
            sendBuffer_ = std::move(other.sendBuffer_);
            sendOffset_ = other.sendOffset_;
            other.sendOffset_ = 0;
            isSending_ = other.isSending_;
            other.isSending_ = false;
        }
    }
    Handler &operator=(Handler &&other) noexcept
    {
        if (&other != this)
            Handler(std::move(other)).swap(*this);
        return *this;
    }
    inline void reset() noexcept
    {
        recvBuffer_.clear();
        sendBuffer_.clear();
        sendOffset_ = 0;
        isSending_ = false;
    }
    inline void swap(Handler &other) noexcept
    {
        std::swap(recvBuffer_, other.recvBuffer_);
        std::swap(sendBuffer_, other.sendBuffer_);
        std::swap(sendOffset_, other.sendOffset_);
        std::swap(isSending_, other.isSending_);
    }
    inline void appendRecvStream(const char *buf, size_t n) { recvBuffer_.append(buf, n); }
    inline const char *responseBegin() const noexcept { return sendBuffer_.data() + sendOffset_; }
    inline size_t responseLength() const noexcept { return sendBuffer_.size() - sendOffset_; }
    inline bool isResponse() noexcept
    {
        if (isSending_)
            return false;
        sendOffset_ = 0;
        isSending_ = false;
        if (sendOffset_ < sendBuffer_.size())
            isSending_ = true;
        return true;
    }
    inline bool stillSending(ssize_t sn) noexcept
    {
        if (sn < 0)
            sn = 0;
        if (!isSending_)
        {
            sendOffset_ = 0;
            isSending_ = false;
            return false;
        }
        sendOffset_ += sn;
        if (sendOffset_ >= sendBuffer_.size())
        {
            sendOffset_ = 0;
            isSending_ = false;
            return false;
        }
        return true;
    }

    void process_stdin()
    {
        std::cout << "send: ";
        std::cin >> sendBuffer_;
    }
    void process_stdout()
    {
        std::cout << "recv: " << recvBuffer_ << std::endl;
    }
    void process_reflect()
    {
        std::cout << "recv: " << recvBuffer_ << std::endl;
        sendBuffer_ = recvBuffer_;
    }
    void process_http() {}
};
