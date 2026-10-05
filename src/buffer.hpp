#pragma once

#include <string>
#include <sys/types.h>
#include <utility>

// A byte buffer with a read cursor on top of a single backing string.
// Writes always append at the tail; reads consume from readIndex_.
// Storage is only reclaimed when the consumed prefix grows large enough
// to be worth compacting, so a long-lived connection does not keep
// reallocating on every request.
class Buffer
{
    std::string data_;
    size_t readIndex_ = 0;
    size_t highWaterMark_ = 64 * 1024;

public:
    Buffer() noexcept = default;
    ~Buffer() noexcept = default;
    Buffer(const Buffer &) = delete("a buffer owns one heap block sized for its connection; a copy would alias the bytes");
    Buffer &operator=(const Buffer &) = delete("a buffer owns one heap block sized for its connection; a copy would alias the bytes");
    Buffer(Buffer &&) noexcept = default;
    Buffer &operator=(Buffer &&) noexcept = default;

    inline void swap(Buffer &other) noexcept
    {
        std::swap(data_, other.data_);
        std::swap(readIndex_, other.readIndex_);
        std::swap(highWaterMark_, other.highWaterMark_);
    }
    // 0 success (mustResettable)
    inline void reset() noexcept
    {
        data_.clear();
        readIndex_ = 0;
    }

    // ---- read side ----
    inline const char *readableBegin() const noexcept { return data_.data() + readIndex_; }
    inline size_t readableBytes() const noexcept { return data_.size() - readIndex_; }
    inline bool empty() const noexcept { return readIndex_ == data_.size(); }

    inline void retrieve(size_t n) noexcept
    {
        if (n >= readableBytes())
        {
            retrieveAll();
            return;
        }
        readIndex_ += n;
        // Compact once the dead prefix outweighs the live tail.
        if (readIndex_ >= 4096 && readIndex_ * 2 >= data_.size())
        {
            data_.erase(0, readIndex_);
            readIndex_ = 0;
        }
    }
    inline void retrieveAll() noexcept
    {
        data_.clear();
        readIndex_ = 0;
    }
    inline std::string retrieveAllAsString()
    {
        std::string out(readableBegin(), readableBytes());
        retrieveAll();
        return out;
    }

    // ---- write side ----
    inline size_t writableBytes() const noexcept { return data_.capacity() - data_.size(); }
    inline void append(const char *buf, ssize_t rn)
    {
        if (buf == nullptr || rn <= 0)
            return;
        data_.append(buf, static_cast<size_t>(rn));
    }
    inline void append(const char *buf, size_t n)
    {
        if (buf == nullptr || n == 0)
            return;
        data_.append(buf, n);
    }
    inline void append(const std::string &s) { data_.append(s); }
    inline void append(char c) { data_.push_back(c); }
    inline void reserve(size_t n) { data_.reserve(n); }

    // ---- water mark ----
    inline size_t highWaterMark() const noexcept { return highWaterMark_; }
    inline void setHighWaterMark(size_t n) noexcept { highWaterMark_ = n; }
    inline bool overHighWater() const noexcept { return readableBytes() > highWaterMark_; }
};
