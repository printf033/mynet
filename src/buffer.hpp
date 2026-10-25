#pragma once

#include "error.hpp"
#include <cstddef>
#include <cstring>
#include <expected>
#include <limits>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace mynet
{

    /**
     * @brief 带游标与自适应收缩的零异常字节缓冲区
     *
     * 底层是自管理单段连续堆存储（operator new[] nothrow 语义），写入始终追加于尾部，
     * 读取由 readIndex_ 游标推进。当已被消费的前缀累计达到阈值（>= 4096 字节且占据
     * 总量一半以上）时才触发就地擦除压缩，使得长连接在持续传输期间能彻底消除每轮
     * 请求的频繁堆内存重分配。
     *
     * 异常策略：全部操作 noexcept。唯一可失败路径是扩容时的堆分配，以显式
     * ERR::BUF_ALLOC_FAILED 错误码交付，绝不抛出 std::bad_alloc。
     *
     * 直接写窗口：writableBytes() 返回当前已分配存储内**真实可直接写入**的连续
     * 字节窗口（writableBegin() 起、不含追加游标左侧可读区）。调用方（如 recv 系
     * 系统调用）可零拷贝直写该窗口，写完后 commitWritten(n) 提交。窗口不足时
     * ensureWritable(n) 预扩容，同样以错误码交付。
     */
    class Buffer
    {
    public:
        Buffer() noexcept = default;

        ~Buffer() noexcept { deallocate(); }

        Buffer(const Buffer &) =
            delete ("a buffer owns one heap block sized for its connection; a copy would alias the bytes");
        Buffer &operator=(const Buffer &) =
            delete ("a buffer owns one heap block sized for its connection; a copy would alias the bytes");

        Buffer(Buffer &&other) noexcept
            : data_(std::exchange(other.data_, nullptr)),
              capacity_(std::exchange(other.capacity_, 0)),
              writeIndex_(std::exchange(other.writeIndex_, 0)),
              readIndex_(std::exchange(other.readIndex_, 0)),
              highWaterMark_(std::exchange(other.highWaterMark_, size_t{0}))
        {
        }

        Buffer &operator=(Buffer &&other) noexcept
        {
            if (this != &other)
            {
                deallocate();
                data_ = std::exchange(other.data_, nullptr);
                capacity_ = std::exchange(other.capacity_, 0);
                writeIndex_ = std::exchange(other.writeIndex_, 0);
                readIndex_ = std::exchange(other.readIndex_, 0);
                highWaterMark_ = std::exchange(other.highWaterMark_, size_t{0});
            }
            return *this;
        }

        /**
         * @brief 交换两个缓冲区的所有权状态
         */
        inline void swap(Buffer &other) noexcept
        {
            std::swap(data_, other.data_);
            std::swap(capacity_, other.capacity_);
            std::swap(writeIndex_, other.writeIndex_);
            std::swap(readIndex_, other.readIndex_);
            std::swap(highWaterMark_, other.highWaterMark_);
        }

        /**
         * @brief 重置缓冲区，清空所有数据并复位游标（保留已分配容量）
         */
        inline void reset() noexcept
        {
            readIndex_ = 0;
            writeIndex_ = 0;
        }

        // ---- 读取侧接口 (Read Side) ----

        /**
         * @brief 获取可读字节序列起始地址指针
         */
        [[nodiscard]] inline const char *readableBegin() const noexcept { return data_ + readIndex_; }

        /**
         * @brief 获取当前未消费的可读字节总数
         */
        [[nodiscard]] inline size_t readableBytes() const noexcept { return writeIndex_ - readIndex_; }

        /**
         * @brief 获取当前可读字节范围的 string_view 零拷贝视图
         */
        [[nodiscard]] inline std::string_view readableView() const noexcept
        {
            return std::string_view(readableBegin(), readableBytes());
        }

        /**
         * @brief 获取当前可读字节范围的 std::span 视图
         */
        [[nodiscard]] inline std::span<const char> readableSpan() const noexcept
        {
            return std::span<const char>(readableBegin(), readableBytes());
        }

        /**
         * @brief 缓冲区当前是否为空（无可读数据）
         */
        [[nodiscard]] inline bool empty() const noexcept { return readIndex_ == writeIndex_; }

        /**
         * @brief 步进消费 n 个字节
         *
         * 若已消费字节超过回收阈值，则自动进行内存紧凑整理。
         *
         * @warning 压缩可能移动底层存储：此前取得的 readableBegin()/readableView()/
         *          readableSpan() 指针与视图在调用后立即失效，必须重新获取。
         *
         * @param n 需消费的字节数量
         */
        inline void retrieve(size_t n) noexcept
        {
            if (n >= readableBytes()) [[unlikely]]
            {
                retrieveAll();
                return;
            }
            readIndex_ += n;
            // 当失效前缀膨胀到 >= 4 KiB 且已超过总大小一半时触发压缩收缩
            if (readIndex_ >= (4 << 10) && (readIndex_ * 2) >= writeIndex_) [[unlikely]]
            {
                const size_t live = writeIndex_ - readIndex_;
                if (live > 0) [[likely]]
                {
                    std::memmove(data_, data_ + readIndex_, live);
                }
                readIndex_ = 0;
                writeIndex_ = live;
            }
        }

        /**
         * @brief 消费并清除所有已有数据（游标归零，保留已分配容量）
         */
        inline void retrieveAll() noexcept
        {
            readIndex_ = 0;
            writeIndex_ = 0;
        }

        // ---- 写入侧接口 (Write Side) ----

        /**
         * @brief 当前已分配存储内真实可直接写的连续窗口大小
         *
         * @note 语义为「调用方现在即可向 writableBegin() 连续写入这么多字节」，
         *       与 reserve() 的预分配概念解耦：窗口不含已消费前缀（那部分在
         *       压缩前不可复用）。
         */
        [[nodiscard]] inline size_t writableBytes() const noexcept { return capacity_ - writeIndex_; }

        /**
         * @brief 直接写窗口起始地址（writableBytes() 为 0 时不得解引用）
         */
        [[nodiscard]] inline char *writableBegin() noexcept { return data_ + writeIndex_; }

        /**
         * @brief 提交直接写入的 n 个字节（n 不得超过 writableBytes()）
         */
        inline void commitWritten(size_t n) noexcept
        {
            contract_assert(n <= writableBytes());
            writeIndex_ += n;
        }

        /**
         * @brief 追加指定长度字节序列（零异常：失败返回错误码，缓冲区保持原样）
         *
         * @param buf 源字节首地址（nullptr 或 n==0 时为无操作）
         * @param n 追加字节数
         * @return 成功 {}；堆扩容失败 std::unexpected(ERR::BUF_ALLOC_FAILED)
         */
        [[nodiscard]] inline Result<> append(const char *buf, size_t n) noexcept
        {
            if (buf == nullptr || n == 0) [[unlikely]]
            {
                return {};
            }
            if (auto res = ensureWritable(n); !res) [[unlikely]]
            {
                return res;
            }
            std::memcpy(writableBegin(), buf, n);
            writeIndex_ += n;
            return {};
        }

        /**
         * @brief 追加字符视图（兼容 std::string 与字符串字面量）
         */
        [[nodiscard]] inline Result<> append(std::string_view sv) noexcept { return append(sv.data(), sv.size()); }

        /**
         * @brief 追加单个字符
         */
        [[nodiscard]] inline Result<> append(char c) noexcept { return append(&c, 1); }

        /**
         * @brief 确保直接写窗口至少有 n 个连续字节（必要时扩容并压缩）
         *
         * 本函数保证 writableBytes() >= n，且优先就地压缩已消费前缀以满足需求，
         * 避免不必要的堆重分配。
         *
         * @return 成功 {}；堆扩容失败 std::unexpected(ERR::BUF_ALLOC_FAILED)
         */
        [[nodiscard]] inline Result<> ensureWritable(size_t n) noexcept
        {
            if (writableBytes() >= n) [[likely]]
            {
                return {};
            }
            // 先就地压缩：已消费前缀让出空间可能已足够
            const size_t live = readableBytes();
            if (n > (std::numeric_limits<size_t>::max)() - live) [[unlikely]]
            {
                return std::unexpected(ERR::BUF_ALLOC_FAILED);
            }
            const size_t total = live + n;
            if (total <= capacity_)
            {
                if (live > 0) [[likely]]
                {
                    std::memmove(data_, data_ + readIndex_, live);
                }
                readIndex_ = 0;
                writeIndex_ = live;
                return {};
            }
            return grow(total) ? Result<>{} : std::unexpected(ERR::BUF_ALLOC_FAILED);
        }

        // ---- 水位与流控 (High Water Mark) ----

        /**
         * @brief 获取高水位阈值设定值
         */
        [[nodiscard]] inline size_t highWaterMark() const noexcept { return highWaterMark_; }

        /**
         * @brief 设置高水位阈值
         */
        inline void setHighWaterMark(size_t n) noexcept { highWaterMark_ = n; }

        /**
         * @brief 检测当前未消费数据量是否已突破高水位线
         */
        [[nodiscard]] inline bool overHighWater() const noexcept { return readableBytes() > highWaterMark_; }

    private:
        /**
         * @brief 确保容量至少 n 字节（noexcept 分配路径）
         *
         * @note 采用 2 倍增长策略；首次分配时请求与容量取平，避免小对象抖动。
         * @return true 成功；false 分配器返回空（需求量过大或内存耗尽）
         */
        [[nodiscard]] inline bool grow(size_t n) noexcept
        {
            if (n <= capacity_) [[likely]]
            {
                return true;
            }
            size_t next = capacity_ == 0 ? n : capacity_ * 2;
            if (next < n) [[unlikely]]
            {
                next = n; // 2 倍溢出回退为精确需求
            }
            char *fresh = static_cast<char *>(::operator new[](next, std::nothrow));
            if (fresh == nullptr) [[unlikely]]
            {
                return false;
            }
            const size_t live = readableBytes();
            if (live > 0) [[likely]]
            {
                std::memcpy(fresh, data_ + readIndex_, live);
            }
            deallocate();
            data_ = fresh;
            capacity_ = next;
            readIndex_ = 0;
            writeIndex_ = live;
            return true;
        }

        /**
         * @brief 释放底层堆存储（析构与移动赋值共用）
         */
        inline void deallocate() noexcept
        {
            if (data_ != nullptr) [[likely]]
            {
                ::operator delete[](data_, std::nothrow);
                data_ = nullptr;
                capacity_ = 0;
            }
        }

        char *data_ = nullptr;
        size_t capacity_ = 0;
        size_t writeIndex_ = 0;
        size_t readIndex_ = 0;
        size_t highWaterMark_ = 64 << 10;
    };

} // namespace mynet
