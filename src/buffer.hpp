#pragma once

#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace mynet
{

    /**
     * @brief 带游标与自适应收缩的高性能字节缓冲区
     *
     * 采用单段连续 std::string 作为底层存储，写入始终追加于尾部，读取由 readIndex_ 游标推进。
     * 当已被消费的前缀累计达到阈值（>= 4096 字节且占据总量一半以上）时才触发就地擦除压缩，
     * 使得长连接在持续传输期间能彻底消除每轮请求的频繁堆内存重分配。
     */
    class Buffer
    {
    public:
        Buffer() noexcept = default;
        ~Buffer() noexcept = default;

        Buffer(const Buffer &) =
            delete ("a buffer owns one heap block sized for its connection; a copy would alias the bytes");
        Buffer &operator=(const Buffer &) =
            delete ("a buffer owns one heap block sized for its connection; a copy would alias the bytes");
        Buffer(Buffer &&other) noexcept
            : data_(std::move(other.data_)),
              readIndex_(std::exchange(other.readIndex_, 0)),
              highWaterMark_(other.highWaterMark_)
        {
        }

        Buffer &operator=(Buffer &&other) noexcept
        {
            if (this != &other)
            {
                data_ = std::move(other.data_);
                readIndex_ = std::exchange(other.readIndex_, 0);
                highWaterMark_ = other.highWaterMark_;
            }
            return *this;
        }

        /**
         * @brief 交换两个缓冲区的所有权状态
         */
        inline void swap(Buffer &other) noexcept
        {
            std::swap(data_, other.data_);
            std::swap(readIndex_, other.readIndex_);
            std::swap(highWaterMark_, other.highWaterMark_);
        }

        /**
         * @brief 重置缓冲区，清空所有数据并复位游标
         */
        inline void reset() noexcept
        {
            data_.clear();
            readIndex_ = 0;
        }

        // ---- 读取侧接口 (Read Side) ----

        /**
         * @brief 获取可读字节序列起始地址指针
         */
        [[nodiscard]] inline const char *readableBegin() const noexcept { return data_.data() + readIndex_; }

        /**
         * @brief 获取当前未消费的可读字节总数
         */
        [[nodiscard]] inline size_t readableBytes() const noexcept { return data_.size() - readIndex_; }

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
        [[nodiscard]] inline bool empty() const noexcept { return readIndex_ == data_.size(); }

        /**
         * @brief 步进消费 n 个字节
         *
         * 若已消费字节超过回收阈值，则自动进行内存紧凑整理。
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
            if (readIndex_ >= (4 << 10) && (readIndex_ * 2) >= data_.size()) [[unlikely]]
            {
                data_.erase(0, readIndex_);
                readIndex_ = 0;
            }
        }

        /**
         * @brief 消费并清除所有已有数据
         */
        inline void retrieveAll() noexcept
        {
            data_.clear();
            readIndex_ = 0;
        }

        /**
         * @brief 消费并提取出全部有效数据作为 std::string 返回
         */
        [[nodiscard]] inline std::string retrieveAllAsString()
        {
            if (readIndex_ == 0)
            {
                std::string out = std::move(data_);
                retrieveAll();
                return out;
            }
            std::string out(readableBegin(), readableBytes());
            retrieveAll();
            return out;
        }

        // ---- 写入侧接口 (Write Side) ----

        /**
         * @brief 当前底层字符串剩余预分配容量
         */
        [[nodiscard]] inline size_t writableBytes() const noexcept { return data_.capacity() - data_.size(); }

        /**
         * @brief 追加指定长度字节序列
         */
        inline void append(const char *buf, size_t n)
        {
            if (buf == nullptr || n == 0) [[unlikely]]
            {
                return;
            }
            data_.append(buf, n);
        }

        /**
         * @brief 追加字符视图（兼容 std::string 与字符串字面量）
         */
        inline void append(std::string_view sv)
        {
            if (!sv.empty()) [[likely]]
            {
                data_.append(sv.data(), sv.size());
            }
        }

        /**
         * @brief 追加单个字符
         */
        inline void append(char c) { data_.push_back(c); }

        /**
         * @brief 预分配保留容量，防止后续多次扩容
         */
        inline void reserve(size_t n) { data_.reserve(n); }

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
        std::string data_;
        size_t readIndex_ = 0;
        size_t highWaterMark_ = 64 << 10;
    };

} // namespace mynet
