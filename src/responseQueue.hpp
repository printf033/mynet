#pragma once

#include "constraints.hpp"
#include "error.hpp"
#include <cstddef>
#include <expected>
#include <limits>
#include <netinet/in.h>
#include <new>
#include <ostream>
#include <string>
#include <string_view>
#include <utility>

namespace mynet
{
    /**
     * @brief 数据报/响应外发数据包结构
     *
     * 兼具流式字节载荷 (std::string bytes) 与数据报对端地址 (sockaddr_in peer)。
     * 提供与 std::string / std::string_view 的隐式转换与兼容接口，
     * 保证流式会话与无连接数据报会话零适配成本无缝复用。
     */
    struct DatagramPacket
    {
        sockaddr_in peer{};
        std::string bytes{};

        DatagramPacket() noexcept = default;
        DatagramPacket(std::string s) noexcept
            : bytes(std::move(s))
        {
        }
        DatagramPacket(std::string_view sv)
            : bytes(sv)
        {
        }
        DatagramPacket(const char *buf, size_t n)
            : bytes((buf != nullptr && n > 0) ? std::string(buf, n) : std::string())
        {
        }
        DatagramPacket(const char *s)
            : bytes(s != nullptr ? s : "")
        {
        }
        DatagramPacket(const sockaddr_in &p, std::string b) noexcept
            : peer(p),
              bytes(std::move(b))
        {
        }
        DatagramPacket(const sockaddr_in &p, const char *buf, size_t n)
            : peer(p),
              bytes((buf != nullptr && n > 0) ? std::string(buf, n) : std::string())
        {
        }

        void clear() noexcept
        {
            peer = {};
            bytes.clear();
        }
        [[nodiscard]] bool empty() const noexcept { return bytes.empty(); }
        [[nodiscard]] size_t size() const noexcept { return bytes.size(); }
        [[nodiscard]] size_t capacity() const noexcept { return bytes.capacity(); }
        [[nodiscard]] const char *data() const noexcept { return bytes.data(); }

        operator std::string &() & noexcept { return bytes; }
        operator const std::string &() const & noexcept { return bytes; }
        operator std::string() && noexcept { return std::move(bytes); }
        operator std::string_view() const noexcept { return bytes; }

        DatagramPacket &operator=(std::string s) noexcept
        {
            bytes = std::move(s);
            return *this;
        }

        DatagramPacket &operator=(std::string_view sv)
        {
            bytes.assign(sv);
            return *this;
        }

        bool operator==(const DatagramPacket &other) const noexcept { return bytes == other.bytes; }
        bool operator==(std::string_view sv) const noexcept { return bytes == sv; }
        bool operator==(const char *s) const noexcept { return bytes == s; }

        friend std::ostream &operator<<(std::ostream &os, const DatagramPacket &p) { return os << p.bytes; }
    };

    /**
     * @brief 定容零异常通用 FIFO 响应队列模板
     *
     * 队列自身是纯粹通用的定容环形队列，默认以 DatagramPacket 作为存储槽位：
     * 队列在 init(capacity) 时一次性分配内存，后续 push/pop 均无任何堆分配，
     * 弹出与重置时调用槽位的 clear() 复用已分配容量。
     */
    template <typename ItemType = DatagramPacket>
    class ResponseQueueBase
    {
    public:
        using Item = ItemType;

        ResponseQueueBase() noexcept = default;

        ~ResponseQueueBase() noexcept { destroy(); }

        ResponseQueueBase(const ResponseQueueBase &) =
            delete; // a response queue owns one slot array; a copy would alias the elements
        ResponseQueueBase &operator=(const ResponseQueueBase &) =
            delete; // a response queue owns one slot array; a copy would alias the elements

        ResponseQueueBase(ResponseQueueBase &&other) noexcept
            : slots_(std::exchange(other.slots_, nullptr)),
              capacity_(std::exchange(other.capacity_, 0)),
              head_(std::exchange(other.head_, 0)),
              size_(std::exchange(other.size_, 0))
        {
        }

        ResponseQueueBase &operator=(ResponseQueueBase &&other) noexcept
        {
            if (this != &other)
            {
                destroy();
                slots_ = std::exchange(other.slots_, nullptr);
                capacity_ = std::exchange(other.capacity_, 0);
                head_ = std::exchange(other.head_, 0);
                size_ = std::exchange(other.size_, 0);
            }
            return *this;
        }

        /**
         * @brief 分配 capacity 个空槽位（幂等：重复 init 前自动释放旧槽）
         *
         * @param capacity 槽位数量（0 视为 1，保证队列至少可用）
         * @return 成功 {}；槽位分配失败 std::unexpected(ERR::POOL_ALLOC_FAILED)
         */
        [[nodiscard]] inline Result<> init(size_t capacity) noexcept
        {
            destroy();
            const size_t n = capacity == 0 ? 1 : capacity;
            if (n > std::numeric_limits<size_t>::max() / sizeof(Item)) [[unlikely]]
            {
                capacity_ = 0;
                return std::unexpected(ERR::POOL_ALLOC_FAILED);
            }
            slots_ = static_cast<Item *>(::operator new[](n * sizeof(Item), std::nothrow));
            if (slots_ == nullptr) [[unlikely]]
            {
                capacity_ = 0;
                return std::unexpected(ERR::POOL_ALLOC_FAILED);
            }
            for (size_t i = 0; i < n; ++i)
            {
                ::new (static_cast<void *>(slots_ + i)) Item();
            }
            capacity_ = n;
            head_ = 0;
            size_ = 0;
            return {};
        }

        /**
         * @brief 队尾推入一个协议参数包（移动语义）
         *
         * 满队时拒绝并返回 ERR::QUEUE_FULL，原队内容与新元素均不受影响。
         *
         * @return 成功 {}；满队 std::unexpected(ERR::QUEUE_FULL)
         */
        [[nodiscard]] inline Result<> push(Item &&item) noexcept
        {
            if (size_ >= capacity_) [[unlikely]]
            {
                return std::unexpected(ERR::QUEUE_FULL);
            }
            const size_t tail = (head_ + size_ >= capacity_) ? (head_ + size_ - capacity_) : (head_ + size_);
            slots_[tail] = std::move(item);
            ++size_;
            return {};
        }

        /**
         * @brief 队尾推入一个协议参数包（左值引用拷贝）
         */
        [[nodiscard]] inline Result<> push(const Item &item) noexcept
        {
            if (size_ >= capacity_) [[unlikely]]
            {
                return std::unexpected(ERR::QUEUE_FULL);
            }
            const size_t tail = (head_ + size_ >= capacity_) ? (head_ + size_ - capacity_) : (head_ + size_);
            slots_[tail] = item;
            ++size_;
            return {};
        }

        /**
         * @brief 队尾原地构造一个协议参数包
         */
        template <typename... Args>
        [[nodiscard]] inline Result<> emplace(Args &&...args) noexcept
        {
            if (size_ >= capacity_) [[unlikely]]
            {
                return std::unexpected(ERR::QUEUE_FULL);
            }
            const size_t tail = (head_ + size_ >= capacity_) ? (head_ + size_ - capacity_) : (head_ + size_);
            slots_[tail] = Item(std::forward<Args>(args)...);
            ++size_;
            return {};
        }

        /**
         * @brief 队头参数包引用（empty() 时不得调用）
         */
        [[nodiscard]] inline Item &front() noexcept
        {
            contract_assert(size_ > 0);
            return slots_[head_];
        }

        /**
         * @brief 队头参数包常量引用（empty() 时不得调用）
         */
        [[nodiscard]] inline const Item &front() const noexcept
        {
            contract_assert(size_ > 0);
            return slots_[head_];
        }

        /**
         * @brief 随机访问队列中的参数包（下标 0 表示队头）
         */
        [[nodiscard]] inline Item &operator[](size_t index) noexcept
        {
            contract_assert(index < size_);
            const size_t pos = (head_ + index >= capacity_) ? (head_ + index - capacity_) : (head_ + index);
            return slots_[pos];
        }

        [[nodiscard]] inline const Item &operator[](size_t index) const noexcept
        {
            contract_assert(index < size_);
            const size_t pos = (head_ + index >= capacity_) ? (head_ + index - capacity_) : (head_ + index);
            return slots_[pos];
        }

        /**
         * @brief 弹出队头并清空槽位（保留槽位内部 string 等动态容量）
         */
        inline void pop() noexcept
        {
            if (size_ == 0) [[unlikely]]
            {
                return;
            }
            slots_[head_].clear();
            head_ = (head_ + 1 >= capacity_) ? 0 : (head_ + 1);
            --size_;
        }

        /**
         * @brief 重置全部元素（保留槽位与各参数包容量，复位游标）
         */
        inline void reset() noexcept
        {
            for (size_t i = 0; i < size_; ++i)
            {
                const size_t idx = (head_ + i >= capacity_) ? (head_ + i - capacity_) : (head_ + i);
                slots_[idx].clear();
            }
            head_ = 0;
            size_ = 0;
        }

        [[nodiscard]] inline bool empty() const noexcept { return size_ == 0; }
        [[nodiscard]] inline size_t size() const noexcept { return size_; }
        [[nodiscard]] inline size_t capacity() const noexcept { return capacity_; }

    private:
        /**
         * @brief 析构全部槽位并释放槽位数组
         */
        inline void destroy() noexcept
        {
            if (slots_ == nullptr) [[likely]]
            {
                return;
            }
            for (size_t i = 0; i < capacity_; ++i)
            {
                slots_[i].~Item();
            }
            ::operator delete[](slots_, std::nothrow);
            slots_ = nullptr;
            capacity_ = 0;
            head_ = 0;
            size_ = 0;
        }

        Item *slots_ = nullptr;
        size_t capacity_ = 0;
        size_t head_ = 0;
        size_t size_ = 0;
    };

    /**
     * @brief 默认流式单连接响应队列别名
     */
    using ResponseQueue = ResponseQueueBase<DatagramPacket>;

} // namespace mynet
