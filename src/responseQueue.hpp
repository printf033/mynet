#pragma once

#include "constraints.hpp"
#include "error.hpp"
#include <cstddef>
#include <expected>
#include <limits>
#include <new>
#include <utility>

namespace mynet
{
    class HandlerConnection;

    /**
     * @brief 定容零异常通用 FIFO 响应队列模板
     *
     * 队列自身是纯粹通用的定容环形队列，通过单一模板参数 Proto 适配不同协议的小型参数包：
     * - 面向连接的流式会话（默认 Proto = Protocol<HandlerConnection>）：存储包含 std::string 的参数包；
     * - 面向无连接的数据报会话（Proto = Protocol<HandlerDatagram>）：存储包含 sockaddr_in peer 与 std::string
     * 的参数包。
     *
     * 队列在 init(capacity) 时一次性分配内存，后续 push/pop 均无任何堆分配，
     * 弹出与重置时调用槽位的 clear() 复用已分配容量。
     */
    template <typename Proto = Protocol<HandlerConnection>>
    class ResponseQueueBase
    {
    public:
        using Item = Proto;

        ResponseQueueBase() noexcept = default;

        ~ResponseQueueBase() noexcept { destroy(); }

        ResponseQueueBase(const ResponseQueueBase &) = delete; // a response queue owns one slot array; a copy would alias the elements
        ResponseQueueBase &operator=(const ResponseQueueBase &) = delete; // a response queue owns one slot array; a copy would alias the elements

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
    using ResponseQueue = ResponseQueueBase<Protocol<HandlerConnection>>;

} // namespace mynet
