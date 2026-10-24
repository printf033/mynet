#pragma once

#include "error.hpp"
#include <cstddef>
#include <cstring>
#include <expected>
#include <new>
#include <string>
#include <utility>

namespace mynet
{

    /**
     * @brief 定容零异常 FIFO 环形队列
     *
     * 面向响应/待发数据这类有界流：init() 一次性分配 capacity 个槽位（每个槽
     * 一个空 std::string），此后 push/pop 全程零堆分配、零异常。满队时 push
     * 返回 ERR::QUEUE_FULL 拒绝新元素——不覆盖、不静默丢弃，背压语义显式。
     *
     * 槽位地址在整个生命周期内稳定（无 rehash、无扩容搬迁），取出的
     * std::string 引用在其他槽位操作期间保持有效。
     *
     * 异常策略：全部操作 noexcept；唯一可失败路径是 init() 的槽位分配，
     * 以 ERR::POOL_ALLOC_FAILED 交付（与对象池同一类失败：一次性预分配失败）。
     */
    class RingQueue
    {
    public:
        RingQueue() noexcept = default;

        ~RingQueue() noexcept { destroy(); }

        RingQueue(const RingQueue &) =
            delete ("a ring queue owns one slot array; a copy would alias the strings");
        RingQueue &operator=(const RingQueue &) =
            delete ("a ring queue owns one slot array; a copy would alias the strings");

        RingQueue(RingQueue &&other) noexcept
            : slots_(std::exchange(other.slots_, nullptr)),
              capacity_(std::exchange(other.capacity_, 0)),
              head_(std::exchange(other.head_, 0)),
              size_(std::exchange(other.size_, 0))
        {
        }

        RingQueue &operator=(RingQueue &&other) noexcept
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
            slots_ = static_cast<std::string *>(::operator new[](n * sizeof(std::string), std::nothrow));
            if (slots_ == nullptr) [[unlikely]]
            {
                capacity_ = 0;
                return std::unexpected(ERR::POOL_ALLOC_FAILED);
            }
            // 空字符串默认构造零堆分配、确定 noexcept，逐槽定位 new 无失败路径
            for (size_t i = 0; i < n; ++i)
            {
                ::new (static_cast<void *>(slots_ + i)) std::string();
            }
            capacity_ = n;
            head_ = 0;
            size_ = 0;
            return {};
        }

        /**
         * @brief 队尾推入一个字符串（移动语义）
         *
         * 满队时拒绝并返回 ERR::QUEUE_FULL，原队内容与新元素均不受影响。
         * std::string 的移动赋值 noexcept（源为普通堆串），失败面不存在。
         *
         * @return 成功 {}；满队 std::unexpected(ERR::QUEUE_FULL)
         */
        [[nodiscard]] inline Result<> push(std::string &&s) noexcept
        {
            if (size_ >= capacity_) [[unlikely]]
            {
                return std::unexpected(ERR::QUEUE_FULL);
            }
            slots_[(head_ + size_) % capacity_] = std::move(s);
            ++size_;
            return {};
        }

        /**
         * @brief 队尾原地构造一个字符串
         */
        [[nodiscard]] inline Result<> emplace(std::string_view sv) noexcept
        {
            if (size_ >= capacity_) [[unlikely]]
            {
                return std::unexpected(ERR::QUEUE_FULL);
            }
            std::string &slot = slots_[(head_ + size_) % capacity_];
            slot.clear();
            const Result<> r = appendTo(slot, sv);
            if (!r) [[unlikely]]
            {
                slot.clear(); // 失败不留半截内容
                return r;
            }
            ++size_;
            return {};
        }

        /**
         * @brief 队头字符串引用（empty() 时不得调用）
         */
        [[nodiscard]] inline std::string &front() noexcept
        {
            contract_assert(size_ > 0);
            return slots_[head_];
        }

        /**
         * @brief 弹出队头（empty() 时为无操作）
         */
        inline void pop() noexcept
        {
            if (size_ == 0) [[unlikely]]
            {
                return;
            }
            std::string &slot = slots_[head_];
            if (!slot.empty()) [[likely]]
            {
                // 归还字符串持有的堆块代价高于清空指针：直接 clear 保留容量复用
                slot.clear();
            }
            head_ = (head_ + 1) % capacity_;
            --size_;
        }

        /**
         * @brief 清空全部元素（保留槽位与各字符串容量，复位游标）
         */
        inline void clear() noexcept
        {
            while (size_ > 0)
            {
                pop();
            }
            head_ = 0;
        }

        [[nodiscard]] inline bool empty() const noexcept { return size_ == 0; }
        [[nodiscard]] inline size_t size() const noexcept { return size_; }
        [[nodiscard]] inline size_t capacity() const noexcept { return capacity_; }

    private:
        /**
         * @brief 向字符串追加视图的零异常路径
         *
         * 先 resize 预留目标长度（resize 越界时抛 length_error/bad_alloc——
         * 标准容器在 -fno-exceptions 下将直接 std::terminate，与库纪律等价：
         * 分配失败是不可恢复的进程级故障），再 memcpy 落数据。
         */
        [[nodiscard]] static inline Result<> appendTo(std::string &dst, std::string_view sv) noexcept
        {
            if (sv.empty()) [[unlikely]]
            {
                return {};
            }
            const size_t base = dst.size();
            dst.resize(base + sv.size());
            std::memcpy(dst.data() + base, sv.data(), sv.size());
            return {};
        }

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
                slots_[i].~basic_string();
            }
            ::operator delete[](slots_, std::nothrow);
            slots_ = nullptr;
            capacity_ = 0;
            head_ = 0;
            size_ = 0;
        }

        std::string *slots_ = nullptr;
        size_t capacity_ = 0;
        size_t head_ = 0;
        size_t size_ = 0;
    };

} // namespace mynet
