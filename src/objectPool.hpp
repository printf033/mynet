#pragma once

#include "concepts.hpp"
#include <functional>
#include <memory>
#include <vector>

namespace mynet
{

    /**
     * @brief 借还周期内地址稳定的高性能定长对象池（非线程安全）
     *
     * 针对单线程网络事件循环（Reactor epoll 或 Proactor io_uring 线程）的高频对象借还与零内存碎片复用设计。
     *
     * 架构契约与地址稳定性：
     * 1. 连续的 acquire() / release() 借还周期内，槽位地址绝对恒定，可安全用于 epoll data.ptr 或 io_uring user_data；
     * 2. 调用 reset() 或重新 init() 时，池将立即彻底销毁所有槽位，所有之前借出的外部悬挂指针就地失效；
     * 3. 严格的 O(1) 释放校验：防范外来指针（避免内存泄漏）与重复释放（防范借出计数腐坏与槽位重叠借出）；
     * 4. 非线程安全：单事件循环独占，消除一切跨线程同步与原子开销。
     *
     * @tparam Object 必须满足 Resettable（具有 noexcept 的 reset() 成员）
     */
    template <Resettable Object>
    class ObjectPool
    {
    public:
        ObjectPool() noexcept = default;
        ~ObjectPool() noexcept { reset(); }

        ObjectPool(const ObjectPool &) =
            delete ("the pool hands out stable slots; a copy would orphan every outstanding pointer");
        ObjectPool &operator=(const ObjectPool &) =
            delete ("the pool hands out stable slots; a copy would orphan every outstanding pointer");
        ObjectPool(ObjectPool &&) noexcept =
            delete ("the pool hands out stable slots; moving would orphan every outstanding pointer");
        ObjectPool &operator=(ObjectPool &&) noexcept =
            delete ("the pool hands out stable slots; moving would orphan every outstanding pointer");

        /**
         * @brief 初始化对象池容量并预先完成所有槽位构建
         *
         * @param capacity 对象池容量大小
         */
        inline void init(size_t capacity)
        {
            reset();
            if (capacity == 0) [[unlikely]]
            {
                return;
            }
            capacity_ = capacity;
            slots_ = std::make_unique<Slot[]>(capacity);
            available_.reserve(capacity);
            for (size_t i = 0; i < capacity; ++i)
            {
                slots_[i].inUse = false;
                available_.push_back(capacity - 1 - i);
            }
        }

        /**
         * @brief 彻底清空并重置对象池
         */
        inline void reset() noexcept
        {
            available_.clear();
            slots_.reset();
            capacity_ = 0;
        }

        /**
         * @brief 从可用空闲栈中借出一个对象
         *
         * @return Object* 若池已耗尽则返回 nullptr，否则返回可用对象裸指针
         */
        [[nodiscard]] inline Object *acquire() noexcept
        {
            if (available_.empty()) [[unlikely]]
            {
                return nullptr;
            }
            const size_t index = available_.back();
            available_.pop_back();
            slots_[index].inUse = true;
            return &slots_[index].object;
        }

        /**
         * @brief 归还借出的对象并自动触发 reset()
         *
         * 内置 O(1) 地址边界与双重归还防护：
         * 1. 验证指针是否在对象池合法地址范围内且对齐；
         * 2. 验证指针所属槽位当前是否处于借出状态（防 double-release）；
         * 3. 校验通过后自动调用 object->reset() 并重新压入空闲栈。
         *
         * @param object 待归还的对象指针
         * @return bool 归还成功返回 true；指针为空、非本池对象或重复归还返回 false
         */
        inline bool release(Object *object) noexcept
        {
            if (slots_ == nullptr || object == nullptr) [[unlikely]]
            {
                return false;
            }

            const char *raw = reinterpret_cast<const char *>(object);
            const char *base = reinterpret_cast<const char *>(&slots_[0].object);
            constexpr size_t stride = sizeof(Slot);
            const size_t totalBytes = capacity_ * stride;

            // 1. 边界校验：地址必须落在连续槽位内存区间内（使用 std::less 建立全序关系规避未定义行为）
            if (std::less<const char *>{}(raw, base) || std::greater_equal<const char *>{}(raw, base + totalBytes))
                [[unlikely]]
            {
                return false;
            }

            // 2. 对齐校验：地址必须严格与槽位起始点对齐
            const size_t offset = static_cast<size_t>(raw - base);
            if (offset % stride != 0) [[unlikely]]
            {
                return false;
            }

            // 3. 映射到具体槽位
            const size_t index = offset / stride;
            Slot &slot = slots_[index];

            // 4. 重复释放校验：已被归还的槽位不可再次归还
            if (!slot.inUse) [[unlikely]]
            {
                return false;
            }

            // 5. 成功回收与复位
            slot.inUse = false;
            slot.object.reset();
            available_.push_back(index);
            return true;
        }

        /**
         * @brief 获取对象池总物理容量
         */
        [[nodiscard]] inline size_t capacity() const noexcept { return capacity_; }

        /**
         * @brief 获取当前未被借出的空闲对象数量
         */
        [[nodiscard]] inline size_t available() const noexcept { return available_.size(); }

    private:
        struct Slot
        {
            Object object{};
            bool inUse{false};
        };

        std::unique_ptr<Slot[]> slots_{nullptr};
        std::vector<size_t> available_{};
        size_t capacity_{0};
    };

} // namespace mynet
