/**
 * @file streamTable.hpp
 * @brief 定容开放寻址流表：多路复用器流 ID → StreamSlot 的零分配热路径存储。
 *
 * 设计取舍（安全、高效、高性能）：
 * - 数组 + 线性探测，槽位地址稳定；erase() 采用墓碑标记，
 *   探测链不会被提前截断，墓碑可被 open() 就地复用。
 * - 键为非零 uint32_t，散列取 键>>1 与 键低位的组合：
 *   HTTP/2 流 ID 全部为奇数（低位全 1），仅用键低位会让新流
 *   恒等键 % 槽数 + 步进 1 的探测链，键 >> 1 提供真实散列性。
 * - 活跃条目达到 75% 时 open() 拒绝新流：定容语义下这是调用方
 *   （池耗尽 → REFUSED_STREAM）已有的降级路径，无新增故障模式。
 * - erase() 留下的墓碑仍占探测链位但不占活跃预算：open() 在活跃
 *   达上限且表内存在墓碑时执行一次 O(容量) 整表压缩（原地重排，
 *   消除全部墓碑后重试），墓碑因此不会永久挤占装填预算；
 *   压缩仅在"拒绝路径 + 存在墓碑"这一低频降级点发生，热路径零开销。
 *
 * 异常策略：全部操作 noexcept；唯一可失败路径是 init() 的槽位分配，
 * 以 Result<> 返回，与 ringQueue.hpp / ObjectPool 的组件契约一致。
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <utility>

#include "error.hpp"

namespace mynet
{
namespace mux
{
    inline constexpr size_t kMaxTableSlots = (1u << 31); ///< 槽位上限（2 的幂），size_t 算术不溢出

    /**
     * @brief 定容开放寻址哈希表（线性探测 + 墓碑删除 + 墓碑复用）。
     * @tparam T 值类型；必须可默认构造（open() 依赖）。
     * @note 容器生命周期：init() 一次分配，之后热路径零堆分配、零异常。
     */
    template <typename T>
    class StreamTable
    {
    public:
        StreamTable() noexcept = default;
        ~StreamTable() noexcept { release(); }
        StreamTable(const StreamTable &) = delete ("流表独占其槽位与流身份");
        StreamTable &operator=(const StreamTable &) = delete ("流表独占其槽位与流身份");
        StreamTable(StreamTable &&) = delete ("流槽位指针对外有效，移动会造成悬垂");
        StreamTable &operator=(StreamTable &&) = delete ("流槽位指针对外有效，移动会造成悬垂");

        /**
         * @brief 一次性分配 2 的幂个槽位（幂等：重复 init 前自动释放旧槽）。
         * @param capacity 期望容量；实际容量向上取到 2 的幂，至少为 8。
         * @return 成功返回 void；分配失败返回 ERR::POOL_ALLOC_FAILED。
         */
        [[nodiscard]] inline Result<> init(size_t capacity) noexcept
        {
            release();
            if (capacity < 8)
            {
                capacity = 8;
            }
            if (capacity > kMaxTableSlots) [[unlikely]]
            {
                capacity = kMaxTableSlots;
            }
            size_t slots = 8;
            while (slots < capacity)
            {
                slots <<= 1;
            }
            slots_ = static_cast<Slot *>(::operator new[](slots * sizeof(Slot), std::nothrow));
            if (slots_ == nullptr) [[unlikely]]
            {
                return std::unexpected(ERR::POOL_ALLOC_FAILED);
            }
            // 原始内存上就地构造（Slot 含 std::string 等非平凡成员，禁止对未构造内存赋值）
            for (size_t i = 0; i < slots; ++i)
            {
                std::construct_at(slots_ + i);
            }
            mask_ = slots - 1;
            size_ = 0;
            capacity_ = slots;
            return {};
        }

        /**
         * @brief 占用 key 对应的槽位（线性探测，墓碑可复用）。
         * @param key 非零流 ID；调用方保证未插入过（find() 为 nullptr）。
         * @return 槽位引用；表未初始化、key 为 0 或装填因子超过 75% 返回 nullptr。
         */
        [[nodiscard]] inline T *open(uint32_t key) noexcept
        {
            if (slots_ == nullptr || key == 0) [[unlikely]]
            {
                return nullptr;
            }
            if (size_ * 4 >= capacity_ * 3) [[unlikely]]
            {
                // 活跃条目达 75%：业务真满（活跃池耗尽），维持既有拒绝语义。
                return nullptr;
            }
            if (occupied_ * 4 >= capacity_ * 3) [[unlikely]]
            {
                // 活跃未满但墓碑挤占了全部链位预算：压缩回收墓碑（低频降级路径），
                // 压缩成功后 occupied_ == size_ 落入下方正常插入；分配失败则拒绝。
                if (!compact()) [[unlikely]]
                {
                    return nullptr;
                }
            }
            const size_t base = static_cast<size_t>(key) & mask_;
            size_t seq = static_cast<size_t>(key) >> 1;
            Slot *reusable = nullptr; // 链上首个墓碑：确认真空位（链尾）后复用
            for (size_t probes = 0; probes <= mask_; ++probes)
            {
                Slot &slot = slots_[(base + seq + probes) & mask_];
                if (!slot.used)
                {
                    if (!slot.tombstone)
                    {
                        // 真空位即链尾：优先复用链上记录的墓碑（回收占位），否则占用此空位
                        if (reusable != nullptr)
                        {
                            reusable->used = true;
                            reusable->tombstone = false;
                            reusable->key = key;
                            reusable->value = T{};
                            ++size_; // 墓碑槽已计入 occupied_，复用不重复计数
                            return &reusable->value;
                        }
                        slot.used = true;
                        slot.tombstone = false;
                        slot.key = key;
                        slot.value = T{};
                        ++size_;
                        ++occupied_;
                        return &slot.value;
                    }
                    if (reusable == nullptr)
                    {
                        reusable = &slot;
                    }
                    continue;
                }
                if (slot.key == key)
                {
                    return &slot.value; // 调用方前置保证不应发生；防御性返回已占用槽位
                }
            }
            if (reusable != nullptr) [[unlikely]]
            {
                // 全表无真空位的兜底（occupied_ < 75% 时理论不可达）：复用墓碑
                reusable->used = true;
                reusable->tombstone = false;
                reusable->key = key;
                reusable->value = T{};
                ++size_;
                return &reusable->value;
            }
            return nullptr; // 理论不可达：装填因子 < 75% 必有空位
        }

        /**
         * @brief 查找 key 对应的槽位。
         * @return 槽位引用；不存在返回 nullptr。
         */
        [[nodiscard]] inline T *find(uint32_t key) noexcept
        {
            if (slots_ == nullptr || key == 0 || size_ == 0)
            {
                return nullptr;
            }
            const size_t base = static_cast<size_t>(key) & mask_;
            size_t seq = static_cast<size_t>(key) >> 1;
            for (size_t probes = 0; probes <= mask_; ++probes)
            {
                const Slot &slot = slots_[(base + seq + probes) & mask_];
                if (!slot.used)
                {
                    if (!slot.tombstone)
                    {
                        return nullptr; // 真空位才是链尾；墓碑不算链尾，继续探
                    }
                    continue;
                }
                if (slot.key == key)
                {
                    return const_cast<T *>(&slot.value);
                }
            }
            return nullptr;
        }

        /**
         * @brief key 是否存在。
         */
        [[nodiscard]] inline bool has(uint32_t key) noexcept
        {
            return find(key) != nullptr;
        }

        /**
         * @brief 摘除 key（墓碑标记，值由调用方先行处置）。
         * @return true 表示确实摘除了一个活跃槽位。
         */
        inline bool erase(uint32_t key) noexcept
        {
            if (slots_ == nullptr || key == 0 || size_ == 0)
            {
                return false;
            }
            const size_t base = static_cast<size_t>(key) & mask_;
            size_t seq = static_cast<size_t>(key) >> 1;
            for (size_t probes = 0; probes <= mask_; ++probes)
            {
                Slot &slot = slots_[(base + seq + probes) & mask_];
                if (!slot.used)
                {
                    if (!slot.tombstone)
                    {
                        return false; // 真空位才是链尾；墓碑不算链尾，继续探
                    }
                    continue;
                }
                if (slot.key == key)
                {
                    slot.used = false;
                    slot.tombstone = true;
                    slot.key = 0;
                    slot.value = T{};
                    --size_; // occupied_ 保持：墓碑仍占探测链位（活跃与墓碑总和不变）
                    return true;
                }
            }
            return false;
        }

        /**
         * @brief 当前活跃槽位数。
         */
        [[nodiscard]] inline size_t size() const noexcept { return size_; }

        /**
         * @brief 底层槽位总数。
         */
        [[nodiscard]] inline size_t capacity() const noexcept { return capacity_; }

        /**
         * @brief 表是否可用（init 成功）。
         */
        [[nodiscard]] inline bool ready() const noexcept { return slots_ != nullptr; }

        /**
         * @brief 就地清空：遍历活跃槽位回调处置后复位全部标记（分配零成本）。
         * @param reset 形如 void(const uint32_t key, T &value) 的回调。
         */
        template <typename F>
        inline void clear(F &&reset) noexcept
        {
            if (slots_ == nullptr)
            {
                return;
            }
            for (size_t i = 0; i <= mask_; ++i)
            {
                Slot &slot = slots_[i];
                if (slot.used)
                {
                    std::forward<F>(reset)(slot.key, slot.value);
                }
                slot.used = false;
                slot.tombstone = false;
                slot.key = 0;
            }
            size_ = 0;
            occupied_ = 0;
        }

        /**
         * @brief 遍历专用：第 i 槽的键（used 槽恒非零，空/墓碑槽已复位为 0）。
         * @param i 槽位下标，需满足 i < capacity()；调用方负责 ready() 前置。
         */
        [[nodiscard]] inline const uint32_t &keyAt(size_t i) const noexcept { return slots_[i].key; }

        /**
         * @brief 遍历专用：第 i 槽的值指针；未占用（空/墓碑）返回 nullptr。
         * @param i 槽位下标，需满足 i < capacity()；调用方负责 ready() 前置。
         */
        [[nodiscard]] inline T *slotAt(size_t i) noexcept { return slots_[i].used ? &slots_[i].value : nullptr; }

        /**
         * @brief 释放槽位内存，表回到未初始化态（析构等价操作）。
         * @note 全部槽位在 init() 后始终处于已构造态，逐一析构后再释放原始内存。
         */
        inline void release() noexcept
        {
            if (slots_ != nullptr)
            {
                for (size_t i = 0; i < capacity_; ++i)
                {
                    std::destroy_at(slots_ + i);
                }
            }
            ::operator delete[](slots_);
            slots_ = nullptr;
            mask_ = 0;
            size_ = 0;
            occupied_ = 0;
            capacity_ = 0;
        }

    private:
        /**
         * @brief 整表压缩：活跃条目重排到紧凑位置，清除全部墓碑。
         * @return 压缩成功返回 true（occupied_ == size_）；临时分配失败返回 false（表保持原状）。
         * @note O(容量) 一次分配 + 一趟搬运，仅在 open() 拒绝路径且存在墓碑时触发。
         */
        [[nodiscard]] inline bool compact() noexcept
        {
            Slot *fresh = static_cast<Slot *>(::operator new[](capacity_ * sizeof(Slot), std::nothrow));
            if (fresh == nullptr) [[unlikely]]
            {
                return false;
            }
            for (size_t i = 0; i < capacity_; ++i)
            {
                std::construct_at(fresh + i);
            }
            size_t placed = 0;
            for (size_t i = 0; i < capacity_; ++i)
            {
                Slot &old = slots_[i];
                if (!old.used)
                {
                    continue;
                }
                const size_t base = static_cast<size_t>(old.key) & mask_;
                const size_t seq = static_cast<size_t>(old.key) >> 1;
                for (size_t probes = 0;; ++probes)
                {
                    Slot &dst = fresh[(base + seq + probes) & mask_];
                    if (!dst.used)
                    {
                        dst.used = true;
                        dst.key = old.key;
                        dst.value = std::move(old.value);
                        ++placed;
                        break;
                    }
                }
            }
            for (size_t i = 0; i < capacity_; ++i)
            {
                std::destroy_at(slots_ + i);
            }
            ::operator delete[](slots_);
            slots_ = fresh;
            size_ = placed;
            occupied_ = placed;
            return true;
        }

        struct Slot
        {
            T value{};
            uint32_t key = 0;
            bool used = false;
            bool tombstone = false; ///< 墓碑：erase 留下的链位，open 可复用，find 视为继续探
        };

        Slot *slots_ = nullptr;
        size_t mask_ = 0;     ///< capacity_ - 1（2 的幂才有意义）
        size_t size_ = 0;     ///< 活跃槽位数
        size_t occupied_ = 0; ///< 活跃 + 墓碑（装填因子的真实分母）
        size_t capacity_ = 0;
    };

} // namespace mux
} // namespace mynet
