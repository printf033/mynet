#pragma once

#include "constraints.hpp"
#include "error.hpp"
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <memory>
#include <new>
#include <thread>
#include <utility>

namespace mynet
{

// ---------------------------------------------------------------------------
// D4：Debug 构建线程归属断言（MYNET_DEBUG 由 CMake 随 Debug 配置定义）。
// 归属凭据采用每线程唯一、永不复用的自增 token（thread_local 生成），
// 而非 std::thread::id：libstdc++ 下 thread::id 包装 pthread_t，
// 线程 join 后其 id 可被后续新线程复用，导致跨线程断言漏报。
// init() 绑定首次调用线程的 token，acquire()/release() 校验调用线程 token，
// 将跨线程误用从静默 UB 升级为确定性中止；
// Release 构建下宏与成员全部展开为空，零存储与零指令开销。
// ---------------------------------------------------------------------------
#ifdef MYNET_DEBUG
#define MYNET_POOL_BIND_OWNER()                                                                                        \
    do                                                                                                                 \
    {                                                                                                                  \
        ownerToken_ = mynet::poolDetail::currentThreadToken();                                                         \
    } while (false)
#define MYNET_POOL_ASSERT_OWNER()                                                                                      \
    do                                                                                                                 \
    {                                                                                                                  \
        if (ownerToken_ != 0 && ownerToken_ != mynet::poolDetail::currentThreadToken()) [[unlikely]]                   \
        {                                                                                                              \
            std::fprintf(stderr,                                                                                       \
                         "mynet::ObjectPool used across threads: owner token %llu != caller token %llu "               \
                         "(non-thread-safe pool)\n",                                                                   \
                         static_cast<unsigned long long>(ownerToken_),                                                 \
                         static_cast<unsigned long long>(mynet::poolDetail::currentThreadToken()));                    \
            std::abort();                                                                                              \
        }                                                                                                              \
    } while (false)
#else
#define MYNET_POOL_BIND_OWNER() static_cast<void>(0)
#define MYNET_POOL_ASSERT_OWNER() static_cast<void>(0)
#endif

    namespace poolDetail
    {
        // 每线程唯一且永不复用的归属 token：1 从 1 递增（0 保留为"未绑定"）。
        // 仅在 Debug 构建被引用；Release 下无任何实例化，零开销。
        // 计数器用 relaxed atomic：多线程同时首次建池时 fetch_add 保证唯一性
        // （仅需唯一性，无发布/同步语义，relaxed 即正确且最廉）。
        inline thread_local unsigned long long t_threadToken = 0;

        [[nodiscard]] inline unsigned long long currentThreadToken() noexcept
        {
            if (t_threadToken == 0) [[unlikely]]
            {
                static std::atomic<unsigned long long> nextToken{0};
                t_threadToken = nextToken.fetch_add(1, std::memory_order_relaxed) + 1;
            }
            return t_threadToken;
        }
    } // namespace poolDetail

    /**
     * @brief 借还周期内地址稳定的高性能定长对象池（非线程安全）
     *
     * 针对单线程网络事件循环（Reactor epoll 或 Proactor io_uring 线程）的高频对象借还与零内存碎片复用设计。
     *
     * 架构契约与地址稳定性：
     * 1. 连续的 acquire() / release() 借还周期内，槽位地址绝对恒定，可安全用于 epoll data.ptr 或 io_uring user_data；
     * 2. 调用 reset() 或重新 init() 时，池将立即彻底销毁所有槽位，所有之前借出的外部悬挂指针就地失效；
     * 3. 严格的 O(1) 释放校验：防范外来指针（避免内存泄漏）与重复释放（防范借出计数腐坏与槽位重叠借出）；
     * 4. 非线程安全：单事件循环独占，消除一切跨线程同步与原子开销；
     *    Debug 构建（MYNET_DEBUG 定义，随 Debug 配置自动开启）在 acquire()/release()
     *    上断言调用线程与 init() 时一致，将跨线程误用从静默 UB 升级为确定性中止；
     *    Release 构建下检查与所有者记录整体编译剔除，热路径零开销；
     * 5. 全库禁用异常：内部不使用任何抛异常设施（std::vector / 抛异常 new），
     *    空闲栈为 nothrow 裸数组，分配失败经显式错误码 Result<> 返回，与全库错误语义一致。
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
         * 强失败保证：任一分配失败时旧池内容完好无损，池保持 init 前状态；
         * 全部分配成功后原子提交新池。capacity() 永不指向未提交状态。
         * 全程无异常设施（nothrow new + nothrow 空闲栈数组），失败显式映射为错误码。
         *
         * @param capacity 对象池容量大小
         * @return Result<> 分配失败时返回 std::unexpected(POOL_ALLOC_FAILED)，
         *                  否则返回成功空值
         */
        [[nodiscard]] inline Result<> init(size_t capacity) noexcept
        {
            if (capacity == 0) [[unlikely]]
            {
                reset();
                return {};
            }
            // 局部构建后原子提交：任一分配失败时旧池完好无损，capacity_ 不被提前污染
            // nothrow 分配：库内资源耗尽属于运行时故障，显式映射为 POOL_ALLOC_FAILED
            const size_t stride = sizeof(Slot);
            if (capacity > (std::numeric_limits<size_t>::max)() / stride) [[unlikely]]
            {
                return std::unexpected(ERR::POOL_ALLOC_FAILED);
            }
            std::unique_ptr<Slot[]> slots{new (std::nothrow) Slot[capacity]};
            if (slots == nullptr) [[unlikely]]
            {
                return std::unexpected(ERR::POOL_ALLOC_FAILED);
            }
            // 空闲栈：逆序压入使首个借出走地址最低槽位（提升局部性），与旧实现语义一致
            std::unique_ptr<size_t[]> stack{new (std::nothrow) size_t[capacity]};
            if (stack == nullptr) [[unlikely]]
            {
                return std::unexpected(ERR::POOL_ALLOC_FAILED);
            }
            for (size_t i = 0; i < capacity; ++i)
            {
                slots[i].inUse = false;
                stack[i] = capacity - 1 - i;
            }
            reset(); // 新池构建完成后才销毁旧池：失败路径旧池完好（强失败保证）
            slots_ = std::move(slots);
            freeStack_ = std::move(stack);
            capacity_ = capacity;
            freeCount_ = capacity; // 全部槽位初始为空闲（等价旧实现的逆序 push_back）
            MYNET_POOL_BIND_OWNER();
            return {};
        }

        /**
         * @brief 彻底清空并重置对象池
         */
        inline void reset() noexcept
        {
            freeStack_.reset();
            freeCount_ = 0;
            slots_.reset();
            capacity_ = 0;
#ifdef MYNET_DEBUG
            ownerToken_ = 0;
#endif
        }

        /**
         * @brief 从可用空闲栈中借出一个对象
         *
         * @return Object* 若池已耗尽（或尚未 init）则返回 nullptr，否则返回可用对象裸指针；
         *         借出对象为默认构造态（Resettable 契约要求 reset() 后状态等价于默认构造，首次与后续借出一致）
         */
        [[nodiscard]] inline Object *acquire() noexcept
        {
            MYNET_POOL_ASSERT_OWNER();
            if (freeCount_ == 0) [[unlikely]]
            {
                return nullptr;
            }
            const size_t index = freeStack_[--freeCount_];
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
         * 对象生命周期贯穿整个池：资源释放责任由 Resettable 契约落在 noexcept 的 reset() 上，
         * 池析构仅隐式析构槽位数组，因此 Object 持有的任何 OS 资源必须在 reset() 中归还。
         *
         * @param object 待归还的对象指针
         * @return bool 归还成功返回 true；指针为空、非本池对象或重复归还返回 false
         */
        inline bool release(Object *object) noexcept
        {
            MYNET_POOL_ASSERT_OWNER();
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

            // 2. 对齐与索引映射：复用除法结果进行乘法回算对齐检验，消弭第二重整数取模除法
            const size_t offset = static_cast<size_t>(raw - base);
            const size_t index = offset / stride;
            if (offset != index * stride) [[unlikely]]
            {
                return false;
            }

            // 3. 定位槽位
            Slot &slot = slots_[index];

            // 4. 重复释放校验：已被归还的槽位不可再次归还
            if (!slot.inUse) [[unlikely]]
            {
                return false;
            }

            // 5. 成功回收与复位
            slot.inUse = false;
            slot.object.reset();
            freeStack_[freeCount_++] = index;
            return true;
        }

        /**
         * @brief 获取对象池总物理容量
         */
        [[nodiscard]] inline size_t capacity() const noexcept { return capacity_; }

        /**
         * @brief 获取当前未被借出的空闲对象数量
         */
        [[nodiscard]] inline size_t available() const noexcept { return freeCount_; }

    private:
        struct Slot
        {
            Object object{};
            bool inUse{false};
        };

        std::unique_ptr<Slot[]> slots_{nullptr};
        std::unique_ptr<size_t[]> freeStack_{nullptr}; // 固定容量 = capacity_，逆序初始（低地址优先借出）
        size_t freeCount_{0};
        size_t capacity_{0};
#ifdef MYNET_DEBUG
        // Debug 专属：所有者线程 token 与归属断言（D4）。0 表示尚未绑定。
        // Release 下成员与宏体整体剔除，ObjectPool 布局与热路径与原先完全一致。
        unsigned long long ownerToken_{0};
#endif
    };

} // namespace mynet
