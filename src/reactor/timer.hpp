#pragma once

#include "error.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <unordered_set>
#include <vector>

namespace mynet
{

    /**
     * @brief 线程安全且支持高效 O(1) 取消的二叉堆定时器队列
     *
     * 底层采用基于截止时间（deadline）排序的二叉最小堆，使事件循环仅需审视堆顶元素即可计算下一次睡眠超时。
     * 有效定时器集合由 std::unordered_set<uint64_t> 维护：
     * 1. 取消定时器 cancelTimer(id) 在哈希集合中直接 O(1) 擦除，重复取消天然返回 ERR::TIMER_NOT_FOUND；
     * 2. 堆结构延迟清理（Lazy Deletion）：被取消的任务在堆顶或过期扫描时被识别并剔除；
     * 3. 单次定时器到期即销毁注册记录，彻底杜绝内存泄漏；
     * 4. 回调在锁外执行，允许回调闭包内部安全取消自身或注册新定时器；
     * 5. size() 严格反映当前活跃存活的定时器总数。
     */
    class TimerQueue
    {
    public:
        using Clock = std::chrono::steady_clock;
        using Time = Clock::time_point;
        using Callback = std::function<void()>;

        struct Timer
        {
            uint64_t id_ = 0;
            Time expire_{};
            std::chrono::milliseconds interval_{};
            Callback callback_{};
            bool repeat_ = false;
        };

        TimerQueue() noexcept
        {
            heap_.reserve(128);
            timers_.reserve(128);
        }

        ~TimerQueue() noexcept = default;

        TimerQueue(const TimerQueue &) =
            delete ("a timer queue owns a mutex and live callbacks; there is nothing to copy");
        TimerQueue &operator=(const TimerQueue &) =
            delete ("a timer queue owns a mutex and live callbacks; there is nothing to copy");

        /**
         * @brief 注册一个新的定时器任务（线程安全）
         *
         * @param when 到期时间点
         * @param callback 触发执行的回调闭包
         * @param interval 周期性重复间隔（默认为 0，表示单次定时器）
         * @return uint64_t 分配的唯一定时器 ID（> 0）
         */
        inline uint64_t addTimer(Time when, Callback callback,
                                 std::chrono::milliseconds interval = std::chrono::milliseconds(0))
        {
            std::lock_guard<std::mutex> lock(mutex_);
            Timer timer;
            timer.id_ = nextId_++;
            if (timer.id_ == 0) [[unlikely]]
            {
                timer.id_ = nextId_++;
            }
            while (timers_.contains(timer.id_)) [[unlikely]]
            {
                timer.id_ = nextId_++;
                if (timer.id_ == 0) [[unlikely]]
                {
                    timer.id_ = nextId_++;
                }
            }
            timer.expire_ = when;
            timer.interval_ = interval;
            timer.callback_ = std::move(callback);
            timer.repeat_ = interval.count() > 0;
            const uint64_t id = timer.id_;
            timers_.insert(id);
            activeCount_.fetch_add(1, std::memory_order_release);
            heap_.push_back(std::move(timer));
            std::push_heap(heap_.begin(), heap_.end(), needSwap);
            return id;
        }

        /**
         * @brief 取消指定 ID 的定时器任务（O(1) 线程安全）
         *
         * @param id 定时器唯一 ID
         * @return Result<> 成功取消返回 {}；若已触发、已取消或不存在返回 std::unexpected(ERR::TIMER_NOT_FOUND)
         */
        [[nodiscard]] inline Result<> cancelTimer(uint64_t id)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = timers_.find(id);
            if (it == timers_.end()) [[unlikely]]
            {
                return std::unexpected(ERR::TIMER_NOT_FOUND);
            }
            timers_.erase(it);
            activeCount_.fetch_sub(1, std::memory_order_release);
            return {};
        }

        /**
         * @brief 获取堆顶最近的有效到期时间点
         *
         * 自动剔除堆顶已取消的失效定时器，防止事件循环因已取消任务发生空轮询自旋。
         *
         * @return Time 下一次到期时间；若无活动定时器则返回 Time::max()
         */
        [[nodiscard]] inline Time nextExpire()
        {
            std::lock_guard<std::mutex> lock(mutex_);
            dropDeadTop();
            if (heap_.empty())
            {
                return Time::max();
            }
            return heap_.front().expire_;
        }

        /**
         * @brief 批量触发已过期的所有定时器回调
         *
         * 回调在锁外执行，允许回调闭包内部注册新定时器或取消现有定时器。
         *
         * @param now 当前时间戳
         * @return size_t 实际执行的回调数量
         *
         * @note 回调可能在闭包内部抛出异常，故本函数不标 noexcept，
         *       异常传播策略交由调用方决定；否则回调一抛即 terminate。
         */
        inline size_t handleExpired(Time now)
        {
            std::vector<Callback> callbacks;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                while (!heap_.empty() && heap_.front().expire_ <= now)
                {
                    std::pop_heap(heap_.begin(), heap_.end(), needSwap);
                    Timer timer = std::move(heap_.back());
                    heap_.pop_back();

                    auto it = timers_.find(timer.id_);
                    if (it == timers_.end()) [[unlikely]]
                    {
                        continue;
                    }

                    if (timer.callback_) [[likely]]
                    {
                        if (timer.repeat_)
                        {
                            callbacks.push_back(timer.callback_);
                        }
                        else
                        {
                            callbacks.push_back(std::move(timer.callback_));
                        }
                    }

                    if (timer.repeat_)
                    {
                        timer.expire_ += timer.interval_;
                        if (timer.expire_ <= now) [[unlikely]]
                        {
                            timer.expire_ = now + timer.interval_;
                        }
                        heap_.push_back(std::move(timer));
                        std::push_heap(heap_.begin(), heap_.end(), needSwap);
                    }
                    else
                    {
                        timers_.erase(it);
                        activeCount_.fetch_sub(1, std::memory_order_release);
                    }
                }
            }

            for (const auto &cb : callbacks)
            {
                cb();
            }

            return callbacks.size();
        }

        /**
         * @brief 判定当前定时器队列是否为空（无活跃定时器，无锁快速路径）
         */
        [[nodiscard]] inline bool empty() const noexcept { return activeCount_.load(std::memory_order_relaxed) == 0; }

        /**
         * @brief 当前有效存活的定时器注册总数
         */
        [[nodiscard]] inline size_t size()
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return timers_.size();
        }

    private:
        static bool needSwap(const Timer &a, const Timer &b) noexcept { return a.expire_ > b.expire_; }

        inline void dropDeadTop()
        {
            while (!heap_.empty())
            {
                if (timers_.contains(heap_.front().id_))
                {
                    return;
                }
                std::pop_heap(heap_.begin(), heap_.end(), needSwap);
                heap_.pop_back();
            }
        }

        std::vector<Timer> heap_;
        std::unordered_set<uint64_t> timers_;
        std::atomic<size_t> activeCount_{0};
        uint64_t nextId_ = 1;
        std::mutex mutex_;
    };

} // namespace mynet
