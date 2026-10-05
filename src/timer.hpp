#pragma once

#include "error.hpp"
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <vector>

// A timer queue you can actually cancel.
//
// The queue is a binary heap ordered by deadline so the loop only ever has to
// look at one element to know how long it may sleep. Cancellation is lazy: the
// entry stays in the heap flagged as dead and is dropped the next time it
// reaches the top. That keeps cancelTimer() O(1) instead of O(n) and keeps a
// callback free to cancel its own timer.
//
// Every public method takes the lock, so a timer may be armed from any thread;
// the callbacks themselves always run on the thread calling handleExpired(),
// which is the loop thread.
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
        bool cancelled_ = false;
    };

    TimerQueue() noexcept = default;
    ~TimerQueue() noexcept = default;
    // A deleted function may now carry the reason, so the diagnostic says why
    // the copy is impossible instead of only that it is gone.
    TimerQueue(const TimerQueue &) = delete("a timer queue owns a mutex and live callbacks; there is nothing to copy");
    TimerQueue &operator=(const TimerQueue &) = delete("a timer queue owns a mutex and live callbacks; there is nothing to copy");

    // >0 timer id, always usable with cancelTimer()
    inline uint64_t addTimer(Time when, Callback callback, std::chrono::milliseconds interval = std::chrono::milliseconds(0))
    {
        std::lock_guard<std::mutex> lock(mutex_);
        Timer timer;
        timer.id_ = nextId_++;
        timer.expire_ = when;
        timer.interval_ = interval;
        timer.callback_ = std::move(callback);
        timer.repeat_ = interval.count() > 0;
        uint64_t id = timer.id_;
        timers_.emplace(id, false);
        heap_.push_back(std::move(timer));
        std::push_heap(heap_.begin(), heap_.end(), laterFirst);
        return id;
    }

    // std::nullopt when the timer was cancelled; timer_not_found when the id
    // has already fired or was never armed. The latter is worth knowing, not
    // worth failing over.
    [[nodiscard]] inline std::optional<Err> cancelTimer(uint64_t id)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = timers_.find(id);
        if (it == timers_.end())
            return Err::timer_not_found;
        it->second = true;
        return std::nullopt;
    }

    // The deadline the loop should wake up for, or Time::max() when idle.
    // Stale entries are discarded here so a cancelled timer cannot keep the
    // loop spinning on a deadline that will never fire.
    inline Time nextExpire()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        dropDeadTop();
        if (heap_.empty())
            return Time::max();
        return heap_.front().expire_;
    }

    // Fire everything due at or before now; returns how many callbacks ran.
    // Callbacks run with the lock released, so they are free to arm or cancel
    // timers of their own.
    inline size_t handleExpired(Time now)
    {
        std::vector<Timer> due;
        std::vector<Timer> again;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            while (!heap_.empty() && heap_.front().expire_ <= now)
            {
                std::pop_heap(heap_.begin(), heap_.end(), laterFirst);
                Timer timer = std::move(heap_.back());
                heap_.pop_back();
                auto it = timers_.find(timer.id_);
                if (it == timers_.end())
                    continue;
                if (it->second)
                {
                    timers_.erase(it);
                    continue;
                }
                if (timer.repeat_)
                    again.push_back(timer);
                due.push_back(std::move(timer));
            }
        }
        for (const Timer &timer : due)
        {
            if (timer.callback_)
                timer.callback_();
        }
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (Timer &timer : again)
            {
                auto it = timers_.find(timer.id_);
                // A callback may have cancelled its own repeating timer.
                if (it == timers_.end() || it->second)
                {
                    if (it != timers_.end())
                        timers_.erase(it);
                    continue;
                }
                timer.expire_ += timer.interval_;
                if (timer.expire_ <= now)
                    timer.expire_ = now + timer.interval_;
                heap_.push_back(std::move(timer));
                std::push_heap(heap_.begin(), heap_.end(), laterFirst);
            }
        }
        return due.size();
    }

    inline size_t size()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return timers_.size();
    }

private:
    static bool laterFirst(const Timer &a, const Timer &b) noexcept { return a.expire_ > b.expire_; }

    inline void dropDeadTop()
    {
        while (!heap_.empty())
        {
            auto it = timers_.find(heap_.front().id_);
            if (it != timers_.end() && !it->second)
                return;
            std::pop_heap(heap_.begin(), heap_.end(), laterFirst);
            if (it != timers_.end())
                timers_.erase(it);
            heap_.pop_back();
        }
    }

    std::vector<Timer> heap_;
    std::unordered_map<uint64_t, bool> timers_; // id -> cancelled
    uint64_t nextId_ = 1;
    std::mutex mutex_;
};
