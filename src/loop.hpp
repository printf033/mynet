#pragma once

#include "error.hpp"
#include "log.hpp"
#include "timer.hpp"
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <thread>
#include <unistd.h>
#include <vector>

// The loop owns the three problems every layer above it would otherwise
// re-solve badly:
//
//   - *When* to wake up. epoll_wait() gets a timeout taken from the timer
//     queue, so a deadline is a deadline instead of "whatever the next socket
//     event happens to be".
//   - *How another thread gets in*. An eventfd is registered with the same
//     epoll set, so runInLoop() from any thread interrupts a blocking wait and
//     the task runs on the loop thread, where protocol state lives.
//   - *Who owns a file descriptor*. The loop only watches; it never closes a
//     descriptor it did not open. That is what keeps a listening socket safe
//     when a connection is torn down.
//
// The dispatcher is a single callback: it receives the fd, the readiness bits
// and the opaque pointer the owner registered. The loop deliberately knows
// nothing about connections, protocols or accept queues.
class EventLoop
{
public:
    using Task = std::function<void()>;
    using EventCallback = std::function<void(uint32_t events, void *ptr)>;
    using Clock = TimerQueue::Clock;
    using Time = TimerQueue::Time;
    using TimerCallback = TimerQueue::Callback;

    // Idempotent: the constructor already initialises once, and every run_*()
    // entry point calls it again before watching descriptors. Re-creating the
    // pair here would leak the first epoll and wakeup descriptors.
    // std::nullopt when the descriptor pair is in place (including when it
    // already was), otherwise the syscall that could not complete.
    [[nodiscard]] inline std::optional<Err> init() noexcept
    {
        if (epollFd_ >= 0 && wakeFd_ >= 0)
            return std::nullopt;
        if (epollFd_ >= 0)
        {
            ::close(epollFd_);
            epollFd_ = -1;
        }
        epollFd_ = ::epoll_create1(EPOLL_CLOEXEC);
        if (epollFd_ < 0)
        {
            LOG_ERROR("EventLoop::init: epoll_create1() failed: {}", mynetlog::errnoText(errno));
            return Err::epoll_create_failed;
        }
        wakeFd_ = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (wakeFd_ < 0)
        {
            LOG_ERROR("EventLoop::init: eventfd() failed: {}", mynetlog::errnoText(errno));
            ::close(epollFd_);
            epollFd_ = -1;
            return Err::eventfd_failed;
        }
        struct epoll_event event;
        std::memset(&event, 0, sizeof event);
        event.events = EPOLLIN;
        event.data.u64 = kWakeToken;
        if (::epoll_ctl(epollFd_, EPOLL_CTL_ADD, wakeFd_, &event) < 0)
        {
            LOG_ERROR("EventLoop::init: epoll_ctl(ADD, wakeup fd {}) failed: {}", wakeFd_,
                      mynetlog::errnoText(errno));
            ::close(wakeFd_);
            wakeFd_ = -1;
            ::close(epollFd_);
            epollFd_ = -1;
            return Err::epoll_ctl_failed;
        }
        return std::nullopt;
    }

    EventLoop()
    {
        threadId_ = std::this_thread::get_id();
        events_.resize(1024);
        // A failure here is not fatal: every run_*() entry point re-runs
        // init() and reports whatever is still wrong at that point.
        (void)init();
    }

    ~EventLoop() noexcept
    {
        if (wakeFd_ != -1)
            ::close(wakeFd_);
        if (epollFd_ != -1)
            ::close(epollFd_);
    }

    EventLoop(const EventLoop &) = delete("the loop owns an epoll set and a wakeup fd; a copy would double-close both");
    EventLoop &operator=(const EventLoop &) = delete("the loop owns an epoll set and a wakeup fd; a copy would double-close both");

    inline int epollFd() const noexcept { return epollFd_; }
    inline bool running() const noexcept { return running_; }
    inline bool inLoopThread() const noexcept { return std::this_thread::get_id() == threadId_; }

    inline void setEventCallback(EventCallback callback) { eventCallback_ = std::move(callback); }
    inline void reserveEvents(size_t count)
    {
        if (count > events_.size())
            events_.resize(count);
    }

    // std::nullopt on success, epoll_ctl_failed otherwise.
    [[nodiscard]] inline std::optional<Err> addFd(int fd, uint32_t events, void *ptr = nullptr) noexcept
    {
        if (epollFd_ < 0 || fd < 0)
        {
            LOG_ERROR("EventLoop::addFd: called with epoll fd {} and fd {} (events {:#x})", epollFd_, fd, events);
            return Err::epoll_ctl_failed;
        }
        struct epoll_event event;
        std::memset(&event, 0, sizeof event);
        event.events = events;
        event.data.ptr = ptr;
        if (::epoll_ctl(epollFd_, EPOLL_CTL_ADD, fd, &event) < 0)
        {
            LOG_ERROR("EventLoop::addFd: epoll_ctl(ADD, fd {}, events {:#x}) failed: {}", fd, events,
                      mynetlog::errnoText(errno));
            return Err::epoll_ctl_failed;
        }
        return std::nullopt;
    }

    // std::nullopt on success, epoll_ctl_failed otherwise.
    [[nodiscard]] inline std::optional<Err> modFd(int fd, uint32_t events, void *ptr = nullptr) noexcept
    {
        if (epollFd_ < 0 || fd < 0)
        {
            LOG_ERROR("EventLoop::modFd: called with epoll fd {} and fd {} (events {:#x})", epollFd_, fd, events);
            return Err::epoll_ctl_failed;
        }
        struct epoll_event event;
        std::memset(&event, 0, sizeof event);
        event.events = events;
        event.data.ptr = ptr;
        if (::epoll_ctl(epollFd_, EPOLL_CTL_MOD, fd, &event) < 0)
        {
            LOG_ERROR("EventLoop::modFd: epoll_ctl(MOD, fd {}, events {:#x}) failed: {}", fd, events,
                      mynetlog::errnoText(errno));
            return Err::epoll_ctl_failed;
        }
        return std::nullopt;
    }

    // std::nullopt on success, epoll_ctl_failed otherwise. A failure here is a
    // warning rather than an error because this runs while a connection is
    // being torn down: the descriptor may already be gone from the set, and
    // the teardown continues either way.
    [[nodiscard]] inline std::optional<Err> delFd(int fd) noexcept
    {
        if (epollFd_ < 0 || fd < 0)
        {
            LOG_WARN("EventLoop::delFd: called with epoll fd {} and fd {}", epollFd_, fd);
            return Err::epoll_ctl_failed;
        }
        if (::epoll_ctl(epollFd_, EPOLL_CTL_DEL, fd, nullptr) < 0)
        {
            LOG_WARN("EventLoop::delFd: epoll_ctl(DEL, fd {}) failed: {}", fd, mynetlog::errnoText(errno));
            return Err::epoll_ctl_failed;
        }
        return std::nullopt;
    }

    // std::nullopt on a normal quit; not_initialised if the loop never got
    // its descriptors; epoll_wait_failed if the wait itself broke.
    [[nodiscard]] inline std::optional<Err> run()
    {
        if (epollFd_ < 0)
        {
            LOG_ERROR("EventLoop::run: no epoll descriptor -- init() never succeeded");
            return Err::not_initialised;
        }
        threadId_ = std::this_thread::get_id();
        quit_ = false;
        running_ = true;
        while (!quit_)
        {
            int timeout = nextTimeout();
            int n = ::epoll_wait(epollFd_, events_.data(), static_cast<int>(events_.size()), timeout);
            if (n < 0)
            {
                if (errno == EINTR)
                    continue;
                LOG_ERROR("EventLoop::run: epoll_wait() failed: {}", mynetlog::errnoText(errno));
                running_ = false;
                return Err::epoll_wait_failed;
            }
            if (n == static_cast<int>(events_.size()))
                events_.resize(events_.size() * 2);

            Time now = Clock::now();
            timerQueue_.handleExpired(now);
            doPendingTasks();
            for (int i = 0; i < n; ++i)
            {
                if (events_[i].data.u64 == kWakeToken)
                {
                    drainWakeup();
                    doPendingTasks();
                    continue;
                }
                if (eventCallback_)
                    eventCallback_(events_[i].events, events_[i].data.ptr);
            }
        }
        running_ = false;
        return std::nullopt;
    }

    inline void quit() noexcept
    {
        quit_ = true;
        // Waking up matters when quit() comes from another thread: the loop
        // may be parked in epoll_wait() with no deadline in sight.
        wakeup();
    }

    // Run now if we are on the loop thread, otherwise hand the task over and
    // wake the loop up. This is the only way another thread is allowed to
    // touch loop-owned state.
    inline void runInLoop(Task task)
    {
        if (task == nullptr)
            return;
        if (inLoopThread())
            task();
        else
            queueInLoop(std::move(task));
    }

    inline void queueInLoop(Task task)
    {
        if (task == nullptr)
            return;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            pending_.push_back(std::move(task));
        }
        wakeup();
    }

    inline size_t pendingTasks()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return pending_.size();
    }

    // Timers are thread safe to arm and cancel; they always fire on the loop
    // thread. The returned id can be used with cancelTimer().
    inline uint64_t runAfter(std::chrono::milliseconds delay, TimerCallback callback)
    {
        return timerQueue_.addTimer(Clock::now() + delay, std::move(callback));
    }

    inline uint64_t runEvery(std::chrono::milliseconds interval, TimerCallback callback)
    {
        return timerQueue_.addTimer(Clock::now() + interval, std::move(callback), interval);
    }

    inline uint64_t runAt(Time when, TimerCallback callback) { return timerQueue_.addTimer(when, std::move(callback)); }

    // std::nullopt when cancelled, Err::timer_not_found when the id is gone.
    [[nodiscard]] inline std::optional<Err> cancelTimer(uint64_t id) { return timerQueue_.cancelTimer(id); }

    inline size_t timerCount() { return timerQueue_.size(); }

private:
    // -1 block until something happens, otherwise the milliseconds until the
    // earliest deadline (never negative, never rounding up past it).
    inline int nextTimeout()
    {
        Time next = timerQueue_.nextExpire();
        if (next == Time::max())
            return -1;
        auto left = std::chrono::duration_cast<std::chrono::milliseconds>(next - Clock::now()).count();
        return left < 0 ? 0 : static_cast<int>(left);
    }

    inline void doPendingTasks()
    {
        std::deque<Task> tasks;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            tasks.swap(pending_);
        }
        for (Task &task : tasks)
        {
            if (task)
                task();
        }
    }

    inline void wakeup() noexcept
    {
        uint64_t one = 1;
        ssize_t ignored = ::write(wakeFd_, &one, sizeof one);
        (void)ignored;
    }

    inline void drainWakeup() noexcept
    {
        uint64_t value = 0;
        while (::read(wakeFd_, &value, sizeof value) > 0)
            continue;
    }

    static constexpr uint64_t kWakeToken = 1;

    int epollFd_ = -1;
    int wakeFd_ = -1;
    bool quit_ = false;
    bool running_ = false;
    std::thread::id threadId_{};
    std::vector<struct epoll_event> events_;
    EventCallback eventCallback_{};
    TimerQueue timerQueue_{};
    std::mutex mutex_{};
    std::deque<Task> pending_{};
};
