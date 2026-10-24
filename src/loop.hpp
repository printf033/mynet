#pragma once

#include "error.hpp"
#include "log.hpp"
#include "timer.hpp"
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <limits>
#include <mutex>
#include <optional>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace mynet
{

    /**
     * @brief 基于 epoll 与 eventfd 的高性能事件循环核心
     *
     * 职责高度内聚：
     * 1. 决定何时被内核唤醒：结合 TimerQueue 动态计算超时，消除空转；
     * 2. 线程安全跨线程穿透：基于 eventfd 注册于同一 epoll 集，runInLoop() 可从任何工作线程将任务送入本循环；
     * 3. 严格的生命周期与描述符所有权隔离：仅负责就绪分发，绝不越权关闭未由自身创建的业务描述符。
     */
    class EventLoop
    {
    public:
        using Task = std::function<void()>;
        using EventCallback = std::function<void(uint32_t events, void *ptr)>;
        using Clock = TimerQueue::Clock;
        using Time = TimerQueue::Time;
        using TimerCallback = TimerQueue::Callback;

        /**
         * @brief 初始化 epoll 与跨线程唤醒 eventfd 描述符对（具备幂等性）
         *
         * @return Result<> 成功返回 {}，失败返回具体系统调用错误枚举
         */
        [[nodiscard]] inline Result<> init() noexcept
        {
            // 运行中禁止重建：此时 epoll 集与 eventfd 正被 run() 持有，
            // 重建会摧毁活跃描述符并使 in-flight 事件全部悬垂
            if (running_.load(std::memory_order_acquire)) [[unlikely]]
            {
                LOG_ERROR("EventLoop::init: refused to re-init while the loop is running");
                return std::unexpected(ERR::LOOP_ALREADY_RUNNING);
            }
            if (epollFd_ >= 0 && wakeFd_ >= 0) [[likely]]
            {
                return {};
            }
            if (wakeFd_ >= 0)
            {
                ::close(wakeFd_);
                wakeFd_ = -1;
            }
            if (epollFd_ >= 0)
            {
                ::close(epollFd_);
                epollFd_ = -1;
            }
            epollFd_ = ::epoll_create1(EPOLL_CLOEXEC);
            if (epollFd_ < 0) [[unlikely]]
            {
                LOG_ERROR("EventLoop::init: epoll_create1() failed: {}", log::errnoText(errno));
                return std::unexpected(ERR::EPOLL_CREATE_FAILED);
            }
            wakeFd_ = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
            if (wakeFd_ < 0) [[unlikely]]
            {
                LOG_ERROR("EventLoop::init: eventfd() failed: {}", log::errnoText(errno));
                ::close(epollFd_);
                epollFd_ = -1;
                return std::unexpected(ERR::EVENTFD_FAILED);
            }
            struct epoll_event event;
            std::memset(&event, 0, sizeof event);
            event.events = EPOLLIN;
            event.data.u64 = kWakeToken;
            if (::epoll_ctl(epollFd_, EPOLL_CTL_ADD, wakeFd_, &event) < 0) [[unlikely]]
            {
                LOG_ERROR("EventLoop::init: epoll_ctl(ADD, wakeup fd {}) failed: {}", wakeFd_, log::errnoText(errno));
                ::close(wakeFd_);
                wakeFd_ = -1;
                ::close(epollFd_);
                epollFd_ = -1;
                return std::unexpected(ERR::EPOLL_CTL_FAILED);
            }
            return {};
        }

        EventLoop()
        {
            threadId_ = std::this_thread::get_id();
            events_.resize(1 << 10);
            (void)init();
        }

        ~EventLoop() noexcept
        {
            if (wakeFd_ != -1)
            {
                ::close(wakeFd_);
            }
            if (epollFd_ != -1)
            {
                ::close(epollFd_);
            }
        }

        EventLoop(const EventLoop &) =
            delete ("the loop owns an epoll set and a wakeup fd; a copy would double-close both");
        EventLoop &operator=(const EventLoop &) =
            delete ("the loop owns an epoll set and a wakeup fd; a copy would double-close both");

        [[nodiscard]] inline int epollFd() const noexcept { return epollFd_; }
        [[nodiscard]] inline bool running() const noexcept { return running_.load(std::memory_order_acquire); }
        [[nodiscard]] inline bool inLoopThread() const noexcept { return std::this_thread::get_id() == threadId_; }

        inline void setEventCallback(EventCallback callback) { eventCallback_ = std::move(callback); }

        inline void reserveEvents(size_t count)
        {
            if (count > events_.size())
            {
                events_.resize(count);
            }
        }

        /**
         * @brief 向 epoll 注册待监听的描述符
         */
        [[nodiscard]] inline Result<> addFd(int fd, uint32_t events, void *ptr = nullptr) noexcept
        {
            if (epollFd_ < 0 || fd < 0) [[unlikely]]
            {
                LOG_ERROR("EventLoop::addFd: invalid epollFd {} or fd {}", epollFd_, fd);
                return std::unexpected(ERR::EPOLL_CTL_FAILED);
            }
            struct epoll_event event;
            std::memset(&event, 0, sizeof event);
            event.events = events;
            event.data.ptr = ptr;
            if (::epoll_ctl(epollFd_, EPOLL_CTL_ADD, fd, &event) < 0) [[unlikely]]
            {
                LOG_ERROR("EventLoop::addFd: epoll_ctl(ADD, fd {}, events {:#x}) failed: {}", fd, events,
                          log::errnoText(errno));
                return std::unexpected(ERR::EPOLL_CTL_FAILED);
            }
            return {};
        }

        /**
         * @brief 修改已监听描述符的事件掩码
         */
        [[nodiscard]] inline Result<> modFd(int fd, uint32_t events, void *ptr = nullptr) noexcept
        {
            if (epollFd_ < 0 || fd < 0) [[unlikely]]
            {
                LOG_ERROR("EventLoop::modFd: invalid epollFd {} or fd {}", epollFd_, fd);
                return std::unexpected(ERR::EPOLL_CTL_FAILED);
            }
            struct epoll_event event;
            std::memset(&event, 0, sizeof event);
            event.events = events;
            event.data.ptr = ptr;
            if (::epoll_ctl(epollFd_, EPOLL_CTL_MOD, fd, &event) < 0) [[unlikely]]
            {
                LOG_ERROR("EventLoop::modFd: epoll_ctl(MOD, fd {}, events {:#x}) failed: {}", fd, events,
                          log::errnoText(errno));
                return std::unexpected(ERR::EPOLL_CTL_FAILED);
            }
            return {};
        }

        /**
         * @brief 从 epoll 移除描述符监听
         */
        [[nodiscard]] inline Result<> delFd(int fd) noexcept
        {
            if (epollFd_ < 0 || fd < 0) [[unlikely]]
            {
                LOG_WARN("EventLoop::delFd: invalid epollFd {} or fd {}", epollFd_, fd);
                return std::unexpected(ERR::EPOLL_CTL_FAILED);
            }
            if (::epoll_ctl(epollFd_, EPOLL_CTL_DEL, fd, nullptr) < 0) [[unlikely]]
            {
                LOG_WARN("EventLoop::delFd: epoll_ctl(DEL, fd {}) failed: {}", fd, log::errnoText(errno));
                return std::unexpected(ERR::EPOLL_CTL_FAILED);
            }
            return {};
        }

        /**
         * @brief 启动事件循环阻塞运行
         *
         * @return Result<> 正常退出返回 {}，非正常退出返回错误枚举
         */
        [[nodiscard]] inline Result<> run()
        {
            if (epollFd_ < 0) [[unlikely]]
            {
                LOG_ERROR("EventLoop::run: no epoll descriptor -- init() never succeeded");
                return std::unexpected(ERR::NOT_INITIALISED);
            }
            threadId_ = std::this_thread::get_id();
            quit_.store(false, std::memory_order_relaxed);
            running_.store(true, std::memory_order_release);
            while (!quit_.load(std::memory_order_acquire))
            {
                const int timeout = nextTimeout();
                const int n = ::epoll_wait(epollFd_, events_.data(), static_cast<int>(events_.size()), timeout);
                if (n < 0) [[unlikely]]
                {
                    if (errno == EINTR)
                    {
                        continue;
                    }
                    LOG_ERROR("EventLoop::run: epoll_wait() failed: {}", log::errnoText(errno));
                    running_.store(false, std::memory_order_release);
                    return std::unexpected(ERR::EPOLL_WAIT_FAILED);
                }
                if (n == static_cast<int>(events_.size())) [[unlikely]]
                {
                    events_.resize(events_.size() * 2);
                }

                const Time now = Clock::now();
                timerQueue_.handleExpired(now);
                doPendingTasks();

                for (int i = 0; i < n; ++i)
                {
                    // 派发前快照当前事件：回调可能关闭连接并使 events_ 中
                    // 同一轮稍后的 data.ptr 悬垂（连接对象可能已回池复用），
                    // 快照本身是平凡值拷贝，消费逻辑不变
                    const uint32_t ev = events_[i].events;
                    const uint64_t token = events_[i].data.u64;
                    if (token == kWakeToken) [[unlikely]]
                    {
                        drainWakeup();
                        doPendingTasks();
                        continue;
                    }
                    if (eventCallback_) [[likely]]
                    {
                        eventCallback_(ev, reinterpret_cast<void *>(static_cast<uintptr_t>(token)));
                    }
                }
            }
            running_.store(false, std::memory_order_release);
            return {};
        }

        /**
         * @brief 请求终止事件循环（线程安全）
         */
        inline void quit() noexcept
        {
            quit_.store(true, std::memory_order_release);
            wakeup();
        }

        /**
         * @brief 在循环所在线程中同步或异步投递执行任务
         */
        inline void runInLoop(Task task)
        {
            if (!task) [[unlikely]]
            {
                return;
            }
            if (inLoopThread())
            {
                task();
            }
            else
            {
                queueInLoop(std::move(task));
            }
        }

        /**
         * @brief 将任务压入待决任务队列并通过 eventfd 触发唤醒
         */
        inline void queueInLoop(Task task)
        {
            if (!task) [[unlikely]]
            {
                return;
            }
            {
                std::lock_guard<std::mutex> lock(mutex_);
                pending_.push_back(std::move(task));
            }
            wakeup();
        }

        [[nodiscard]] inline size_t pendingTasks()
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return pending_.size();
        }

        inline uint64_t runAfter(std::chrono::milliseconds delay, TimerCallback callback)
        {
            contract_assert(callback != nullptr);
            return timerQueue_.addTimer(Clock::now() + delay, std::move(callback));
        }

        inline uint64_t runEvery(std::chrono::milliseconds interval, TimerCallback callback)
        {
            contract_assert(callback != nullptr);
            return timerQueue_.addTimer(Clock::now() + interval, std::move(callback), interval);
        }

        inline uint64_t runAt(Time when, TimerCallback callback)
        {
            contract_assert(callback != nullptr);
            return timerQueue_.addTimer(when, std::move(callback));
        }

        [[nodiscard]] inline Result<> cancelTimer(uint64_t id) { return timerQueue_.cancelTimer(id); }

        [[nodiscard]] inline size_t timerCount() { return timerQueue_.size(); }

    private:
        inline int nextTimeout()
        {
            const Time next = timerQueue_.nextExpire();
            if (next == Time::max())
            {
                return -1;
            }
            const Time now = Clock::now();
            if (next <= now)
            {
                return 0;
            }
            // next > now 保证差值非负；先分桶截断再做 duration_cast，
            // 避免极大过期时间在有符号差值上未定义溢出
            if (next - now > std::chrono::milliseconds(std::numeric_limits<int>::max()))
            {
                return std::numeric_limits<int>::max();
            }
            return static_cast<int>(
                std::chrono::duration_cast<std::chrono::milliseconds>(next - now).count());
        }

        inline void doPendingTasks()
        {
            std::deque<Task> tasks;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (pending_.empty())
                {
                    return;
                }
                tasks.swap(pending_);
            }
            for (Task &task : tasks)
            {
                if (task) [[likely]]
                {
                    task();
                }
            }
        }

        inline void wakeup() noexcept
        {
            if (wakeFd_ < 0) [[unlikely]]
            {
                return;
            }
            constexpr uint64_t one = 1;
            const ssize_t ignored = ::write(wakeFd_, &one, sizeof one);
            (void)ignored;
        }

        inline void drainWakeup() noexcept
        {
            uint64_t value = 0;
            while (::read(wakeFd_, &value, sizeof value) > 0)
            {
                continue;
            }
        }

        static constexpr uint64_t kWakeToken = ~uint64_t{0};

        int epollFd_ = -1;
        int wakeFd_ = -1;
        std::atomic<bool> quit_{false};
        std::atomic<bool> running_{false};
        std::thread::id threadId_{};
        std::vector<struct epoll_event> events_;
        EventCallback eventCallback_{};
        TimerQueue timerQueue_{};
        std::mutex mutex_{};
        std::deque<Task> pending_{};
    };

} // namespace mynet
