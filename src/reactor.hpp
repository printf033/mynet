#pragma once

/**
 * @file reactor.hpp
 * @brief 基于 epoll 的高性能反应器（Reactor）事件解复用器、事件循环核心与多接收器调度。
 */

#include "acceptor.hpp"
#include "config/log.hpp"
#include "config/tls.hpp"
#include "configHolder.hpp"
#include "connection.hpp"
#include "datagram.hpp"
#include "error.hpp"
#include "objectPool.hpp"
#include "timer.hpp"
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <utility>
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

        ///
        /// epoll 就绪事件数组的初始槽位数量。
        ///
        /// 只服务于**不显式设定容量**的使用方（例如 Client，它不接收 maxEvents
        /// 配置）。Reactor 一侧会用 reactor.maxEvents 调 setEventCapacity() 覆盖
        /// 这个值，因此它不构成引擎的默认值，也不进入 config.lua。
        ///
        static constexpr size_t kInitialEventCapacity = 1 << 10;

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
                LOG_ERROR("EventLoop::init: epoll_create1() failed: {}", errnoText(errno));
                return std::unexpected(ERR::EPOLL_CREATE_FAILED);
            }
            wakeFd_ = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
            if (wakeFd_ < 0) [[unlikely]]
            {
                LOG_ERROR("EventLoop::init: eventfd() failed: {}", errnoText(errno));
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
                LOG_ERROR("EventLoop::init: epoll_ctl(ADD, wakeup fd {}) failed: {}", wakeFd_, errnoText(errno));
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
            events_.resize(kInitialEventCapacity);
            if (auto res = init(); !res) [[unlikely]]
            {
                LOG_ERROR("EventLoop: constructor init failed: {}", toString(res.error()));
            }
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
            delete; // the loop owns an epoll set and a wakeup fd; a copy would double-close both
        EventLoop &operator=(const EventLoop &) =
            delete; // the loop owns an epoll set and a wakeup fd; a copy would double-close both

        [[nodiscard]] inline int epollFd() const noexcept { return epollFd_; }
        [[nodiscard]] inline bool running() const noexcept { return running_.load(std::memory_order_acquire); }
        [[nodiscard]] inline bool inLoopThread() const noexcept { return std::this_thread::get_id() == threadId_; }

        inline void setEventCallback(EventCallback callback) { eventCallback_ = std::move(callback); }

        /**
         * @brief 当前单次 epoll_wait 的就绪事件数组容量（诊断用）。
         */
        [[nodiscard]] inline size_t eventCapacity() const noexcept { return events_.size(); }

        /**
         * @brief 精确设定单次 epoll_wait 的就绪事件数组容量。
         *
         * 必须**精确**而不是只增：引擎把 reactor.maxEvents 传进来，若配置写 512
         * 而实际仍按 1024 收事件，这项配置就成了一句谎。下限 1，因为 epoll_wait
         * 的 maxevents 必须大于 0。
         *
         * 注意 run() 在"本轮事件数恰好填满数组"时会翻倍扩容——那是满载时的
         * 自适应，用于避免就绪事件被丢弃。因此本容量是**启动值**：空闲时就是
         * reactor.maxEvents，只有真正打满过一轮之后才会增长到更高水位。
         */
        inline void setEventCapacity(size_t count)
        {
            const size_t target = count > 0 ? count : 1;
            if (target != events_.size())
            {
                events_.resize(target);
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
                          errnoText(errno));
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
                          errnoText(errno));
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
                LOG_WARN("EventLoop::delFd: epoll_ctl(DEL, fd {}) failed: {}", fd, errnoText(errno));
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
            bool expected = false;
            if (!running_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) [[unlikely]]
            {
                LOG_ERROR("EventLoop::run: loop is already running");
                return std::unexpected(ERR::LOOP_ALREADY_RUNNING);
            }
            threadId_ = std::this_thread::get_id();
            quit_.store(false, std::memory_order_relaxed);
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
                    LOG_ERROR("EventLoop::run: epoll_wait() failed: {}", errnoText(errno));
                    running_.store(false, std::memory_order_release);
                    return std::unexpected(ERR::EPOLL_WAIT_FAILED);
                }
                if (n == static_cast<int>(events_.size())) [[unlikely]]
                {
                    events_.resize(events_.size() * 2);
                }

                if (!timerQueue_.empty()) [[unlikely]]
                {
                    const Time now = Clock::now();
                    timerQueue_.handleExpired(now);
                }
                if (hasPending_.load(std::memory_order_acquire)) [[unlikely]]
                {
                    doPendingTasks();
                }

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
                hasPending_.store(true, std::memory_order_release);
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
            if (timerQueue_.empty()) [[likely]]
            {
                return -1;
            }
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
            const auto diff = next - now;
            if (diff > std::chrono::milliseconds(std::numeric_limits<int>::max()))
            {
                return std::numeric_limits<int>::max();
            }
            auto ms = std::chrono::ceil<std::chrono::milliseconds>(diff).count();
            return static_cast<int>(ms);
        }

        inline void doPendingTasks()
        {
            if (!hasPending_.load(std::memory_order_acquire)) [[likely]]
            {
                return;
            }
            std::deque<Task> tasks;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (pending_.empty())
                {
                    hasPending_.store(false, std::memory_order_release);
                    return;
                }
                tasks.swap(pending_);
                hasPending_.store(false, std::memory_order_release);
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
            [[maybe_unused]] const ssize_t ignored = ::write(wakeFd_, &one, sizeof one);
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
        std::atomic<bool> hasPending_{false};
        std::mutex mutex_{};
        std::deque<Task> pending_{};
    };

    /**
     * @class Reactor
     * @brief 基于单线程 epoll 的反应器引擎，管理套接字生命周期与 I/O 事件分发。
     *
     * 采用边沿触发（EPOLLET）模式驱动新连接接入、SSL 握手与 UDP 数据报收发。
     * 支持原生单 Acceptor 模式与多入站接收器（Multi-Acceptor）统一事件驱动。
     *
     * @tparam Acceptor 满足 DerivedFromAcceptorBase 与 Resettable 约束的套接字接收器包装类型。
     */
    template <typename Acceptor>
        requires DerivedFromAcceptor<Acceptor> && Resettable<Acceptor> &&
                 (MandatoryMethodConnection<typename Acceptor::Handler> ||
                  MandatoryMethodDatagram<typename Acceptor::Handler>)
    class Reactor
    {
    public:
        using Handler = typename Acceptor::Handler;
        using Conn = typename ConnectionSlot<Handler>::Type;

        ///
        /// 该处理器是否由 Connection 承载会话（即满足流式契约）。
        ///
        /// 为 false 时（纯数据报处理器）Conn 退化为 NoConnection，会话对象不携带
        /// 任何流式状态；runTcp / runSsl 另以 kStreaming 约束自身，因此纯报文
        /// 处理器只暴露 runUdp，不会把 Connection<H> 拉进编译。
        ///
        static constexpr bool kStreaming = MandatoryMethodConnection<Handler>;

        Reactor() = default;

        ~Reactor() noexcept { reset(); }

        Reactor(const Reactor &) = delete;            // a reactor owns the epoll registration of every live connection
        Reactor &operator=(const Reactor &) = delete; // a reactor owns the epoll registration of every live connection

        /**
         * @brief 获取底层的事件循环引用。
         */
        [[nodiscard]] inline EventLoop &loop() noexcept { return loop_; }

        /**
         * @brief 当前活跃的连接数量。
         */
        [[nodiscard]] inline size_t connections() const noexcept { return index_.size(); }

        /**
         * @brief 预分配连接池的总容量。
         */
        [[nodiscard]] inline size_t connectionPoolCapacity() const noexcept { return connPool_.capacity(); }

        /**
         * @brief 请求事件循环安全退出。
         */
        inline void stop() noexcept { loop_.quit(); }

        inline void quit() noexcept { loop_.quit(); }

        using AcceptCallback = std::function<void(int clientFd, const sockaddr_in &clientAddr)>;

        struct ExtraListener
        {
            int fd{-1};
            AcceptCallback onAccept{};
        };

        [[nodiscard]] inline Acceptor &acceptor() noexcept { return acceptor_; }
        [[nodiscard]] inline const Acceptor &acceptor() const noexcept { return acceptor_; }

        /**
         * @brief 注册外部监听描述符（如各 Inbound::listenFd()）至当前 Reactor 事件循环
         *
         * 实现了将多个入站端口统一交由同一事件引擎多路复用驱动。
         *
         * @param listenFd 外部监听描述符
         * @param onAccept 接入新客户端连接的回调函数；若为空则自动接入 Reactor 内部流式连接池
         * @return Result<> 成功返回 {}，失败返回错误枚举
         */
        Result<> addListener(int listenFd, AcceptCallback onAccept = nullptr)
        {
            if (listenFd < 0)
            {
                return std::unexpected(ERR::SOCKET_FAILED);
            }
            if (extraListenersByFd_.contains(listenFd))
            {
                return {};
            }

            auto listener = std::make_shared<ExtraListener>();
            listener->fd = listenFd;
            listener->onAccept = std::move(onAccept);

            if (loop_.running())
            {
                if (auto res = loop_.addFd(listenFd, EPOLLIN | EPOLLET, listener.get()); !res)
                {
                    return res;
                }
            }

            extraListeners_.emplace(listener.get(), listener);
            extraListenersByFd_.emplace(listenFd, listener);
            return {};
        }

        /**
         * @brief 注册外部 Acceptor 实例到事件循环
         */
        template <typename AnyHandler>
        Result<> addAcceptor(mynet::Acceptor<AnyHandler> &acc, AcceptCallback onAccept = nullptr)
        {
            if (acc.fd < 0)
            {
                return std::unexpected(ERR::SOCKET_FAILED);
            }
            return addListener(acc.fd, std::move(onAccept));
        }

        /**
         * @brief 移除外部监听描述符
         */
        Result<> removeListener(int listenFd)
        {
            auto it = extraListenersByFd_.find(listenFd);
            if (it == extraListenersByFd_.end())
            {
                return {};
            }
            auto listener = it->second;
            if (listener->fd >= 0)
            {
                [[maybe_unused]] auto _ = loop_.delFd(listener->fd);
            }
            extraListeners_.erase(listener.get());
            extraListenersByFd_.erase(it);
            return {};
        }

        [[nodiscard]] inline size_t listenerCount() const noexcept
        {
            return (acceptor_.fd >= 0 ? 1 : 0) + extraListenersByFd_.size();
        }

        /**
         * @brief 完全以全局配置运行 TCP 服务器（监听地址取自 server.host/port）。
         * @return 正常停止返回 {}，启动或运行时失败返回错误码。
         */
        [[nodiscard]] Result<> runTcp()
            requires BaseAcceptor<Acceptor> && kStreaming
        {
            // 深拷贝一份：get*Config() 返回的是 thread_local 快照的引用，并发的
            // reloadConfig() 会重新赋值该快照，令 host.c_str() 在调用栈更深处悬垂。
            // 拷贝成局部值后，指针的生命周期覆盖整个 run* 调用。
            const MynetConfig cfg = getMynetConfig();
            return runTcp(cfg.server.host.c_str(), static_cast<int>(cfg.server.port), cfg.server, cfg.reactor);
        }

        /**
         * @brief 以全局配置（server + reactor 段）运行 TCP 服务器，直至被请求停止。
         * @param ip 监听 IPv4 地址字面量。
         * @param port 监听端口。
         * @return 正常停止返回 {}，启动或运行时失败返回错误码。
         */
        [[nodiscard]] Result<> runTcp(const char *ip, int port)
            requires BaseAcceptor<Acceptor> && kStreaming
        {
            const MynetConfig cfg = getMynetConfig();
            return runTcp(ip, port, cfg.server, cfg.reactor);
        }

        /**
         * @brief 以显式配置运行 TCP 服务器，直至被请求停止。
         *
         * 监听参数取自 server 段，事件循环参数取自 reactor 段；两者都由
         * config.lua 解析并钳位，引擎侧不再保留任何默认实参。
         *
         * @param ip 监听 IPv4 地址字面量。
         * @param port 监听端口。
         * @param server 服务端传输配置（backlog / maxConnections / idleTimeoutSecs 等）。
         * @param reactor 反应器运行时配置（maxEvents / idleSweepIntervalMs）。
         * @return 正常停止返回 {}，启动或运行时失败返回错误码。
         */
        [[nodiscard]] Result<> runTcp(const char *ip, int port, const ServerConfig &server,
                                      const ReactorConfig &reactor)
            requires BaseAcceptor<Acceptor> && kStreaming
        {
            contract_assert(validServerConfig(server));
            contract_assert(validReactorConfig(reactor));
            if (auto err = acceptor_.listenTcp(ip, port, server.backlog, server.reuseAddr, server.reusePort); !err)
                [[unlikely]]
            {
                reset();
                return err;
            }
            Result<> rc = serve(server, reactor);
            reset();
            return rc;
        }

        /**
         * @brief 完全以全局配置运行 TLS 服务器：监听地址与证书路径都取自配置段。
         *
         * 证书与私钥取自 security.certFile / security.keyFile；任一为空表示"未配置"，
         * 直接失败而不是悄悄降级成明文——TLS 服务端不应在配置缺失时静默裸奔。
         * @return 正常停止返回 {}，启动或运行时失败返回错误码。
         */
        [[nodiscard]] Result<> runSsl()
            requires kStreaming
        {
            const MynetConfig cfg = getMynetConfig();
            if (cfg.security.certFile.empty() || cfg.security.keyFile.empty()) [[unlikely]]
            {
                LOG_ERROR("runSsl: security.certFile / security.keyFile are empty; "
                          "set them in config.lua or call the explicit-path overload");
                return std::unexpected(ERR::SSL_CERT_FAILED);
            }
            return runSsl(cfg.server.host.c_str(), static_cast<int>(cfg.server.port), cfg.security.certFile.c_str(),
                          cfg.security.keyFile.c_str(), cfg.server, cfg.reactor, cfg.security);
        }

        /**
         * @brief 以全局配置的监听地址 + 显式证书路径运行 TLS 服务器。
         */
        [[nodiscard]] Result<> runSsl(const char *crt, const char *key)
            requires kStreaming
        {
            const MynetConfig cfg = getMynetConfig();
            return runSsl(cfg.server.host.c_str(), static_cast<int>(cfg.server.port), crt, key, cfg.server, cfg.reactor,
                          cfg.security);
        }

        /**
         * @brief 以全局配置运行 TLS/SSL 服务器，TLS 协商参数取自 security 段。
         * @param ip 监听 IPv4 地址字面量。
         * @param port 监听端口。
         * @param crt PEM 格式证书文件路径。
         * @param key PEM 格式私钥文件路径。
         * @return 正常停止返回 {}，启动或运行时失败返回错误码。
         */
        [[nodiscard]] Result<> runSsl(const char *ip, int port, const char *crt, const char *key)
            requires kStreaming
        {
            const MynetConfig cfg = getMynetConfig();
            return runSsl(ip, port, crt, key, cfg.server, cfg.reactor, cfg.security);
        }

        /**
         * @brief 以显式 TLS 选项 + 全局 server/reactor 配置运行 TLS/SSL 服务器。
         * @param ip 监听 IPv4 地址字面量。
         * @param port 监听端口。
         * @param crt PEM 格式证书文件路径。
         * @param key PEM 格式私钥文件路径。
         * @param security TLS 安全与协议协商配置。
         * @return 正常停止返回 {}，启动或运行时失败返回错误码。
         */
        [[nodiscard]] Result<> runSsl(const char *ip, int port, const char *crt, const char *key,
                                      const SecurityConfig &security)
            requires kStreaming
        {
            const MynetConfig cfg = getMynetConfig();
            return runSsl(ip, port, crt, key, cfg.server, cfg.reactor, security);
        }

        /**
         * @brief 以显式配置运行 TLS/SSL 服务器，直至被请求停止。
         * @param ip 监听 IPv4 地址字面量。
         * @param port 监听端口。
         * @param crt PEM 格式证书文件路径。
         * @param key PEM 格式私钥文件路径。
         * @param server 服务端传输配置。
         * @param reactor 反应器运行时配置。
         * @param security TLS 安全配置。
         * @return 正常停止返回 {}，启动或运行时失败返回错误码。
         */
        [[nodiscard]] Result<> runSsl(const char *ip, int port, const char *crt, const char *key,
                                      const ServerConfig &server, const ReactorConfig &reactor,
                                      const SecurityConfig &security)
            requires kStreaming
        {
            contract_assert(validServerConfig(server));
            contract_assert(validReactorConfig(reactor));
            if (auto err = acceptor_.listenTcp(ip, port, server.backlog, server.reuseAddr, server.reusePort); !err)
                [[unlikely]]
            {
                reset();
                return err;
            }
            security_ = security;
            alpnList_ = detail::splitAlpnList(security_.alpnProtocols);
            auto ctxRes = detail::createServerContext(crt, key, security_, &alpnList_);
            if (!ctxRes) [[unlikely]]
            {
                reset();
                return std::unexpected(ctxRes.error());
            }
            sslCtx_ = *ctxRes;
            Result<> rc = serve(server, reactor);
            reset();
            return rc;
        }

        /**
         * @brief 使用 SNI 多域名证书调度器运行 TLS 服务器。
         */
        [[nodiscard]] Result<> runSsl(const char *ip, int port, SniCertificateManager &sniManager,
                                      const ServerConfig &server, const ReactorConfig &reactor)
            requires kStreaming
        {
            contract_assert(validServerConfig(server));
            contract_assert(validReactorConfig(reactor));
            if (auto err = acceptor_.listenTcp(ip, port, server.backlog, server.reuseAddr, server.reusePort); !err)
                [[unlikely]]
            {
                reset();
                return err;
            }
            sslCtx_ = sniManager.defaultContext();
            if (sslCtx_ == nullptr) [[unlikely]]
            {
                reset();
                return std::unexpected(ERR::SSL_CTX_FAILED);
            }
            Result<> rc = serve(server, reactor);
            // 由 sniManager 管理其托管的 SSL_CTX 生命周期，退出时置空避免 double-free
            sslCtx_ = nullptr;
            reset();
            return rc;
        }

        [[nodiscard]] Result<> runSsl(const char *ip, int port, SniCertificateManager &sniManager)
            requires kStreaming
        {
            const MynetConfig cfg = getMynetConfig();
            return runSsl(ip, port, sniManager, cfg.server, cfg.reactor);
        }

        [[nodiscard]] Result<> runSsl(SniCertificateManager &sniManager)
            requires kStreaming
        {
            const MynetConfig cfg = getMynetConfig();
            return runSsl(cfg.server.host.c_str(), static_cast<int>(cfg.server.port), sniManager, cfg.server,
                          cfg.reactor);
        }

        /**
         * @brief 完全以全局配置运行 UDP 数据报服务器（监听地址取自 server.host/port）。
         * @param handler 数据报处理器引用。
         * @return 正常停止返回 {}，启动或运行时失败返回错误码。
         */
        [[nodiscard]] Result<> runUdp(Handler &handler)
            requires MandatoryMethodDatagram<Handler>
        {
            const MynetConfig cfg = getMynetConfig();
            return runUdp(cfg.server.host.c_str(), static_cast<int>(cfg.server.port), handler, cfg.reactor);
        }

        /**
         * @brief 以全局配置（reactor 段）运行 UDP 数据报服务器，直至被请求停止。
         * @param ip 监听 IPv4 地址字面量。
         * @param port 监听端口。
         * @param handler 数据报处理器引用。
         * @return 正常停止返回 {}，启动或运行时失败返回错误码。
         */
        [[nodiscard]] Result<> runUdp(const char *ip, int port, Handler &handler)
            requires MandatoryMethodDatagram<Handler>
        {
            const ReactorConfig cfg = getReactorConfig();
            return runUdp(ip, port, handler, cfg);
        }

        /**
         * @brief 以显式配置运行 UDP 数据报服务器，直至被请求停止。
         * @param ip 监听 IPv4 地址字面量。
         * @param port 监听端口。
         * @param handler 数据报处理器引用。
         * @param reactor 反应器运行时配置（maxEvents）。
         * @return 正常停止返回 {}，启动或运行时失败返回错误码。
         */
        [[nodiscard]] Result<> runUdp(const char *ip, int port, Handler &handler, const ReactorConfig &reactor)
            requires MandatoryMethodDatagram<Handler>
        {
            contract_assert(validReactorConfig(reactor));
            if (auto err = acceptor_.listenUdp(ip, port); !err) [[unlikely]]
            {
                reset();
                return err;
            }
            handler.reset();
            datagram_.bind(handler);
            Result<> rc = serveDatagram(reactor);
            reset();
            return rc;
        }

        /**
         * @brief 完全以全局配置运行 QUIC (HTTP/3 over UDP) 服务器。
         */
        [[nodiscard]] Result<> runQuic(Handler &handler)
            requires MandatoryMethodDatagram<Handler>
        {
            const MynetConfig cfg = getMynetConfig();
            return runQuic(cfg.server.host.c_str(), static_cast<int>(cfg.server.port), handler);
        }

        /**
         * @brief 以全局配置（reactor/security 段）运行 QUIC 服务器。
         */
        [[nodiscard]] Result<> runQuic(const char *ip, int port, Handler &handler)
            requires MandatoryMethodDatagram<Handler>
        {
            const MynetConfig cfg = getMynetConfig();
            const char *crt = cfg.security.certFile.empty() ? "certs/ser.crt" : cfg.security.certFile.c_str();
            const char *key = cfg.security.keyFile.empty() ? "certs/ser.key" : cfg.security.keyFile.c_str();
            return runQuic(ip, port, crt, key, handler, cfg.reactor);
        }

        /**
         * @brief 以显式证书路径 + 全局 reactor 配置运行 QUIC 服务器。
         */
        [[nodiscard]] Result<> runQuic(const char *ip, int port, const char *crt, const char *key, Handler &handler)
            requires MandatoryMethodDatagram<Handler>
        {
            const ReactorConfig cfg = getReactorConfig();
            return runQuic(ip, port, crt, key, handler, cfg);
        }

        /**
         * @brief 以显式配置与证书路径运行 QUIC 服务器，直至被请求停止。
         */
        [[nodiscard]] Result<> runQuic(const char *ip, int port, const char *crt, const char *key, Handler &handler,
                                       const ReactorConfig &reactor)
            requires MandatoryMethodDatagram<Handler>
        {
            contract_assert(validReactorConfig(reactor));
            if (auto err = acceptor_.listenUdp(ip, port); !err) [[unlikely]]
            {
                reset();
                return err;
            }
            handler.reset();
            datagram_.bind(handler);

            SecurityConfig security{};
            security.alpnProtocols = "h3";
            auto ctxRes = detail::createServerContext(crt, key, security, &alpnList_, TlsProtocolType::DatagramQuic);
            if (!ctxRes) [[unlikely]]
            {
                LOG_ERROR("Reactor::runQuic: TLS context creation failed: {}", ctxRes.error());
                reset();
                return std::unexpected(ctxRes.error());
            }
            sslCtx_ = *ctxRes;

            if (auto tlsErr = datagram_.startTLS(sslCtx_, acceptor_.fd); !tlsErr) [[unlikely]]
            {
                LOG_ERROR("Reactor::runQuic: datagram startTLS failed: {}", tlsErr.error());
                reset();
                return tlsErr;
            }

            Result<> rc = serveDatagram(reactor);
            reset();
            return rc;
        }

        /**
         * @brief 提交任务至事件循环线程异步执行。
         * @param task 可调用任务对象。
         */
        inline void runInLoop(EventLoop::Task task) { loop_.runInLoop(std::move(task)); }

        /**
         * @brief 在事件循环线程上针对指定连接执行任务。
         * @param fd 连接文件描述符。
         * @param task 连接任务回调。
         */
        inline void runOnConnection(int fd, std::function<void(Conn &)> task)
            requires kStreaming
        {
            loop_.runInLoop(
                [this, fd, task = std::move(task)]
                {
                    auto it = index_.find(fd);
                    if (it == index_.end())
                    {
                        return;
                    }
                    Conn *conn = it->second;
                    task(*conn);
                    conn->setWantWrite(conn->hasPendingWrite());
                    if (updateInterest(conn) == IO_STATUS::CLOSE)
                    {
                        closeConn(conn);
                    }
                });
        }

        /**
         * @brief 根据文件描述符查找活跃连接。
         * @param fd 连接文件描述符。
         * @return 连接指针，若未找到则返回 nullptr。
         */
        [[nodiscard]] inline Conn *find(int fd) noexcept
            requires kStreaming
        {
            auto it = index_.find(fd);
            return it == index_.end() ? nullptr : it->second;
        }

        /**
         * @brief 面向流式连接的核心事件循环。
         */
        [[nodiscard]] inline Result<> serve(const ServerConfig &server, const ReactorConfig &reactor)
            requires kStreaming
        {
            // 这两个 serve 是 public 的（可在 runTcp 之外直接驱动），因此校验必须
            // 落在它们自己身上，而不是只靠调用方。maxConnections == 0 会让
            // ObjectPool::init(0) 成功返回一个空池，随后每个 accept 都被当作
            // "池耗尽"关掉——表现为一个静默不服务的服务器，而不是明确失败。
            contract_assert(validServerConfig(server));
            contract_assert(validReactorConfig(reactor));
            if (loop_.epollFd() < 0) [[unlikely]]
            {
                LOG_ERROR("Reactor::serve: the event loop has no epoll descriptor");
                return std::unexpected(ERR::EPOLL_CREATE_FAILED);
            }
            // 配置在 lua_config 解析阶段已完成钳位，这里不再重复兜底，
            // 避免两处默认值分叉。
            loop_.setEventCapacity(static_cast<size_t>(reactor.maxEvents));
            const size_t connSlots = server.maxConnections;
            if (auto poolRes = connPool_.init(connSlots); !poolRes) [[unlikely]]
            {
                LOG_ERROR("Reactor::serve: initialising connection pool ({} slots) failed", connSlots);
                return std::unexpected(ERR::POOL_ALLOC_FAILED);
            }
            sweepScratch_.reserve(connSlots);
            loop_.setEventCallback([this](uint32_t events, void *ptr) { onEvent(events, ptr); });
            if (acceptor_.fd >= 0)
            {
                if (auto res = loop_.addFd(acceptor_.fd, EPOLLIN | EPOLLET, &acceptor_); !res) [[unlikely]]
                {
                    LOG_ERROR("Reactor::serve: adding listener fd {} to loop failed: {}", acceptor_.fd,
                              errnoText(errno));
                    return std::unexpected(ERR::EPOLL_CTL_FAILED);
                }
            }
            for (auto &[ptr, listener] : extraListeners_)
            {
                if (listener->fd >= 0)
                {
                    if (auto res = loop_.addFd(listener->fd, EPOLLIN | EPOLLET, listener.get()); !res) [[unlikely]]
                    {
                        LOG_ERROR("Reactor::serve: adding extra listener fd {} to loop failed: {}", listener->fd,
                                  errnoText(errno));
                        return std::unexpected(ERR::EPOLL_CTL_FAILED);
                    }
                }
            }
            if (server.idleTimeoutSecs > 0)
            {
                idleTimeout_ = std::chrono::seconds(server.idleTimeoutSecs);
                idleTimerId_ =
                    loop_.runEvery(std::chrono::milliseconds(reactor.idleSweepIntervalMs), [this] { sweepIdle(); });
            }
            return loop_.run();
        }

        /**
         * @brief 面向数据报的核心事件循环。
         */
        [[nodiscard]] inline Result<> serveDatagram(const ReactorConfig &reactor)
        {
            contract_assert(validReactorConfig(reactor));
            if (loop_.epollFd() < 0) [[unlikely]]
            {
                LOG_ERROR("Reactor::serveDatagram: the event loop has no epoll descriptor");
                return std::unexpected(ERR::EPOLL_CREATE_FAILED);
            }
            loop_.setEventCapacity(static_cast<size_t>(reactor.maxEvents));
            loop_.setEventCallback([this](uint32_t events, void *ptr) { onEvent(events, ptr); });
            if (auto res = loop_.addFd(acceptor_.fd, EPOLLIN | EPOLLET, &acceptor_); !res) [[unlikely]]
            {
                LOG_ERROR("Reactor::serveDatagram: adding datagram fd {} to loop failed: {}", acceptor_.fd,
                          errnoText(errno));
                return std::unexpected(ERR::EPOLL_CTL_FAILED);
            }
            uint64_t quicTimerId = 0;
            if (datagram_.isQuic())
            {
                quicTimerId = loop_.runEvery(std::chrono::milliseconds(20), [this] { datagram_.tick(acceptor_.fd); });
            }
            Result<> rc = loop_.run();
            if (quicTimerId != 0)
            {
                [[maybe_unused]] auto _ = loop_.cancelTimer(quicTimerId);
            }
            return rc;
        }

        /**
         * @brief 重置反应器状态并清理全部关联资源。
         */
        inline void reset() noexcept
        {
            if (idleTimerId_ != 0)
            {
                [[maybe_unused]] auto _ = loop_.cancelTimer(idleTimerId_);
                idleTimerId_ = 0;
            }
            if (acceptor_.fd != -1)
            {
                [[maybe_unused]] auto _ = loop_.delFd(acceptor_.fd);
            }
            for (auto &[ptr, listener] : extraListeners_)
            {
                if (listener->fd >= 0)
                {
                    [[maybe_unused]] auto _ = loop_.delFd(listener->fd);
                }
            }
            extraListeners_.clear();
            extraListenersByFd_.clear();
            for (auto &entry : index_)
            {
                [[maybe_unused]] auto _ = loop_.delFd(entry.first);
                connPool_.release(entry.second);
            }
            index_.clear();
            connPool_.reset();
            loop_.setEventCallback({});
            if (sslCtx_ != nullptr)
            {
                detail::freeContext(sslCtx_);
                sslCtx_ = nullptr;
            }
            acceptor_.reset();
            datagram_.reset();
            idleTimeout_ = std::chrono::seconds(0);
            security_ = {};
            alpnList_.clear();
        }

    private:
        inline void onEvent(uint32_t events, void *ptr)
        {
            if (ptr == nullptr) [[unlikely]]
            {
                return;
            }
            if (ptr == &acceptor_)
            {
                if (datagram_.bound())
                {
                    if (events & EPOLLIN)
                    {
                        [[maybe_unused]] auto _ = datagram_.handleRead(acceptor_.fd);
                    }
                    if (events & EPOLLOUT)
                    {
                        [[maybe_unused]] auto _ = datagram_.handleWrite(acceptor_.fd);
                    }
                    return;
                }
                if (events & EPOLLIN)
                {
                    if constexpr (kStreaming)
                    {
                        if (auto err = acceptAll(); !err) [[unlikely]]
                        {
                            LOG_DEBUG("Reactor::onEvent: draining accept backlog ended with {}", toString(err.error()));
                        }
                    }
                }
                return;
            }
            auto itL = extraListeners_.find(ptr);
            if (itL != extraListeners_.end())
            {
                if (events & EPOLLIN)
                {
                    drainExtraListener(*itL->second);
                }
                return;
            }
            if constexpr (kStreaming)
            {
                onConnection(static_cast<Conn *>(ptr), events);
            }
        }

        inline void drainExtraListener(ExtraListener &listener)
        {
            while (true)
            {
                sockaddr_in addr{};
                socklen_t len = sizeof(addr);
                int clientFd =
                    ::accept4(listener.fd, reinterpret_cast<sockaddr *>(&addr), &len, SOCK_NONBLOCK | SOCK_CLOEXEC);
                if (clientFd < 0)
                {
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                    {
                        break;
                    }
                    if (errno == EINTR)
                    {
                        continue;
                    }
                    if (errno == EMFILE || errno == ENFILE || errno == ENOBUFS || errno == ENOMEM) [[unlikely]]
                    {
                        break;
                    }
                    LOG_ERROR("Reactor: accept4() on extra listener fd {} failed: {}", listener.fd, errnoText(errno));
                    break;
                }

                if (listener.onAccept)
                {
                    listener.onAccept(clientFd, addr);
                }
                else
                {
                    if constexpr (kStreaming)
                    {
                        onNewConnection(clientFd, addr);
                    }
                    else
                    {
                        ::close(clientFd);
                    }
                }
            }
        }

        inline void onConnection(Conn *conn, uint32_t events)
            requires kStreaming
        {
            // 陈旧事件守卫：同一轮 epoll_wait 里回调可能已关闭本连接，
            // 对象回池后 fd 被重置为 -1；后续到达的残留事件直接丢弃，
            // 否则会对已释放对象重新派发 IO
            if (conn->fd() < 0) [[unlikely]]
            {
                return;
            }
            if ((events & (EPOLLERR | EPOLLHUP)) && !(events & EPOLLIN)) [[unlikely]]
            {
                closeConn(conn);
                return;
            }
            if (events & EPOLLIN)
            {
                if (conn->handleRead() == IO_STATUS::CLOSE) [[unlikely]]
                {
                    closeConn(conn);
                    return;
                }
                if (conn->hasPendingWrite() && !(events & EPOLLOUT))
                {
                    if (conn->handleWrite() == IO_STATUS::CLOSE) [[unlikely]]
                    {
                        closeConn(conn);
                        return;
                    }
                }
            }
            if (events & EPOLLOUT)
            {
                if (conn->handleWrite() == IO_STATUS::CLOSE) [[unlikely]]
                {
                    closeConn(conn);
                    return;
                }
            }
            if (updateInterest(conn) == IO_STATUS::CLOSE)
            {
                closeConn(conn);
            }
        }

        /**
         * @brief 根据 Conn 当前读写意愿计算期望的 epoll 兴趣集。
         * @param conn 目标连接。
         * @return 期望兴趣集（恒含 EPOLLET），无任何兴趣时为 0。
         */
        [[nodiscard]] inline uint32_t computeInterest(const Conn *conn) const noexcept
            requires kStreaming
        {
            uint32_t wanted = EPOLLET;
            if (conn->wantRead())
            {
                wanted |= EPOLLIN;
            }
            if (conn->wantWrite())
            {
                wanted |= EPOLLOUT;
            }
            return wanted;
        }

        /**
         * @brief 将期望兴趣集写入内核（仅当与当前注册集不同时调用 epoll_ctl）。
         * @param conn 目标连接。
         * @param wanted 期望兴趣集（需已含 EPOLLET）。
         * @return true=内核已同步；false=epoll_ctl 失败，调用方应关闭连接。
         */
        inline bool applyInterest(Conn *conn, uint32_t wanted)
            requires kStreaming
        {
            if (wanted == conn->events())
            {
                return true;
            }
            if (!loop_.modFd(conn->fd(), wanted, conn)) [[unlikely]]
            {
                return false;
            }
            conn->setEvents(wanted);
            return true;
        }

        /**
         * @brief 边缘触发下的“重读”策略：读意愿刚恢复但内核尚未投递就绪事件时，
         *        同步驱动一次读取，并以读取后的最新意愿重新收敛兴趣集。
         * @param conn 目标连接。
         * @return KEEP=继续维持连接；CLOSE=连接需关闭。
         */
        [[nodiscard]] inline IO_STATUS rearmRead(Conn *conn)
            requires kStreaming
        {
            if (conn->handleRead() == IO_STATUS::CLOSE) [[unlikely]]
            {
                return IO_STATUS::CLOSE;
            }
            const uint32_t after = computeInterest(conn);
            if ((after & ~static_cast<uint32_t>(EPOLLET)) == 0)
            {
                return IO_STATUS::CLOSE;
            }
            if (!applyInterest(conn, after)) [[unlikely]]
            {
                return IO_STATUS::CLOSE;
            }
            return IO_STATUS::KEEP;
        }

        /**
         * @brief 将连接的 epoll 兴趣集与其当前读写意愿同步（纯编排，不做 I/O）。
         * @param conn 目标连接。
         * @return KEEP=继续维持连接；CLOSE=连接需关闭。
         */
        [[nodiscard]] inline IO_STATUS updateInterest(Conn *conn)
            requires kStreaming
        {
            const uint32_t wanted = computeInterest(conn);
            if ((wanted & ~static_cast<uint32_t>(EPOLLET)) == 0)
            {
                return IO_STATUS::CLOSE;
            }
            // 注意：判定必须基于本次 apply 之前的注册集（旧 events），
            // 与原实现行为完全一致，否则读意愿刚恢复时不会同步重读。
            const bool needRearmRead = (wanted & EPOLLIN) != 0 && (conn->events() & EPOLLIN) == 0;
            if (!applyInterest(conn, wanted)) [[unlikely]]
            {
                return IO_STATUS::CLOSE;
            }
            if (needRearmRead)
            {
                return rearmRead(conn);
            }
            return IO_STATUS::KEEP;
        }

        [[nodiscard]] inline Result<> acceptAll()
            requires kStreaming
        {
            while (true)
            {
                sockaddr_in addr{};
                socklen_t len = sizeof(addr);
                int fd =
                    ::accept4(acceptor_.fd, reinterpret_cast<sockaddr *>(&addr), &len, SOCK_NONBLOCK | SOCK_CLOEXEC);
                if (fd < 0)
                {
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                    {
                        return {};
                    }
                    if (errno == EINTR)
                    {
                        continue;
                    }
                    if (errno == EMFILE || errno == ENFILE || errno == ENOBUFS || errno == ENOMEM) [[unlikely]]
                    {
                        return {};
                    }
                    LOG_ERROR("Reactor::acceptAll: accept4() on fd {} failed: {}", acceptor_.fd, errnoText(errno));
                    return std::unexpected(ERR::ACCEPT_FAILED);
                }
                onNewConnection(fd, addr);
            }
        }

        inline void onNewConnection(int fd, const sockaddr_in &addr)
            requires kStreaming
        {
            Conn *conn = connPool_.acquire();
            if (conn == nullptr) [[unlikely]]
            {
                LOG_WARN("Reactor::onNewConnection: connection pool exhausted, closing fd {}", fd);
                ::close(fd);
                return;
            }
            conn->setFd(fd);
            conn->addr() = addr;
            conn->touch();
            if (sslCtx_ != nullptr && !conn->startTLS(sslCtx_)) [[unlikely]]
            {
                LOG_WARN("Reactor::onNewConnection: TLS setup for fd {} failed: {}", fd, sslText());
                connPool_.release(conn);
                return;
            }
            index_.emplace(fd, conn);
            uint32_t events = EPOLLIN | EPOLLET;
            if (conn->wantWrite())
            {
                events |= EPOLLOUT;
            }
            if (!loop_.addFd(fd, events, conn)) [[unlikely]]
            {
                LOG_WARN("Reactor::onNewConnection: adding fd {} to loop failed: {}", fd, errnoText(errno));
                index_.erase(fd);
                connPool_.release(conn);
                return;
            }
            conn->setEvents(events);
        }

        inline void closeConn(Conn *conn)
            requires kStreaming
        {
            int fd = conn->fd();
            if (fd != -1)
            {
                [[maybe_unused]] auto _ = loop_.delFd(fd);
                index_.erase(fd);
            }
            connPool_.release(conn);
        }

        inline void drainDatagrams() { [[maybe_unused]] auto _ = datagram_.handleRead(acceptor_.fd); }

        inline void sweepIdle()
            requires kStreaming
        {
            if (idleTimeout_.count() <= 0)
            {
                return;
            }
            auto now = std::chrono::steady_clock::now();
            sweepScratch_.clear();
            for (auto &entry : index_)
            {
                if (now - entry.second->lastActive() >= idleTimeout_)
                {
                    sweepScratch_.push_back(entry.second);
                }
            }
            for (Conn *conn : sweepScratch_)
            {
                closeConn(conn);
            }
        }

        Acceptor acceptor_;
        EventLoop loop_;
        SSL_CTX *sslCtx_{nullptr};
        ObjectPool<Conn> connPool_{};
        std::unordered_map<int, Conn *> index_{};
        std::vector<Conn *> sweepScratch_{};
        typename DatagramSlot<Handler>::Type datagram_{};
        SecurityConfig security_{};
        std::vector<std::string> alpnList_{};
        std::chrono::seconds idleTimeout_{0};
        uint64_t idleTimerId_ = 0;
        std::unordered_map<void *, std::shared_ptr<ExtraListener>> extraListeners_{};
        std::unordered_map<int, std::shared_ptr<ExtraListener>> extraListenersByFd_{};
    };

} // namespace mynet
