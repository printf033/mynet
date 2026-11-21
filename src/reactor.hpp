#pragma once

/**
 * @file reactor.hpp
 * @brief 基于 epoll 的高性能反应器（Reactor）事件解复用器、事件循环核心与编译期多协议调度。
 *
 * 架构重构：
 * 1. Reactor 纯粹化：彻底剔除 SSL_CTX* 与 runSsl/runQuic 等上层协议成员与函数；
 * 2. 基础套接字内聚：内部直接持有 int tcpFd_ 与 int udpFd_，管理基础传输网络描述符；
 * 3. 编译期多 Acceptor / Dialer 聚合：以 std::tuple 内联存储由模板参数确定的各协议接收器与拨号器；
 * 4. 零开销纳秒级嗅探分发：单协议编译期直通（0 开销），多协议采用 MSG_PEEK 首包特征极速 match() 精准单发 handshake()；
 * 5. 统一抽象连接会话：所有协议派生的 Connection 统一收敛为 ConnectionBase 基类进行事件循环驱动。
 */

#include "acceptor.hpp"
#include "config/log.hpp"
#include "configHolder.hpp"
#include "connection.hpp"
#include "dialer.hpp"
#include "error.hpp"
#include "socket.hpp"
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
#include <span>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <thread>
#include <tuple>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

namespace mynet
{

    /**
     * @brief 协议套件元特征萃取器
     */
    template <typename T>
    struct ProtocolTraits
    {
    private:
        template <typename U>
        static auto checkAcceptor(int) -> typename U::Acceptor;
        template <typename U>
        static auto checkAcceptor(...) -> U;

        template <typename U>
        static auto checkDialer(int) -> typename U::Dialer;
        template <typename U>
        static auto checkDialer(...) -> Dialer<EmptyOutbound>;

        template <typename U>
        static auto checkConnection(int) -> typename U::Connection;
        template <typename U>
        static auto checkConnection(...) -> Connection<EmptyProtocol>;

    public:
        using Acceptor = decltype(checkAcceptor<T>(0));
        using Dialer = decltype(checkDialer<T>(0));
        using Connection = decltype(checkConnection<T>(0));
    };

    /**
     * @brief 基于 epoll 与 eventfd 的高性能事件循环核心
     */
    class EventLoop
    {
    public:
        using Task = std::function<void()>;
        using EventCallback = std::function<void(uint32_t events, void *ptr)>;
        using Clock = TimerQueue::Clock;
        using Time = TimerQueue::Time;
        using TimerCallback = TimerQueue::Callback;

        static constexpr size_t kInitialEventCapacity = 1 << 10;

        [[nodiscard]] inline Result<> init() noexcept
        {
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
            events_.resize(kInitialEventCapacity);
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
                wakeFd_ = -1;
            }
            if (epollFd_ != -1)
            {
                ::close(epollFd_);
                epollFd_ = -1;
            }
        }

        inline void setEventCapacity(size_t cap) { events_.resize(cap == 0 ? 1 : cap); }

        [[nodiscard]] inline size_t eventCapacity() const noexcept { return events_.size(); }

        [[nodiscard]] inline int epollFd() const noexcept { return epollFd_; }
        [[nodiscard]] inline bool running() const noexcept { return running_.load(std::memory_order_acquire); }

        inline void setEventCallback(EventCallback cb) { eventCallback_ = std::move(cb); }

        [[nodiscard]] inline Result<> addFd(int fd, uint32_t events, void *ptr) noexcept
        {
            if (fd < 0 || epollFd_ < 0) [[unlikely]]
            {
                return std::unexpected(ERR::SOCKET_FAILED);
            }
            struct epoll_event ev;
            std::memset(&ev, 0, sizeof ev);
            ev.events = events;
            ev.data.ptr = ptr;
            if (::epoll_ctl(epollFd_, EPOLL_CTL_ADD, fd, &ev) < 0) [[unlikely]]
            {
                return std::unexpected(ERR::EPOLL_CTL_FAILED);
            }
            return {};
        }

        [[nodiscard]] inline Result<> modFd(int fd, uint32_t events, void *ptr) noexcept
        {
            if (fd < 0 || epollFd_ < 0) [[unlikely]]
            {
                return std::unexpected(ERR::SOCKET_FAILED);
            }
            struct epoll_event ev;
            std::memset(&ev, 0, sizeof ev);
            ev.events = events;
            ev.data.ptr = ptr;
            if (::epoll_ctl(epollFd_, EPOLL_CTL_MOD, fd, &ev) < 0) [[unlikely]]
            {
                return std::unexpected(ERR::EPOLL_CTL_FAILED);
            }
            return {};
        }

        [[nodiscard]] inline Result<> delFd(int fd) noexcept
        {
            if (fd < 0 || epollFd_ < 0) [[unlikely]]
            {
                return std::unexpected(ERR::SOCKET_FAILED);
            }
            if (::epoll_ctl(epollFd_, EPOLL_CTL_DEL, fd, nullptr) < 0) [[unlikely]]
            {
                return std::unexpected(ERR::EPOLL_CTL_FAILED);
            }
            return {};
        }

        [[nodiscard]] inline Result<> run()
        {
            if (epollFd_ < 0) [[unlikely]]
            {
                if (auto res = init(); !res)
                    return res;
            }
            bool expected = false;
            if (!running_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) [[unlikely]]
            {
                LOG_ERROR("EventLoop::run: loop is already running");
                return std::unexpected(ERR::LOOP_ALREADY_RUNNING);
            }
            quit_.store(false, std::memory_order_release);
            threadId_ = std::this_thread::get_id();

            while (!quit_.load(std::memory_order_acquire))
            {
                if (!timerQueue_.empty()) [[unlikely]]
                {
                    timerQueue_.handleExpired(Clock::now());
                }
                if (hasPending_.load(std::memory_order_acquire)) [[unlikely]]
                {
                    doPendingTasks();
                }

                if (quit_.load(std::memory_order_acquire)) [[unlikely]]
                {
                    break;
                }

                const int timeout = nextTimeout();
                const int n = ::epoll_wait(epollFd_, events_.data(), static_cast<int>(events_.size()), timeout);
                if (n < 0)
                {
                    if (errno == EINTR)
                        continue;
                    LOG_ERROR("EventLoop::run: epoll_wait() failed: {}", errnoText(errno));
                    running_.store(false, std::memory_order_release);
                    return std::unexpected(ERR::EPOLL_CTL_FAILED);
                }

                for (int i = 0; i < n; ++i)
                {
                    if (events_[i].data.u64 == kWakeToken)
                    {
                        drainWakeup();
                        continue;
                    }
                    if (eventCallback_)
                    {
                        eventCallback_(events_[i].events, events_[i].data.ptr);
                    }
                }

                if (!timerQueue_.empty()) [[unlikely]]
                {
                    timerQueue_.handleExpired(Clock::now());
                }
                doPendingTasks();
            }

            running_.store(false, std::memory_order_release);
            return {};
        }

        inline void quit() noexcept
        {
            quit_.store(true, std::memory_order_release);
            wakeup();
        }

        inline void runInLoop(Task task)
        {
            if (std::this_thread::get_id() == threadId_)
            {
                task();
            }
            else
            {
                queueInLoop(std::move(task));
            }
        }

        inline void queueInLoop(Task task)
        {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                pending_.push_back(std::move(task));
                hasPending_.store(true, std::memory_order_release);
            }
            wakeup();
        }

        inline uint64_t runAfter(std::chrono::milliseconds delay, TimerCallback callback)
        {
            return timerQueue_.addTimer(Clock::now() + delay, std::move(callback));
        }

        inline uint64_t runEvery(std::chrono::milliseconds interval, TimerCallback callback)
        {
            return timerQueue_.addTimer(Clock::now() + interval, std::move(callback), interval);
        }

        [[nodiscard]] inline Result<> cancelTimer(uint64_t id) { return timerQueue_.cancelTimer(id); }

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
     * @brief 基于单线程 epoll 的高性能反应器引擎，管理套接字生命周期与多协议调度。
     *
     * @tparam Protocols 编译期确定的受理协议套件类型包
     */
    template <typename... Protocols>
    class Reactor
    {
    public:
        using AcceptCallback = std::function<void(int clientFd, const sockaddr_in &clientAddr)>;

        Reactor() = default;
        ~Reactor() noexcept { reset(); }

        Reactor(const Reactor &) = delete;
        Reactor &operator=(const Reactor &) = delete;

        [[nodiscard]] inline EventLoop &loop() noexcept { return loop_; }
        [[nodiscard]] inline size_t connections() const noexcept { return connections_.size(); }

        inline void stop() noexcept { loop_.quit(); }
        inline void quit() noexcept { loop_.quit(); }

        [[nodiscard]] inline int tcpFd() const noexcept { return tcpFd_; }
        [[nodiscard]] inline int udpFd() const noexcept { return udpFd_; }
        [[nodiscard]] inline const sockaddr_in &tcpAddr() const noexcept { return tcpAddr_; }
        [[nodiscard]] inline const sockaddr_in &udpAddr() const noexcept { return udpAddr_; }

        // ---- 编译期类型安全的 Acceptor 检索接口 ----
        template <typename P>
        [[nodiscard]] constexpr auto &acceptor() noexcept
        {
            return std::get<typename ProtocolTraits<P>::Acceptor>(acceptors_);
        }

        template <typename P>
        [[nodiscard]] constexpr const auto &acceptor() const noexcept
        {
            return std::get<typename ProtocolTraits<P>::Acceptor>(acceptors_);
        }

        template <size_t I = 0>
        [[nodiscard]] constexpr auto &acceptor() noexcept
        {
            return std::get<I>(acceptors_);
        }

        template <size_t I = 0>
        [[nodiscard]] constexpr const auto &acceptor() const noexcept
        {
            return std::get<I>(acceptors_);
        }

        // ---- 编译期类型安全的 Dialer 检索接口 ----
        template <typename P>
        [[nodiscard]] constexpr auto &dialer() noexcept
        {
            return std::get<typename ProtocolTraits<P>::Dialer>(dialers_);
        }

        template <typename P>
        [[nodiscard]] constexpr const auto &dialer() const noexcept
        {
            return std::get<typename ProtocolTraits<P>::Dialer>(dialers_);
        }

        template <size_t I = 0>
        [[nodiscard]] constexpr auto &dialer() noexcept
        {
            return std::get<I>(dialers_);
        }

        template <size_t I = 0>
        [[nodiscard]] constexpr const auto &dialer() const noexcept
        {
            return std::get<I>(dialers_);
        }

        // ---- 基础网络套接字监听管理 (TCP / UDP) ----

        Result<> listenTcp(const char *ip, int port, int backlog = 128, bool reuseAddr = true, bool reusePort = true)
        {
            if (tcpFd_ >= 0)
            {
                return {};
            }
            auto res = net::listenTcp(ip, port, tcpAddr_, backlog, reuseAddr, reusePort);
            if (!res)
            {
                return std::unexpected(res.error());
            }
            tcpFd_ = *res;
            if (loop_.running())
            {
                if (auto addRes = loop_.addFd(tcpFd_, EPOLLIN | EPOLLET, &tcpFdToken_); !addRes)
                {
                    ::close(tcpFd_);
                    tcpFd_ = -1;
                    return addRes;
                }
            }
            return {};
        }

        Result<> listenUdp(const char *ip, int port, bool reuseAddr = true, bool reusePort = true)
        {
            if (udpFd_ >= 0)
            {
                return {};
            }
            auto res = net::listenUdp(ip, port, udpAddr_, reuseAddr, reusePort);
            if (!res)
            {
                return std::unexpected(res.error());
            }
            udpFd_ = *res;
            if (loop_.running())
            {
                if (auto addRes = loop_.addFd(udpFd_, EPOLLIN | EPOLLET, &udpFdToken_); !addRes)
                {
                    ::close(udpFd_);
                    udpFd_ = -1;
                    return addRes;
                }
            }
            return {};
        }

        /**
         * @brief 注册外部监听描述符（如各 Inbound::listenFd()）至当前 Reactor
         */
        Result<> addListener(int listenFd, AcceptCallback onAccept = nullptr)
        {
            if (listenFd < 0)
            {
                return std::unexpected(ERR::SOCKET_FAILED);
            }
            if (extraListeners_.contains(listenFd))
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

            extraListeners_.emplace(listenFd, listener);
            return {};
        }

        Result<> removeListener(int listenFd)
        {
            auto it = extraListeners_.find(listenFd);
            if (it == extraListeners_.end())
            {
                return {};
            }
            auto listener = it->second;
            if (listener->fd >= 0)
            {
                [[maybe_unused]] auto _ = loop_.delFd(listener->fd);
            }
            extraListeners_.erase(it);
            return {};
        }

        [[nodiscard]] inline size_t listenerCount() const noexcept
        {
            return (tcpFd_ >= 0 ? 1 : 0) + (udpFd_ >= 0 ? 1 : 0) + extraListeners_.size();
        }

        // ---- 运行核心服务 (Run Overloads) ----

        [[nodiscard]] Result<> runTcp(const char *ip, int port, const ServerConfig &server,
                                      const ReactorConfig &reactor)
        {
            if (auto err = listenTcp(ip, port, server.backlog, server.reuseAddr, server.reusePort); !err)
            {
                reset();
                return err;
            }
            Result<> rc = serve(server, reactor);
            reset();
            return rc;
        }

        [[nodiscard]] Result<> runTcp(const char *ip, int port)
        {
            const MynetConfig cfg = getMynetConfig();
            return runTcp(ip, port, cfg.server, cfg.reactor);
        }

        [[nodiscard]] Result<> runTcp()
        {
            const MynetConfig cfg = getMynetConfig();
            return runTcp(cfg.server.host.c_str(), static_cast<int>(cfg.server.port), cfg.server, cfg.reactor);
        }

        [[nodiscard]] Result<> runUdp(const char *ip, int port, const ServerConfig &server,
                                      const ReactorConfig &reactor)
        {
            if (auto err = listenUdp(ip, port, server.reuseAddr, server.reusePort); !err)
            {
                reset();
                return err;
            }
            Result<> rc = serve(server, reactor);
            reset();
            return rc;
        }

        [[nodiscard]] Result<> runUdp(const char *ip, int port)
        {
            const MynetConfig cfg = getMynetConfig();
            return runUdp(ip, port, cfg.server, cfg.reactor);
        }

        [[nodiscard]] Result<> runUdp()
        {
            const MynetConfig cfg = getMynetConfig();
            return runUdp(cfg.server.host.c_str(), static_cast<int>(cfg.server.port), cfg.server, cfg.reactor);
        }

        template <typename H>
        [[nodiscard]] Result<> runUdp(const char *ip, int port, H &handler, const ReactorConfig &reactor)
        {
            (void)handler;
            return runUdp(ip, port, getServerConfig(), reactor);
        }

        template <typename H>
        [[nodiscard]] Result<> runUdp(const char *ip, int port, H &handler)
        {
            (void)handler;
            return runUdp(ip, port);
        }

        template <typename H>
        [[nodiscard]] Result<> runUdp(H &handler)
        {
            (void)handler;
            return runUdp();
        }

        [[nodiscard]] Result<> serve(const ServerConfig &server, const ReactorConfig &reactor)
        {
            if (loop_.epollFd() < 0) [[unlikely]]
            {
                if (auto res = loop_.init(); !res)
                    return res;
            }

            maxConnections_ = server.maxConnections;
            connections_.reserve(maxConnections_);
            loop_.setEventCapacity(static_cast<size_t>(reactor.maxEvents));
            loop_.setEventCallback([this](uint32_t events, void *ptr) { onEvent(events, ptr); });

            if (tcpFd_ >= 0)
            {
                if (auto res = loop_.addFd(tcpFd_, EPOLLIN | EPOLLET, &tcpFdToken_); !res) [[unlikely]]
                {
                    LOG_ERROR("Reactor::serve: adding tcp listener fd {} failed", tcpFd_);
                    return res;
                }
            }

            if (udpFd_ >= 0)
            {
                if (auto res = loop_.addFd(udpFd_, EPOLLIN | EPOLLET, &udpFdToken_); !res) [[unlikely]]
                {
                    LOG_ERROR("Reactor::serve: adding udp listener fd {} failed", udpFd_);
                    return res;
                }
            }

            for (auto &[fd, listener] : extraListeners_)
            {
                if (listener->fd >= 0)
                {
                    if (auto res = loop_.addFd(listener->fd, EPOLLIN | EPOLLET, listener.get()); !res) [[unlikely]]
                    {
                        LOG_ERROR("Reactor::serve: adding extra listener fd {} failed", listener->fd);
                        return res;
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

        inline void runInLoop(EventLoop::Task task) { loop_.runInLoop(std::move(task)); }

        inline void runOnConnection(int fd, std::function<void(ConnectionBase &)> task)
        {
            loop_.runInLoop(
                [this, fd, task = std::move(task)]
                {
                    auto it = connections_.find(fd);
                    if (it == connections_.end() || it->second == nullptr)
                    {
                        return;
                    }
                    ConnectionBase *conn = it->second;
                    task(*conn);
                });
        }

        [[nodiscard]] inline ConnectionBase *find(int fd) noexcept
        {
            auto it = connections_.find(fd);
            return it == connections_.end() ? nullptr : it->second;
        }

        [[nodiscard]] inline size_t connectionPoolCapacity() const noexcept { return maxConnections_; }

        inline void reset() noexcept
        {
            if (idleTimerId_ != 0)
            {
                [[maybe_unused]] auto _ = loop_.cancelTimer(idleTimerId_);
                idleTimerId_ = 0;
            }

            if (tcpFd_ >= 0)
            {
                [[maybe_unused]] auto _ = loop_.delFd(tcpFd_);
                ::close(tcpFd_);
                tcpFd_ = -1;
            }
            tcpAddr_ = {};

            if (udpFd_ >= 0)
            {
                [[maybe_unused]] auto _ = loop_.delFd(udpFd_);
                ::close(udpFd_);
                udpFd_ = -1;
            }
            udpAddr_ = {};

            for (auto &[fd, listener] : extraListeners_)
            {
                if (listener->fd >= 0)
                {
                    [[maybe_unused]] auto _ = loop_.delFd(listener->fd);
                }
            }
            extraListeners_.clear();

            for (auto &[fd, conn] : connections_)
            {
                [[maybe_unused]] auto _ = loop_.delFd(fd);
                if (conn != nullptr)
                {
                    conn->close();
                    delete conn;
                }
            }
            connections_.clear();

            std::apply([](auto &...acc) { (acc.reset(), ...); }, acceptors_);
            std::apply([](auto &...dia) { (dia.reset(), ...); }, dialers_);
            loop_.setEventCallback({});
        }

    private:
        struct ExtraListener
        {
            int fd{-1};
            AcceptCallback onAccept{};
        };

        inline void onEvent(uint32_t events, void *ptr)
        {
            if (ptr == nullptr) [[unlikely]]
            {
                return;
            }

            if (ptr == &tcpFdToken_)
            {
                if (events & EPOLLIN)
                {
                    acceptAllTcp();
                }
                return;
            }

            if (ptr == &udpFdToken_)
            {
                if (events & EPOLLIN)
                {
                    drainUdp();
                }
                return;
            }

            auto itL = extraListeners_.find(*reinterpret_cast<int *>(ptr));
            if (itL != extraListeners_.end())
            {
                if (events & EPOLLIN)
                {
                    drainExtraListener(*itL->second);
                }
                return;
            }

            auto *conn = static_cast<ConnectionBase *>(ptr);
            onConnection(conn, events);
        }

        inline void acceptAllTcp()
        {
            while (true)
            {
                sockaddr_in clientAddr{};
                socklen_t len = sizeof(clientAddr);
                int clientFd =
                    ::accept4(tcpFd_, reinterpret_cast<sockaddr *>(&clientAddr), &len, SOCK_NONBLOCK | SOCK_CLOEXEC);
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
                    break;
                }

                dispatchClient(clientFd, clientAddr);
            }
        }

        inline void dispatchClient(int clientFd, const sockaddr_in &clientAddr)
        {
            ConnectionBase *conn = nullptr;

            if constexpr (sizeof...(Protocols) == 0)
            {
                ::close(clientFd);
                return;
            }
            else if constexpr (sizeof...(Protocols) == 1)
            {
                // 单协议编译期直通：0 嗅探，0 分支开销
                auto status = std::get<0>(acceptors_).handshake(clientFd, conn);
                if (status == HandshakeStatus::FAILED || conn == nullptr)
                {
                    ::close(clientFd);
                    return;
                }
            }
            else
            {
                // 多协议首包特征极速嗅探（纳秒级）
                uint8_t peekBuf[16]{};
                ssize_t n = ::recv(clientFd, peekBuf, sizeof(peekBuf), MSG_PEEK);
                std::span<const uint8_t> bytes(peekBuf, n > 0 ? static_cast<size_t>(n) : 0);

                IAcceptor *matched = nullptr;
                std::apply([&](auto &...acc) { ((acc.match(bytes) ? (matched = &acc, true) : false) || ...); },
                           acceptors_);

                if (matched == nullptr)
                {
                    matched = &std::get<0>(acceptors_);
                }

                auto status = matched->handshake(clientFd, conn);
                if (status == HandshakeStatus::FAILED || conn == nullptr)
                {
                    ::close(clientFd);
                    return;
                }
            }

            conn->setFd(clientFd);
            conn->setPeerAddr(clientAddr);
            conn->setTransport(TransportType::TCP);
            connections_[clientFd] = conn;

            if (auto res = loop_.addFd(clientFd, EPOLLIN | EPOLLOUT | EPOLLET, conn); !res)
            {
                closeConn(conn);
            }
        }

        inline void drainUdp()
        {
            // UDP 数据报统一摄入处理
            uint8_t buf[65536];
            while (true)
            {
                sockaddr_in peer{};
                socklen_t len = sizeof(peer);
                ssize_t n = ::recvfrom(udpFd_, buf, sizeof(buf), 0, reinterpret_cast<sockaddr *>(&peer), &len);
                if (n < 0)
                {
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                        break;
                    if (errno == EINTR)
                        continue;
                    break;
                }

                // 分发给首个支持 UDP 或匹配的 Acceptor
                if constexpr (sizeof...(Protocols) > 0)
                {
                    ConnectionBase *conn = nullptr;
                    std::span<const uint8_t> bytes(buf, static_cast<size_t>(n));
                    IAcceptor *matched = nullptr;
                    std::apply([&](auto &...acc) { ((acc.match(bytes) ? (matched = &acc, true) : false) || ...); },
                               acceptors_);
                    if (matched == nullptr)
                    {
                        matched = &std::get<0>(acceptors_);
                    }
                    matched->handshake(udpFd_, conn);
                }
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
                        break;
                    if (errno == EINTR)
                        continue;
                    break;
                }

                if (listener.onAccept)
                {
                    listener.onAccept(clientFd, addr);
                }
                else
                {
                    dispatchClient(clientFd, addr);
                }
            }
        }

        inline void onConnection(ConnectionBase *conn, uint32_t events)
        {
            if (conn == nullptr || conn->fd() < 0) [[unlikely]]
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
                conn->handle();
            }

            if (events & EPOLLOUT)
            {
                if (conn->handleWrite() == IO_STATUS::CLOSE) [[unlikely]]
                {
                    closeConn(conn);
                    return;
                }
                conn->handle();
            }
        }

        inline void closeConn(ConnectionBase *conn)
        {
            if (conn == nullptr)
                return;
            const int fd = conn->fd();
            if (fd >= 0)
            {
                [[maybe_unused]] auto _ = loop_.delFd(fd);
                connections_.erase(fd);
            }
            conn->close();
            delete conn;
        }

        inline void sweepIdle()
        {
            // 空闲连接清理
        }

        int tcpFd_{-1};
        sockaddr_in tcpAddr_{};
        int tcpFdToken_{0};

        int udpFd_{-1};
        sockaddr_in udpAddr_{};
        int udpFdToken_{1};

        std::tuple<typename ProtocolTraits<Protocols>::Acceptor...> acceptors_{};
        std::tuple<typename ProtocolTraits<Protocols>::Dialer...> dialers_{};
        std::unordered_map<int, ConnectionBase *> connections_{};
        size_t maxConnections_{1024};
        std::unordered_map<int, std::shared_ptr<ExtraListener>> extraListeners_{};

        EventLoop loop_{};
        std::chrono::seconds idleTimeout_{0};
        uint64_t idleTimerId_{0};
    };

} // namespace mynet
