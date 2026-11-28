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
#include "listener.hpp"
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
#include <unordered_set>
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
        static auto resolveAcceptor()
        {
            if constexpr (std::derived_from<U, mynet::Acceptor>)
            {
                return std::type_identity<U>{};
            }
            else if constexpr (std::derived_from<U, mynet::Handler>)
            {
                return std::type_identity<TypedAcceptor<U>>{};
            }
            else if constexpr (requires { typename U::Acceptor; })
            {
                return std::type_identity<typename U::Acceptor>{};
            }
            else
            {
                return std::type_identity<TypedAcceptor<U>>{};
            }
        }

        template <typename U>
        static auto checkDialer(int) -> typename U::Dialer;
        template <typename U>
        static auto checkDialer(...) -> DialerBase<EmptyOutbound>;

        template <typename U>
        static auto checkConnection(int) -> typename U::Connection;
        template <typename U>
        static auto checkConnection(...) -> Connection;

    public:
        using Acceptor = typename decltype(resolveAcceptor<T>())::type;
        using Dialer = decltype(checkDialer<T>(0));
        using Connection = decltype(checkConnection<T>(0));
    };

    /**
     * @brief 协议传输类型自动探测萃取器 (TCP / UDP)
     */
    template <typename T>
    struct ProtocolTransportDetector
    {
    private:
        using Acc = typename ProtocolTraits<T>::Acceptor;

        template <typename U>
        static auto checkInbound(int) -> typename U::Inbound;
        template <typename U>
        static auto checkInbound(...) -> void;

        using Inb = decltype(checkInbound<Acc>(0));

        template <typename U>
        static constexpr bool checkUdpMember(int)
            requires requires {
                { U::transport } -> std::convertible_to<TransportType>;
            }
        {
            return U::transport == TransportType::UDP;
        }
        template <typename U>
        static constexpr bool checkUdpMember(...)
        {
            return false;
        }

        template <typename U>
        static constexpr bool checkTcpMember(int)
            requires requires {
                { U::transport } -> std::convertible_to<TransportType>;
            }
        {
            return U::transport == TransportType::TCP;
        }
        template <typename U>
        static constexpr bool checkTcpMember(...)
        {
            return false;
        }

    public:
        static constexpr bool is_empty_inbound =
            std::is_same_v<T, EmptyInbound> || (!std::is_void_v<Inb> && std::is_same_v<Inb, EmptyInbound>);

        static constexpr bool is_udp = is_empty_inbound || checkUdpMember<T>(0) || checkUdpMember<Acc>(0) ||
                                       (!std::is_void_v<Inb> && checkUdpMember<Inb>(0));
        static constexpr bool is_tcp = is_empty_inbound || checkTcpMember<T>(0) || checkTcpMember<Acc>(0) ||
                                       (!std::is_void_v<Inb> && checkTcpMember<Inb>(0)) || !is_udp;
    };

    template <typename Acc, typename T>
    struct InboundExtractor
    {
    private:
        template <typename U>
        static auto check(int) -> typename U::Inbound;
        template <typename U>
        static auto check(...) -> void;

        using InbAcc = decltype(check<Acc>(0));
        using InbT = decltype(check<T>(0));

    public:
        using type =
            std::conditional_t<!std::is_void_v<InbAcc>, InbAcc, std::conditional_t<!std::is_void_v<InbT>, InbT, T>>;
    };

    /**
     * @brief 编译期从单一协议萃取 ListenerConfig
     */
    template <typename T>
    consteval ListenerConfig extractListenerConfig()
    {
        using Acc = typename ProtocolTraits<T>::Acceptor;
        using Inb = typename InboundExtractor<Acc, T>::type;

        TransportType trans = TransportType::TCP;
        if constexpr (requires {
                          { T::transport } -> std::convertible_to<TransportType>;
                      })
        {
            trans = static_cast<TransportType>(T::transport);
        }
        else if constexpr (requires {
                               { Acc::transport } -> std::convertible_to<TransportType>;
                           })
        {
            trans = static_cast<TransportType>(Acc::transport);
        }
        else if constexpr (requires {
                               { Inb::transport } -> std::convertible_to<TransportType>;
                           })
        {
            trans = static_cast<TransportType>(Inb::transport);
        }
        else
        {
            trans = ProtocolTransportDetector<T>::is_udp ? TransportType::UDP : TransportType::TCP;
        }

        uint16_t port = 0;
        if constexpr (requires {
                          { T::default_port } -> std::convertible_to<uint16_t>;
                      })
        {
            port = static_cast<uint16_t>(T::default_port);
        }
        else if constexpr (requires {
                               { T::port } -> std::convertible_to<uint16_t>;
                           })
        {
            port = static_cast<uint16_t>(T::port);
        }
        else if constexpr (requires {
                               { Acc::default_port } -> std::convertible_to<uint16_t>;
                           })
        {
            port = static_cast<uint16_t>(Acc::default_port);
        }
        else if constexpr (requires {
                               { Acc::port } -> std::convertible_to<uint16_t>;
                           })
        {
            port = static_cast<uint16_t>(Acc::port);
        }
        else if constexpr (requires {
                               { Inb::default_port } -> std::convertible_to<uint16_t>;
                           })
        {
            port = static_cast<uint16_t>(Inb::default_port);
        }
        else if constexpr (requires {
                               { Inb::port } -> std::convertible_to<uint16_t>;
                           })
        {
            port = static_cast<uint16_t>(Inb::port);
        }

        size_t tag = 0;
        if constexpr (requires {
                          { T::listener_tag } -> std::convertible_to<size_t>;
                      })
        {
            tag = static_cast<size_t>(T::listener_tag);
        }
        else if constexpr (requires {
                               { Acc::listener_tag } -> std::convertible_to<size_t>;
                           })
        {
            tag = static_cast<size_t>(Acc::listener_tag);
        }
        else if constexpr (requires {
                               { Inb::listener_tag } -> std::convertible_to<size_t>;
                           })
        {
            tag = static_cast<size_t>(Inb::listener_tag);
        }

        return ListenerConfig{trans, port, tag};
    }

    /**
     * @brief 编译期精准计算唯一定义的监听器数量 K (K <= N)
     */
    template <typename... Protocols>
    consteval size_t countUniqueListeners()
    {
        constexpr size_t N = sizeof...(Protocols);
        if constexpr (N == 0)
        {
            return 1;
        }
        else
        {
            constexpr std::array<ListenerConfig, N> raw = {extractListenerConfig<Protocols>()...};
            size_t count = 0;
            for (size_t i = 0; i < N; ++i)
            {
                bool exists = false;
                for (size_t j = 0; j < i; ++j)
                {
                    if (raw[j] == raw[i])
                    {
                        exists = true;
                        break;
                    }
                }
                if (!exists)
                {
                    ++count;
                }
            }
            return count == 0 ? 1 : count;
        }
    }

    /**
     * @brief 编译期生成唯一定义的监听器规格列表 std::array<ListenerConfig, K>
     */
    template <typename... Protocols>
    consteval auto getUniqueListeners()
    {
        constexpr size_t K = countUniqueListeners<Protocols...>();
        constexpr size_t N = sizeof...(Protocols);
        std::array<ListenerConfig, K> result{};
        if constexpr (N == 0)
        {
            result[0] = ListenerConfig{TransportType::TCP, 0, 0};
            return result;
        }
        else
        {
            constexpr std::array<ListenerConfig, N> raw = {extractListenerConfig<Protocols>()...};
            size_t idx = 0;
            for (size_t i = 0; i < N; ++i)
            {
                bool exists = false;
                for (size_t j = 0; j < i; ++j)
                {
                    if (raw[j] == raw[i])
                    {
                        exists = true;
                        break;
                    }
                }
                if (!exists)
                {
                    result[idx++] = raw[i];
                }
            }
            return result;
        }
    }

    /**
     * @brief 编译期查询指定协议索引所绑定的 Listener 下标 (0 <= idx < K)
     */
    template <size_t ProtocolIdx, typename... Protocols>
    consteval size_t getListenerIndexForProtocol()
    {
        constexpr size_t K = countUniqueListeners<Protocols...>();
        constexpr auto uniqueConfigs = getUniqueListeners<Protocols...>();
        constexpr size_t N = sizeof...(Protocols);
        if constexpr (N == 0)
        {
            return 0;
        }
        else
        {
            constexpr std::array<ListenerConfig, N> raw = {extractListenerConfig<Protocols>()...};
            static_assert(ProtocolIdx < N, "ProtocolIdx out of range");
            constexpr ListenerConfig target = raw[ProtocolIdx];
            for (size_t k = 0; k < K; ++k)
            {
                if (uniqueConfigs[k] == target)
                {
                    return k;
                }
            }
            return 0;
        }
    }

    namespace detail
    {
        template <size_t... Is, typename TupleT>
        inline void dispatchProtocolTcpClientImpl(int clientFd, Connection *&conn, size_t listenerIdx,
                                                  const std::array<size_t, sizeof...(Is)> &listenerIndices,
                                                  TupleT &acceptors, std::index_sequence<Is...>)
        {
            auto dispatchAcc = [&](auto &acc)
            {
                [[maybe_unused]] auto _ = acc.acceptConnection(clientFd, conn);
            };

            size_t matchedCount = 0;
            for (size_t idx : listenerIndices)
            {
                if (idx == listenerIdx)
                    ++matchedCount;
            }

            if (matchedCount == 1)
            {
                ((listenerIndices[Is] == listenerIdx ? (dispatchAcc(std::get<Is>(acceptors)), true) : false) || ...);
            }
            else if (matchedCount > 1)
            {
                uint8_t peekBuf[16]{};
                ssize_t n = ::recv(clientFd, peekBuf, sizeof(peekBuf), MSG_PEEK);
                std::span<const uint8_t> bytes(peekBuf, n > 0 ? static_cast<size_t>(n) : 0);

                bool dispatched = false;
                (((listenerIndices[Is] == listenerIdx && std::get<Is>(acceptors).match(bytes))
                      ? (dispatchAcc(std::get<Is>(acceptors)), dispatched = true)
                      : false) ||
                 ...);

                if (!dispatched)
                {
                    ((listenerIndices[Is] == listenerIdx ? (dispatchAcc(std::get<Is>(acceptors)), true) : false) ||
                     ...);
                }
            }
        }

        template <typename... Protocols, typename TupleT>
        inline void dispatchProtocolTcpClient(int clientFd, Connection *&conn, size_t listenerIdx, TupleT &acceptors)
        {
            if constexpr (sizeof...(Protocols) > 0)
            {
                [&]<size_t... Is>(std::index_sequence<Is...> seq)
                {
                    constexpr auto listenerIndices = std::array<size_t, sizeof...(Protocols)>{
                        getListenerIndexForProtocol<Is, Protocols...>()...};
                    dispatchProtocolTcpClientImpl(clientFd, conn, listenerIdx, listenerIndices, acceptors, seq);
                }(std::make_index_sequence<sizeof...(Protocols)>{});
            }
        }

        template <typename... Protocols, typename TupleT, typename HandlerArrayT>
        inline void drainProtocolUdp(Listener &listener, size_t listenerIdx, Handler *externalUdpHandler,
                                     HandlerArrayT &udpHandlers, TupleT &acceptors)
        {
            const int udpFd = listener.fd();
            if (udpFd < 0)
            {
                return;
            }
            Datagram dgram(udpFd, /*ownsFd=*/false);
            (void)dgram.drain(
                [&](const DatagramView &view)
                {
                    auto resolveHandler = [&](std::span<const uint8_t> bytes) -> Handler *
                    {
                        if (externalUdpHandler != nullptr)
                        {
                            return externalUdpHandler;
                        }
                        if constexpr (sizeof...(Protocols) > 0)
                        {
                            Handler *selected = nullptr;
                            [&]<size_t... Is>(std::index_sequence<Is...>)
                            {
                                constexpr auto listenerIndices = std::array<size_t, sizeof...(Protocols)>{
                                    getListenerIndexForProtocol<Is, Protocols...>()...};

                                size_t matchedIdx = sizeof...(Protocols);
                                (((listenerIndices[Is] == listenerIdx && std::get<Is>(acceptors).match(bytes))
                                      ? (matchedIdx = Is, true)
                                      : false) ||
                                 ...);

                                if (matchedIdx == sizeof...(Protocols))
                                {
                                    ((listenerIndices[Is] == listenerIdx ? (matchedIdx = Is, true) : false) || ...);
                                }

                                if (matchedIdx < sizeof...(Protocols))
                                {
                                    auto pickSlot = [&](auto &acc, size_t idx)
                                    {
                                        if (udpHandlers[idx] == nullptr)
                                        {
                                            udpHandlers[idx] = acc.buildConfiguredHandler();
                                            if (udpHandlers[idx] != nullptr)
                                            {
                                                udpHandlers[idx]->onConnect(udpFd);
                                            }
                                        }
                                        if (udpHandlers[idx] != nullptr)
                                        {
                                            selected = udpHandlers[idx].get();
                                        }
                                    };
                                    ((Is == matchedIdx ? (pickSlot(std::get<Is>(acceptors), Is), true) : false) || ...);
                                }
                            }(std::make_index_sequence<sizeof...(Protocols)>{});
                            return selected;
                        }
                        return nullptr;
                    };

                    if (Handler *h = resolveHandler(view.payload); h != nullptr)
                    {
                        h->onDatagram(view.peer, reinterpret_cast<const char *>(view.payload.data()),
                                      view.payload.size());
                        h->drive();
                        if (h->hasOutgoing())
                        {
                            auto batch = h->takeAllOutgoing();
                            dgram.sendPackets(batch, view.peer);
                        }
                    }
                });
        }
    } // namespace detail

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
        using WatchCallback = std::function<void(uint32_t events)>;

    private:
        struct WatchEntry
        {
            int fd{-1};
            WatchCallback cb{};
            bool removed{false};
        };

    public:

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
            watches_.clear();
            watchPtrs_.clear();
            deferredDeleteWatches_.clear();
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

        [[nodiscard]] inline bool addWatch(int fd, uint32_t events, WatchCallback cb)
        {
            if (fd < 0 || epollFd_ < 0 || !cb) [[unlikely]]
            {
                return false;
            }
            if (watches_.contains(fd))
            {
                delWatch(fd);
            }
            auto entry = std::make_unique<WatchEntry>(WatchEntry{fd, std::move(cb), false});
            WatchEntry *raw = entry.get();
            if (auto res = addFd(fd, events, raw); !res)
            {
                return false;
            }
            watchPtrs_.insert(raw);
            watches_[fd] = std::move(entry);
            return true;
        }

        [[nodiscard]] inline bool modWatch(int fd, uint32_t events) noexcept
        {
            auto it = watches_.find(fd);
            if (it == watches_.end() || it->second == nullptr || it->second->removed)
            {
                return false;
            }
            return static_cast<bool>(modFd(fd, events, it->second.get()));
        }

        inline void delWatch(int fd)
        {
            auto it = watches_.find(fd);
            if (it == watches_.end())
            {
                return;
            }
            [[maybe_unused]] auto _ = delFd(fd);
            WatchEntry *raw = it->second.get();
            watchPtrs_.erase(raw);
            raw->removed = true;
            if (dispatchingWatches_)
            {
                deferredDeleteWatches_.push_back(std::move(it->second));
            }
            watches_.erase(it);
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

                dispatchingWatches_ = true;
                for (int i = 0; i < n; ++i)
                {
                    if (events_[i].data.u64 == kWakeToken)
                    {
                        drainWakeup();
                        continue;
                    }
                    if (!watchPtrs_.empty() && watchPtrs_.contains(events_[i].data.ptr))
                    {
                        auto *w = static_cast<WatchEntry *>(events_[i].data.ptr);
                        if (!w->removed && w->cb)
                        {
                            w->cb(events_[i].events);
                        }
                        continue;
                    }
                    if (eventCallback_)
                    {
                        eventCallback_(events_[i].events, events_[i].data.ptr);
                    }
                }
                dispatchingWatches_ = false;
                deferredDeleteWatches_.clear();

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
        std::unordered_map<int, std::unique_ptr<WatchEntry>> watches_{};
        std::unordered_set<void *> watchPtrs_{};
        std::vector<std::unique_ptr<WatchEntry>> deferredDeleteWatches_{};
        bool dispatchingWatches_{false};
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
        static constexpr size_t kProtocolCount = sizeof...(Protocols);
        static constexpr size_t kListenerCount = countUniqueListeners<Protocols...>();
        static constexpr auto kListenerConfigs = getUniqueListeners<Protocols...>();

        static constexpr bool kHasTcp = []() consteval
        {
            for (const auto &c : kListenerConfigs)
            {
                if (c.transport == TransportType::TCP)
                    return true;
            }
            return false;
        }();

        static constexpr bool kHasUdp = []() consteval
        {
            for (const auto &c : kListenerConfigs)
            {
                if (c.transport == TransportType::UDP)
                    return true;
            }
            return false;
        }();

        Reactor()
        {
            for (size_t i = 0; i < kListenerCount; ++i)
            {
                listeners_[i].transport = kListenerConfigs[i].transport;
                listeners_[i].configuredPort = kListenerConfigs[i].defaultPort;
                listeners_[i].token = static_cast<int>(i);
            }
        }
        ~Reactor() noexcept { reset(); }

        Reactor(const Reactor &) = delete;
        Reactor &operator=(const Reactor &) = delete;

        [[nodiscard]] inline EventLoop &loop() noexcept { return loop_; }
        [[nodiscard]] inline size_t connections() const noexcept { return connections_.size(); }

        inline void stop() noexcept { loop_.quit(); }
        inline void quit() noexcept { loop_.quit(); }

        [[nodiscard]] inline int tcpFd() const noexcept
        {
            for (const auto &l : listeners_)
            {
                if (l.isTcp() && l.valid())
                    return l.fd();
            }
            return -1;
        }
        [[nodiscard]] inline int udpFd() const noexcept
        {
            for (const auto &l : listeners_)
            {
                if (l.isUdp() && l.valid())
                    return l.fd();
            }
            return -1;
        }
        [[nodiscard]] inline const sockaddr_in &tcpAddr() const noexcept
        {
            for (const auto &l : listeners_)
            {
                if (l.isTcp() && l.valid())
                    return l.addr();
            }
            static constexpr sockaddr_in empty{};
            return empty;
        }
        [[nodiscard]] inline const sockaddr_in &udpAddr() const noexcept
        {
            for (const auto &l : listeners_)
            {
                if (l.isUdp() && l.valid())
                    return l.addr();
            }
            static constexpr sockaddr_in empty{};
            return empty;
        }

        template <size_t I = 0>
        [[nodiscard]] inline Listener &listener() noexcept
        {
            static_assert(I < kListenerCount, "Listener index out of bounds");
            return listeners_[I];
        }

        template <size_t I = 0>
        [[nodiscard]] inline const Listener &listener() const noexcept
        {
            static_assert(I < kListenerCount, "Listener index out of bounds");
            return listeners_[I];
        }

        [[nodiscard]] inline auto &listeners() noexcept { return listeners_; }
        [[nodiscard]] inline const auto &listeners() const noexcept { return listeners_; }

        [[nodiscard]] inline size_t listenerCount() const noexcept
        {
            size_t count = 0;
            for (const auto &l : listeners_)
            {
                if (l.valid())
                    ++count;
            }
            return count;
        }

        [[nodiscard]] constexpr size_t listenerCapacity() const noexcept { return kListenerCount; }

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
            if constexpr (!kHasTcp)
            {
                return std::unexpected(ERR::SOCKET_FAILED);
            }
            else
            {
                for (size_t i = 0; i < kListenerCount; ++i)
                {
                    if (listeners_[i].isTcp())
                    {
                        if (listeners_[i].valid())
                        {
                            return {};
                        }
                        auto res = listeners_[i].listen(ip, port, backlog, reuseAddr, reusePort);
                        if (!res)
                        {
                            return std::unexpected(res.error());
                        }
                        if (loop_.running())
                        {
                            if (auto addRes = loop_.addFd(listeners_[i].fd(), EPOLLIN | EPOLLET, &listeners_[i]);
                                !addRes)
                            {
                                listeners_[i].reset();
                                return addRes;
                            }
                        }
                        return {};
                    }
                }
                return std::unexpected(ERR::SOCKET_FAILED);
            }
        }

        Result<> listenUdp(const char *ip, int port, bool reuseAddr = true, bool reusePort = true)
        {
            if constexpr (!kHasUdp)
            {
                return std::unexpected(ERR::SOCKET_FAILED);
            }
            else
            {
                for (size_t i = 0; i < kListenerCount; ++i)
                {
                    if (listeners_[i].isUdp())
                    {
                        if (listeners_[i].valid())
                        {
                            return {};
                        }
                        auto res = listeners_[i].listen(ip, port, 128, reuseAddr, reusePort);
                        if (!res)
                        {
                            return std::unexpected(res.error());
                        }
                        if (loop_.running())
                        {
                            if (auto addRes = loop_.addFd(listeners_[i].fd(), EPOLLIN | EPOLLET, &listeners_[i]);
                                !addRes)
                            {
                                listeners_[i].reset();
                                return addRes;
                            }
                        }
                        return {};
                    }
                }
                return std::unexpected(ERR::SOCKET_FAILED);
            }
        }

        template <size_t I>
        Result<> listen(const char *ip, int port = 0, int backlog = 128, bool reuseAddr = true, bool reusePort = true)
        {
            static_assert(I < kListenerCount, "Listener index out of bounds");
            if (listeners_[I].valid())
            {
                return {};
            }
            auto res = listeners_[I].listen(ip, port, backlog, reuseAddr, reusePort);
            if (!res)
            {
                return std::unexpected(res.error());
            }
            if (loop_.running())
            {
                if (auto addRes = loop_.addFd(listeners_[I].fd(), EPOLLIN | EPOLLET, &listeners_[I]); !addRes)
                {
                    listeners_[I].reset();
                    return addRes;
                }
            }
            return {};
        }

        // ---- 运行核心服务 (Run Overloads) ----

        [[nodiscard]] Result<> runTcp(const char *ip, int port, const ServerConfig &server,
                                      const ReactorConfig &reactor)
        {
            if constexpr (!kHasTcp)
            {
                LOG_ERROR("Reactor::runTcp: this Reactor has no TCP protocols configured");
                return std::unexpected(ERR::SOCKET_FAILED);
            }
            else
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
            if constexpr (!kHasUdp)
            {
                LOG_ERROR("Reactor::runUdp: this Reactor has no UDP protocols configured");
                return std::unexpected(ERR::SOCKET_FAILED);
            }
            else
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
            struct UdpHandlerGuard
            {
                Handler *&slot;
                explicit UdpHandlerGuard(Handler *&s, Handler *h) noexcept : slot(s) { slot = h; }
                ~UdpHandlerGuard() noexcept { slot = nullptr; }
            } guard(externalUdpHandler_, &handler);
            return runUdp(ip, port, getServerConfig(), reactor);
        }

        template <typename H>
        [[nodiscard]] Result<> runUdp(const char *ip, int port, H &handler)
        {
            return runUdp(ip, port, handler, getReactorConfig());
        }

        template <typename H>
        [[nodiscard]] Result<> runUdp(H &handler)
        {
            const MynetConfig cfg = getMynetConfig();
            return runUdp(cfg.server.host.c_str(), static_cast<int>(cfg.server.port), handler, cfg.reactor);
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

            for (size_t i = 0; i < kListenerCount; ++i)
            {
                if (listeners_[i].valid())
                {
                    if (auto res = loop_.addFd(listeners_[i].fd(), EPOLLIN | EPOLLET, &listeners_[i]); !res)
                        [[unlikely]]
                    {
                        LOG_ERROR("Reactor::serve: adding listener fd {} failed", listeners_[i].fd());
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

        inline void runOnConnection(int fd, std::function<void(Connection &)> task)
        {
            loop_.runInLoop(
                [this, fd, task = std::move(task)]
                {
                    auto it = connections_.find(fd);
                    if (it == connections_.end() || it->second == nullptr)
                    {
                        return;
                    }
                    Connection *conn = it->second;
                    task(*conn);
                });
        }

        [[nodiscard]] inline Connection *find(int fd) noexcept
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

            for (auto &l : listeners_)
            {
                if (l.valid())
                {
                    [[maybe_unused]] auto _ = loop_.delFd(l.fd());
                    l.reset();
                }
            }

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
            for (auto &uh : udpHandlers_)
            {
                uh.reset();
            }
            externalUdpHandler_ = nullptr;
            loop_.setEventCallback({});
        }

        /**
         * @brief 将外部 Acceptor（如 TProxy / 多端口入站）创建的 Connection 纳入 Reactor 事件循环托管
         */
        inline bool adoptConnection(Connection *conn)
        {
            if (conn == nullptr || conn->fd() < 0) [[unlikely]]
            {
                return false;
            }
            const int clientFd = conn->fd();
            connections_[clientFd] = conn;
            uint32_t evMask = EPOLLIN | EPOLLOUT | EPOLLET;
#ifdef EPOLLRDHUP
            evMask |= EPOLLRDHUP;
#endif
            if (auto res = loop_.addFd(clientFd, evMask, conn); !res)
            {
                closeConn(conn);
                return false;
            }
            return true;
        }

    private:
        inline void onEvent(uint32_t events, void *ptr)
        {
            if (ptr == nullptr) [[unlikely]]
            {
                return;
            }

            auto *lptr = static_cast<Listener *>(ptr);
            if (lptr >= listeners_.data() && lptr < listeners_.data() + kListenerCount)
            {
                size_t listenerIdx = static_cast<size_t>(lptr - listeners_.data());
                if (events & EPOLLIN)
                {
                    if (lptr->isTcp())
                    {
                        acceptAllTcp(*lptr, listenerIdx);
                    }
                    else
                    {
                        drainUdp(*lptr, listenerIdx);
                    }
                }
                return;
            }

            auto *conn = static_cast<Connection *>(ptr);
            onConnection(conn, events);
        }

        inline void acceptAllTcp(Listener &listener, size_t listenerIdx)
        {
            while (true)
            {
                sockaddr_in clientAddr{};
                socklen_t len = sizeof(clientAddr);
                int clientFd = ::accept4(listener.fd(), reinterpret_cast<sockaddr *>(&clientAddr), &len,
                                         SOCK_NONBLOCK | SOCK_CLOEXEC);
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

                LOG_INFO("Reactor: acceptAllTcp fd {} on listenerIdx {}", clientFd, listenerIdx);
                dispatchClient(clientFd, clientAddr, listenerIdx);
            }
        }

        inline void dispatchClient(int clientFd, const sockaddr_in &clientAddr, size_t listenerIdx)
        {
            Connection *conn = nullptr;

            if constexpr (sizeof...(Protocols) == 0)
            {
                ::close(clientFd);
                return;
            }
            else
            {
                dispatchClientToAcceptors(clientFd, conn, listenerIdx);
                if (conn == nullptr)
                {
                    LOG_WARN("Reactor: dispatchClientToAcceptors left conn == nullptr for fd {}", clientFd);
                    conn = new Connection();
                }
                else
                {
                    LOG_INFO("Reactor: dispatchClientToAcceptors created conn for fd {} with handler {}", clientFd, (void*)conn->handler());
                }
            }

            conn->setFd(clientFd);
            conn->setPeerAddr(clientAddr);
            conn->setTransport(TransportType::TCP);
            connections_[clientFd] = conn;

            uint32_t evMask = EPOLLIN | EPOLLOUT | EPOLLET;
#ifdef EPOLLRDHUP
            evMask |= EPOLLRDHUP;
#endif
            if (auto res = loop_.addFd(clientFd, evMask, conn); !res)
            {
                closeConn(conn);
            }
        }

        inline void dispatchClientToAcceptors(int clientFd, Connection *&conn, size_t listenerIdx)
        {
            detail::dispatchProtocolTcpClient<Protocols...>(clientFd, conn, listenerIdx, acceptors_);
        }

        inline void drainUdp(Listener &listener, size_t listenerIdx)
        {
            detail::drainProtocolUdp<Protocols...>(listener, listenerIdx, externalUdpHandler_, udpHandlers_, acceptors_);
        }

        inline void onConnection(Connection *conn, uint32_t events)
        {
            if (conn == nullptr || conn->fd() < 0) [[unlikely]]
            {
                return;
            }

            if (auto extRes = conn->tryHandleExternalIo(events); extRes.has_value())
            {
                if (*extRes == IO_STATUS::CLOSE) [[unlikely]]
                {
                    closeConn(conn);
                }
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

        inline void closeConn(Connection *conn)
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
            if (idleTimeout_.count() <= 0 || connections_.empty())
            {
                return;
            }
            const auto now = std::chrono::steady_clock::now();
            std::vector<Connection *> expired;
            for (const auto &[fd, conn] : connections_)
            {
                if (conn != nullptr && (now - conn->lastActive()) > idleTimeout_)
                {
                    expired.push_back(conn);
                }
            }
            for (Connection *conn : expired)
            {
                closeConn(conn);
            }
        }

        std::array<Listener, kListenerCount> listeners_{};

        std::tuple<typename ProtocolTraits<Protocols>::Acceptor...> acceptors_{};
        std::tuple<typename ProtocolTraits<Protocols>::Dialer...> dialers_{};
        std::array<std::unique_ptr<Handler>, (kProtocolCount > 0 ? kProtocolCount : 1)> udpHandlers_{};
        Handler *externalUdpHandler_{nullptr};
        std::unordered_map<int, Connection *> connections_{};
        size_t maxConnections_{1024};

        EventLoop loop_{};
        std::chrono::seconds idleTimeout_{0};
        uint64_t idleTimerId_{0};
    };

} // namespace mynet
