#pragma once

#if defined(MYNET_ENABLE_URING)

/**
 * @file proactor.hpp
 * @brief 基于 Linux io_uring 的高性能前摄器（Proactor）引擎实现。
 *
 * 与 Reactor 对齐且全面释放 io_uring 异步完成态能力：
 * 1. 多协议 Listener 去重与共用 dispatchProtocolTcpClient / drainProtocolUdp；
 * 2. 提供对等 LoopAdapter (proactor.loop())：基于 IORING_OP_POLL_ADD 实现 addWatch / modWatch / delWatch，
 *    基于 eventfd 实现跨线程 runInLoop / queueInLoop，复用 TimerQueue + io_uring_wait_cqe_timeout 驱动定时器；
 * 3. 原生出站异步完成引擎：为 ForwarderStreamSession 直接下发 io_uring_prep_connect / io_uring_prep_recv /
 *    io_uring_prep_send 与双向 io_uring_prep_splice 内核零拷贝，实现单线程 0 轮询端到端异步转发。
 */

#include "acceptor.hpp"
#include "config/log.hpp"
#include "configHolder.hpp"
#include "connection.hpp"
#include "dialer.hpp"
#include "error.hpp"
#include "forwarder.hpp"
#include "listener.hpp"
#include "reactor.hpp"
#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <functional>
#include <liburing.h>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <poll.h>
#include <span>
#include <stop_token>
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

    namespace detail
    {
        [[nodiscard]] constexpr unsigned epollToPollMask(uint32_t events) noexcept
        {
            unsigned mask = 0;
            if (events & EPOLLIN)
                mask |= POLLIN;
            if (events & EPOLLOUT)
                mask |= POLLOUT;
            if (events & EPOLLERR)
                mask |= POLLERR;
            if (events & EPOLLHUP)
                mask |= POLLHUP;
            if (events & EPOLLRDHUP)
                mask |= POLLRDHUP;
            if (mask == 0)
                mask = POLLIN;
            return mask;
        }

        [[nodiscard]] constexpr uint32_t pollToEpollMask(int revents) noexcept
        {
            uint32_t ev = 0;
            if (revents & POLLIN)
                ev |= EPOLLIN;
            if (revents & POLLOUT)
                ev |= EPOLLOUT;
            if (revents & POLLERR)
                ev |= EPOLLERR;
            if (revents & POLLHUP)
                ev |= EPOLLHUP;
            if (revents & POLLRDHUP)
                ev |= EPOLLRDHUP;
            return ev;
        }

        /**
         * @brief Proactor 与协议包无关的底层 io_uring 事件环、Watch 表与异步出站中继核
         */
        class ProactorCore
        {
        public:
            using Task = std::function<void()>;
            using TimerCallback = TimerQueue::Callback;
            using WatchCallback = std::function<void(uint32_t events)>;

            enum class OpKind : uint8_t
            {
                WAKE = 1,
                ACCEPT = 2,
                UDP_POLL = 3,
                RECV = 4,
                SEND = 5,
                WATCH_POLL = 6,
                ASYNC_CONNECT = 7,
                FWD_OUT_CONNECT = 8,
                FWD_OUT_POLL_CONNECT = 9,
                FWD_OUT_RECV = 10,
                FWD_OUT_SEND = 11,
                FWD_SPLICE_POLL_IN = 12,
                FWD_SPLICE_IN = 13,
                FWD_SPLICE_POLL_OUT = 14,
                FWD_SPLICE_OUT = 15,
                FWD_SOCKMAP_POLL = 16
            };

            struct WatchEntry
            {
                int fd{-1};
                uint32_t epollEvents{0};
                unsigned pollMask{0};
                WatchCallback cb{};
                bool removed{false};
                bool armed{false};
                uint64_t activeUid{0};
            };

            struct ConnTrack
            {
                bool recvActive{false};
                bool sendActive{false};
                bool closing{false};
            };

            struct SpliceDirTrack
            {
                bool pollIn{false};
                bool inPipe{false};
                bool pollOut{false};
                bool outPipe{false};
                size_t pipePending{0};
                uint64_t pollInUid{0};
                uint64_t pollOutUid{0};
                bool eofReached{false};
            };

            struct SessionTrack
            {
                std::shared_ptr<ForwarderStreamSession> session{};
                int inboundFd{-1};
                int outboundFd{-1};
                bool ownsOutboundFd{false};
                bool connectActive{false};
                bool outRecvActive{false};
                bool outSendActive{false};
                bool sockmapInPollActive{false};
                bool sockmapOutPollActive{false};
                uint64_t sockmapInPollUid{0};
                uint64_t sockmapOutPollUid{0};
                bool outboundShutWrSent{false};
                bool inboundShutWrSent{false};
                bool closing{false};
                uint32_t pendingOps{0};
                std::array<SpliceDirTrack, 2> spliceDirs{};
                std::vector<char> outRecvBuf{};
            };

            struct PendingOp
            {
                OpKind kind{OpKind::WAKE};
                int fd{-1};
                size_t idx{0};
                uint64_t sessionId{0};
                unsigned pollMask{0};
                sockaddr_in addr{};
                socklen_t addrLen{sizeof(sockaddr_in)};
                uint64_t wakeBuf{0};
                std::unique_ptr<char[]> fallbackBuf{};
                std::weak_ptr<WatchEntry> watchWeak{};
                std::function<void(int)> connectCb{};
            };

            // ---- 基础任务队列与唤醒 ----
            inline void setWakeFd(int fd) noexcept { wakeFd_.store(fd, std::memory_order_release); }

            inline void wakeup() noexcept
            {
                const int wfd = wakeFd_.load(std::memory_order_acquire);
                if (wfd >= 0)
                {
                    constexpr uint64_t one = 1;
                    [[maybe_unused]] const ssize_t ignored = ::write(wfd, &one, sizeof(one));
                }
            }

            inline void runInLoop(Task task)
            {
                if (ring_ != nullptr && std::this_thread::get_id() == loopThreadId_)
                {
                    if (task)
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
                    std::lock_guard<std::mutex> lock(taskMutex_);
                    pendingTasks_.push_back(std::move(task));
                    hasPending_.store(true, std::memory_order_release);
                }
                wakeup();
            }

            inline void doPendingTasks()
            {
                if (!hasPending_.load(std::memory_order_acquire)) [[likely]]
                {
                    return;
                }
                std::deque<Task> tasks;
                {
                    std::lock_guard<std::mutex> lock(taskMutex_);
                    if (pendingTasks_.empty())
                    {
                        hasPending_.store(false, std::memory_order_release);
                        return;
                    }
                    tasks.swap(pendingTasks_);
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

            // ---- 定时器 ----
            inline uint64_t runAfter(std::chrono::milliseconds delay, TimerCallback cb)
            {
                const uint64_t id = timerQueue_.addTimer(TimerQueue::Clock::now() + delay, std::move(cb));
                if (ring_ != nullptr && std::this_thread::get_id() != loopThreadId_)
                {
                    wakeup();
                }
                return id;
            }

            inline uint64_t runEvery(std::chrono::milliseconds interval, TimerCallback cb)
            {
                const uint64_t id = timerQueue_.addTimer(TimerQueue::Clock::now() + interval, std::move(cb), interval);
                if (ring_ != nullptr && std::this_thread::get_id() != loopThreadId_)
                {
                    wakeup();
                }
                return id;
            }

            [[nodiscard]] inline Result<> cancelTimer(uint64_t id) { return timerQueue_.cancelTimer(id); }

            [[nodiscard]] inline long computeWaitMs(int configuredMaxMs)
            {
                const long fallback = (configuredMaxMs > 0) ? static_cast<long>(configuredMaxMs) : 50L;
                if (timerQueue_.empty()) [[likely]]
                {
                    return fallback;
                }
                const auto next = timerQueue_.nextExpire();
                if (next == TimerQueue::Time::max())
                {
                    return fallback;
                }
                const auto now = TimerQueue::Clock::now();
                if (next <= now)
                {
                    return 0L;
                }
                const auto diffMs = std::chrono::ceil<std::chrono::milliseconds>(next - now).count();
                return std::clamp<long>(static_cast<long>(diffMs), 0L, fallback);
            }

            inline void expireTimers()
            {
                if (!timerQueue_.empty())
                {
                    timerQueue_.handleExpired(TimerQueue::Clock::now());
                }
            }

            // ---- Watch 表管理（对等 EventLoop::addWatch / modWatch / delWatch） ----
            [[nodiscard]] inline bool addWatch(int fd, uint32_t events, WatchCallback cb)
            {
                if (fd < 0 || !cb) [[unlikely]]
                {
                    return false;
                }
                if (watches_.contains(fd))
                {
                    delWatch(fd);
                }
                auto entry = std::make_shared<WatchEntry>();
                entry->fd = fd;
                entry->epollEvents = events;
                entry->pollMask = epollToPollMask(events);
                entry->cb = std::move(cb);
                watches_.emplace(fd, entry);
                if (ring_ != nullptr)
                {
                    armWatch(entry);
                }
                return true;
            }

            [[nodiscard]] inline bool modWatch(int fd, uint32_t events) noexcept
            {
                auto it = watches_.find(fd);
                if (it == watches_.end() || it->second == nullptr || it->second->removed)
                {
                    return false;
                }
                auto &entry = it->second;
                const unsigned newMask = epollToPollMask(events);
                entry->epollEvents = events;
                if (entry->pollMask == newMask)
                {
                    return true;
                }
                entry->pollMask = newMask;
                if (ring_ != nullptr)
                {
                    if (entry->armed && entry->activeUid != 0)
                    {
                        submitCancel64(entry->activeUid);
                        entry->armed = false;
                        entry->activeUid = 0;
                    }
                    armWatch(entry);
                }
                return true;
            }

            inline void delWatch(int fd)
            {
                auto it = watches_.find(fd);
                if (it == watches_.end())
                {
                    return;
                }
                auto entry = it->second;
                entry->removed = true;
                if (ring_ != nullptr && entry->armed && entry->activeUid != 0)
                {
                    submitCancel64(entry->activeUid);
                }
                entry->armed = false;
                entry->activeUid = 0;
                watches_.erase(it);
            }

            // ---- 原生异步建连 (io_uring_prep_connect) ----
            [[nodiscard]] inline bool asyncConnect(int fd, const sockaddr_in &addr, std::function<void(int)> cb)
            {
                if (fd < 0 || ring_ == nullptr || !cb)
                {
                    return false;
                }
                io_uring_sqe *sqe = getSqe();
                if (sqe == nullptr)
                {
                    return false;
                }
                auto op = std::make_unique<PendingOp>();
                op->kind = OpKind::ASYNC_CONNECT;
                op->fd = fd;
                op->addr = addr;
                op->connectCb = std::move(cb);
                const uint64_t uid = allocOp(sqe, std::move(op));
                ::io_uring_prep_connect(sqe, fd, reinterpret_cast<const sockaddr *>(&ops_[uid]->addr),
                                        sizeof(sockaddr_in));
                ::io_uring_sqe_set_data64(sqe, uid);
                return true;
            }

            // ---- Proactor 托管 Forwarder 会话生命周期 ----
            [[nodiscard]] inline bool registerSession(const std::shared_ptr<ForwarderStreamSession> &session)
            {
                if (session == nullptr || session->outboundFd() < 0)
                {
                    return false;
                }
                const uint64_t sid = session->id();
                auto st = std::make_unique<SessionTrack>();
                st->session = session;
                st->inboundFd = session->inboundFd();
                st->outboundFd = session->outboundFd();
                st->outRecvBuf.resize(std::max<size_t>(4096, session->config().bufferChunkSize));
                if ((session->activeMode() == ForwardMode::ZERO_COPY_SPLICE ||
                     session->activeMode() == ForwardMode::KERNEL_SOCKMAP) &&
                    st->inboundFd >= 0)
                {
                    spliceInboundFds_.insert(st->inboundFd);
                }
                sessions_.emplace(sid, std::move(st));
                if (ring_ != nullptr)
                {
                    driveSession(sid);
                }
                return true;
            }

            inline void notifySession(uint64_t sid)
            {
                if (ring_ == nullptr)
                {
                    return;
                }
                driveSession(sid);
            }

            [[nodiscard]] inline bool retireSession(uint64_t sid, bool transferOutboundFdOwnership)
            {
                auto it = sessions_.find(sid);
                if (it == sessions_.end())
                {
                    return false;
                }
                SessionTrack &st = *it->second;
                if (st.inboundFd >= 0)
                {
                    spliceInboundFds_.erase(st.inboundFd);
                }
                if (ring_ == nullptr || st.pendingOps == 0)
                {
                    const int outFd = st.outboundFd;
                    sessions_.erase(it);
                    if (transferOutboundFdOwnership && outFd >= 0)
                    {
                        ::close(outFd);
                    }
                    return true;
                }

                st.closing = true;
                st.ownsOutboundFd = transferOutboundFdOwnership;
                if (st.outboundFd >= 0)
                {
                    ::shutdown(st.outboundFd, SHUT_RDWR);
                    submitCancelFd(st.outboundFd);
                }
                if (st.sockmapInPollActive && st.sockmapInPollUid != 0)
                {
                    submitCancel64(st.sockmapInPollUid);
                }
                if (st.sockmapOutPollActive && st.sockmapOutPollUid != 0)
                {
                    submitCancel64(st.sockmapOutPollUid);
                }
                for (auto &d : st.spliceDirs)
                {
                    if (d.pollIn && d.pollInUid != 0)
                    {
                        submitCancel64(d.pollInUid);
                    }
                    if (d.pollOut && d.pollOutUid != 0)
                    {
                        submitCancel64(d.pollOutUid);
                    }
                }
                return true;
            }

            // ---- SQE 辅助与 Ring 会话绑定 ----
            inline void attachRing(io_uring *ring, std::unordered_map<int, Connection *> *conns,
                                   std::stop_source *stopSrc) noexcept
            {
                ring_ = ring;
                connections_ = conns;
                stopSource_ = stopSrc;
                loopThreadId_ = std::this_thread::get_id();
            }

            inline void reset() noexcept
            {
                detachRing();
                for (auto &[sid, st] : sessions_)
                {
                    (void)sid;
                    if (st != nullptr && st->ownsOutboundFd && st->outboundFd >= 0)
                    {
                        ::close(st->outboundFd);
                        st->outboundFd = -1;
                    }
                }
                sessions_.clear();
                watches_.clear();
                spliceInboundFds_.clear();
                {
                    std::lock_guard<std::mutex> lock(taskMutex_);
                    pendingTasks_.clear();
                    hasPending_.store(false, std::memory_order_release);
                }
            }

            inline void detachRing() noexcept
            {
                for (auto &[sid, st] : sessions_)
                {
                    (void)sid;
                    if (st != nullptr && st->closing && st->ownsOutboundFd && st->outboundFd >= 0)
                    {
                        ::close(st->outboundFd);
                        st->outboundFd = -1;
                    }
                    if (st != nullptr)
                    {
                        st->connectActive = false;
                        st->outRecvActive = false;
                        st->outSendActive = false;
                        st->sockmapInPollActive = false;
                        st->sockmapOutPollActive = false;
                        st->sockmapInPollUid = 0;
                        st->sockmapOutPollUid = 0;
                        st->pendingOps = 0;
                        st->spliceDirs = {};
                    }
                }
                std::erase_if(sessions_, [](const auto &kv) { return kv.second == nullptr || kv.second->closing; });
                for (auto &[fd, w] : watches_)
                {
                    (void)fd;
                    if (w != nullptr)
                    {
                        w->armed = false;
                        w->activeUid = 0;
                    }
                }
                ops_.clear();
                tracks_.clear();
                ring_ = nullptr;
                connections_ = nullptr;
                stopSource_ = nullptr;
            }

            [[nodiscard]] inline bool isSpliceInboundFd(int fd) const noexcept
            {
                return fd >= 0 && spliceInboundFds_.contains(fd);
            }

            [[nodiscard]] inline io_uring_sqe *getSqe() noexcept
            {
                if (ring_ == nullptr)
                    return nullptr;
                io_uring_sqe *sqe = ::io_uring_get_sqe(ring_);
                if (sqe == nullptr)
                {
                    ::io_uring_submit(ring_);
                    sqe = ::io_uring_get_sqe(ring_);
                }
                return sqe;
            }

            inline uint64_t allocOp(io_uring_sqe *sqe, std::unique_ptr<PendingOp> op)
            {
                (void)sqe;
                const uint64_t uid = nextOpId_++;
                ops_.emplace(uid, std::move(op));
                return uid;
            }

            inline void submitCancel64(uint64_t uid) noexcept
            {
                if (uid == 0 || ring_ == nullptr)
                    return;
                if (io_uring_sqe *sqe = getSqe(); sqe != nullptr)
                {
                    ::io_uring_prep_cancel64(sqe, uid, 0);
                    ::io_uring_sqe_set_data64(sqe, 0);
                }
            }

            inline void submitCancelFd(int fd) noexcept
            {
                if (fd < 0 || ring_ == nullptr)
                    return;
                if (io_uring_sqe *sqe = getSqe(); sqe != nullptr)
                {
                    ::io_uring_prep_cancel_fd(sqe, fd, 0);
                    ::io_uring_sqe_set_data64(sqe, 0);
                }
            }

            inline void armAllPreRegistered()
            {
                std::vector<std::shared_ptr<WatchEntry>> toArm;
                toArm.reserve(watches_.size());
                for (const auto &[fd, w] : watches_)
                {
                    (void)fd;
                    if (w != nullptr && !w->removed && !w->armed)
                    {
                        toArm.push_back(w);
                    }
                }
                for (const auto &w : toArm)
                {
                    armWatch(w);
                }

                std::vector<uint64_t> sids;
                sids.reserve(sessions_.size());
                for (const auto &[sid, st] : sessions_)
                {
                    (void)st;
                    sids.push_back(sid);
                }
                for (uint64_t sid : sids)
                {
                    driveSession(sid);
                }
                doPendingTasks();
                expireTimers();
            }

            // ---- 入站 Connection 收发控制 ----
            inline void beginCloseConn(int fd)
            {
                auto tIt = tracks_.find(fd);
                if (tIt == tracks_.end())
                {
                    closeConnectionNow(fd);
                    return;
                }
                if (!tIt->second.closing)
                {
                    tIt->second.closing = true;
                    ::shutdown(fd, SHUT_RDWR);
                    if (tIt->second.recvActive || tIt->second.sendActive)
                    {
                        submitCancelFd(fd);
                    }
                }
                maybeFinishCloseConn(fd);
            }

            inline void maybeFinishCloseConn(int fd)
            {
                auto tIt = tracks_.find(fd);
                if (tIt == tracks_.end() || !tIt->second.closing)
                {
                    return;
                }
                if (tIt->second.recvActive || tIt->second.sendActive)
                {
                    return;
                }
                tracks_.erase(tIt);
                closeConnectionNow(fd);
            }

            inline void startConnRecv(int fd)
            {
                if (ring_ == nullptr || connections_ == nullptr ||
                    (stopSource_ != nullptr && stopSource_->stop_requested()))
                {
                    return;
                }
                auto cIt = connections_->find(fd);
                auto tIt = tracks_.find(fd);
                if (cIt == connections_->end() || tIt == tracks_.end())
                {
                    return;
                }
                Connection *conn = cIt->second;
                ConnTrack &tr = tIt->second;
                if (conn == nullptr || tr.closing || tr.recvActive || !conn->wantRead())
                {
                    return;
                }
                if (isSpliceInboundFd(fd) ||
                    (conn->handler() != nullptr && conn->handler()->shouldSuppressConnRecv()))
                {
                    return;
                }

                void *dstPtr = nullptr;
                size_t dstLen = 0;
                auto op = std::make_unique<PendingOp>();
                if (Handler *h = conn->handler(); h != nullptr)
                {
                    const size_t credit = h->readCredit();
                    if (credit == 0)
                    {
                        conn->pauseRead();
                        return;
                    }
                    const size_t want = std::min(getConnectionConfig().readChunkSize, credit);
                    auto prep = h->prepareRequestWritable(want);
                    if (!prep)
                    {
                        beginCloseConn(fd);
                        return;
                    }
                    dstPtr = *prep;
                    dstLen = std::min(h->requestWritableBytes(), credit);
                }
                else
                {
                    op->fallbackBuf = std::make_unique<char[]>(4096);
                    dstPtr = op->fallbackBuf.get();
                    dstLen = 4096;
                }

                if (dstLen == 0)
                {
                    return;
                }
                if (io_uring_sqe *sqe = getSqe(); sqe != nullptr)
                {
                    op->kind = OpKind::RECV;
                    op->fd = fd;
                    const uint64_t uid = allocOp(sqe, std::move(op));
                    ::io_uring_prep_recv(sqe, fd, dstPtr, dstLen, 0);
                    ::io_uring_sqe_set_data64(sqe, uid);
                    tr.recvActive = true;
                }
            }

            inline void maybeStartConnSend(int fd)
            {
                if (ring_ == nullptr || connections_ == nullptr ||
                    (stopSource_ != nullptr && stopSource_->stop_requested()))
                {
                    return;
                }
                auto cIt = connections_->find(fd);
                auto tIt = tracks_.find(fd);
                if (cIt == connections_->end() || tIt == tracks_.end())
                {
                    return;
                }
                Connection *conn = cIt->second;
                ConnTrack &tr = tIt->second;
                if (conn == nullptr || tr.closing)
                {
                    return;
                }

                conn->pump();
                if (tr.sendActive)
                {
                    return;
                }
                if (!conn->hasQueuedWrite())
                {
                    if (conn->closeAfterWrite())
                    {
                        beginCloseConn(fd);
                    }
                    return;
                }
                std::string_view sp = conn->frontWriteSpan();
                if (sp.empty())
                {
                    return;
                }

                if (io_uring_sqe *sqe = getSqe(); sqe != nullptr)
                {
                    auto op = std::make_unique<PendingOp>();
                    op->kind = OpKind::SEND;
                    op->fd = fd;
                    const uint64_t uid = allocOp(sqe, std::move(op));
                    ::io_uring_prep_send(sqe, fd, sp.data(), sp.size(), MSG_NOSIGNAL);
                    ::io_uring_sqe_set_data64(sqe, uid);
                    tr.sendActive = true;
                }
            }

            // ---- 出站与双向 Splice 异步调度 ----
            struct SpliceEndpoints
            {
                int srcFd{-1};
                int pipeWr{-1};
                int pipeRd{-1};
                int dstFd{-1};
                bool isDown{false};
            };

            [[nodiscard]] static inline SpliceEndpoints getSpliceEndpoints(ForwarderStreamSession &s, size_t dir) noexcept
            {
                if (dir == 0)
                {
                    return {s.inboundFd(), s.pipeUpWrite(), s.pipeUpRead(), s.outboundFd(), false};
                }
                return {s.outboundFd(), s.pipeDownWrite(), s.pipeDownRead(), s.inboundFd(), true};
            }

            inline void driveSession(uint64_t sid)
            {
                if (ring_ == nullptr || (stopSource_ != nullptr && stopSource_->stop_requested()))
                {
                    return;
                }
                auto it = sessions_.find(sid);
                if (it == sessions_.end())
                {
                    return;
                }
                SessionTrack &st = *it->second;
                auto &s = st.session;
                if (st.closing || s == nullptr || s->isClosed())
                {
                    maybeFinishSessionClose(sid);
                    return;
                }

                if (st.outboundFd < 0)
                {
                    st.outboundFd = s->outboundFd();
                }
                if (st.inboundFd < 0)
                {
                    st.inboundFd = s->inboundFd();
                }

                // 1. 异步建连阶段：io_uring_prep_connect 或等待 EINPROGRESS 可写
                if (s->isOutboundConnecting())
                {
                    if (!st.connectActive && st.outboundFd >= 0)
                    {
                        submitOutboundConnect(sid, st);
                    }
                    return;
                }

                // 2. 冲刷已存在的出站队列（握手首包、prebuffered 载荷或已编码报文）
                if (!st.outSendActive && !s->isOutboundClosed() && st.outboundFd >= 0 &&
                    s->hasOutboundPendingToSend())
                {
                    submitOutboundSend(sid, st);
                }

                // 3. 按当前数据面自适应模式分别调度：KERNEL_SOCKMAP / ZERO_COPY_SPLICE / BUFFER_PUMP
                if (s->activeMode() == ForwardMode::KERNEL_SOCKMAP && st.inboundFd >= 0 && st.outboundFd >= 0)
                {
                    spliceInboundFds_.insert(st.inboundFd);
                    auto armSockmapPoll = [&](size_t idx, int fd, bool &activeFlag, uint64_t &uidSlot)
                    {
                        if (activeFlag || fd < 0)
                        {
                            return;
                        }
                        if (io_uring_sqe *sqe = getSqe(); sqe != nullptr)
                        {
                            unsigned mask = POLLIN | POLLERR | POLLHUP;
#ifdef POLLRDHUP
                            mask |= POLLRDHUP;
#endif
                            auto op = std::make_unique<PendingOp>();
                            op->kind = OpKind::FWD_SOCKMAP_POLL;
                            op->idx = idx;
                            op->sessionId = sid;
                            op->fd = fd;
                            const uint64_t uid = allocOp(sqe, std::move(op));
                            ::io_uring_prep_poll_add(sqe, fd, mask);
                            ::io_uring_sqe_set_data64(sqe, uid);
                            activeFlag = true;
                            uidSlot = uid;
                            ++st.pendingOps;
                        }
                    };
                    if (!s->isInboundClosed())
                    {
                        bool inRecvActive = false;
                        if (auto tIt = tracks_.find(st.inboundFd); tIt != tracks_.end())
                        {
                            inRecvActive = tIt->second.recvActive;
                        }
                        if (!inRecvActive)
                        {
                            armSockmapPoll(0, st.inboundFd, st.sockmapInPollActive, st.sockmapInPollUid);
                        }
                    }
                    if (!s->isOutboundClosed() && !st.outRecvActive)
                    {
                        armSockmapPoll(1, st.outboundFd, st.sockmapOutPollActive, st.sockmapOutPollUid);
                    }
                }
                else if (s->activeMode() == ForwardMode::ZERO_COPY_SPLICE && st.inboundFd >= 0 && st.outboundFd >= 0 &&
                         s->pipeUpWrite() >= 0 && s->pipeDownWrite() >= 0)
                {
                    spliceInboundFds_.insert(st.inboundFd);
                    driveSpliceDir(sid, st, 0);
                    driveSpliceDir(sid, st, 1);
                }
                else
                {
                    if (st.inboundFd >= 0)
                    {
                        spliceInboundFds_.erase(st.inboundFd);
                    }
                    // BUFFER_PUMP 模式：出站与入站均通过 io_uring RECV/SEND 泵送
                    if (!st.outRecvActive && !s->isOutboundClosed() && st.outboundFd >= 0)
                    {
                        submitOutboundRecv(sid, st);
                    }
                    if (st.inboundFd >= 0 && !s->isInboundClosed())
                    {
                        startConnRecv(st.inboundFd);
                    }
                }

                if (st.inboundFd >= 0)
                {
                    maybeStartConnSend(st.inboundFd);
                }
                if (s->isInboundClosed() && s->isOutboundClosed())
                {
                    s->close();
                }
            }

            inline void kickSpliceInboundWriteReady(int inboundFd)
            {
                for (auto &[sid, st] : sessions_)
                {
                    if (st != nullptr && !st->closing && st->inboundFd == inboundFd && st->session != nullptr &&
                        st->session->activeMode() == ForwardMode::ZERO_COPY_SPLICE)
                    {
                        driveSpliceDir(sid, *st, 1);
                    }
                }
            }

            inline void handlePendingOpCqe(uint64_t uid, int res)
            {
                auto oIt = ops_.find(uid);
                if (oIt == ops_.end())
                    return;
                std::unique_ptr<PendingOp> op = std::move(oIt->second);
                ops_.erase(oIt);

                switch (op->kind)
                {
                case OpKind::WATCH_POLL:
                {
                    auto entry = op->watchWeak.lock();
                    if (!entry || entry->removed)
                        break;
                    entry->armed = false;
                    entry->activeUid = 0;
                    if (res >= 0)
                    {
                        if (entry->cb)
                        {
                            entry->cb(pollToEpollMask(res));
                        }
                        if (!entry->removed && watches_.contains(entry->fd) && !entry->armed &&
                            (stopSource_ == nullptr || !stopSource_->stop_requested()))
                        {
                            armWatch(entry);
                        }
                    }
                    break;
                }
                case OpKind::ASYNC_CONNECT:
                {
                    if (op->connectCb)
                    {
                        op->connectCb(res < 0 ? -res : 0);
                    }
                    break;
                }
                case OpKind::FWD_OUT_CONNECT:
                case OpKind::FWD_OUT_POLL_CONNECT:
                {
                    auto sIt = sessions_.find(op->sessionId);
                    if (sIt == sessions_.end())
                        break;
                    SessionTrack &st = *sIt->second;
                    if (st.pendingOps > 0)
                        --st.pendingOps;
                    st.connectActive = false;
                    if (st.closing)
                    {
                        maybeFinishSessionClose(op->sessionId);
                        break;
                    }
                    int err = 0;
                    if (op->kind == OpKind::FWD_OUT_CONNECT)
                    {
                        err = (res < 0) ? -res : 0;
                    }
                    else
                    {
                        socklen_t elen = sizeof(err);
                        if (res < 0)
                        {
                            err = -res;
                        }
                        else if (::getsockopt(op->fd, SOL_SOCKET, SO_ERROR, &err, &elen) < 0)
                        {
                            err = errno != 0 ? errno : ECONNREFUSED;
                        }
                    }
                    st.session->onProactorConnectComplete(err);
                    driveSession(op->sessionId);
                    break;
                }
                case OpKind::FWD_OUT_RECV:
                {
                    auto sIt = sessions_.find(op->sessionId);
                    if (sIt == sessions_.end())
                        break;
                    SessionTrack &st = *sIt->second;
                    if (st.pendingOps > 0)
                        --st.pendingOps;
                    st.outRecvActive = false;
                    if (st.closing)
                    {
                        maybeFinishSessionClose(op->sessionId);
                        break;
                    }
                    st.session->onProactorOutboundRecv(st.outRecvBuf.data(), static_cast<ssize_t>(res));
                    driveSession(op->sessionId);
                    break;
                }
                case OpKind::FWD_OUT_SEND:
                {
                    auto sIt = sessions_.find(op->sessionId);
                    if (sIt == sessions_.end())
                        break;
                    SessionTrack &st = *sIt->second;
                    if (st.pendingOps > 0)
                        --st.pendingOps;
                    st.outSendActive = false;
                    if (st.closing)
                    {
                        maybeFinishSessionClose(op->sessionId);
                        break;
                    }
                    (void)st.session->finishProactorOutboundSend(static_cast<ssize_t>(res));
                    driveSession(op->sessionId);
                    break;
                }
                case OpKind::FWD_SPLICE_POLL_IN:
                case OpKind::FWD_SPLICE_IN:
                case OpKind::FWD_SPLICE_POLL_OUT:
                case OpKind::FWD_SPLICE_OUT:
                    handleSpliceOpCqe(*op, res);
                    break;
                case OpKind::FWD_SOCKMAP_POLL:
                {
                    auto sIt = sessions_.find(op->sessionId);
                    if (sIt == sessions_.end())
                        break;
                    SessionTrack &st = *sIt->second;
                    if (st.pendingOps > 0)
                        --st.pendingOps;
                    if (op->idx == 0)
                    {
                        st.sockmapInPollActive = false;
                        st.sockmapInPollUid = 0;
                    }
                    else
                    {
                        st.sockmapOutPollActive = false;
                        st.sockmapOutPollUid = 0;
                    }
                    if (st.closing)
                    {
                        maybeFinishSessionClose(op->sessionId);
                        break;
                    }
                    if (res == -ECANCELED || st.session == nullptr ||
                        st.session->activeMode() != ForwardMode::KERNEL_SOCKMAP)
                    {
                        break;
                    }

                    auto cancelPeerPoll = [&]()
                    {
                        if (op->idx == 0 && st.sockmapOutPollActive && st.sockmapOutPollUid != 0)
                        {
                            submitCancel64(st.sockmapOutPollUid);
                        }
                        else if (op->idx == 1 && st.sockmapInPollActive && st.sockmapInPollUid != 0)
                        {
                            submitCancel64(st.sockmapInPollUid);
                        }
                    };

                    if (res >= 0)
                    {
                        char peekByte = 0;
                        const ssize_t pk = ::recv(op->fd, &peekByte, 1, MSG_PEEK | MSG_DONTWAIT);
                        if (pk > 0)
                        {
                            // 内核 Sockmap 返回 SK_PASS 落回用户态接收队列 -> 降级到 SPLICE（或无损 BUFFER_PUMP）
                            cancelPeerPoll();
                            st.session->downgradeSockmapToSplice(false);
                        }
                        else if (pk == 0 || (pk < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) ||
                                 ((res & (POLLERR | POLLHUP)) && !(res & POLLIN)))
                        {
                            if (op->idx == 0)
                                st.session->markInboundClosed();
                            else
                                st.session->markOutboundClosed();
                        }
                        else
                        {
                            st.session->checkAndApplySockmapBackpressure();
                            if (st.session->activeMode() != ForwardMode::KERNEL_SOCKMAP)
                            {
                                cancelPeerPoll();
                            }
                        }
                    }
                    else if (res != -EAGAIN && res != -EINTR)
                    {
                        if (op->idx == 0)
                            st.session->markInboundClosed();
                        else
                            st.session->markOutboundClosed();
                    }

                    driveSession(op->sessionId);
                    break;
                }
                default:
                    break;
                }
            }

            inline void closeConnectionNow(int fd)
            {
                if (connections_ == nullptr)
                    return;
                if (auto cIt = connections_->find(fd); cIt != connections_->end())
                {
                    Connection *c = cIt->second;
                    connections_->erase(cIt);
                    if (c != nullptr)
                    {
                        c->close();
                        delete c;
                    }
                }
            }

            // 允许 Proactor 主循环访问共享追踪表
            std::unordered_map<uint64_t, std::unique_ptr<PendingOp>> ops_{};
            std::unordered_map<int, ConnTrack> tracks_{};
            std::unordered_map<uint64_t, std::unique_ptr<SessionTrack>> sessions_{};
            std::unordered_map<int, std::shared_ptr<WatchEntry>> watches_{};
            std::unordered_set<int> spliceInboundFds_{};

        private:
            inline void armWatch(const std::shared_ptr<WatchEntry> &entry)
            {
                if (!entry || entry->removed || entry->armed || ring_ == nullptr)
                    return;
                io_uring_sqe *sqe = getSqe();
                if (sqe == nullptr)
                    return;
                auto op = std::make_unique<PendingOp>();
                op->kind = OpKind::WATCH_POLL;
                op->fd = entry->fd;
                op->pollMask = entry->pollMask;
                op->watchWeak = entry;
                const uint64_t uid = allocOp(sqe, std::move(op));
                ::io_uring_prep_poll_add(sqe, entry->fd, entry->pollMask);
                ::io_uring_sqe_set_data64(sqe, uid);
                entry->armed = true;
                entry->activeUid = uid;
            }

            inline void maybeFinishSessionClose(uint64_t sid)
            {
                auto it = sessions_.find(sid);
                if (it == sessions_.end())
                    return;
                SessionTrack &st = *it->second;
                if (!st.closing || st.pendingOps > 0)
                {
                    return;
                }
                const int outFd = st.outboundFd;
                const bool ownsOut = st.ownsOutboundFd;
                sessions_.erase(it);
                if (ownsOut && outFd >= 0)
                {
                    ::close(outFd);
                }
            }

            inline void submitOutboundConnect(uint64_t sid, SessionTrack &st)
            {
                io_uring_sqe *sqe = getSqe();
                if (sqe == nullptr)
                    return;
                auto op = std::make_unique<PendingOp>();
                op->sessionId = sid;
                op->fd = st.outboundFd;
                if (st.session->isOutboundConnectDeferred())
                {
                    op->kind = OpKind::FWD_OUT_CONNECT;
                    op->addr = st.session->outboundTargetAddr();
                    const uint64_t uid = allocOp(sqe, std::move(op));
                    ::io_uring_prep_connect(sqe, st.outboundFd, reinterpret_cast<const sockaddr *>(&ops_[uid]->addr),
                                            sizeof(sockaddr_in));
                    ::io_uring_sqe_set_data64(sqe, uid);
                }
                else
                {
                    op->kind = OpKind::FWD_OUT_POLL_CONNECT;
                    const uint64_t uid = allocOp(sqe, std::move(op));
                    ::io_uring_prep_poll_add(sqe, st.outboundFd, POLLOUT);
                    ::io_uring_sqe_set_data64(sqe, uid);
                }
                st.connectActive = true;
                ++st.pendingOps;
            }

            inline void submitOutboundSend(uint64_t sid, SessionTrack &st)
            {
                const size_t chunk = std::max<size_t>(4096, st.session->config().bufferChunkSize);
                std::string_view sp = st.session->beginProactorOutboundSend(chunk);
                if (sp.empty())
                    return;
                io_uring_sqe *sqe = getSqe();
                if (sqe == nullptr)
                    return;
                auto op = std::make_unique<PendingOp>();
                op->kind = OpKind::FWD_OUT_SEND;
                op->sessionId = sid;
                op->fd = st.outboundFd;
                const uint64_t uid = allocOp(sqe, std::move(op));
                ::io_uring_prep_send(sqe, st.outboundFd, sp.data(), sp.size(), MSG_NOSIGNAL);
                ::io_uring_sqe_set_data64(sqe, uid);
                st.outSendActive = true;
                ++st.pendingOps;
            }

            inline void submitOutboundRecv(uint64_t sid, SessionTrack &st)
            {
                const size_t credit = st.session->outboundReadCredit();
                if (credit == 0)
                    return;
                const size_t want = std::min(st.outRecvBuf.size(), credit);
                if (want == 0)
                    return;
                io_uring_sqe *sqe = getSqe();
                if (sqe == nullptr)
                    return;
                auto op = std::make_unique<PendingOp>();
                op->kind = OpKind::FWD_OUT_RECV;
                op->sessionId = sid;
                op->fd = st.outboundFd;
                const uint64_t uid = allocOp(sqe, std::move(op));
                ::io_uring_prep_recv(sqe, st.outboundFd, st.outRecvBuf.data(), want, 0);
                ::io_uring_sqe_set_data64(sqe, uid);
                st.outRecvActive = true;
                ++st.pendingOps;
            }

            inline bool isInboundWriteBusy(int inboundFd) const noexcept
            {
                if (inboundFd < 0 || connections_ == nullptr)
                    return false;
                auto tIt = tracks_.find(inboundFd);
                if (tIt != tracks_.end() && tIt->second.sendActive)
                    return true;
                auto cIt = connections_->find(inboundFd);
                return cIt != connections_->end() && cIt->second != nullptr && cIt->second->hasQueuedWrite();
            }

            inline void submitSpliceOp(uint64_t sid, SessionTrack &st, size_t dir, OpKind kind, int fd, int fdIn,
                                       int fdOut, unsigned int nbytes, unsigned pollMask)
            {
                io_uring_sqe *sqe = getSqe();
                if (sqe == nullptr)
                    return;
                auto op = std::make_unique<PendingOp>();
                op->kind = kind;
                op->idx = dir;
                op->sessionId = sid;
                op->fd = fd;
                const uint64_t uid = allocOp(sqe, std::move(op));
                auto &d = st.spliceDirs[dir];
                if (kind == OpKind::FWD_SPLICE_POLL_IN)
                {
                    ::io_uring_prep_poll_add(sqe, fd, pollMask);
                    d.pollIn = true;
                    d.pollInUid = uid;
                }
                else if (kind == OpKind::FWD_SPLICE_POLL_OUT)
                {
                    ::io_uring_prep_poll_add(sqe, fd, pollMask);
                    d.pollOut = true;
                    d.pollOutUid = uid;
                }
                else
                {
                    ::io_uring_prep_splice(sqe, fdIn, -1, fdOut, -1, nbytes, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
                    if (kind == OpKind::FWD_SPLICE_IN)
                        d.inPipe = true;
                    else
                        d.outPipe = true;
                }
                ::io_uring_sqe_set_data64(sqe, uid);
                ++st.pendingOps;
            }

            inline void driveSpliceDir(uint64_t sid, SessionTrack &st, size_t dir)
            {
                if (st.closing || st.session == nullptr)
                    return;
                const auto ep = getSpliceEndpoints(*st.session, dir);
                if (ep.srcFd < 0 || ep.dstFd < 0 || ep.pipeWr < 0 || ep.pipeRd < 0)
                    return;

                auto &d = st.spliceDirs[dir];
                const unsigned chunk =
                    static_cast<unsigned>(std::clamp<size_t>(st.session->config().spliceChunkSize, 4096u, 65536u));

                if (d.pipePending > 0)
                {
                    if (ep.isDown && isInboundWriteBusy(ep.dstFd))
                        return;
                    if (!d.outPipe && !d.pollOut)
                    {
                        const unsigned n = static_cast<unsigned>(std::min<size_t>(chunk, d.pipePending));
                        submitSpliceOp(sid, st, dir, OpKind::FWD_SPLICE_OUT, ep.dstFd, ep.pipeRd, ep.dstFd, n, 0);
                    }
                    return;
                }

                const bool dstClosed = ep.isDown ? st.session->isInboundClosed() : st.session->isOutboundClosed();
                const bool srcClosed = ep.isDown ? st.session->isOutboundClosed() : st.session->isInboundClosed();
                if (srcClosed || d.eofReached)
                {
                    bool &shutFlag = ep.isDown ? st.inboundShutWrSent : st.outboundShutWrSent;
                    if (!shutFlag)
                    {
                        shutFlag = true;
                        ::shutdown(ep.dstFd, SHUT_WR);
                    }
                    return;
                }
                if (dstClosed)
                    return;

                // 若刚刚从 BUFFER_PUMP 升级为 SPLICE，确保前序在途 io_uring RECV 完成后再发起同方向 SPLICE，避免双读并发
                if (ep.isDown && st.outRecvActive)
                    return;
                if (!ep.isDown)
                {
                    auto tIt = tracks_.find(ep.srcFd);
                    if (tIt != tracks_.end() && tIt->second.recvActive)
                        return;
                }

                if (!d.pollIn && !d.inPipe)
                {
                    submitSpliceOp(sid, st, dir, OpKind::FWD_SPLICE_POLL_IN, ep.srcFd, -1, -1, 0, POLLIN);
                }
            }

            inline void handleSpliceOpCqe(const PendingOp &op, int res)
            {
                auto sIt = sessions_.find(op.sessionId);
                if (sIt == sessions_.end())
                    return;
                SessionTrack &st = *sIt->second;
                if (st.pendingOps > 0)
                    --st.pendingOps;

                const size_t dir = op.idx & 1u;
                auto &d = st.spliceDirs[dir];
                if (op.kind == OpKind::FWD_SPLICE_POLL_IN)
                {
                    d.pollIn = false;
                    d.pollInUid = 0;
                }
                else if (op.kind == OpKind::FWD_SPLICE_IN)
                {
                    d.inPipe = false;
                }
                else if (op.kind == OpKind::FWD_SPLICE_POLL_OUT)
                {
                    d.pollOut = false;
                    d.pollOutUid = 0;
                }
                else if (op.kind == OpKind::FWD_SPLICE_OUT)
                {
                    d.outPipe = false;
                }

                if (st.closing)
                {
                    maybeFinishSessionClose(op.sessionId);
                    return;
                }
                if (st.session == nullptr || st.session->activeMode() != ForwardMode::ZERO_COPY_SPLICE)
                {
                    return;
                }

                const auto ep = getSpliceEndpoints(*st.session, dir);
                const unsigned chunk =
                    static_cast<unsigned>(std::clamp<size_t>(st.session->config().spliceChunkSize, 4096u, 65536u));

                auto fallbackSpliceSessionToBufferPump = [&]()
                {
                    for (size_t other = 0; other < 2; ++other)
                    {
                        auto &od = st.spliceDirs[other];
                        if (od.pollIn && od.pollInUid != 0)
                        {
                            submitCancel64(od.pollInUid);
                        }
                        if (od.pollOut && od.pollOutUid != 0)
                        {
                            submitCancel64(od.pollOutUid);
                        }
                        od = {};
                    }
                    if (st.inboundFd >= 0)
                    {
                        spliceInboundFds_.erase(st.inboundFd);
                    }
                    st.session->downgradeSpliceToBufferPump();
                    driveSession(op.sessionId);
                    if (st.inboundFd >= 0)
                    {
                        startConnRecv(st.inboundFd);
                        maybeStartConnSend(st.inboundFd);
                    }
                };

                if (op.kind == OpKind::FWD_SPLICE_POLL_IN)
                {
                    if (res > 0 && (res & POLLIN))
                    {
                        submitSpliceOp(op.sessionId, st, dir, OpKind::FWD_SPLICE_IN, ep.srcFd, ep.srcFd, ep.pipeWr,
                                       chunk, 0);
                    }
                    else if (res >= 0 && (res & (POLLERR | POLLHUP | POLLRDHUP)))
                    {
                        d.eofReached = true;
                        st.session->onProactorSpliceResult(ep.isDown, 0);
                        driveSpliceDir(op.sessionId, st, dir);
                    }
                    else if (res == -EAGAIN || res == -EINTR)
                    {
                        driveSpliceDir(op.sessionId, st, dir);
                    }
                }
                else if (op.kind == OpKind::FWD_SPLICE_IN)
                {
                    if (res > 0)
                    {
                        d.pipePending += static_cast<size_t>(res);
                        driveSpliceDir(op.sessionId, st, dir);
                    }
                    else if (res == -EAGAIN || res == -EINTR)
                    {
                        driveSpliceDir(op.sessionId, st, dir);
                    }
                    else if (res < 0 && isSpliceUnsupportedErrno(-res))
                    {
                        fallbackSpliceSessionToBufferPump();
                        return;
                    }
                    else
                    {
                        d.eofReached = true;
                        st.session->onProactorSpliceResult(ep.isDown, static_cast<ssize_t>(res));
                        driveSpliceDir(op.sessionId, st, dir);
                    }
                }
                else if (op.kind == OpKind::FWD_SPLICE_OUT)
                {
                    if (res > 0)
                    {
                        const size_t sent = static_cast<size_t>(res);
                        d.pipePending = (sent >= d.pipePending) ? 0 : (d.pipePending - sent);
                        st.session->onProactorSpliceResult(ep.isDown, static_cast<ssize_t>(res));
                        driveSpliceDir(op.sessionId, st, dir);
                    }
                    else if (res == -EAGAIN || res == -EINTR)
                    {
                        submitSpliceOp(op.sessionId, st, dir, OpKind::FWD_SPLICE_POLL_OUT, ep.dstFd, -1, -1, 0,
                                       POLLOUT);
                    }
                    else if (res < 0 && isSpliceUnsupportedErrno(-res))
                    {
                        fallbackSpliceSessionToBufferPump();
                        return;
                    }
                    else
                    {
                        // 目标可写端失败（对端断连）
                        if (ep.isDown)
                        {
                            st.session->markInboundClosed();
                        }
                        else
                        {
                            st.session->markOutboundClosed();
                        }
                    }
                }
                else if (op.kind == OpKind::FWD_SPLICE_POLL_OUT)
                {
                    if (res >= 0 && (res & POLLOUT))
                    {
                        driveSpliceDir(op.sessionId, st, dir);
                    }
                    else if (res >= 0 && (res & (POLLERR | POLLHUP)))
                    {
                        if (ep.isDown)
                        {
                            st.session->markInboundClosed();
                        }
                        else
                        {
                            st.session->markOutboundClosed();
                        }
                    }
                    else if (res == -EAGAIN || res == -EINTR)
                    {
                        driveSpliceDir(op.sessionId, st, dir);
                    }
                }
            }

            io_uring *ring_{nullptr};
            std::unordered_map<int, Connection *> *connections_{nullptr};
            std::stop_source *stopSource_{nullptr};
            uint64_t nextOpId_{1};

            std::atomic<int> wakeFd_{-1};
            std::thread::id loopThreadId_{};
            TimerQueue timerQueue_{};
            std::atomic<bool> hasPending_{false};
            std::mutex taskMutex_{};
            std::deque<Task> pendingTasks_{};
        };

    } // namespace detail

    /**
     * @brief Proactor 与 EventLoop 对等适配器：暴露 addWatch / modWatch / delWatch / 定时器 / 异步会话钩子
     */
    class ProactorLoop
    {
    public:
        using Task = detail::ProactorCore::Task;
        using TimerCallback = detail::ProactorCore::TimerCallback;
        using WatchCallback = detail::ProactorCore::WatchCallback;

        explicit ProactorLoop(detail::ProactorCore &core) noexcept
            : core_(core)
        {
        }

        [[nodiscard]] inline bool addWatch(int fd, uint32_t events, WatchCallback cb)
        {
            return core_.addWatch(fd, events, std::move(cb));
        }
        [[nodiscard]] inline bool modWatch(int fd, uint32_t events) noexcept { return core_.modWatch(fd, events); }
        inline void delWatch(int fd) { core_.delWatch(fd); }

        inline void runInLoop(Task task) { core_.runInLoop(std::move(task)); }
        inline void queueInLoop(Task task) { core_.queueInLoop(std::move(task)); }

        inline uint64_t runAfter(std::chrono::milliseconds delay, TimerCallback cb)
        {
            return core_.runAfter(delay, std::move(cb));
        }
        inline uint64_t runEvery(std::chrono::milliseconds interval, TimerCallback cb)
        {
            return core_.runEvery(interval, std::move(cb));
        }
        [[nodiscard]] inline Result<> cancelTimer(uint64_t id) { return core_.cancelTimer(id); }

        inline void attachForwarderHooks(ForwarderLoopHooks &hooks)
        {
            hooks.deferOutboundConnect = true;
            hooks.registerSession = [this](const std::shared_ptr<ForwarderStreamSession> &session)
            { return core_.registerSession(session); };
            hooks.notifySession = [this](uint64_t sid) { core_.notifySession(sid); };
            hooks.retireSession = [this](uint64_t sid, bool ownsFd) { return core_.retireSession(sid, ownsFd); };
        }

    private:
        detail::ProactorCore &core_;
    };

    template <typename... Protocols>
    class Proactor
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

        Proactor()
        {
            for (size_t i = 0; i < kListenerCount; ++i)
            {
                listeners_[i].transport = kListenerConfigs[i].transport;
                listeners_[i].configuredPort = kListenerConfigs[i].defaultPort;
                listeners_[i].token = static_cast<int>(i);
            }
        }
        ~Proactor() noexcept { reset(); }

        Proactor(const Proactor &) = delete;
        Proactor &operator=(const Proactor &) = delete;

        [[nodiscard]] inline ProactorLoop &loop() noexcept { return loopAdapter_; }
        [[nodiscard]] inline size_t connections() const noexcept { return connections_.size(); }

        [[nodiscard]] inline bool asyncConnect(int fd, const sockaddr_in &target, std::function<void(int)> cb)
        {
            return core_.asyncConnect(fd, target, std::move(cb));
        }

        inline void stop() noexcept
        {
            stopSource_.request_stop();
            core_.wakeup();
        }
        inline void quit() noexcept { stop(); }

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
            return {};
        }

        /**
         * @brief 将外部 Acceptor（如 TProxy / 多端口入站）创建的 Connection 纳入 Proactor 异步 io_uring 托管
         */
        inline bool adoptConnection(Connection *conn)
        {
            if (conn == nullptr || conn->fd() < 0) [[unlikely]]
            {
                return false;
            }
            const int clientFd = conn->fd();
            connections_[clientFd] = conn;
            core_.tracks_.emplace(clientFd, detail::ProactorCore::ConnTrack{});
            core_.maybeStartConnSend(clientFd);
            core_.startConnRecv(clientFd);
            return true;
        }

        [[nodiscard]] Result<> runTcp(const char *ip, int port, const ServerConfig &server,
                                      const ProactorConfig &proactor)
        {
            if constexpr (!kHasTcp)
            {
                LOG_ERROR("Proactor::runTcp: this Proactor has no TCP protocols configured");
                return std::unexpected(ERR::SOCKET_FAILED);
            }
            else
            {
                if (auto err = listenTcp(ip, port, server.backlog, server.reuseAddr, server.reusePort); !err)
                {
                    reset();
                    return err;
                }
                Result<> rc = serve(server, proactor);
                reset();
                return rc;
            }
        }

        [[nodiscard]] Result<> runTcp(const char *ip, int port)
        {
            const MynetConfig cfg = getMynetConfig();
            return runTcp(ip, port, cfg.server, cfg.proactor);
        }

        [[nodiscard]] Result<> runTcp()
        {
            const MynetConfig cfg = getMynetConfig();
            return runTcp(cfg.server.host.c_str(), static_cast<int>(cfg.server.port), cfg.server, cfg.proactor);
        }

        [[nodiscard]] Result<> runUdp(const char *ip, int port, const ServerConfig &server,
                                      const ProactorConfig &proactor)
        {
            if constexpr (!kHasUdp)
            {
                LOG_ERROR("Proactor::runUdp: this Proactor has no UDP protocols configured");
                return std::unexpected(ERR::SOCKET_FAILED);
            }
            else
            {
                if (auto err = listenUdp(ip, port, server.reuseAddr, server.reusePort); !err)
                {
                    reset();
                    return err;
                }
                Result<> rc = serve(server, proactor);
                reset();
                return rc;
            }
        }

        [[nodiscard]] Result<> runUdp(const char *ip, int port)
        {
            const MynetConfig cfg = getMynetConfig();
            return runUdp(ip, port, cfg.server, cfg.proactor);
        }

        [[nodiscard]] Result<> runUdp()
        {
            const MynetConfig cfg = getMynetConfig();
            return runUdp(cfg.server.host.c_str(), static_cast<int>(cfg.server.port), cfg.server, cfg.proactor);
        }

        template <typename H>
        [[nodiscard]] Result<> runUdp(const char *ip, int port, H &handler, const ProactorConfig &proactor)
        {
            struct UdpHandlerGuard
            {
                Handler *&slot;
                explicit UdpHandlerGuard(Handler *&s, Handler *h) noexcept : slot(s) { slot = h; }
                ~UdpHandlerGuard() noexcept { slot = nullptr; }
            } guard(externalUdpHandler_, &handler);
            return runUdp(ip, port, getServerConfig(), proactor);
        }

        template <typename H>
        [[nodiscard]] Result<> runUdp(const char *ip, int port, H &handler)
        {
            return runUdp(ip, port, handler, getProactorConfig());
        }

        template <typename H>
        [[nodiscard]] Result<> runUdp(H &handler)
        {
            const MynetConfig cfg = getMynetConfig();
            return runUdp(cfg.server.host.c_str(), static_cast<int>(cfg.server.port), handler, cfg.proactor);
        }

        [[nodiscard]] Result<> serve(const ServerConfig &server, const ProactorConfig &proactor)
        {
            const int wfd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
            if (wfd < 0) [[unlikely]]
            {
                return std::unexpected(ERR::EVENTFD_FAILED);
            }
            struct WakeGuard
            {
                detail::ProactorCore &core;
                int fd;
                ~WakeGuard() noexcept
                {
                    core.setWakeFd(-1);
                    if (fd >= 0)
                        ::close(fd);
                }
            } wakeGuard{core_, wfd};
            core_.setWakeFd(wfd);

            io_uring ring{};
            const unsigned sqEntries = (proactor.sqEntries >= 16) ? static_cast<unsigned>(proactor.sqEntries) : 256u;
            if (::io_uring_queue_init(sqEntries, &ring, 0) < 0) [[unlikely]]
            {
                return std::unexpected(ERR::URING_QUEUE_FAILED);
            }
            struct RingGuard
            {
                detail::ProactorCore &core;
                io_uring *r;
                ~RingGuard() noexcept
                {
                    core.detachRing();
                    ::io_uring_queue_exit(r);
                }
            } ringGuard{core_, &ring};
            core_.attachRing(&ring, &connections_, &stopSource_);

            submitWake(wfd);
            for (size_t i = 0; i < kListenerCount; ++i)
            {
                if (!listeners_[i].valid())
                    continue;
                if (listeners_[i].isTcp())
                {
                    submitAccept(i);
                }
                else
                {
                    submitUdpPoll(i);
                }
            }
            core_.armAllPreRegistered();

            while (!stopSource_.stop_requested())
            {
                core_.expireTimers();
                core_.doPendingTasks();
                if (stopSource_.stop_requested())
                {
                    break;
                }

                const long waitMs = core_.computeWaitMs(proactor.cqeWaitMs);
                __kernel_timespec ts{};
                ts.tv_sec = waitMs / 1000L;
                ts.tv_nsec = (waitMs % 1000L) * 1000000L;

                ::io_uring_submit(&ring);
                io_uring_cqe *cqe = nullptr;
                const int wrc = ::io_uring_wait_cqe_timeout(&ring, &cqe, &ts);
                if (wrc == -ETIME || wrc == -EINTR || wrc == -EAGAIN)
                {
                    core_.expireTimers();
                    core_.doPendingTasks();
                    sweepIdleConnections(server);
                    continue;
                }
                if (wrc < 0)
                {
                    break;
                }

                while (::io_uring_peek_cqe(&ring, &cqe) == 0 && cqe != nullptr)
                {
                    const uint64_t uid = cqe->user_data;
                    const int res = cqe->res;
                    ::io_uring_cqe_seen(&ring, cqe);
                    if (uid != 0)
                    {
                        dispatchCqe(uid, res, wfd);
                    }
                }
                core_.expireTimers();
                core_.doPendingTasks();
                sweepIdleConnections(server);
            }

            return {};
        }

        inline void reset() noexcept
        {
            for (auto &l : listeners_)
            {
                l.reset();
            }

            for (auto &[fd, conn] : connections_)
            {
                if (conn != nullptr)
                {
                    conn->close();
                    delete conn;
                }
            }
            connections_.clear();
            core_.reset();

            std::apply([](auto &...acc) { (acc.reset(), ...); }, acceptors_);
            std::apply([](auto &...dia) { (dia.reset(), ...); }, dialers_);
            for (auto &uh : udpHandlers_)
            {
                uh.reset();
            }
            externalUdpHandler_ = nullptr;
            stopSource_ = std::stop_source{};
        }

    private:
        using OpKind = detail::ProactorCore::OpKind;
        using PendingOp = detail::ProactorCore::PendingOp;

        inline void submitWake(int wfd)
        {
            if (stopSource_.stop_requested())
                return;
            if (io_uring_sqe *sqe = core_.getSqe(); sqe != nullptr)
            {
                auto op = std::make_unique<PendingOp>();
                op->kind = OpKind::WAKE;
                op->fd = wfd;
                const uint64_t uid = core_.allocOp(sqe, std::move(op));
                ::io_uring_prep_read(sqe, wfd, &core_.ops_[uid]->wakeBuf, sizeof(uint64_t), 0);
                ::io_uring_sqe_set_data64(sqe, uid);
            }
        }

        inline void submitAccept(size_t lidx)
        {
            if (stopSource_.stop_requested() || !listeners_[lidx].valid())
                return;
            if (io_uring_sqe *sqe = core_.getSqe(); sqe != nullptr)
            {
                auto op = std::make_unique<PendingOp>();
                op->kind = OpKind::ACCEPT;
                op->fd = listeners_[lidx].fd();
                op->idx = lidx;
                const uint64_t uid = core_.allocOp(sqe, std::move(op));
                PendingOp *raw = core_.ops_[uid].get();
                ::io_uring_prep_accept(sqe, raw->fd, reinterpret_cast<sockaddr *>(&raw->addr), &raw->addrLen,
                                       SOCK_NONBLOCK | SOCK_CLOEXEC);
                ::io_uring_sqe_set_data64(sqe, uid);
            }
        }

        inline void submitUdpPoll(size_t lidx)
        {
            if (stopSource_.stop_requested() || !listeners_[lidx].valid())
                return;
            if (io_uring_sqe *sqe = core_.getSqe(); sqe != nullptr)
            {
                auto op = std::make_unique<PendingOp>();
                op->kind = OpKind::UDP_POLL;
                op->fd = listeners_[lidx].fd();
                op->idx = lidx;
                const uint64_t uid = core_.allocOp(sqe, std::move(op));
                ::io_uring_prep_poll_add(sqe, op->fd, POLLIN);
                ::io_uring_sqe_set_data64(sqe, uid);
            }
        }

        inline void sweepIdleConnections(const ServerConfig &server)
        {
            if (server.idleTimeoutSecs <= 0 || connections_.empty())
                return;
            const auto maxIdle = std::chrono::seconds(server.idleTimeoutSecs);
            const auto now = std::chrono::steady_clock::now();
            std::vector<int> expired;
            for (const auto &[fd, conn] : connections_)
            {
                if (conn != nullptr && (now - conn->lastActive()) > maxIdle)
                {
                    expired.push_back(fd);
                }
            }
            for (int fd : expired)
            {
                core_.beginCloseConn(fd);
            }
        }

        inline void dispatchCqe(uint64_t uid, int res, int wfd)
        {
            auto oIt = core_.ops_.find(uid);
            if (oIt == core_.ops_.end())
                return;

            switch (oIt->second->kind)
            {
            case OpKind::WAKE:
            {
                core_.ops_.erase(oIt);
                uint64_t val = 0;
                while (::read(wfd, &val, sizeof(val)) > 0)
                {
                }
                core_.doPendingTasks();
                if (!stopSource_.stop_requested())
                {
                    submitWake(wfd);
                }
                break;
            }
            case OpKind::ACCEPT:
            {
                auto op = std::move(oIt->second);
                core_.ops_.erase(oIt);
                if (res >= 0)
                {
                    const int clientFd = res;
                    Connection *conn = nullptr;
                    if constexpr (sizeof...(Protocols) > 0)
                    {
                        detail::dispatchProtocolTcpClient<Protocols...>(clientFd, conn, op->idx, acceptors_);
                    }
                    if (conn == nullptr)
                    {
                        conn = new Connection();
                    }
                    conn->setFd(clientFd);
                    conn->setPeerAddr(op->addr);
                    conn->setTransport(TransportType::TCP);
                    connections_[clientFd] = conn;
                    core_.tracks_.emplace(clientFd, detail::ProactorCore::ConnTrack{});
                    core_.maybeStartConnSend(clientFd);
                    core_.startConnRecv(clientFd);
                }
                if (!stopSource_.stop_requested())
                {
                    submitAccept(op->idx);
                }
                break;
            }
            case OpKind::UDP_POLL:
            {
                auto op = std::move(oIt->second);
                core_.ops_.erase(oIt);
                if (res > 0)
                {
                    detail::drainProtocolUdp<Protocols...>(listeners_[op->idx], op->idx, externalUdpHandler_,
                                                           udpHandlers_, acceptors_);
                }
                if (!stopSource_.stop_requested())
                {
                    submitUdpPoll(op->idx);
                }
                break;
            }
            case OpKind::RECV:
            {
                auto op = std::move(oIt->second);
                core_.ops_.erase(oIt);
                auto tIt = core_.tracks_.find(op->fd);
                if (tIt == core_.tracks_.end())
                    break;
                tIt->second.recvActive = false;
                if (tIt->second.closing)
                {
                    core_.maybeFinishCloseConn(op->fd);
                    break;
                }
                auto cIt = connections_.find(op->fd);
                Connection *conn = (cIt != connections_.end()) ? cIt->second : nullptr;
                if (conn == nullptr)
                {
                    core_.tracks_.erase(tIt);
                    break;
                }
                if (res > 0)
                {
                    conn->touch();
                    conn->applyQuickAck();
                    if (Handler *h = conn->handler(); h != nullptr)
                    {
                        h->commitRequest(static_cast<size_t>(res));
                        if (h->requestOverLimit()) [[unlikely]]
                        {
                            h->onParseError("request exceeds the read limit");
                            conn->pump();
                            conn->setCloseAfterWrite(true);
                            conn->pauseRead();
                        }
                        else
                        {
                            h->drive();
                            h->notifyExternalData();
                            conn->pump();
                        }
                    }
                    core_.maybeStartConnSend(op->fd);
                    core_.startConnRecv(op->fd);
                    if (core_.isSpliceInboundFd(op->fd))
                    {
                        for (const auto &[sid, st] : core_.sessions_)
                        {
                            if (st != nullptr && !st->closing && st->inboundFd == op->fd)
                            {
                                core_.driveSession(sid);
                            }
                        }
                    }
                }
                else if (res == -EAGAIN || res == -EINTR)
                {
                    core_.startConnRecv(op->fd);
                }
                else
                {
                    core_.beginCloseConn(op->fd);
                }
                break;
            }
            case OpKind::SEND:
            {
                auto op = std::move(oIt->second);
                core_.ops_.erase(oIt);
                auto tIt = core_.tracks_.find(op->fd);
                if (tIt == core_.tracks_.end())
                    break;
                tIt->second.sendActive = false;
                if (tIt->second.closing)
                {
                    core_.maybeFinishCloseConn(op->fd);
                    break;
                }
                auto cIt = connections_.find(op->fd);
                Connection *conn = (cIt != connections_.end()) ? cIt->second : nullptr;
                if (conn == nullptr)
                {
                    core_.tracks_.erase(tIt);
                    break;
                }
                if (res > 0)
                {
                    conn->touch();
                    conn->commitSent(static_cast<size_t>(res));
                    core_.maybeStartConnSend(op->fd);
                    if (connections_.contains(op->fd) && conn->wantRead() && !core_.tracks_[op->fd].recvActive)
                    {
                        core_.startConnRecv(op->fd);
                    }
                    if (!conn->hasQueuedWrite() && !core_.tracks_[op->fd].sendActive &&
                        core_.isSpliceInboundFd(op->fd))
                    {
                        core_.kickSpliceInboundWriteReady(op->fd);
                    }
                }
                else if (res == -EAGAIN || res == -EINTR)
                {
                    core_.maybeStartConnSend(op->fd);
                }
                else
                {
                    core_.beginCloseConn(op->fd);
                }
                break;
            }
            default:
                core_.handlePendingOpCqe(uid, res);
                break;
            }
        }

        std::array<Listener, kListenerCount> listeners_{};

        std::tuple<typename ProtocolTraits<Protocols>::Acceptor...> acceptors_{};
        std::tuple<typename ProtocolTraits<Protocols>::Dialer...> dialers_{};
        std::array<std::unique_ptr<Handler>, (kProtocolCount > 0 ? kProtocolCount : 1)> udpHandlers_{};
        Handler *externalUdpHandler_{nullptr};
        std::unordered_map<int, Connection *> connections_{};

        std::stop_source stopSource_{};
        detail::ProactorCore core_{};
        ProactorLoop loopAdapter_{core_};
    };

} // namespace mynet

#endif
