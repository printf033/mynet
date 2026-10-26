#pragma once

/**
 * @file reactor.hpp
 * @brief 基于 epoll 的高性能反应器（Reactor）事件解复用器与服务器事件循环。
 */

#include "concepts.hpp"
#include "connection.hpp"
#include "datagram.hpp"
#include "event.hpp"
#include "log.hpp"
#include "loop.hpp"
#include "objectPool.hpp"
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <optional>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unordered_map>
#include <utility>
#include <vector>

namespace mynet
{

    /**
     * @class Reactor
     * @brief 基于单线程 epoll 的反应器引擎，管理套接字生命周期与 I/O 事件分发。
     *
     * 采用边沿触发（EPOLLET）模式驱动新连接接入、SSL 握手与 UDP 数据报收发。
     *
     * @tparam Event 满足 DerivedFromEventBase 与 Resettable 约束的套接字事件包装类型。
     */
    template <typename Event>
        requires DerivedFromEventBase<Event> && Resettable<Event> &&
                 (ProtocolHandler<typename Event::Handler> || DerivedFromDatagramHandler<typename Event::Handler>)
    class Reactor
    {
    public:
        using Handler = typename Event::Handler;
        using Conn = Connection<Handler>;

        Reactor() = default;

        ~Reactor() noexcept { reset(); }

        Reactor(const Reactor &) = delete("a reactor owns the epoll registration of every live connection");
        Reactor &operator=(const Reactor &) = delete("a reactor owns the epoll registration of every live connection");

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

        /**
         * @brief 在指定 IP 和端口上运行 TCP 服务器，直至被请求停止。
         * @param ip 监听 IPv4 地址字面量。
         * @param port 监听端口。
         * @param backlog 监听全连接队列长度。
         * @param connectionPoolSize 预分配连接池容量。
         * @param maxEvents 每次 epoll_wait 最大返回事件数。
         * @param idleTimeoutSecs 空闲连接超时时间（秒，0 表示禁用）。
         * @return 正常停止返回 {}，启动或运行时失败返回错误码。
         */
        [[nodiscard]] Result<> runTcp(const char *ip, int port, int backlog = 511, size_t connectionPoolSize = 1 << 10,
                                      int maxEvents = 1 << 10, int idleTimeoutSecs = 0)
        {
            if (auto err = listener_.listenTcp(ip, port, backlog); !err) [[unlikely]]
            {
                reset();
                return err;
            }
            Result<> rc = serve(connectionPoolSize, maxEvents, idleTimeoutSecs);
            reset();
            return rc;
        }

        /**
         * @brief 在指定 IP 和端口上运行 TLS/SSL 服务器，直至被请求停止。
         * @param ip 监听 IPv4 地址字面量。
         * @param port 监听端口。
         * @param crt PEM 格式证书文件路径。
         * @param key PEM 格式私钥文件路径。
         * @param backlog 监听全连接队列长度。
         * @param connectionPoolSize 预分配连接池容量。
         * @param maxEvents 每次 epoll_wait 最大返回事件数。
         * @param idleTimeoutSecs 空闲连接超时时间（秒，0 表示禁用）。
         * @return 正常停止返回 {}，启动或运行时失败返回错误码。
         */
        [[nodiscard]] Result<> runSsl(const char *ip, int port, const char *crt, const char *key, int backlog = 511,
                                      size_t connectionPoolSize = 1 << 10, int maxEvents = 1 << 10,
                                      int idleTimeoutSecs = 0)
            requires SslEvent<Event>
        {
            if (auto err = listener_.listenTcp(ip, port, backlog); !err) [[unlikely]]
            {
                reset();
                return err;
            }
            if ((protocol_.ctx = SSL_CTX_new(TLS_server_method())) == nullptr) [[unlikely]]
            {
                LOG_ERROR("Reactor::runSsl: SSL_CTX_new() failed: {}", log::sslText());
                reset();
                return std::unexpected(ERR::SSL_CTX_FAILED);
            }
            // 现代 TLS 安全基线：强制启用最低 TLS 1.2 并禁用不安全压缩与客户端弱密码套件偏好
            SSL_CTX_set_min_proto_version(protocol_.ctx, TLS1_2_VERSION);
            SSL_CTX_set_options(protocol_.ctx, SSL_OP_CIPHER_SERVER_PREFERENCE | SSL_OP_NO_COMPRESSION);
            if (SSL_CTX_use_certificate_file(protocol_.ctx, crt, SSL_FILETYPE_PEM) <= 0) [[unlikely]]
            {
                LOG_ERROR("Reactor::runSsl: certificate file \"{}\" could not be loaded: {}", crt, log::sslText());
                reset();
                return std::unexpected(ERR::SSL_CERT_FAILED);
            }
            if (SSL_CTX_use_PrivateKey_file(protocol_.ctx, key, SSL_FILETYPE_PEM) <= 0) [[unlikely]]
            {
                LOG_ERROR("Reactor::runSsl: private key file \"{}\" could not be loaded: {}", key, log::sslText());
                reset();
                return std::unexpected(ERR::SSL_KEY_FAILED);
            }
            if (SSL_CTX_check_private_key(protocol_.ctx) <= 0) [[unlikely]]
            {
                LOG_ERROR("Reactor::runSsl: private key \"{}\" does not match certificate \"{}\": {}", key, crt,
                          log::sslText());
                reset();
                return std::unexpected(ERR::SSL_KEY_MISMATCH);
            }
            Result<> rc = serve(connectionPoolSize, maxEvents, idleTimeoutSecs);
            reset();
            return rc;
        }

        /**
         * @brief 在指定 IP 和端口上运行 UDP 数据报服务器，直至被请求停止。
         * @param ip 监听 IPv4 地址字面量。
         * @param port 监听端口。
         * @param handler 数据报处理器引用。
         * @param maxEvents 每次 epoll_wait 最大返回事件数。
         * @return 正常停止返回 {}，启动或运行时失败返回错误码。
         */
        [[nodiscard]] Result<> runUdp(const char *ip, int port, Handler &handler, int maxEvents = 1 << 10)
            requires DerivedFromDatagramHandler<Handler>
        {
            if (auto err = listener_.listenUdp(ip, port); !err) [[unlikely]]
            {
                reset();
                return err;
            }
            handler.reset();
            datagram_ = &handler;
            udpIn_.resize(handler.maxDatagramBytes() + 1);
            Result<> rc = serveDatagram(maxEvents);
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
        {
            auto it = index_.find(fd);
            return it == index_.end() ? nullptr : it->second;
        }

        /**
         * @brief 面向流式连接的核心事件循环。
         */
        [[nodiscard]] inline Result<> serve(size_t connectionPoolSize, int maxEvents, int idleTimeoutSecs)
        {
            if (loop_.epollFd() < 0) [[unlikely]]
            {
                LOG_ERROR("Reactor::serve: the event loop has no epoll descriptor");
                return std::unexpected(ERR::EPOLL_CREATE_FAILED);
            }
            loop_.reserveEvents(maxEvents > 0 ? static_cast<size_t>(maxEvents) : (1 << 10));
            const size_t connSlots = connectionPoolSize > 0 ? connectionPoolSize : (1 << 10);
            if (auto poolRes = connPool_.init(connSlots); !poolRes) [[unlikely]]
            {
                LOG_ERROR("Reactor::serve: initialising connection pool ({} slots) failed", connSlots);
                return std::unexpected(ERR::POOL_ALLOC_FAILED);
            }
            sweepScratch_.reserve(connSlots);
            loop_.setEventCallback([this](uint32_t events, void *ptr) { onEvent(events, ptr); });
            if (auto res = loop_.addFd(listener_.fd, EPOLLIN | EPOLLET, &listener_); !res) [[unlikely]]
            {
                LOG_ERROR("Reactor::serve: adding listener fd {} to loop failed: {}", listener_.fd,
                          log::errnoText(errno));
                return std::unexpected(ERR::EPOLL_CTL_FAILED);
            }
            if (idleTimeoutSecs > 0)
            {
                idleTimeout_ = std::chrono::seconds(idleTimeoutSecs);
                idleTimerId_ = loop_.runEvery(std::chrono::seconds(1), [this] { sweepIdle(); });
            }
            return loop_.run();
        }

        /**
         * @brief 面向数据报的核心事件循环。
         */
        [[nodiscard]] inline Result<> serveDatagram(int maxEvents)
        {
            if (loop_.epollFd() < 0) [[unlikely]]
            {
                LOG_ERROR("Reactor::serveDatagram: the event loop has no epoll descriptor");
                return std::unexpected(ERR::EPOLL_CREATE_FAILED);
            }
            loop_.reserveEvents(maxEvents > 0 ? static_cast<size_t>(maxEvents) : (1 << 10));
            loop_.setEventCallback([this](uint32_t events, void *ptr) { onEvent(events, ptr); });
            if (auto res = loop_.addFd(listener_.fd, EPOLLIN | EPOLLET, &listener_); !res) [[unlikely]]
            {
                LOG_ERROR("Reactor::serveDatagram: adding datagram fd {} to loop failed: {}", listener_.fd,
                          log::errnoText(errno));
                return std::unexpected(ERR::EPOLL_CTL_FAILED);
            }
            return loop_.run();
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
            if (listener_.fd != -1)
            {
                [[maybe_unused]] auto _ = loop_.delFd(listener_.fd);
            }
            for (auto &entry : index_)
            {
                [[maybe_unused]] auto _ = loop_.delFd(entry.first);
                connPool_.release(entry.second);
            }
            index_.clear();
            connPool_.reset();
            loop_.setEventCallback({});
            if constexpr (SslEvent<Event>)
            {
                if (protocol_.ctx != nullptr)
                {
                    SSL_CTX_free(protocol_.ctx);
                    protocol_.ctx = nullptr;
                }
            }
            listener_.reset();
            datagram_ = nullptr;
            udpIn_.clear();
            idleTimeout_ = std::chrono::seconds(0);
        }

    private:
        inline void onEvent(uint32_t events, void *ptr)
        {
            if (ptr == nullptr) [[unlikely]]
            {
                return;
            }
            if (ptr == &listener_)
            {
                if (datagram_ != nullptr)
                {
                    if (events & EPOLLIN)
                    {
                        drainDatagrams();
                    }
                    return;
                }
                if (events & EPOLLIN)
                {
                    if (auto err = acceptAll(); !err) [[unlikely]]
                    {
                        LOG_DEBUG("Reactor::onEvent: draining accept backlog ended with {}", toString(err.error()));
                    }
                }
                return;
            }
            onConnection(static_cast<Conn *>(ptr), events);
        }

        inline void onConnection(Conn *conn, uint32_t events)
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
        {
            while (true)
            {
                sockaddr_in addr{};
                socklen_t len = sizeof(addr);
                int fd =
                    ::accept4(listener_.fd, reinterpret_cast<sockaddr *>(&addr), &len, SOCK_NONBLOCK | SOCK_CLOEXEC);
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
                    LOG_ERROR("Reactor::acceptAll: accept4() on fd {} failed: {}", listener_.fd, log::errnoText(errno));
                    return std::unexpected(ERR::ACCEPT_FAILED);
                }
                onNewConnection(fd, addr);
            }
        }

        inline void onNewConnection(int fd, const sockaddr_in &addr)
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
            if constexpr (SslEvent<Event>)
            {
                if (protocol_.ctx != nullptr && !conn->startTLS(protocol_.ctx)) [[unlikely]]
                {
                    LOG_WARN("Reactor::onNewConnection: TLS setup for fd {} failed: {}", fd, log::sslText());
                    connPool_.release(conn);
                    return;
                }
            }
            index_.emplace(fd, conn);
            uint32_t events = EPOLLIN | EPOLLET;
            if (conn->wantWrite())
            {
                events |= EPOLLOUT;
            }
            if (!loop_.addFd(fd, events, conn)) [[unlikely]]
            {
                LOG_WARN("Reactor::onNewConnection: adding fd {} to loop failed: {}", fd, log::errnoText(errno));
                index_.erase(fd);
                connPool_.release(conn);
                return;
            }
            conn->setEvents(events);
        }

        inline void closeConn(Conn *conn)
        {
            int fd = conn->fd();
            if (fd != -1)
            {
                [[maybe_unused]] auto _ = loop_.delFd(fd);
                index_.erase(fd);
            }
            connPool_.release(conn);
        }

        inline void drainDatagrams()
        {
            const size_t cap = datagram_->maxDatagramBytes();
            for (;;)
            {
                sockaddr_in peer{};
                socklen_t peerLen = static_cast<socklen_t>(sizeof(sockaddr_in));
                ssize_t n = ::recvfrom(listener_.fd, udpIn_.data(), static_cast<size_t>(udpIn_.size()), 0,
                                       reinterpret_cast<sockaddr *>(&peer), &peerLen);
                if (n < 0)
                {
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                    {
                        break;
                    }
                    if (errno == EINTR)
                    {
                        continue;
                    }
                    LOG_WARN("Reactor::drainDatagrams: recvfrom on fd {} failed: {}", listener_.fd,
                             log::errnoText(errno));
                    break;
                }
                size_t got = static_cast<size_t>(n);
                if (got > cap) [[unlikely]]
                {
                    LOG_WARN("Reactor::drainDatagrams: {} bytes from {} exceeds {} limit, truncated", got,
                             datagramPeerText(peer), cap);
                    got = cap;
                }
                datagram_->onDatagram(peer, udpIn_.data(), got);
            }
            flushDatagrams();
        }

        inline void flushDatagrams()
        {
            while (datagram_->hasReply())
            {
                DatagramReply reply = datagram_->takeReply();
                while (true)
                {
                    ssize_t sent = ::sendto(listener_.fd, reply.bytes.data(), reply.bytes.size(), 0,
                                            reinterpret_cast<const sockaddr *>(&reply.peer),
                                            static_cast<socklen_t>(sizeof(sockaddr_in)));
                    if (sent < 0) [[unlikely]]
                    {
                        if (errno == EINTR)
                        {
                            continue;
                        }
                        LOG_WARN("Reactor::flushDatagrams: sendto to {} failed: {}", datagramPeerText(reply.peer),
                                 log::errnoText(errno));
                    }
                    break;
                }
            }
        }

        inline void sweepIdle()
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

        Event listener_;
        EventLoop loop_;
        Protocol<Event> protocol_{};
        ObjectPool<Conn> connPool_{};
        std::unordered_map<int, Conn *> index_{};
        std::vector<Conn *> sweepScratch_{};
        DatagramHandler *datagram_ = nullptr;
        std::vector<char> udpIn_{};
        std::chrono::seconds idleTimeout_{0};
        uint64_t idleTimerId_ = 0;
    };

} // namespace mynet
