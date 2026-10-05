#pragma once

#include "connection.hpp"
#include "datagram.hpp"
#include "event.hpp"
#include "log.hpp"
#include "loop.hpp"
#include "myconcepts.hpp"
#include "objectPool.hpp"
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unordered_map>
#include <vector>

// The reactor keeps every socket of a server on one thread, and pushes the
// details down to two places:
//
//   - Connection<> owns one socket: its TLS state, its read buffer, its
//     handler and its write queue. TCP and TLS therefore share a single
//     recv/send path, and a half sent response lives in exactly one object.
//   - EventLoop owns *time* and *wake-ups*: a timer queue, so idle deadlines
//     and heartbeats are real instead of a comment, and an eventfd, so
//     another thread can hand work over without touching loop state.
//
// What is left here is what is genuinely about accepting: turn a readable
// listening socket into connections, translate readiness into
// handleRead()/handleWrite(), and recycle a connection only after the loop
// has stopped watching its descriptor.
//
// Later protocols hang off this seam rather than replace it: h2 keeps the
// same accept path and adds an ALPN decision in onNewConnection()
// (Connection::alpnSelected() is the hook), h3 needs a different Connection
// and the same loop.
// The stream path needs a protocol handler; the datagram path needs a
// datagram handler. A type shaped for both -- see the UDP samples, where one
// class answers to either -- may use either run_* here.
template <typename Event>
    requires mustDerivedFromEventBase<Event> && mustResettable<Event> &&
             (mustHandleProtocol<typename Event::Handler> ||
              mustDerivedFromDatagramHandler<typename Event::Handler>)
class Reactor
{
public:
    using Handler = typename Event::Handler;
    using Conn = Connection<Handler>;

    Reactor() = default;

    ~Reactor() noexcept { reset(); }

    Reactor(const Reactor &) = delete("a reactor owns the epoll registration of every live connection");
    Reactor &operator=(const Reactor &) = delete("a reactor owns the epoll registration of every live connection");

    inline EventLoop &loop() noexcept { return loop_; }
    inline size_t connections() const noexcept { return index_.size(); }
    inline size_t connectionPoolCapacity() const noexcept { return connPool_.capacity(); }

    // Ask a running loop to return from run(). Safe to call from any thread:
    // quit() wakes the eventfd the loop is waiting on.
    inline void stop() noexcept { loop_.quit(); }
    inline void quit() noexcept { loop_.quit(); }

    // std::nullopt once the loop has returned; otherwise why the listener
    // could not be brought up. Every failure now has one name, see Err.
    [[nodiscard]] std::optional<Err> run_tcp(const char *ip, int port, int backlog = 511,
                                             size_t connectionPoolSize = 1024, int maxEvents = 1024,
                                             int idleTimeoutSecs = 0)
    {
        if (std::optional<Err> err = listener_.listen_tcp(ip, port, backlog))
        {
            reset();
            return err;
        }
        std::optional<Err> rc = serve(connectionPoolSize, maxEvents, idleTimeoutSecs, nullptr);
        reset();
        return rc;
    }

    // std::nullopt once the loop has returned; otherwise the listener, the
    // certificate material or the loop refused to come up.
    [[nodiscard]] std::optional<Err> run_ssl(const char *ip, int port,
                                             const char *crt, const char *key,
                                             int backlog = 511,
                                             size_t connectionPoolSize = 1024, int maxEvents = 1024,
                                             int idleTimeoutSecs = 0)
        requires mustEventSSL<Event>
    {
        if (std::optional<Err> err = listener_.listen_tcp(ip, port, backlog))
        {
            reset();
            return err;
        }
        if ((protocol_.ctx = SSL_CTX_new(TLS_server_method())) == nullptr)
        {
            LOG_ERROR("Reactor::run_ssl: SSL_CTX_new() failed: {}", mynetlog::sslText());
            reset();
            return Err::ssl_ctx_failed;
        }
        if (SSL_CTX_use_certificate_file(protocol_.ctx, crt, SSL_FILETYPE_PEM) <= 0)
        {
            LOG_ERROR("Reactor::run_ssl: certificate file \"{}\" could not be loaded: {}", crt, mynetlog::sslText());
            reset();
            return Err::ssl_cert_failed;
        }
        if (SSL_CTX_use_PrivateKey_file(protocol_.ctx, key, SSL_FILETYPE_PEM) <= 0)
        {
            LOG_ERROR("Reactor::run_ssl: private key file \"{}\" could not be loaded: {}", key, mynetlog::sslText());
            reset();
            return Err::ssl_key_failed;
        }
        if (SSL_CTX_check_private_key(protocol_.ctx) <= 0)
        {
            LOG_ERROR("Reactor::run_ssl: private key \"{}\" does not match certificate \"{}\": {}", key, crt, mynetlog::sslText());
            reset();
            return Err::ssl_key_mismatch;
        }
        std::optional<Err> rc = serve(connectionPoolSize, maxEvents, idleTimeoutSecs, protocol_.ctx);
        reset();
        return rc;
    }

    // Serve one datagram socket until stop().
    //
    // There is no pool and no accept path here: a UDP socket is one endpoint
    // that every peer shares, so there is nothing per-connection to own and
    // the handler -- not a Connection -- is what the loop talks to. The
    // handler is passed in rather than constructed here because its settings
    // (queue limits, keys it verifies against) belong to the application.
    [[nodiscard]] std::optional<Err> run_udp(const char *ip, int port, Handler &handler, int maxEvents = 1024)
        requires mustDerivedFromDatagramHandler<Handler>
    {
        if (std::optional<Err> err = listener_.listen_udp(ip, port))
        {
            reset();
            return err;
        }
        handler.reset();
        datagram_ = &handler;
        // One byte past the limit, so an oversized datagram is seen as
        // oversized instead of silently looking like a datagram of exactly
        // the limit.
        udpIn_.resize(handler.maxDatagramBytes() + 1);
        std::optional<Err> rc = serveDatagram(maxEvents);
        reset();
        return rc;
    }

    // Hand a task to the loop thread. It may be called from any thread, so a
    // response produced by a timer or by another thread reaches its socket
    // without touching loop state directly.
    inline void runInLoop(EventLoop::Task task) { loop_.runInLoop(std::move(task)); }

    // Same, but addressed to one connection: the descriptor is looked up
    // again on the loop thread (it may have gone away meanwhile) and the
    // interest set is refreshed afterwards, so a response queued by the task
    // is actually written.
    inline void runOnConnection(int fd, std::function<void(Conn &)> task)
    {
        loop_.runInLoop([this, fd, task = std::move(task)] {
            auto it = index_.find(fd);
            if (it == index_.end())
                return;
            Conn *conn = it->second;
            task(*conn);
            conn->setWantWrite(conn->hasPendingWrite());
            if (updateInterest(conn) == IoStatus::close)
                closeConn(conn);
        });
    }

    inline Conn *find(int fd) noexcept
    {
        auto it = index_.find(fd);
        return it == index_.end() ? nullptr : it->second;
    }

    // std::nullopt when the loop ran and stopped; otherwise why it could not
    // be set up or why it stopped early.
    [[nodiscard]] inline std::optional<Err> serve(size_t connectionPoolSize, int maxEvents, int idleTimeoutSecs, SSL_CTX *ctx)
    {
        if (loop_.epollFd() < 0)
        {
            LOG_ERROR("Reactor::serve: the event loop has no epoll descriptor");
            return Err::epoll_create_failed;
        }
        loop_.reserveEvents(maxEvents > 0 ? static_cast<size_t>(maxEvents) : 1024);
        connPool_.init(connectionPoolSize > 0 ? connectionPoolSize : 1024);
        sweepScratch_.reserve(connectionPoolSize > 0 ? connectionPoolSize : 1024);
        loop_.setEventCallback([this](uint32_t events, void *ptr) { onEvent(events, ptr); });
        if (loop_.addFd(listener_.fd, EPOLLIN | EPOLLET, &listener_))
        {
            LOG_ERROR("Reactor::serve: adding the listener fd {} to the loop failed: {}", listener_.fd,
                      mynetlog::errnoText(errno));
            return Err::epoll_ctl_failed;
        }
        if (idleTimeoutSecs > 0)
        {
            idleTimeout_ = std::chrono::seconds(idleTimeoutSecs);
            idleTimerId_ = loop_.runEvery(std::chrono::seconds(1), [this] { sweepIdle(); });
        }
        (void)ctx;
        return loop_.run();
    }

    // The datagram twin of serve(): same loop, same callback, one descriptor
    // that is never accepted from and never closed on error -- only stopped.
    [[nodiscard]] inline std::optional<Err> serveDatagram(int maxEvents)
    {
        if (loop_.epollFd() < 0)
        {
            LOG_ERROR("Reactor::serveDatagram: the event loop has no epoll descriptor");
            return Err::epoll_create_failed;
        }
        loop_.reserveEvents(maxEvents > 0 ? static_cast<size_t>(maxEvents) : 1024);
        loop_.setEventCallback([this](uint32_t events, void *ptr) { onEvent(events, ptr); });
        if (loop_.addFd(listener_.fd, EPOLLIN | EPOLLET, &listener_))
        {
            LOG_ERROR("Reactor::serveDatagram: adding the datagram fd {} to the loop failed: {}", listener_.fd,
                      mynetlog::errnoText(errno));
            return Err::epoll_ctl_failed;
        }
        return loop_.run();
    }

    inline void reset() noexcept
    {
        if (idleTimerId_ != 0)
        {
            (void)loop_.cancelTimer(idleTimerId_);
            idleTimerId_ = 0;
        }
        if (listener_.fd != -1)
            (void)loop_.delFd(listener_.fd);
        for (auto &entry : index_)
            connPool_.release(entry.second);
        index_.clear();
        connPool_.reset();
        loop_.setEventCallback({});
        if constexpr (mustEventSSL<Event>)
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
        if (ptr == &listener_)
        {
            if (datagram_ != nullptr)
            {
                if (events & EPOLLIN)
                    drainDatagrams();
                return;
            }
            if (events & EPOLLIN)
            {
                if (std::optional<Err> err = acceptAll())
                    LOG_DEBUG("Reactor::onEvent: draining the accept backlog ended with {}", to_string(*err));
            }
            return;
        }
        onConnection(static_cast<Conn *>(ptr), events);
    }

    inline void onConnection(Conn *conn, uint32_t events)
    {
        // A peer that hung up usually still has an EOF (or a last request)
        // pending, so let the read path see it. Without EPOLLIN there is
        // nothing left that this socket can tell us.
        if ((events & (EPOLLERR | EPOLLHUP)) && !(events & EPOLLIN))
        {
            closeConn(conn);
            return;
        }
        if (events & EPOLLIN)
        {
            if (conn->handleRead() == IoStatus::close)
            {
                closeConn(conn);
                return;
            }
        }
        if (events & EPOLLOUT)
        {
            if (conn->handleWrite() == IoStatus::close)
            {
                closeConn(conn);
                return;
            }
        }
        if (updateInterest(conn) == IoStatus::close)
            closeConn(conn);
    }

    // IoStatus::close once the peer is gone with nothing left to say, or once
    // epoll will no longer take interest in the descriptor -- both mean this
    // connection has no future and the caller should recycle it.
    [[nodiscard]] inline IoStatus updateInterest(Conn *conn)
    {
        uint32_t wanted = EPOLLET;
        if (conn->wantRead())
            wanted |= EPOLLIN;
        if (conn->wantWrite())
            wanted |= EPOLLOUT;
        if ((wanted & ~static_cast<uint32_t>(EPOLLET)) == 0)
            return IoStatus::close; // peer is gone and there is nothing left to send
        bool rearmRead = (wanted & EPOLLIN) != 0 && (conn->events() & EPOLLIN) == 0;
        if (wanted != conn->events())
        {
            if (loop_.modFd(conn->fd(), wanted, conn))
                return IoStatus::close;
            conn->setEvents(wanted);
        }
        if (rearmRead)
        {
            // While read interest was off, level triggered semantics would
            // have kept reporting the pending bytes; edge triggered ones will
            // not, so drain once before trusting the next notification.
            if (conn->handleRead() == IoStatus::close)
                return IoStatus::close;
            uint32_t after = EPOLLET;
            if (conn->wantRead())
                after |= EPOLLIN;
            if (conn->wantWrite())
                after |= EPOLLOUT;
            if ((after & ~static_cast<uint32_t>(EPOLLET)) == 0)
                return IoStatus::close;
            if (after != conn->events())
            {
                if (loop_.modFd(conn->fd(), after, conn))
                    return IoStatus::close;
                conn->setEvents(after);
            }
        }
        return IoStatus::keep;
    }

    // std::nullopt once the backlog is drained, otherwise the errno that
    // ended the sweep. A caller may ignore it: a refused accept is a load
    // signal and the listener stays up either way.
    [[nodiscard]] inline std::optional<Err> acceptAll()
    {
        // The listening socket is edge triggered, so one notification has to
        // be drained completely or the backlog stalls until the next connect.
        while (true)
        {
            sockaddr_in addr{};
            socklen_t len = sizeof addr;
            int fd = ::accept4(listener_.fd, reinterpret_cast<sockaddr *>(&addr), &len, SOCK_NONBLOCK | SOCK_CLOEXEC);
            if (fd < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    return std::nullopt;
                if (errno == EINTR)
                    continue;
                // Descriptor or buffer exhaustion is a load signal, not a
                // reason to tear the listener down.
                if (errno == EMFILE || errno == ENFILE || errno == ENOBUFS || errno == ENOMEM)
                    return std::nullopt;
                LOG_ERROR("Reactor::acceptAll: accept4() on fd {} failed: {}", listener_.fd, mynetlog::errnoText(errno));
                return Err::accept_failed;
            }
            onNewConnection(fd, addr);
        }
    }

    inline void onNewConnection(int fd, const sockaddr_in &addr)
    {
        Conn *conn = connPool_.acquire();
        if (conn == nullptr)
        {
            // The pool is the admission limit: refusing here keeps the
            // descriptor from leaking and keeps accept() moving.
            LOG_WARN("Reactor::onNewConnection: connection pool exhausted, closing fd {}", fd);
            ::close(fd);
            return;
        }
        conn->setFd(fd);
        conn->addr() = addr;
        conn->touch();
        if constexpr (mustEventSSL<Event>)
        {
            if (protocol_.ctx != nullptr && conn->startTLS(protocol_.ctx).has_value())
            {
                LOG_WARN("Reactor::onNewConnection: TLS setup for fd {} failed: {}", fd, mynetlog::sslText());
                connPool_.release(conn);
                return;
            }
        }
        index_.emplace(fd, conn);
        uint32_t events = EPOLLIN | EPOLLET;
        if (conn->wantWrite())
            events |= EPOLLOUT; // a TLS handshake wants to write straight away
        if (loop_.addFd(fd, events, conn))
        {
            LOG_WARN("Reactor::onNewConnection: adding fd {} to the loop failed: {}", fd, mynetlog::errnoText(errno));
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
            (void)loop_.delFd(fd);
            index_.erase(fd);
        }
        // release() resets the connection, which closes the descriptor and
        // clears the handler and its queues before the pool hands it out
        // again.
        connPool_.release(conn);
    }

    // One descriptor wears every peer, so a readiness notification says only
    // that *somebody* wrote. Read until the socket is empty, however many
    // senders that takes: edge triggered epoll will not mention the rest of
    // them again.
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
                    break;
                if (errno == EINTR)
                    continue;
                LOG_WARN("Reactor::drainDatagrams: recvfrom on fd {} failed: {}", listener_.fd, mynetlog::errnoText(errno));
                break;
            }
            size_t got = static_cast<size_t>(n);
            if (got > cap)
            {
                LOG_WARN("Reactor::drainDatagrams: {} bytes from {} exceeds the {} byte limit, truncated to the limit", got,
                         datagramPeerText(peer), cap);
                got = cap;
            }
            datagram_->onDatagram(peer, udpIn_.data(), got);
        }
        flushDatagrams();
    }

    // A reply that the kernel will not take is dropped rather than retried: a
    // datagram socket has nowhere to hold it, and a UDP queue that grows on
    // EAGAIN would turn a dropped packet into unbounded memory.
    inline void flushDatagrams()
    {
        while (datagram_->hasReply())
        {
            DatagramReply reply = datagram_->takeReply();
            ssize_t sent = ::sendto(listener_.fd, reply.bytes.data(), reply.bytes.size(), 0,
                                    reinterpret_cast<const sockaddr *>(&reply.peer), static_cast<socklen_t>(sizeof(sockaddr_in)));
            if (sent < 0)
                LOG_WARN("Reactor::flushDatagrams: sendto to {} failed: {}", datagramPeerText(reply.peer), mynetlog::errnoText(errno));
        }
    }

    inline void sweepIdle()
    {
        if (idleTimeout_.count() <= 0)
            return;
        auto now = std::chrono::steady_clock::now();
        sweepScratch_.clear();
        for (auto &entry : index_)
        {
            if (now - entry.second->lastActive() >= idleTimeout_)
                sweepScratch_.push_back(entry.second);
        }
        for (Conn *conn : sweepScratch_)
            closeConn(conn);
    }

    Event listener_;
    EventLoop loop_;
    Protocol<Event> protocol_{};
    ObjectPool<Conn> connPool_{};
    std::unordered_map<int, Conn *> index_{};
    std::vector<Conn *> sweepScratch_{};
    // Non-null only between run_udp()'s bind and its return: it is what tells
    // the shared onEvent() that this listener has peers instead of clients.
    DatagramHandler *datagram_ = nullptr;
    std::vector<char> udpIn_{};
    std::chrono::seconds idleTimeout_{0};
    uint64_t idleTimerId_ = 0;
};
