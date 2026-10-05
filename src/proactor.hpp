#pragma once

#include "connection.hpp"
#include "datagram.hpp"
#include "event.hpp"
#include "log.hpp"
#include "myconcepts.hpp"
#include "objectPool.hpp"
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <liburing.h>
#include <poll.h>
#include <stop_token>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

// The proactor answers the same question as the reactor -- what happens when a
// socket becomes readable or writable -- with a different engine: io_uring,
// where the completions arrive instead of the readiness.
//
// The shape it keeps from the old version is the one that pays off:
// a registered buffer ring plus multishot recv, so one submission keeps
// delivering received bytes without a syscall per packet, and the receive
// buffer is picked by the kernel rather than allocated by us.
//
// The shape it changes is ownership. A Session owns its Connection, and the
// Connection owns its handler, its read buffer and its write queue. Every
// io_uring operation that names a session bumps inFlight; the session is only
// handed back to the pool once it is dead *and* nothing is in flight. That is
// what stops a connection from being recycled while the kernel is still
// writing into it or still reading from its send buffer.
//
// Later protocols hang off the same seam as in the reactor: one Session per
// connection, one handler, one write queue. A datagram socket is the one
// shape that does not fit that seam -- there is no connection to own -- so it
// gets one outstanding recvmsg and no session at all, sharing the ring and
// the wait loop with everything else.
template <typename Event>
    requires mustDerivedFromEventBase<Event> && mustResettable<Event> &&
             (mustHandleProtocol<typename Event::Handler> ||
              mustDerivedFromDatagramHandler<typename Event::Handler>)
class Proactor
{
public:
    using Handler = typename Event::Handler;
    using Conn = Connection<Handler>;

private:
    enum class OpKind : uint8_t
    {
        accept = 1,
        recv = 2,
        send = 3,
        poll = 4,
        datagram = 5
    };

    struct Session;

    struct OpBase
    {
        OpKind kind{};
        Session *session = nullptr;
    };

    struct Session
    {
        Conn conn{};
        OpBase recvOp{OpKind::recv, this};
        OpBase sendOp{OpKind::send, this};
        OpBase pollOp{OpKind::poll, this};
        size_t slot = 0;
        int inFlight = 0;
        bool dead = false;
        bool recycled = false;
        bool recvPosted = false;
        bool sendPosted = false;
        bool pollPosted = false;
        // Set when a poll this session owns was withdrawn by closeSession():
        // the completion is still owed, and it is the one that releases the
        // session's last in-flight count.
        bool pollRetired = false;

        inline void reset() noexcept
        {
            conn.reset();
            slot = 0;
            inFlight = 0;
            dead = false;
            recycled = false;
            recvPosted = false;
            sendPosted = false;
            pollPosted = false;
            pollRetired = false;
        }
    };

    struct AcceptOp : public OpBase
    {
        AcceptOp() noexcept { this->kind = OpKind::accept; }

        sockaddr_in addr{};
        socklen_t addrLen = static_cast<socklen_t>(sizeof(sockaddr_in));

        inline void reset() noexcept
        {
            addr = {};
            addrLen = static_cast<socklen_t>(sizeof(sockaddr_in));
        }
    };

    // A datagram socket's one outstanding read.
    //
    // There is nothing to pool here and no session to hang it on: the socket
    // outlives every message, and the sender travels inside the message
    // instead of being a property of a connection. The operation is a plain
    // member whose address never moves, which is what io_uring requires and
    // what the msghdr pointing at its own fields relies on.
    struct DatagramOp : public OpBase
    {
        DatagramOp() noexcept { this->kind = OpKind::datagram; }

        sockaddr_in peer{};
        struct iovec iov{};
        struct msghdr msg{};
    };

public:
    Proactor() noexcept = default;
    ~Proactor() noexcept { reset(); }
    Proactor(const Proactor &) = delete("a proactor owns the io_uring ring and the buffers handed to the kernel");
    Proactor &operator=(const Proactor &) = delete("a proactor owns the io_uring ring and the buffers handed to the kernel");
    Proactor(Proactor &&) noexcept = delete("a proactor owns the io_uring ring and the buffers handed to the kernel");
    Proactor &operator=(Proactor &&) noexcept = delete("a proactor owns the io_uring ring and the buffers handed to the kernel");

    // std::nullopt once the engine has run and been stopped; otherwise the
    // named failure -- see Err. The reactor and the proactor now report the
    // same failure with the same name instead of two private numberings.
    [[nodiscard]] std::optional<Err> run_tcp(const char *ip, int port, int backlog = 511,
                                             unsigned int sqEntries = 512, unsigned int cqEntries = 1024,
                                             int maxAcceptEvents = 256, size_t sessionPoolSize = 512,
                                             int maxBufEntrs = 1024, int bufSize = 4096,
                                             int idleTimeoutSecs = 0)
        requires mustEventSocket<Event>
    {
        if (std::optional<Err> err = acceptor_.listen_tcp(ip, port, backlog))
        {
            reset();
            return err;
        }
        std::optional<Err> rc = serve(sqEntries, cqEntries, maxAcceptEvents, sessionPoolSize,
                                      maxBufEntrs, bufSize, idleTimeoutSecs);
        reset();
        return rc;
    }

    // The TLS run adds a context to the skeleton run_tcp uses. The ring, the
    // buffer ring and the accept pipeline are protocol independent; what TLS
    // changes is how an accepted session's bytes are driven -- a poll that
    // hands the descriptor to the SSL object, instead of a multishot recv that
    // would take the records away from it.
    //
    // Returns everything run_tcp does, plus the failures that belong to the
    // certificate material.
    [[nodiscard]] std::optional<Err> run_ssl(const char *ip, int port, const char *crt, const char *key,
                                             int backlog = 511, unsigned int sqEntries = 512,
                                             unsigned int cqEntries = 1024, int maxAcceptEvents = 256,
                                             size_t sessionPoolSize = 512, int maxBufEntrs = 1024,
                                             int bufSize = 4096, int idleTimeoutSecs = 0)
        requires mustEventSSL<Event>
    {
        if (std::optional<Err> err = acceptor_.listen_tcp(ip, port, backlog))
        {
            reset();
            return err;
        }
        if ((protocol_.ctx = SSL_CTX_new(TLS_server_method())) == nullptr)
        {
            LOG_ERROR("Proactor::run_ssl: SSL_CTX_new() failed: {}", mynetlog::sslText());
            reset();
            return Err::ssl_ctx_failed;
        }
        if (SSL_CTX_use_certificate_file(protocol_.ctx, crt, SSL_FILETYPE_PEM) <= 0)
        {
            LOG_ERROR("Proactor::run_ssl: certificate file \"{}\" could not be loaded: {}", crt, mynetlog::sslText());
            reset();
            return Err::ssl_cert_failed;
        }
        if (SSL_CTX_use_PrivateKey_file(protocol_.ctx, key, SSL_FILETYPE_PEM) <= 0)
        {
            LOG_ERROR("Proactor::run_ssl: private key file \"{}\" could not be loaded: {}", key, mynetlog::sslText());
            reset();
            return Err::ssl_key_failed;
        }
        if (SSL_CTX_check_private_key(protocol_.ctx) <= 0)
        {
            LOG_ERROR("Proactor::run_ssl: private key \"{}\" does not match certificate \"{}\": {}", key, crt, mynetlog::sslText());
            reset();
            return Err::ssl_key_mismatch;
        }
        std::optional<Err> rc = serve(sqEntries, cqEntries, maxAcceptEvents, sessionPoolSize,
                                      maxBufEntrs, bufSize, idleTimeoutSecs);
        reset();
        return rc;
    }

    // One datagram socket, one outstanding recvmsg, no sessions.
    //
    // The engine below is shared with run_tcp: the same ring, the same buffer
    // pool, the same wait loop and the same stop(). What differs is the
    // operation that is armed. A datagram read needs recvmsg() rather than
    // recv() because the sender's address is part of the message, and it is
    // single shot rather than multishot because the registered buffer ring
    // exists so that *many* connections can share receive buffers -- which one
    // socket does not need, and which would interleave peers' messages
    // unpredictably if it did.
    //
    // The handler is passed in rather than owned: its limits and any keys it
    // verifies against are the application's to set.
    [[nodiscard]] std::optional<Err> run_udp(const char *ip, int port, Handler &handler,
                                             unsigned int sqEntries = 512, unsigned int cqEntries = 1024,
                                             size_t sessionPoolSize = 512, int bufSize = 65536,
                                             int idleTimeoutSecs = 0)
        requires mustDerivedFromDatagramHandler<Handler>
    {
        if (std::optional<Err> err = acceptor_.listen_udp(ip, port))
        {
            reset();
            return err;
        }
        handler.reset();
        datagram_ = &handler;
        datagramIn_.resize(static_cast<size_t>(bufSize > 0 ? bufSize : 65536));
        // No accepts, and no buffer ring: 0 entries is what tells serve() to
        // arm the datagram read instead.
        std::optional<Err> rc = serve(sqEntries, cqEntries, 0, sessionPoolSize, 0, bufSize, idleTimeoutSecs);
        reset();
        return rc;
    }

    inline void stop() const noexcept { stopSource_.request_stop(); }

    // The engine both runs share: everything from the ring itself down to the
    // wait loop. It differs from the two callers only in what a session is, not
    // in how one is accepted or retired.
    // std::nullopt once the wait loop has been stopped; otherwise why the ring
    // could not be brought up or why the wait itself failed.
    [[nodiscard]] inline std::optional<Err> serve(unsigned int sqEntries, unsigned int cqEntries,
                                                  int maxAcceptEvents, size_t sessionPoolSize,
                                                  int maxBufEntrs, int bufSize, int idleTimeoutSecs)
    {
        io_uring_params params = {};
        params.flags = IORING_SETUP_CQSIZE;
        params.cq_entries = cqEntries;
        int qi = io_uring_queue_init_params(sqEntries, &uring_, &params);
        if (qi < 0)
        {
            LOG_ERROR("Proactor::serve: io_uring_queue_init_params({} submission entries) failed: {}", sqEntries,
                      mynetlog::errnoText(-qi));
            reset();
            return Err::uring_queue_failed;
        }
        uringInited_ = true;
        // A datagram run has no sessions at all, so one spare slot is enough
        // to keep the pool honest without constructing hundreds of connection
        // objects nobody will ever accept.
        sessionPool_.init(datagram_ != nullptr ? 1 : (sessionPoolSize > 0 ? sessionPoolSize : 1));
        acceptPool_.init(static_cast<size_t>(maxAcceptEvents > 0 ? maxAcceptEvents : 1));
        sessions_.reserve(sessionPoolSize > 0 ? sessionPoolSize : 1);
        maxAccepts_ = maxAcceptEvents > 0 ? maxAcceptEvents : 1;
        maxBufEntrs_ = maxBufEntrs > 0 ? maxBufEntrs : 0;
        bufSize_ = bufSize > 0 ? bufSize : 4096;
        if (maxBufEntrs_ > 0)
        {
            int ma = posix_memalign(&bufBase_, 4096, static_cast<size_t>(maxBufEntrs_) * static_cast<size_t>(bufSize_));
            if (ma != 0)
            {
                LOG_ERROR("Proactor::serve: posix_memalign for {} buffers of {} bytes failed: {}", maxBufEntrs_,
                          bufSize_, mynetlog::errnoText(ma));
                bufBase_ = nullptr;
                reset();
                return Err::uring_memalign_failed;
            }
            int ringErr = 0;
            bufRing_ = io_uring_setup_buf_ring(&uring_, static_cast<unsigned>(maxBufEntrs_), bgid_, 0, &ringErr);
            if (bufRing_ == nullptr)
            {
                LOG_ERROR("Proactor::serve: io_uring_setup_buf_ring({} buffers, bgid {}) failed: {}", maxBufEntrs_, bgid_,
                          mynetlog::errnoText(ringErr));
                reset();
                return Err::uring_buf_ring_failed;
            }
            for (int i = 0; i < maxBufEntrs_; ++i)
                io_uring_buf_ring_add(bufRing_, reinterpret_cast<char *>(bufBase_) + static_cast<size_t>(i) * static_cast<size_t>(bufSize_), static_cast<unsigned int>(bufSize_), i,
                                      io_uring_buf_ring_mask(static_cast<unsigned>(maxBufEntrs_)), i);
            io_uring_buf_ring_advance(bufRing_, maxBufEntrs_);
        }
        idleTimeout_ = std::chrono::seconds(idleTimeoutSecs > 0 ? idleTimeoutSecs : 0);
        std::optional<Err> armed = datagram_ != nullptr ? postDatagramRecv() : postAccepts(maxAccepts_);
        if (armed)
        {
            reset();
            return armed;
        }
        int si = io_uring_submit(&uring_);
        if (si < 0)
        {
            LOG_ERROR("Proactor::serve: submitting the initial accepts failed: {}", mynetlog::errnoText(-si));
            reset();
            return Err::uring_submit_failed;
        }
        // A one second cap on the wait is what lets stop() and the idle sweep
        // work without a second thread or an eventfd: the loop simply wakes up
        // on its own when no completion arrives.
        __kernel_timespec ts = {1, 0};
        while (!stopSource_.stop_requested())
        {
            io_uring_cqe *cqe = nullptr;
            int e = io_uring_wait_cqe_timeout(&uring_, &cqe, &ts);
            if (e == -ETIME || e == -EINTR)
            {
                sweepIdle();
                continue;
            }
            if (e < 0)
            {
                LOG_ERROR("Proactor::serve: io_uring_wait_cqe_timeout() failed: {}", mynetlog::errnoText(-e));
                reset();
                return Err::uring_wait_failed;
            }
            unsigned int head = 0;
            unsigned int count = 0;
            io_uring_for_each_cqe(&uring_, head, cqe)
            {
                ++count;
                handleCqe(cqe);
            }
            io_uring_cq_advance(&uring_, count);
            while (datagram_ == nullptr && acceptOutstanding_ < maxAccepts_)
            {
                if (postOneAccept().has_value())
                    break;
            }
            postCancels();
            int si = io_uring_submit(&uring_);
            if (si < 0)
            {
                LOG_ERROR("Proactor::serve: submitting the completion batch failed: {}", mynetlog::errnoText(-si));
                reset();
                return Err::uring_submit_failed;
            }
            sweepIdle();
        }
        reset();
        return std::nullopt;
    }

    inline void reset() noexcept
    {
        if (bufRing_ != nullptr && uringInited_)
        {
            io_uring_free_buf_ring(&uring_, bufRing_, static_cast<unsigned>(maxBufEntrs_), bgid_);
            bufRing_ = nullptr;
        }
        if (bufBase_ != nullptr)
        {
            ::free(bufBase_);
            bufBase_ = nullptr;
        }
        maxBufEntrs_ = 0;
        bufSize_ = 4096;
        bgid_ = 1;
        acceptPool_.reset();
        sessionPool_.reset();
        sessions_.clear();
        acceptOutstanding_ = 0;
        maxAccepts_ = 0;
        idleTimeout_ = std::chrono::seconds(0);
        if (uringInited_)
        {
            io_uring_queue_exit(&uring_);
            uring_ = {};
            uringInited_ = false;
        }
        acceptor_.reset();
        datagram_ = nullptr;
        datagramIn_.clear();
        cancelScratch_.clear();
        if constexpr (mustEventSSL<Event>)
        {
            if (protocol_.ctx != nullptr)
            {
                SSL_CTX_free(protocol_.ctx);
                protocol_.ctx = nullptr;
            }
        }
    }

    inline size_t sessions() const noexcept { return sessions_.size(); }
    inline io_uring *ring() noexcept { return &uring_; }

private:
    inline void handleCqe(io_uring_cqe *cqe)
    {
        auto *base = static_cast<OpBase *>(io_uring_cqe_get_data(cqe));
        if (base == nullptr)
            return;
        switch (base->kind)
        {
        case OpKind::accept:
            onAcceptDone(cqe, static_cast<AcceptOp *>(base));
            break;
        case OpKind::recv:
            onRecvDone(cqe, base->session);
            break;
        case OpKind::send:
            onSendDone(cqe, base->session);
            break;
        case OpKind::poll:
            onPollDone(cqe, base->session);
            break;
        case OpKind::datagram:
            onDatagramDone(cqe);
            break;
        default:
            break;
        }
    }

    // The sender's address arrives in the msghdr's msg_name, which is why this
    // path cannot use the multishot recv the stream path is built on: that one
    // is bound to a buffer ring and hands back bytes without a peer.
    inline void onDatagramDone(io_uring_cqe *cqe)
    {
        if (cqe->res < 0)
        {
            LOG_WARN("Proactor::onDatagramDone: recvmsg on fd {} failed: {}", acceptor_.fd, mynetlog::errnoText(-cqe->res));
        }
        else if (cqe->res > 0)
        {
            const size_t asked = datagram_->maxDatagramBytes();
            size_t got = static_cast<size_t>(cqe->res);
            if (got > asked)
            {
                LOG_WARN("Proactor::onDatagramDone: {} bytes from {} exceeds the {} byte limit, truncated to the limit", got,
                         datagramPeerText(datagramOp_.peer), asked);
                got = asked;
            }
            if ((datagramOp_.msg.msg_flags & MSG_TRUNC) != 0)
                LOG_WARN("Proactor::onDatagramDone: a datagram from {}", datagramPeerText(datagramOp_.peer));
            datagram_->onDatagram(datagramOp_.peer, datagramIn_.data(), got);
            flushDatagrams();
        }
        // Re-arm before returning: the socket must not wait for the next
        // event-loop turn to have a read outstanding, or a peer that sends
        // twice in a row would see the second message delayed by a full wait.
        if (!stopSource_.stop_requested())
        {
            if (std::optional<Err> rc = postDatagramRecv())
                LOG_ERROR("Proactor::onDatagramDone: re-arming the datagram read failed: {}", to_string(*rc));
        }
    }

    // A reply the kernel will not take is dropped rather than retried: a
    // datagram socket has nowhere to hold it.
    inline void flushDatagrams()
    {
        while (datagram_->hasReply())
        {
            DatagramReply reply = datagram_->takeReply();
            ssize_t sent = ::sendto(acceptor_.fd, reply.bytes.data(), reply.bytes.size(), 0,
                                    reinterpret_cast<const sockaddr *>(&reply.peer), static_cast<socklen_t>(sizeof(sockaddr_in)));
            if (sent < 0)
                LOG_WARN("Proactor::flushDatagrams: sendto to {} failed: {}", datagramPeerText(reply.peer), mynetlog::errnoText(errno));
        }
    }

    // std::nullopt once the datagram read is on the ring, otherwise the
    // submission queue refused to arm it.
    [[nodiscard]] inline std::optional<Err> postDatagramRecv()
    {
        io_uring_sqe *sqe = getSqe();
        if (sqe == nullptr)
            return Err::uring_sqe_failed;
        datagramOp_.peer = {};
        datagramOp_.iov.iov_base = datagramIn_.data();
        datagramOp_.iov.iov_len = datagramIn_.size();
        datagramOp_.msg = {};
        datagramOp_.msg.msg_name = &datagramOp_.peer;
        datagramOp_.msg.msg_namelen = static_cast<socklen_t>(sizeof(sockaddr_in));
        datagramOp_.msg.msg_iov = &datagramOp_.iov;
        datagramOp_.msg.msg_iovlen = 1;
        io_uring_prep_recvmsg(sqe, acceptor_.fd, &datagramOp_.msg, 0);
        io_uring_sqe_set_data(sqe, &datagramOp_);
        return std::nullopt;
    }

    // std::nullopt once every requested accept is posted, otherwise the
    // reason the last one could not be.
    [[nodiscard]] inline std::optional<Err> postAccepts(int count)
    {
        for (int i = 0; i < count; ++i)
        {
            if (std::optional<Err> rc = postOneAccept())
                return rc;
        }
        return std::nullopt;
    }

    inline io_uring_sqe *getSqe()
    {
        io_uring_sqe *sqe = io_uring_get_sqe(&uring_);
        if (sqe != nullptr)
            return sqe;
        // The submission queue is full: pushing what is already queued is what
        // frees a slot. Failing here would otherwise drop a live connection.
        int si = io_uring_submit(&uring_);
        if (si < 0)
        {
            LOG_ERROR("Proactor::getSqe: flushing a full submission queue failed: {}", mynetlog::errnoText(-si));
            return nullptr;
        }
        return io_uring_get_sqe(&uring_);
    }

    // std::nullopt when the accept is on the ring; otherwise the pool or the
    // submission queue refused to arm it.
    [[nodiscard]] inline std::optional<Err> postOneAccept()
    {
        AcceptOp *op = acceptPool_.acquire();
        if (op == nullptr)
        {
            LOG_WARN("Proactor::postOneAccept: all {} accept slots are in use", maxAccepts_);
            return Err::uring_accept_exhausted;
        }
        io_uring_sqe *sqe = getSqe();
        if (sqe == nullptr)
        {
            LOG_WARN("Proactor::postOneAccept: no submission queue entry available");
            acceptPool_.release(op);
            return Err::uring_sqe_failed;
        }
        op->addrLen = static_cast<socklen_t>(sizeof(sockaddr_in));
        io_uring_prep_accept(sqe, acceptor_.fd, reinterpret_cast<sockaddr *>(&op->addr), &op->addrLen, SOCK_NONBLOCK | SOCK_CLOEXEC);
        io_uring_sqe_set_data(sqe, op);
        ++acceptOutstanding_;
        return std::nullopt;
    }

    inline void onAcceptDone(io_uring_cqe *cqe, AcceptOp *op)
    {
        --acceptOutstanding_;
        if (cqe->res >= 0)
            onNewConnection(cqe->res, op->addr);
        // A refused accept (descriptor or buffer exhaustion) is a load signal:
        // the op goes back and the connection is simply not taken. Logged at
        // debug level: under a full backlog this is the expected steady state.
        else
            LOG_DEBUG("Proactor::onAcceptDone: accept() failed: {}", mynetlog::errnoText(-cqe->res));
        acceptPool_.release(op);
    }

    inline void onNewConnection(int fd, const sockaddr_in &addr)
    {
        Session *session = sessionPool_.acquire();
        if (session == nullptr)
        {
            LOG_WARN("Proactor::onNewConnection: session pool exhausted, closing fd {}", fd);
            ::close(fd);
            return;
        }
        session->dead = false;
        session->recycled = false;
        session->inFlight = 0;
        session->recvPosted = false;
        session->sendPosted = false;
        session->pollPosted = false;
        session->pollRetired = false;
        session->conn.setFd(fd);
        session->conn.addr() = addr;
        session->conn.touch();
        if constexpr (mustEventSSL<Event>)
        {
            // The handshake starts as soon as the descriptor exists: it is the
            // first poll, posted just below, that carries it from there.
            if (protocol_.ctx == nullptr || session->conn.startTLS(protocol_.ctx).has_value())
            {
                LOG_WARN("Proactor::onNewConnection: TLS setup for fd {} failed: {}", fd, mynetlog::sslText());
                sessionPool_.release(session);
                return;
            }
        }
        session->slot = sessions_.size();
        sessions_.push_back(session);
        if (postRecv(session) == IoStatus::close)
            closeSession(session);
    }

    // A TLS session is driven rather than read. SSL_read()/SSL_write() own the
    // record layer, so a recv(2) posted on the same descriptor would take bytes
    // out from under the SSL object and leave it holding a stream that is no
    // longer the one on the wire. What the ring is asked for instead is
    // readiness -- and because poll reports a state rather than an edge, the
    // mask may name only what the connection is really blocked on.
    // writeBlocked() is that mask's writable half: wantWrite() counts an
    // unfinished handshake as writable, which is exactly right for an edge
    // triggered epoll and a spin for a level triggered poll.
    // IoStatus::close when there is nothing left to wait for, or when the
    // submission queue would not take another wait; both mean this session has
    // no future and the caller should retire it.
    [[nodiscard]] inline IoStatus postPoll(Session *session)
    {
        Conn &conn = session->conn;
        unsigned int mask = 0;
        if (conn.wantRead())
            mask |= POLLIN;
        if (conn.writeBlocked())
            mask |= POLLOUT;
        if (mask == 0)
            return IoStatus::close;
        io_uring_sqe *sqe = getSqe();
        if (sqe == nullptr)
        {
            LOG_WARN("Proactor::postPoll: no submission queue entry for fd {}", conn.fd());
            return IoStatus::close;
        }
        io_uring_prep_poll_add(sqe, conn.fd(), mask);
        io_uring_sqe_set_data(sqe, &session->pollOp);
        session->pollPosted = true;
        ++session->inFlight;
        return IoStatus::keep;
    }

    [[nodiscard]] inline IoStatus postRecv(Session *session)
    {
        if (session->conn.ssl() != nullptr)
            return postPoll(session);
        io_uring_sqe *sqe = getSqe();
        if (sqe == nullptr)
        {
            LOG_WARN("Proactor::postRecv: no submission queue entry for fd {}", session->conn.fd());
            return IoStatus::close;
        }
        io_uring_prep_recv_multishot(sqe, session->conn.fd(), nullptr, 0, 0);
        sqe->buf_group = static_cast<uint16_t>(bgid_);
        sqe->flags |= IOSQE_BUFFER_SELECT;
        io_uring_sqe_set_data(sqe, &session->recvOp);
        session->recvPosted = true;
        ++session->inFlight;
        return IoStatus::keep;
    }

    inline void onRecvDone(io_uring_cqe *cqe, Session *session)
    {
        // A TLS session arms no raw recv -- the poll path drives it -- so a
        // completion here can only belong to a teardown. The count is settled
        // anyway, because it is what lets the session reach zero and be
        // recycled.
        if (session->conn.ssl() != nullptr)
        {
            if (!(cqe->flags & IORING_CQE_F_MORE))
            {
                session->recvPosted = false;
                --session->inFlight;
            }
            settleSession(session);
            return;
        }
        // A multishot recv is one submitted operation that reports many
        // completions; the operation itself is only in flight until the stream
        // ends. Decrementing per completion would drive the count negative and
        // keep the session from ever being recycled.
        if (!(cqe->flags & IORING_CQE_F_MORE))
        {
            session->recvPosted = false;
            --session->inFlight;
        }
        bool peerGone = false;
        bool fatal = false;
        if (cqe->res == 0)
        {
            peerGone = true;
        }
        else if (cqe->res < 0)
        {
            int err = -cqe->res;
            if (err == ECANCELED)
                peerGone = true;
            else if (err == EAGAIN || err == EWOULDBLOCK || err == EINTR || err == ENOBUFS)
            {} // transient: the multishot stream, if it ended, is re-armed below
            else
            {
                LOG_WARN("Proactor::onRecvDone: fd {}: recv() failed: {}", session->conn.fd(),
                         mynetlog::errnoText(err));
                fatal = true;
            }
        }
        else if (cqe->flags & IORING_CQE_F_BUFFER)
        {
            unsigned int bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
            if (static_cast<int>(bid) < maxBufEntrs_)
            {
                char *buf = reinterpret_cast<char *>(bufBase_) + static_cast<size_t>(bid) * static_cast<size_t>(bufSize_);
                Handler &handler = session->conn.handler();
                handler.appendRequest(buf, static_cast<ssize_t>(cqe->res));
                if (handler.requestOverLimit())
                {
                    handler.onParseError("request exceeds the read limit");
                    session->conn.setCloseAfterWrite(true);
                }
                else
                {
                    handler.process();
                }
                session->conn.touch();
                // The handler has copied what it needs, so the kernel can have
                // the buffer back before the response is written.
                recycleBuffer(bid);
                session->conn.pump();
                sendPending(session);
            }
        }
        if (fatal)
        {
            session->conn.onFatal();
            closeSession(session);
            settleSession(session);
            return;
        }
        if (peerGone)
        {
            session->conn.onPeerGone();
            if (session->conn.pendingSize() == 0)
            {
                closeSession(session);
                settleSession(session);
                return;
            }
        }
        else if (!session->dead && !session->recvPosted)
        {
            // A multishot stream that ended for a transient reason (a full
            // buffer ring, say) is re-armed: the connection is still alive.
            if (postRecv(session) == IoStatus::close)
                closeSession(session);
        }
        settleSession(session);
    }

    // A poll completion carries a readiness mask in res, not a byte count, and
    // it is level triggered: the readiness is acted on once and then the wait
    // is armed again. The connection is read and written directly here, exactly
    // as the reactor does it -- one TLS state machine, driven by two engines.
    inline void onPollDone(io_uring_cqe *cqe, Session *session)
    {
        // A withdrawn poll still completes, and by the time it does the session
        // may already have been handed to a new connection: only the completion
        // that pollRetired marked is still owed to this generation, every other
        // one names a session that no longer exists.
        if (!session->pollPosted && !session->pollRetired)
            return;
        session->pollPosted = false;
        bool retired = session->pollRetired;
        session->pollRetired = false;
        --session->inFlight;
        if (retired)
        {
            settleSession(session);
            return;
        }
        Conn &conn = session->conn;
        if (cqe->res < 0)
        {
            int err = -cqe->res;
            if (err != EAGAIN && err != EWOULDBLOCK && err != EINTR)
            {
                LOG_WARN("Proactor::onPollDone: fd {}: poll() failed: {}", conn.fd(), mynetlog::errnoText(err));
                conn.onFatal();
                closeSession(session);
            }
            else if (postPoll(session) == IoStatus::close)
            {
                closeSession(session);
            }
            settleSession(session);
            return;
        }
        // A hangup with nothing readable behind it is a peer that is already
        // gone: there is no last request left to hand the handler.
        if ((cqe->res & (POLLERR | POLLHUP)) && !(cqe->res & POLLIN))
        {
            closeSession(session);
            settleSession(session);
            return;
        }
        if (cqe->res & POLLIN)
        {
            if (conn.handleRead() == IoStatus::close)
            {
                closeSession(session);
                settleSession(session);
                return;
            }
        }
        if (cqe->res & POLLOUT)
        {
            if (conn.handleWrite() == IoStatus::close)
            {
                closeSession(session);
                settleSession(session);
                return;
            }
        }
        conn.pump();
        // The wait goes back armed with what the connection is blocked on now:
        // a socket with nothing left to say is retired.
        if (postPoll(session) == IoStatus::close)
            closeSession(session);
        settleSession(session);
    }

    inline void sendPending(Session *session)
    {
        if (session->sendPosted || session->dead)
            return;
        Conn &conn = session->conn;
        // The write of a TLS session belongs to the poll path, where
        // SSL_write() turns the queued bytes into records: a raw send(2) here
        // would put ciphertext on the wire that no SSL object produced, and
        // would leave the handshake bytes of a not yet finished session
        // queued behind them.
        if (conn.ssl() != nullptr)
            return;
        size_t n = conn.pendingSize();
        if (n == 0)
        {
            if (conn.closeAfterWrite())
                closeSession(session);
            return;
        }
        io_uring_sqe *sqe = getSqe();
        if (sqe == nullptr)
        {
            LOG_WARN("Proactor::sendPending: no submission queue entry for fd {}", conn.fd());
            closeSession(session);
            return;
        }
        // pendingData() points into the front response of the write queue. The
        // queue is only advanced when this send completes, and a new response
        // is appended at the back, so the pointer stays valid for the whole
        // operation.
        io_uring_prep_send(sqe, conn.fd(), conn.pendingData(), n, MSG_NOSIGNAL);
        io_uring_sqe_set_data(sqe, &session->sendOp);
        session->sendPosted = true;
        ++session->inFlight;
    }

    inline void onSendDone(io_uring_cqe *cqe, Session *session)
    {
        --session->inFlight;
        session->sendPosted = false;
        if (cqe->res < 0)
        {
            int err = -cqe->res;
            if (err != EAGAIN && err != EWOULDBLOCK && err != EINTR && err != ECANCELED)
            {
                LOG_WARN("Proactor::onSendDone: fd {}: send() failed: {}", session->conn.fd(),
                         mynetlog::errnoText(err));
                session->conn.onFatal();
                closeSession(session);
                settleSession(session);
                return;
            }
        }
        else if (cqe->res > 0)
        {
            (void)session->conn.commitSent(static_cast<size_t>(cqe->res));
            session->conn.touch();
        }
        else
        {
            // A send that moved no bytes can only repeat itself.
            LOG_WARN("Proactor::onSendDone: fd {}: send() completed without moving bytes", session->conn.fd());
            session->conn.onFatal();
            closeSession(session);
            settleSession(session);
            return;
        }
        if (session->dead)
        {
            settleSession(session);
            return;
        }
        if (session->conn.closeAfterWrite() && session->conn.pendingSize() == 0)
        {
            closeSession(session);
            settleSession(session);
            return;
        }
        sendPending(session);
        settleSession(session);
    }

    inline void closeSession(Session *session)
    {
        if (session->dead)
            return;
        session->dead = true;
        session->recvPosted = false;
        session->sendPosted = false;
        // A poll still parked on the ring holds a reference to the descriptor,
        // so it does not complete on its own when the descriptor goes away:
        // the wait has to be withdrawn before the session can be recycled. The
        // withdrawal is queued and submitted with the next batch, and the
        // completion it produces is what releases the last in-flight count.
        if (session->pollPosted)
        {
            session->pollPosted = false;
            session->pollRetired = true;
            cancelScratch_.push_back(session);
        }
        // The descriptor stays open until every operation that names it has
        // completed: closing it early would let the kernel write into a
        // recycled connection object, and would let a brand new connection
        // inherit the descriptor number still in flight.
        if (session->inFlight == 0)
            recycleSession(session);
    }

    // Queue the withdrawal of every poll that closeSession() retired. The
    // removal is an operation like any other, so it needs a submission slot;
    // one that does not fit this round keeps its place and is retired by a
    // later one.
    inline void postCancels()
    {
        size_t done = 0;
        for (Session *session : cancelScratch_)
        {
            io_uring_sqe *sqe = io_uring_get_sqe(&uring_);
            if (sqe == nullptr)
                break;
            io_uring_prep_poll_remove(sqe, reinterpret_cast<uint64_t>(&session->pollOp));
            io_uring_sqe_set_data(sqe, nullptr);
            ++done;
        }
        if (done > 0)
            cancelScratch_.erase(cancelScratch_.begin(), cancelScratch_.begin() + static_cast<long>(done));
    }

    inline void settleSession(Session *session)
    {
        if (session->dead && session->inFlight == 0)
            recycleSession(session);
    }

    inline void recycleSession(Session *session)
    {
        // closeSession() and settleSession() can both reach here for the same
        // session in one completion, so the release has to be idempotent: a
        // second release would put the same object in the pool twice.
        if (session->recycled)
            return;
        session->recycled = true;
        size_t slot = session->slot;
        if (slot < sessions_.size() && sessions_[slot] == session)
        {
            sessions_[slot] = sessions_.back();
            sessions_[slot]->slot = slot;
            sessions_.pop_back();
        }
        sessionPool_.release(session);
    }

    inline void recycleBuffer(unsigned int bid)
    {
        if (bufRing_ == nullptr)
            return;
        io_uring_buf_ring_add(bufRing_, reinterpret_cast<char *>(bufBase_) + static_cast<size_t>(bid) * static_cast<size_t>(bufSize_), static_cast<unsigned int>(bufSize_), static_cast<int>(bid),
                              io_uring_buf_ring_mask(static_cast<unsigned>(maxBufEntrs_)), 0);
        io_uring_buf_ring_advance(bufRing_, 1);
    }

    inline void sweepIdle()
    {
        if (idleTimeout_.count() <= 0)
            return;
        auto now = std::chrono::steady_clock::now();
        sweepScratch_.clear();
        for (Session *session : sessions_)
        {
            if (now - session->conn.lastActive() >= idleTimeout_)
                sweepScratch_.push_back(session);
        }
        for (Session *session : sweepScratch_)
            closeSession(session);
    }

    io_uring uring_{};
    bool uringInited_ = false;
    int bgid_ = 1;
    io_uring_buf_ring *bufRing_ = nullptr;
    int maxBufEntrs_ = 0;
    int bufSize_ = 4096;
    void *bufBase_ = nullptr;
    Event acceptor_;
    Protocol<Event> protocol_{};
    ObjectPool<Session> sessionPool_{};
    ObjectPool<AcceptOp> acceptPool_{};
    std::vector<Session *> sessions_{};
    std::vector<Session *> sweepScratch_{};
    // Polls that closeSession() withdrew, waiting for a free submission slot.
    std::vector<Session *> cancelScratch_{};
    int acceptOutstanding_ = 0;
    int maxAccepts_ = 0;
    // Non-null only for the duration of run_udp(): it is what turns serve()
    // from an accept pipeline into a datagram read, and the one flag every
    // session-shaped step in the loop consults before doing its work.
    DatagramHandler *datagram_ = nullptr;
    DatagramOp datagramOp_{};
    std::vector<char> datagramIn_{};
    std::chrono::seconds idleTimeout_{0};
    std::stop_source stopSource_{};
};
