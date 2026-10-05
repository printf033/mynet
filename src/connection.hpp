#pragma once

#include "error.hpp"
#include "handler.hpp"
#include "log.hpp"
#include "myconcepts.hpp"
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <expected>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <optional>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

// IoEnd -- why one recv() or send() moved no bytes -- lives in error.hpp,
// next to Err, because the peer answers the same question about the same kind
// of socket and both should name the answer identically.

// What the loop should do with the socket once the read or the write path is
// done with it. Two outcomes, because two is all the loop ever decides.
enum class IoStatus : uint8_t
{
    keep,  // still alive: wait for the next readiness event
    close, // drop it now
};

// How far an in-progress TLS handshake got.
enum class HandshakeStatus : uint8_t
{
    done,        // the handshake finished; the connection is open
    in_progress, // more records to exchange
    failed,      // the peer or the library refused
};

// Everything one live connection owns.
//
// The event loop decides *when* a socket is readable or writable; this class
// decides *what that means*. Keeping those apart is what makes the rest
// possible:
//   - TCP and TLS share one code path, so there is exactly one recv/send
//     implementation to get right (TLS is a transport detail, not a second
//     loop).
//   - The handler and its read buffer live here by value, next to the write
//     queue, so a partially sent response can never outlive the object the
//     pool is about to recycle.
//   - writeQueue_ carries whole responses, so one read event may produce
//     several (HTTP/1.1 pipelining) without any of them overwriting another.
//   - state_ plus readPaused_ give the loop the back pressure hooks a real
//     server needs, and give h2/h3 somewhere to hang stream state later.
template <typename HandlerType>
    requires mustHandleProtocol<HandlerType>
class Connection
{
public:
    using Handler = HandlerType;

    enum class ConnState : uint8_t
    {
        handshake,
        open,
        closing,
        closed
    };

private:
    int fd_ = -1;
    sockaddr_in addr_{};
    SSL *ssl_ = nullptr;
    bool handshakeDone_ = false;
    HandlerType handler_{};

    std::deque<std::string> writeQueue_;
    size_t writeOffset_ = 0;
    size_t pendingBytes_ = 0;
    size_t writeHighWaterMark_ = 4 * 1024 * 1024;

    ConnState state_ = ConnState::open;
    bool readPaused_ = false;
    bool wantWrite_ = false;
    bool closeAfterWrite_ = false;
    bool peerGone_ = false;
    bool shutdownSent_ = false;

    uint64_t timerId_ = 0;
    std::chrono::steady_clock::time_point lastActive_{};
    uint32_t events_ = 0;

    // A peer that vanished without sending its close_notify. OpenSSL reads
    // that as a truncated stream: 1.1.1 reported it as SSL_ERROR_SYSCALL with
    // errno == 0 (handled above), 3.0 as an SSL error whose reason code says
    // exactly this. The plain path has no such notion -- recv() returns 0 for
    // a clean and a vanished peer alike -- so both are the same end of
    // stream. Checking the code keeps every other SSL error fatal instead of
    // guessing from the return value.
    inline static bool unexpectedEof() noexcept
    {
#ifdef SSL_R_UNEXPECTED_EOF_WHILE_READING
        unsigned long e = ERR_peek_last_error();
        return e != 0 && ERR_GET_LIB(e) == ERR_LIB_SSL &&
               ERR_GET_REASON(e) == SSL_R_UNEXPECTED_EOF_WHILE_READING;
#else
        return false;
#endif
    }

    // Up to cap bytes, or why none arrived. The count on success is always
    // > 0 -- a read that returned zero is a closed stream, so it is reported
    // as eof rather than as a success the caller has to reinterpret.
    [[nodiscard]] inline std::expected<size_t, IoEnd> doRecv(char *buf, size_t cap) noexcept
    {
        if (ssl_ != nullptr)
        {
            int rn = SSL_read(ssl_, buf, static_cast<int>(cap));
            if (rn > 0)
                return static_cast<size_t>(rn);
            switch (SSL_get_error(ssl_, rn))
            {
            case SSL_ERROR_WANT_READ:
                wantWrite_ = false;
                return std::unexpected(IoEnd::wouldblock);
            case SSL_ERROR_WANT_WRITE:
                wantWrite_ = true;
                return std::unexpected(IoEnd::wouldblock);
            case SSL_ERROR_ZERO_RETURN:
                return std::unexpected(IoEnd::eof);
            case SSL_ERROR_SYSCALL:
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    return std::unexpected(IoEnd::wouldblock);
                if (errno == EINTR)
                    return std::unexpected(IoEnd::interrupted);
                // errno == 0 is a peer that dropped the connection without a
                // close_notify; both cases are an orderly-enough end of stream.
                if (errno == 0 || errno == ECONNRESET || errno == EPIPE)
                    return std::unexpected(IoEnd::eof);
                LOG_WARN("Connection::doRecv: fd {}: SSL_read() failed: {}", fd_, mynetlog::errnoText(errno));
                return std::unexpected(IoEnd::fatal);
            case SSL_ERROR_SSL:
                // A peer that went away without a close_notify surfaces here
                // on OpenSSL 3, not as an end of stream. Handing that back as
                // fatal would throw away a response that is already queued --
                // which is exactly what an HTTP client sending its request
                // and then half closing does. Any other SSL error stays fatal.
                if (unexpectedEof())
                    return std::unexpected(IoEnd::eof);
                LOG_WARN("Connection::doRecv: fd {}: SSL_read() failed: {}", fd_, mynetlog::sslText());
                return std::unexpected(IoEnd::fatal);
            default:
                LOG_WARN("Connection::doRecv: fd {}: SSL_read() failed: {}", fd_, mynetlog::sslText());
                return std::unexpected(IoEnd::fatal);
            }
        }
        ssize_t rn = ::recv(fd_, buf, cap, 0);
        if (rn > 0)
            return static_cast<size_t>(rn);
        if (rn == 0)
            return std::unexpected(IoEnd::eof);
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return std::unexpected(IoEnd::wouldblock);
        if (errno == EINTR)
            return std::unexpected(IoEnd::interrupted);
        if (errno == ECONNRESET || errno == EPIPE)
            return std::unexpected(IoEnd::eof);
        LOG_WARN("Connection::doRecv: fd {}: recv() failed: {}", fd_, mynetlog::errnoText(errno));
        return std::unexpected(IoEnd::fatal);
    }

    // Bytes handed to the kernel, or why nothing moved. No eof: a send to a
    // peer that is gone reports the failure through the socket error itself.
    [[nodiscard]] inline std::expected<size_t, IoEnd> doSend(const char *buf, size_t n) noexcept
    {
        if (ssl_ != nullptr)
        {
            int sn = SSL_write(ssl_, buf, static_cast<int>(n));
            if (sn > 0)
                return static_cast<size_t>(sn);
            switch (SSL_get_error(ssl_, sn))
            {
            case SSL_ERROR_WANT_WRITE:
                wantWrite_ = true;
                return std::unexpected(IoEnd::wouldblock);
            case SSL_ERROR_WANT_READ:
                wantWrite_ = false;
                return std::unexpected(IoEnd::wouldblock);
            case SSL_ERROR_SYSCALL:
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    wantWrite_ = true;
                    return std::unexpected(IoEnd::wouldblock);
                }
                if (errno == EINTR)
                    return std::unexpected(IoEnd::interrupted);
                LOG_WARN("Connection::doSend: fd {}: SSL_write() failed: {}", fd_, mynetlog::errnoText(errno));
                return std::unexpected(IoEnd::fatal);
            default:
                LOG_WARN("Connection::doSend: fd {}: SSL_write() failed: {}", fd_, mynetlog::sslText());
                return std::unexpected(IoEnd::fatal);
            }
        }
        ssize_t sn = ::send(fd_, buf, n, MSG_NOSIGNAL);
        if (sn > 0)
            return static_cast<size_t>(sn);
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            wantWrite_ = true;
            return std::unexpected(IoEnd::wouldblock);
        }
        if (errno == EINTR)
            return std::unexpected(IoEnd::interrupted);
        LOG_WARN("Connection::doSend: fd {}: send() failed: {}", fd_, mynetlog::errnoText(errno));
        return std::unexpected(IoEnd::fatal);
    }

    // Copy whatever the handler has finished into the write queue. Every
    // response keeps its own std::string until it is fully on the wire,
    // which is what makes pipelining lossless.
    inline void collectResponses()
    {
        while (handler_.hasResponse())
        {
            std::string response = handler_.takeResponse();
            if (response.empty())
                continue;
            pendingBytes_ += response.size();
            writeQueue_.push_back(std::move(response));
        }
        if (handler_.closeAfterResponse())
            closeAfterWrite_ = true;
        if (pendingBytes_ > writeHighWaterMark_)
            readPaused_ = true;
    }

public:
    Connection() noexcept = default;
    ~Connection() noexcept { reset(); }
    Connection(const Connection &) = delete("a connection owns a socket, its TLS state and its handler; there is nothing to share");
    Connection &operator=(const Connection &) = delete("a connection owns a socket, its TLS state and its handler; there is nothing to share");
    Connection(Connection &&) noexcept = delete("a connection owns a socket, its TLS state and its handler; it stays put in its session");
    Connection &operator=(Connection &&) noexcept = delete("a connection owns a socket, its TLS state and its handler; it stays put in its session");

    // 0 success
    inline void reset() noexcept
    {
        if (ssl_ != nullptr)
        {
            SSL_free(ssl_);
            ssl_ = nullptr;
        }
        if (fd_ != -1)
        {
            ::close(fd_);
            fd_ = -1;
        }
        addr_ = {};
        handshakeDone_ = false;
        writeQueue_.clear();
        writeOffset_ = 0;
        pendingBytes_ = 0;
        state_ = ConnState::open;
        readPaused_ = false;
        wantWrite_ = false;
        closeAfterWrite_ = false;
        peerGone_ = false;
        shutdownSent_ = false;
        timerId_ = 0;
        lastActive_ = std::chrono::steady_clock::time_point{};
        events_ = 0;
        handler_.reset();
    }

    inline int fd() const noexcept { return fd_; }
    inline void setFd(int fd) noexcept { fd_ = fd; }
    inline const sockaddr_in &addr() const noexcept { return addr_; }
    inline sockaddr_in &addr() noexcept { return addr_; }
    inline HandlerType &handler() noexcept { return handler_; }
    inline const HandlerType &handler() const noexcept { return handler_; }
    inline SSL *ssl() const noexcept { return ssl_; }
    inline ConnState state() const noexcept
    {
        return state_;
    }
    inline uint32_t events() const noexcept { return events_; }
    inline void setEvents(uint32_t events) noexcept { events_ = events; }
    inline bool wantRead() const noexcept { return !readPaused_ && !peerGone_ && state_ != ConnState::closed; }
    inline bool wantWrite() const noexcept { return pendingBytes_ > 0 || wantWrite_ || closeAfterWrite_ || state_ == ConnState::handshake || handler_.hasResponse(); }
    // Whether the transport is blocked waiting for the socket to drain, as
    // opposed to merely having something to say later. wantWrite() reports
    // "a handshake is in progress" as writable on purpose -- an edge triggered
    // epoll wants exactly that, because it fires once on the transition into
    // writability. A level triggered waiter cannot use the same test: a socket
    // is writable almost all of the time, so waiting on it would spin.
    inline bool writeBlocked() const noexcept { return pendingBytes_ > 0 || wantWrite_ || closeAfterWrite_ || handler_.hasResponse(); }
    inline bool hasPendingWrite() const noexcept { return pendingBytes_ > 0 || handler_.hasResponse(); }
    inline size_t pendingBytes() const noexcept { return pendingBytes_; }
    inline size_t writeHighWaterMark() const noexcept { return writeHighWaterMark_; }
    inline void setWriteHighWaterMark(size_t n) noexcept { writeHighWaterMark_ = n; }
    inline bool closeAfterWrite() const noexcept { return closeAfterWrite_; }
    inline void setCloseAfterWrite(bool v) noexcept { closeAfterWrite_ = v; }
    inline uint64_t timerId() const noexcept { return timerId_; }
    inline void setTimerId(uint64_t id) noexcept { timerId_ = id; }
    inline std::chrono::steady_clock::time_point lastActive() const noexcept { return lastActive_; }
    inline void touch() noexcept { lastActive_ = std::chrono::steady_clock::now(); }

    // ---- TLS ----
    // std::nullopt once the SSL handle is attached and a handshake is owed;
    // otherwise the call that refused.
    [[nodiscard]] inline std::optional<Err> startTLS(SSL_CTX *ctx) noexcept
    {
        if (ctx == nullptr)
        {
            LOG_ERROR("Connection::startTLS: no SSL_CTX (fd {}) -- the listener was not configured for TLS", fd_);
            return Err::ssl_ctx_failed;
        }
        ssl_ = SSL_new(ctx);
        if (ssl_ == nullptr)
        {
            LOG_ERROR("Connection::startTLS: SSL_new() failed on fd {}: {}", fd_, mynetlog::sslText());
            return Err::ssl_new_failed;
        }
        if (SSL_set_fd(ssl_, fd_) != 1)
        {
            LOG_ERROR("Connection::startTLS: SSL_set_fd({}) failed: {}", fd_, mynetlog::sslText());
            SSL_free(ssl_);
            ssl_ = nullptr;
            return Err::ssl_set_fd_failed;
        }
        SSL_set_accept_state(ssl_);
        handshakeDone_ = false;
        state_ = ConnState::handshake;
        return std::nullopt;
    }

    [[nodiscard]] inline HandshakeStatus doHandshake() noexcept
    {
        if (ssl_ == nullptr || handshakeDone_)
            return HandshakeStatus::done;
        int r = SSL_accept(ssl_);
        if (r == 1)
        {
            handshakeDone_ = true;
            return HandshakeStatus::done;
        }
        switch (SSL_get_error(ssl_, r))
        {
        case SSL_ERROR_WANT_READ:
            wantWrite_ = false;
            return HandshakeStatus::in_progress;
        case SSL_ERROR_WANT_WRITE:
            wantWrite_ = true;
            return HandshakeStatus::in_progress;
        default:
            // The handshake itself failed -- bad certificate, no shared
            // cipher, a peer that is not speaking TLS. The connection is
            // dropped; the OpenSSL queue says which of those it was.
            LOG_WARN("Connection::doHandshake: fd {}: {}", fd_, mynetlog::sslText());
            return HandshakeStatus::failed;
        }
    }

    // The protocol chosen during the TLS handshake. This is the hook a
    // dispatcher uses to pick h1 or h2 after ALPN, i.e. the run-time
    // counterpart of the compile-time HandlerType.
    inline const unsigned char *alpnSelected(unsigned int *len) const noexcept
    {
        const unsigned char *p = nullptr;
        if (ssl_ == nullptr)
        {
            *len = 0;
            return nullptr;
        }
        SSL_get0_alpn_selected(ssl_, &p, len);
        return p;
    }

    // ---- read path ----
    [[nodiscard]] IoStatus handleRead()
    {
        if (state_ == ConnState::handshake)
        {
            HandshakeStatus h = doHandshake();
            if (h == HandshakeStatus::failed)
                return IoStatus::close;
            if (h == HandshakeStatus::in_progress)
                return IoStatus::keep;
            state_ = ConnState::open;
        }

        char buf[4096];
        while (!readPaused_)
        {
            std::expected<size_t, IoEnd> rn = doRecv(buf, sizeof(buf));
            if (!rn)
            {
                if (rn.error() == IoEnd::eof)
                {
                    peerGone_ = true;
                    closeAfterWrite_ = true;
                    if (pendingBytes_ > 0)
                        return IoStatus::keep;
                    return finishClose() ? IoStatus::close : IoStatus::keep;
                }
                if (rn.error() == IoEnd::fatal)
                {
                    peerGone_ = true;
                    return IoStatus::close;
                }
                break; // wouldblock or interrupted: nothing more to read now
            }

            handler_.appendRequest(buf, static_cast<ssize_t>(*rn));
            touch();
            if (handler_.requestOverLimit())
            {
                handler_.onParseError("request exceeds the read limit");
                collectResponses();
                closeAfterWrite_ = true;
                readPaused_ = true;
                return IoStatus::keep;
            }
            handler_.process();
            collectResponses();
        }
        // A response may also be produced without a read event following it
        // (an application pushing work from a timer), so settle here too.
        collectResponses();
        if (handler_.closeAfterResponse())
            closeAfterWrite_ = true;
        if (pendingBytes_ > writeHighWaterMark_)
            readPaused_ = true;
        if (peerGone_ && pendingBytes_ == 0)
            return finishClose() ? IoStatus::close : IoStatus::keep;
        return IoStatus::keep;
    }

    // A TLS stream ends with a close_notify, not with a bare FIN: a peer that
    // only sees close() reports the stream as truncated and may discard a
    // response it already received. Writing the notice before the descriptor
    // goes away is the whole handshake this path needs -- the peer's own
    // notice is not waited for, because a peer that vanished without one is
    // precisely the case this exists for.
    //
    // true once the socket may be dropped, false while the notice is still
    // not out and the call has to be repeated when the socket is writable.
    [[nodiscard]] inline bool finishClose() noexcept
    {
        if (ssl_ != nullptr && !shutdownSent_)
        {
            int e = SSL_shutdown(ssl_);
            if (e < 0 && SSL_get_error(ssl_, e) == SSL_ERROR_WANT_WRITE)
                return false;
            shutdownSent_ = true;
        }
        return true;
    }

    // ---- write path ----
    [[nodiscard]] IoStatus handleWrite()
    {
        collectResponses();
        std::optional<IoEnd> r = flush();
        if (r)
        {
            // wouldblock is the ordinary "come back when writable"; only a
            // broken transport ends the connection here.
            if (*r == IoEnd::fatal)
                return IoStatus::close;
            return IoStatus::keep;
        }
        if (closeAfterWrite_)
            return finishClose() ? IoStatus::close : IoStatus::keep;
        if (!peerGone_ && handler_.readCredit() > 0 && pendingBytes_ <= writeHighWaterMark_)
            readPaused_ = false;
        return IoStatus::keep;
    }

    // 0 all queued bytes are with the kernel
    // std::nullopt once every queued byte is with the kernel; otherwise why
    // the draining stopped -- wouldblock keeps the rest queued, fatal ends it.
    [[nodiscard]] inline std::optional<IoEnd> flush() noexcept
    {
        while (true)
        {
            if (writeQueue_.empty())
            {
                writeOffset_ = 0;
                return std::nullopt;
            }
            std::string &front = writeQueue_.front();
            if (writeOffset_ >= front.size())
            {
                writeQueue_.pop_front();
                writeOffset_ = 0;
                continue;
            }
            std::expected<size_t, IoEnd> sn = doSend(front.data() + writeOffset_, front.size() - writeOffset_);
            if (sn)
            {
                writeOffset_ += *sn;
                pendingBytes_ -= *sn;
                continue;
            }
            if (sn.error() == IoEnd::interrupted)
                continue;
            return sn.error();
        }
    }

    // ---- hooks shared by both event loops ----

    // Move whatever the handler has finished into the send queue. The reactor
    // calls this right after handleRead(), the proactor as soon as an
    // io_uring receive completes; either way there is exactly one place where
    // a handler's output becomes queued bytes.
    inline void pump() noexcept
    {
        collectResponses();
        if (handler_.closeAfterResponse())
            closeAfterWrite_ = true;
    }

    inline void setWantWrite(bool v) noexcept { wantWrite_ = v; }
    // An orderly EOF carries both flags on the reactor path (the -2 return of
    // the read loop), because a peer that is gone is also a peer there is
    // nothing left to write for. The proactor learns about the same EOF from a
    // zero length recv completion and keys its teardown off closeAfterWrite(),
    // so the two flags have to travel together here as well -- with only
    // peerGone_ set, a session whose last response was still in flight when the
    // peer half closed was never closed at all.
    inline void onPeerGone() noexcept
    {
        peerGone_ = true;
        closeAfterWrite_ = true;
    }
    inline void onFatal() noexcept
    {
        peerGone_ = true;
        state_ = ConnState::closed;
    }

    // ---- asynchronous send (the proactor owns the socket write) ----
    inline const char *pendingData() const noexcept
    {
        if (writeQueue_.empty())
            return nullptr;
        return writeQueue_.front().data() + writeOffset_;
    }

    inline size_t pendingSize() const noexcept
    {
        return writeQueue_.empty() ? 0 : writeQueue_.front().size() - writeOffset_;
    }

    // true once the queue drained, false while it still holds data. The
    // caller decides what to do about it; there is no error to report here.
    [[nodiscard]] inline bool commitSent(size_t n) noexcept
    {
        while (n > 0 && !writeQueue_.empty())
        {
            std::string &front = writeQueue_.front();
            size_t left = front.size() - writeOffset_;
            size_t step = n < left ? n : left;
            writeOffset_ += step;
            pendingBytes_ -= step;
            n -= step;
            if (writeOffset_ >= front.size())
            {
                writeQueue_.pop_front();
                writeOffset_ = 0;
            }
            else
                break;
        }
        return writeQueue_.empty();
    }
};
