#pragma once

#include "error.hpp"
#include "event.hpp"
#include "log.hpp"
#include "loop.hpp"
#include "myconcepts.hpp"
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <expected>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <optional>
#include <pthread.h>
#include <stop_token>
#include <string>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

// The peer is the other half of the library: a client that moves bytes between
// stdin and one socket, in both directions, without knowing what protocol is
// on the wire. `cat request.bin | peer_tcp host port > response.bin` is the
// whole contract, which makes it the tool to test a server with rather than a
// second, half-written HTTP client.
//
// It deliberately does not reuse Connection. Connection answers the question a
// *server* asks -- parse a request, produce a response, write it back to the
// same peer. A client's two directions are unrelated: what stdin produces goes
// to the peer, what the peer produces goes to stdout. One shared write queue
// would conflate two destinations, so the peer keeps two, one per direction.
//
// What it does reuse is the loop. The same epoll-based EventLoop that drives
// Reactor drives this, so timers, cross-thread wakeups and stop() behave the
// same here as they do server side.
template <typename Event>
    requires mustDerivedFromEventBase<Event> && mustResettable<Event>
class Peer
{
    enum class PeerState : uint8_t
    {
        connecting = 0,
        handshake = 1,
        open = 2,
        closed = 3
    };

public:
    Peer() noexcept = default;
    ~Peer() noexcept { reset(); }
    Peer(const Peer &) = delete("a peer owns a socket and the loop registration that drives it");
    Peer &operator=(const Peer &) = delete("a peer owns a socket and the loop registration that drives it");
    Peer(Peer &&) noexcept = delete("a peer owns a socket and the loop registration that drives it");
    Peer &operator=(Peer &&) noexcept = delete("a peer owns a socket and the loop registration that drives it");

    // Bytes read from stdin are forwarded as they arrive, so a slow peer slows
    // the reads down instead of growing an unbounded buffer. Past the high
    // water mark stdin is unwatched; once drained below the low water mark it
    // is watched again.
    static constexpr size_t kHighWater = 256 * 1024;
    static constexpr size_t kLowWater = 64 * 1024;

    // std::nullopt once everything stdin produced has reached the peer and
    // everything the peer produced has reached stdout; otherwise the first
    // thing that refused. The address text, the port range and the buffer size
    // are contract preconditions -- a null pointer, a port outside the 16-bit
    // range or a zero-sized buffer is a bug in the caller, and failing the
    // contract says so where a return value the caller may ignore does not.
    // What is left as an Err is only what the kernel can refuse at run time.
    [[nodiscard]] std::optional<Err> run_tcp(const char *ip, int port,
                                             int bufSize = 16384)
        requires mustEventSocket<Event>
    {
        contract_assert(ip != nullptr);
        contract_assert(port >= 0 && port <= 65535);
        contract_assert(bufSize > 0);
        if (std::optional<Err> err = setup(ip, port, SOCK_STREAM, bufSize))
            return err;
        if (::connect(fd_, reinterpret_cast<const sockaddr *>(&addr_), sizeof(addr_)) < 0 && errno != EINPROGRESS)
        {
            LOG_ERROR("Peer::run_tcp: connect() to {}:{} failed: {}", ip, port, mynetlog::errnoText(errno));
            reset();
            return Err::connect_failed;
        }
        state_ = PeerState::connecting;
        return runLoop();
    }

    // Same contract as run_tcp(). A datagram exchange ends differently: a UDP
    // peer never reports end of stream, so the run finishes when one answered
    // request has been written out and stdin has nothing more to give.
    [[nodiscard]] std::optional<Err> run_udp(const char *ip, int port,
                                             int bufSize = 4096)
        requires mustEventSocket<Event>
    {
        contract_assert(ip != nullptr);
        contract_assert(port >= 0 && port <= 65535);
        contract_assert(bufSize > 0);
        if (std::optional<Err> err = setup(ip, port, SOCK_DGRAM, bufSize))
            return err;
        // A connected datagram socket pins one peer address, so the same
        // send()/recv() pair the stream path uses works here too.
        if (::connect(fd_, reinterpret_cast<const sockaddr *>(&addr_), sizeof(addr_)) < 0)
        {
            LOG_ERROR("Peer::run_udp: connect() to {}:{} failed: {}", ip, port, mynetlog::errnoText(errno));
            reset();
            return Err::connect_failed;
        }
        state_ = PeerState::open;
        return runLoop();
    }

    // Same contract as run_tcp(), plus TLS setup. Each refusal has its own
    // name: `serverName` failing the SNI call, the CA bundle not loading and
    // SSL_new() running out of memory are three different things to fix, and
    // an umbrella code would have made them one.
    [[nodiscard]] std::optional<Err> run_ssl(const char *ip, int port,
                                             const char *serverName = nullptr,
                                             const char *caFile = nullptr,
                                             int bufSize = 16384)
        requires mustEventSSL<Event>
    {
        contract_assert(ip != nullptr);
        contract_assert(port >= 0 && port <= 65535);
        contract_assert(bufSize > 0);
        if (std::optional<Err> err = setup(ip, port, SOCK_STREAM, bufSize))
            return err;
        protocol_.ctx = SSL_CTX_new(TLS_client_method());
        if (protocol_.ctx == nullptr)
        {
            LOG_ERROR("Peer::run_ssl: SSL_CTX_new() failed: {}", mynetlog::sslText());
            reset();
            return Err::ssl_ctx_failed;
        }
        if (caFile != nullptr)
        {
            SSL_CTX_set_verify(protocol_.ctx, SSL_VERIFY_PEER, nullptr);
            if (SSL_CTX_load_verify_locations(protocol_.ctx, caFile, nullptr) != 1)
            {
                LOG_ERROR("Peer::run_ssl: CA bundle \"{}\" could not be loaded: {}", caFile, mynetlog::sslText());
                reset();
                return Err::ssl_ca_failed;
            }
        }
        ssl_ = SSL_new(protocol_.ctx);
        if (ssl_ == nullptr)
        {
            LOG_ERROR("Peer::run_ssl: SSL_new() failed: {}", mynetlog::sslText());
            reset();
            return Err::ssl_new_failed;
        }
        if (SSL_set_fd(ssl_, fd_) != 1)
        {
            LOG_ERROR("Peer::run_ssl: SSL_set_fd({}) failed: {}", fd_, mynetlog::sslText());
            reset();
            return Err::ssl_set_fd_failed;
        }
        SSL_set_connect_state(ssl_);
        if (serverName != nullptr && SSL_set_tlsext_host_name(ssl_, serverName) != 1)
        {
            LOG_ERROR("Peer::run_ssl: SNI \"{}\" was refused: {}", serverName, mynetlog::sslText());
            reset();
            return Err::ssl_sni_failed;
        }
        if (::connect(fd_, reinterpret_cast<const sockaddr *>(&addr_), sizeof(addr_)) < 0 && errno != EINPROGRESS)
        {
            LOG_ERROR("Peer::run_ssl: connect() to {}:{} failed: {}", ip, port, mynetlog::errnoText(errno));
            reset();
            return Err::connect_failed;
        }
        state_ = PeerState::connecting;
        return runLoop();
    }

    // Safe from any thread. The loop notices through a short heartbeat timer,
    // which keeps the flag itself on the loop thread.
    inline void stop() noexcept { stopSource_.request_stop(); }

    inline void reset() noexcept
    {
        loop_.quit();
        if (stopTimer_ != 0)
        {
            (void)loop_.cancelTimer(stopTimer_);
            stopTimer_ = 0;
        }
        // A stop token cannot be un-requested, so a stopped peer is made
        // runnable again by replacing the source, not by clearing a flag.
        stopSource_ = std::stop_source{};
        if (ssl_ != nullptr)
        {
            SSL_free(ssl_);
            ssl_ = nullptr;
        }
        // pauseStdin() removes the descriptor from the loop without clearing
        // stdinRegistered_, so only an unpaused registration still needs the
        // delete. Repeating it for an already-removed descriptor is what
        // epoll answers ENOENT to.
        if (stdinRegistered_ && !stdinPaused_)
            (void)loop_.delFd(STDIN_FILENO);
        stdinRegistered_ = false;
        stdinPaused_ = false;
        if (stdinFlags_ >= 0)
        {
            // Leave the terminal the way it was found.
            ::fcntl(STDIN_FILENO, F_SETFL, stdinFlags_);
            stdinFlags_ = -1;
        }
        if (fd_ != -1)
        {
            (void)loop_.delFd(fd_);
            ::close(fd_);
            fd_ = -1;
        }
        if constexpr (mustEventSSL<Event>)
        {
            if (protocol_.ctx != nullptr)
                SSL_CTX_free(protocol_.ctx);
            protocol_.ctx = nullptr;
        }
        addr_ = {};
        toPeer_.clear();
        toPeerOffset_ = 0;
        toOut_.clear();
        toOutOffset_ = 0;
        buf_.clear();
        stdinEof_ = false;
        pendingShutdown_ = false;
        peerEof_ = false;
        fatal_ = false;
        failReason_.reset();
        type_ = 0;
        state_ = PeerState::closed;
    }

    inline size_t sent() const noexcept { return sentTotal_; }
    inline size_t received() const noexcept { return recvTotal_; }
    inline int fd() const noexcept { return fd_; }

private:
    // "ip:port" of the peer this socket was set up for, built only for log
    // lines on paths that have already failed; the hot path never formats it.
    [[nodiscard]] inline std::string peerText() const
    {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "%s:%d", ::inet_ntoa(addr_.sin_addr),
                      static_cast<int>(::ntohs(addr_.sin_port)));
        return buf;
    }
    // std::nullopt once the socket exists, is non-blocking and is bound to
    // nothing yet; otherwise the call that refused. The address text and the
    // port range are checked as contracts by the public entry points above.
    [[nodiscard]] inline std::optional<Err> setup(const char *ip, int port, int type, int bufSize)
    {
        reset();
        addr_.sin_family = AF_INET;
        if (::inet_pton(AF_INET, ip, &addr_.sin_addr) <= 0)
        {
            LOG_ERROR("Peer::setup: \"{}\" is not an IPv4 address literal", ip);
            return Err::addr_invalid;
        }
        addr_.sin_port = ::htons(static_cast<uint16_t>(port));
        fd_ = ::socket(AF_INET, type | SOCK_CLOEXEC, 0);
        if (fd_ < 0)
        {
            LOG_ERROR("Peer::setup: socket() failed: {}", mynetlog::errnoText(errno));
            return Err::socket_failed;
        }
        int flg = ::fcntl(fd_, F_GETFL, 0);
        if (flg < 0 || ::fcntl(fd_, F_SETFL, flg | O_NONBLOCK) < 0)
        {
            LOG_ERROR("Peer::setup: making fd {} non-blocking failed: {}", fd_, mynetlog::errnoText(errno));
            reset();
            return Err::fcntl_failed;
        }
        int opt = 1;
        if (::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        {
            LOG_ERROR("Peer::setup: setsockopt(SO_REUSEADDR) failed: {}", mynetlog::errnoText(errno));
            reset();
            return Err::setsockopt_failed;
        }
        // stdin is made non-blocking as well: it is watched by epoll, and a
        // blocking read would park the whole loop on the last drained byte.
        // A pipe or a terminal accepts the flag; a regular file ignores it,
        // which is fine because the first read reaches EOF anyway.
        stdinFlags_ = ::fcntl(STDIN_FILENO, F_GETFL, 0);
        if (stdinFlags_ >= 0)
            ::fcntl(STDIN_FILENO, F_SETFL, stdinFlags_ | O_NONBLOCK);
        bufSize_ = bufSize;
        type_ = type;
        return std::nullopt;
    }

    // std::nullopt once the loop has finished without a fatal condition;
    // otherwise the loop failure itself, or the reason the run ended badly.
    // A peer that simply closed its half is a normal end, so "the run
    // stopped" and "the run stopped well" are two questions: failReason_
    // answers the second, and it is read before reset() clears it.
    [[nodiscard]] inline std::optional<Err> runLoop()
    {
        // The reader of stdout may walk away -- `peer_tcp ... | head -c 100`
        // is a normal thing to type -- and the write that notices raises
        // SIGPIPE, whose default action kills the process before the loop can
        // tear anything down. Blocking it on this thread turns that write into
        // EPIPE, which flushToOut() reports as a fatal condition. The mask
        // belongs to the thread, so no other thread is affected, and it is
        // restored on the way out.
        sigset_t maskPipe{}, maskSaved{};
        ::sigemptyset(&maskPipe);
        ::sigaddset(&maskPipe, SIGPIPE);
        bool maskBlocked = ::pthread_sigmask(SIG_BLOCK, &maskPipe, &maskSaved) == 0;
        if (std::optional<Err> err = loop_.init())
        {
            if (maskBlocked)
                ::pthread_sigmask(SIG_SETMASK, &maskSaved, nullptr);
            reset();
            return err;
        }
        // One callback for both descriptors. The socket registers this as its
        // context, stdin registers the tag below, so a single dispatcher can
        // tell the two apart without the loop needing per-fd callbacks.
        loop_.setEventCallback([this](uint32_t events, void *ptr) {
            if (ptr == &stdinTag_)
                onStdinEvent();
            else
                onPeerEvent(events);
        });
        if (std::optional<Err> err = loop_.addFd(fd_, EPOLLIN | EPOLLOUT, this))
        {
            reset();
            return err;
        }
        // A pipe or a terminal is watchable, so the loop drives stdin. A
        // regular file is not -- and nothing about a file becomes readable
        // later -- so `peer_tcp host port < request.bin` is left to
        // pumpStdin() below. Asking epoll about it first is what would turn
        // the EPERM it answers into a logged failure of a path that works.
        if (!isRegularFile(STDIN_FILENO) && !loop_.addFd(STDIN_FILENO, EPOLLIN, &stdinTag_))
            stdinRegistered_ = true;
        buf_.assign(static_cast<size_t>(bufSize_), '\0');
        // stop() is called from other threads; sampling the token here keeps
        // the quit flag itself loop-owned.
        stopTimer_ = loop_.runEvery(std::chrono::milliseconds(100), [this]() {
            if (stopSource_.stop_requested())
                loop_.quit();
            pumpStdin();
        });
        std::optional<Err> loopErr = loop_.run();
        if (maskBlocked)
            restoreSigpipeMask(maskPipe, maskSaved);
        std::optional<Err> reason = failReason_;
        reset();
        if (loopErr)
            return loopErr;
        return reason;
    }

    // Restoring a mask while a SIGPIPE is still pending would deliver it right
    // there and kill the process at the very end, so the pending signal is
    // consumed first. A zero timeout keeps this from blocking.
    inline static void restoreSigpipeMask(const sigset_t &blocked, const sigset_t &saved)
    {
        sigset_t pend{};
        if (::sigpending(&pend) == 0 && ::sigismember(&pend, SIGPIPE) == 1)
        {
            timespec zero{};
            while (::sigtimedwait(&blocked, nullptr, &zero) == SIGPIPE)
            {
            }
        }
        ::pthread_sigmask(SIG_SETMASK, &saved, nullptr);
    }

    inline void onPeerEvent(uint32_t events)
    {
        if (events & (EPOLLHUP | EPOLLERR))
            peerEof_ = true;
        if (state_ == PeerState::connecting || state_ == PeerState::handshake)
            handshakeOrConnect();
        if (state_ == PeerState::open)
        {
            if (events & EPOLLIN)
                drainPeer();
            if (events & EPOLLOUT)
                flushToPeer();
        }
        flushToOut();
        pumpStdin();
        updateInterest();
    }

    // A regular file on stdin has no descriptor the loop can watch, so its
    // bytes are pulled in whenever the loop happens to be awake: after a
    // socket event and on the stop tick. A pipe or a terminal has one and is
    // driven by epoll instead, which makes this a no-op there.
    inline void pumpStdin()
    {
        if (!stdinRegistered_ && !stdinEof_ && backlog() < kHighWater)
            onStdinEvent();
    }

    inline void onStdinEvent()
    {
        while (!stdinEof_ && backlog() < kHighWater)
        {
            ssize_t n = ::read(STDIN_FILENO, buf_.data(), buf_.size());
            if (n > 0)
            {
                toPeer_.append(buf_.data(), static_cast<size_t>(n));
                continue;
            }
            if (n == 0)
            {
                stdinEof_ = true;
                break;
            }
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            // A read error on stdin is an end of input, not a failure of the
            // connection: whatever was read still gets sent.
            stdinEof_ = true;
            break;
        }
        if (stdinEof_)
        {
            pauseStdin();
            // Forward the end of input, but only once what stdin already
            // produced has actually left: the FIN must not overtake it.
            pendingShutdown_ = true;
        }
        else if (backlog() >= kHighWater)
            pauseStdin();
        flushToPeer();
        flushToOut();
        updateInterest();
    }

    inline void handshakeOrConnect()
    {
        if (state_ == PeerState::connecting)
        {
            int soError = 0;
            socklen_t len = sizeof(soError);
            if (::getsockopt(fd_, SOL_SOCKET, SO_ERROR, &soError, &len) < 0 || soError != 0)
            {
                LOG_ERROR("Peer::handshakeOrConnect: connect to {} failed: {}", peerText(),
                          soError != 0 ? mynetlog::errnoText(soError) : mynetlog::errnoText(errno));
                fatal_ = true;
                failReason_ = Err::connect_failed;
                peerEof_ = true;
                return;
            }
            // TCP with TLS may still be in EINPROGRESS here; SSL_connect()
            // below reports WANT_READ/WANT_WRITE until the socket is usable.
            state_ = ssl_ != nullptr ? PeerState::handshake : PeerState::open;
        }
        if (state_ == PeerState::handshake)
        {
            int e = SSL_connect(ssl_);
            if (e == 1)
                state_ = PeerState::open;
            else
            {
                int reason = SSL_get_error(ssl_, e);
                if (reason != SSL_ERROR_WANT_READ && reason != SSL_ERROR_WANT_WRITE)
                {
                    LOG_ERROR("Peer::handshakeOrConnect: TLS handshake with {} failed: {}", peerText(),
                              mynetlog::sslText());
                    fatal_ = true;
                    // The stream never came up; for the caller that is the
                    // same class of failure as a refused connect().
                    failReason_ = Err::connect_failed;
                    peerEof_ = true;
                }
            }
        }
    }

    inline void drainPeer()
    {
        while (true)
        {
            std::expected<size_t, IoEnd> n = readSome(buf_.data(), buf_.size());
            if (n)
            {
                toOut_.append(buf_.data(), *n);
                recvTotal_ += *n;
                continue;
            }
            // wouldblock and interrupted both mean "nothing more this time":
            // the loop calls again when the descriptor reports readiness.
            if (n.error() == IoEnd::eof || n.error() == IoEnd::fatal)
                peerEof_ = true;
            break;
        }
        flushToOut();
    }

    inline void flushToPeer()
    {
        if (state_ != PeerState::open)
            return;
        while (toPeerOffset_ < toPeer_.size())
        {
            std::expected<size_t, IoEnd> n = writeSome(toPeer_.data() + toPeerOffset_, toPeer_.size() - toPeerOffset_);
            if (n)
            {
                toPeerOffset_ += *n;
                sentTotal_ += *n;
                continue;
            }
            if (n.error() == IoEnd::wouldblock)
                return; // nothing fits yet: the next EPOLLOUT picks it up
            peerEof_ = true;
            return;
        }
        toPeer_.clear();
        toPeerOffset_ = 0;
        // Deferred half close: everything stdin produced is on the wire now,
        // so the peer may be told that no more is coming. Closing the write
        // side earlier would throw away whatever was still buffered here.
        if (pendingShutdown_)
            halfClosePeer();
        // The peer caught up, so stdin may be watched again.
        if (!stdinEof_ && stdinPaused_ && backlog() <= kLowWater)
            resumeStdin();
    }

    // Forward the end of stdin to the peer. TCP says it with a FIN, but a TLS
    // stream carries its own end marker: a bare FIN reaches the peer as a
    // truncated record stream, which OpenSSL reports as an error and a client
    // reads as a broken response. close_notify is the honest signal, and the
    // peer's own notice is deliberately not waited for -- a half close is
    // what was asked for, not a full teardown.
    inline void halfClosePeer()
    {
        if (ssl_ != nullptr)
        {
            int e = SSL_shutdown(ssl_);
            if (e < 0)
            {
                int reason = SSL_get_error(ssl_, e);
                if (reason == SSL_ERROR_WANT_READ || reason == SSL_ERROR_WANT_WRITE)
                {
                    // The notice did not fit in the socket buffer yet; the
                    // next readable or writable event finishes it.
                    pendingShutdown_ = true;
                    return;
                }
            }
            pendingShutdown_ = false;
            return;
        }
        pendingShutdown_ = false;
        ::shutdown(fd_, SHUT_WR);
    }

    inline void flushToOut()
    {
        while (toOutOffset_ < toOut_.size())
        {
            ssize_t n = ::write(STDOUT_FILENO, toOut_.data() + toOutOffset_, toOut_.size() - toOutOffset_);
            if (n > 0)
            {
                toOutOffset_ += static_cast<size_t>(n);
                continue;
            }
            if (n < 0 && errno == EINTR)
                continue;
            // stdout is left blocking on purpose: a full pipe is backpressure,
            // and waiting on it is the honest behaviour. Any other failure
            // means the reader is gone for good (EPIPE, EBADF), and retrying a
            // descriptor that can never accept another byte would park the
            // loop in epoll_wait() forever -- nothing else is left to wake it.
            if (n < 0)
            {
                LOG_ERROR("Peer: writing to stdout failed: {}", mynetlog::errnoText(errno));
                fatal_ = true;
                failReason_ = Err::stdout_failed;
                peerEof_ = true;
            }
            break;
        }
        if (toOutOffset_ == toOut_.size())
        {
            toOut_.clear();
            toOutOffset_ = 0;
        }
    }

    // True for a descriptor epoll() cannot watch at all: a regular file, which
    // is what `< request.bin` puts on stdin, answers EPERM to every
    // registration attempt. Read-only -- it changes no state.
    [[nodiscard]] static bool isRegularFile(int fd) noexcept
    {
        struct stat st;
        return ::fstat(fd, &st) == 0 && S_ISREG(st.st_mode);
    }

    inline void pauseStdin()
    {
        if (!stdinRegistered_ || stdinPaused_)
            return;
        (void)loop_.delFd(STDIN_FILENO);
        stdinPaused_ = true;
    }

    inline void resumeStdin()
    {
        if (!stdinRegistered_ || !stdinPaused_)
            return;
        if (!loop_.addFd(STDIN_FILENO, EPOLLIN, &stdinTag_))
            stdinPaused_ = false;
    }

    inline void updateInterest()
    {
        if (fd_ == -1)
            return;
        // EPOLLOUT only while it can actually make progress. The loop is
        // level-triggered, so watching a writable socket unconditionally would
        // turn epoll_wait() into a spin.
        uint32_t events = EPOLLIN;
        if (state_ == PeerState::connecting || state_ == PeerState::handshake || toPeerOffset_ < toPeer_.size() || pendingShutdown_)
            events |= EPOLLOUT;
        // A rearm that fails means the descriptor can no longer be watched,
        // so the run cannot make progress; record why and let the test below
        // end it the same way any other fatal condition does.
        if (std::optional<Err> err = loop_.modFd(fd_, events, this))
        {
            fatal_ = true;
            failReason_ = err;
            peerEof_ = true;
        }
        // A datagram peer never reports EOF, so without this an echo would
        // leave the loop waiting on a socket that has nothing more to say.
        // One answered request with stdin drained is the whole exchange.
        bool udpAnswered = type_ == SOCK_DGRAM && stdinEof_ && backlog() == 0 &&
                           recvTotal_ > 0 && toOutOffset_ == toOut_.size();
        if (fatal_ || udpAnswered || (peerEof_ && toOutOffset_ == toOut_.size() && backlog() == 0))
        {
            // Everything the peer had to say reached stdout and everything
            // stdin produced reached the peer. Nothing can move any more, so
            // this is the end either way.
            loop_.quit();
        }
    }

    inline size_t backlog() const noexcept { return toPeer_.size() - toPeerOffset_; }

    // >0 bytes, or why none moved. A successful result is always positive:
    // zero bytes read is the peer's end of stream, reported as IoEnd::eof
    // rather than as a special case of success every caller re-interprets.
    [[nodiscard]] inline std::expected<size_t, IoEnd> readSome(char *p, size_t cap)
    {
        while (true)
        {
            // The handshake is still running: the socket is readable because
            // of TLS records, not because application data arrived.
            if (state_ != PeerState::open)
                return std::unexpected(IoEnd::wouldblock);
            if (ssl_ != nullptr)
            {
                int e = SSL_read(ssl_, p, static_cast<int>(cap));
                if (e > 0)
                    return static_cast<size_t>(e);
                int reason = SSL_get_error(ssl_, e);
                if (reason == SSL_ERROR_WANT_READ || reason == SSL_ERROR_WANT_WRITE)
                    return std::unexpected(IoEnd::wouldblock);
                // ZERO_RETURN, SYSCALL, SSL and everything else all mean the
                // stream is over; the distinction is only useful for logging.
                LOG_DEBUG("Peer::readSome: fd {}: TLS stream ended: {}", fd_, mynetlog::sslText());
                return std::unexpected(IoEnd::eof);
            }
            ssize_t n = ::recv(fd_, p, cap, 0);
            if (n > 0)
                return static_cast<size_t>(n);
            if (n == 0)
                return std::unexpected(IoEnd::eof);
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return std::unexpected(IoEnd::wouldblock);
            LOG_WARN("Peer::readSome: fd {}: recv() failed: {}", fd_, mynetlog::errnoText(errno));
            return std::unexpected(IoEnd::fatal);
        }
    }

    // >0 bytes, or why none moved. There is no eof here: a write does not
    // discover the peer's end of stream, the read side does.
    [[nodiscard]] inline std::expected<size_t, IoEnd> writeSome(const char *p, size_t n)
    {
        while (true)
        {
            if (ssl_ != nullptr)
            {
                int e = SSL_write(ssl_, p, static_cast<int>(n));
                if (e > 0)
                    return static_cast<size_t>(e);
                int reason = SSL_get_error(ssl_, e);
                if (reason == SSL_ERROR_WANT_READ || reason == SSL_ERROR_WANT_WRITE)
                    return std::unexpected(IoEnd::wouldblock);
                LOG_WARN("Peer::writeSome: fd {}: SSL_write() failed: {}", fd_, mynetlog::sslText());
                return std::unexpected(IoEnd::fatal);
            }
            ssize_t r = ::send(fd_, p, n, MSG_NOSIGNAL);
            if (r > 0)
                return static_cast<size_t>(r);
            if (r == 0)
                return std::unexpected(IoEnd::wouldblock);
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return std::unexpected(IoEnd::wouldblock);
            LOG_WARN("Peer::writeSome: fd {}: send() failed: {}", fd_, mynetlog::errnoText(errno));
            return std::unexpected(IoEnd::fatal);
        }
    }

    [[no_unique_address]] Protocol<Event> protocol_{};
    EventLoop loop_{};
    sockaddr_in addr_{};
    SSL *ssl_ = nullptr;
    int fd_ = -1;
    int stdinFlags_ = -1;
    int bufSize_ = 16384;
    uint64_t stopTimer_ = 0;
    char stdinTag_ = 0;
    bool stdinRegistered_ = false;
    bool stdinPaused_ = false;
    bool stdinEof_ = false;
    bool pendingShutdown_ = false;
    bool peerEof_ = false;
    int type_ = 0;
    bool fatal_ = false;
    // Kept separately from fatal_: a peer that simply closed its half is a
    // normal end (nullopt), while a refused connect or a dead stdout is not.
    std::optional<Err> failReason_{};
    PeerState state_ = PeerState::closed;
    std::string toPeer_{};
    size_t toPeerOffset_ = 0;
    std::string toOut_{};
    size_t toOutOffset_ = 0;
    size_t sentTotal_ = 0;
    size_t recvTotal_ = 0;
    std::vector<char> buf_{};
    std::stop_source stopSource_{};
};
