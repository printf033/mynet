#pragma once

/**
 * @file client.hpp
 * @brief High-performance client-side bidirectional pipe connecting stdin/stdout to network sockets.
 */

#include "concepts.hpp"
#include "error.hpp"
#include "event.hpp"
#include "log.hpp"
#include "loop.hpp"
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
#include <utility>
#include <vector>

namespace mynet
{

    /**
     * @class Client
     * @brief Full-duplex streaming network client bridging standard streams with TCP/TLS/UDP.
     *
     * @tparam Event Event base wrapper type satisfying DerivedFromEventBase and Resettable.
     */
    template <typename Event>
        requires DerivedFromEventBase<Event> && Resettable<Event>
    class Client
    {
        enum class PEER_STATE : uint8_t
        {
            CONNECTING = 0,
            HANDSHAKE = 1,
            OPEN = 2,
            CLOSED = 3
        };

    public:
        Client() noexcept = default;

        ~Client() noexcept { reset(); }

        Client(const Client &) = delete ("a client owns a socket and the loop registration that drives it");
        Client &operator=(const Client &) = delete ("a client owns a socket and the loop registration that drives it");
        Client(Client &&) noexcept = delete ("a client owns a socket and the loop registration that drives it");
        Client &
        operator=(Client &&) noexcept = delete ("a client owns a socket and the loop registration that drives it");

        static constexpr size_t kHighWater = 256ULL << 10;
        static constexpr size_t kLowWater = 64ULL << 10;

        /**
         * @brief Run TCP client connection to remote peer until EOF on both directions.
         * @param ip Remote IPv4 literal address.
         * @param port Remote port.
         * @param bufSize Buffer size for socket read/write operations.
         * @return nullopt on success, or error code on failure.
         */
        [[nodiscard]] Result<> runTcp(const char *ip, int port, int bufSize = 16 << 10)
            requires SocketEvent<Event>
        {
            contract_assert(ip != nullptr);
            contract_assert(port >= 0 && port <= ((1 << 16) - 1));
            contract_assert(bufSize > 0);
            if (auto err = setup(ip, port, SOCK_STREAM, bufSize); !err) [[unlikely]]
            {
                return err;
            }
            if (::connect(fd_, reinterpret_cast<const sockaddr *>(&addr_), sizeof(addr_)) < 0 && errno != EINPROGRESS)
                [[unlikely]]
            {
                LOG_ERROR("Client::runTcp: connect() to {}:{} failed: {}", ip, port, log::errnoText(errno));
                reset();
                return std::unexpected(ERR::CONNECT_FAILED);
            }
            state_ = PEER_STATE::CONNECTING;
            return runLoop();
        }

        /**
         * @brief Run UDP client connection to remote peer.
         */
        [[nodiscard]] Result<> runUdp(const char *ip, int port, int bufSize = 4 << 10)
            requires SocketEvent<Event>
        {
            contract_assert(ip != nullptr);
            contract_assert(port >= 0 && port <= ((1 << 16) - 1));
            contract_assert(bufSize > 0);
            if (auto err = setup(ip, port, SOCK_DGRAM, bufSize); !err) [[unlikely]]
            {
                return err;
            }
            if (::connect(fd_, reinterpret_cast<const sockaddr *>(&addr_), sizeof(addr_)) < 0) [[unlikely]]
            {
                LOG_ERROR("Client::runUdp: connect() to {}:{} failed: {}", ip, port, log::errnoText(errno));
                reset();
                return std::unexpected(ERR::CONNECT_FAILED);
            }
            state_ = PEER_STATE::OPEN;
            return runLoop();
        }

        /**
         * @brief Run TLS/SSL client connection to remote peer.
         */
        [[nodiscard]] Result<> runSsl(const char *ip, int port, const char *serverName = nullptr,
                                      const char *caFile = nullptr, int bufSize = 16 << 10)
            requires SslEvent<Event>
        {
            contract_assert(ip != nullptr);
            contract_assert(port >= 0 && port <= ((1 << 16) - 1));
            contract_assert(bufSize > 0);
            if (auto err = setup(ip, port, SOCK_STREAM, bufSize); !err) [[unlikely]]
            {
                return err;
            }
            protocol_.ctx = SSL_CTX_new(TLS_client_method());
            if (protocol_.ctx == nullptr) [[unlikely]]
            {
                LOG_ERROR("Client::runSsl: SSL_CTX_new() failed: {}", log::sslText());
                reset();
                return std::unexpected(ERR::SSL_CTX_FAILED);
            }
            if (caFile != nullptr)
            {
                SSL_CTX_set_verify(protocol_.ctx, SSL_VERIFY_PEER, nullptr);
                if (SSL_CTX_load_verify_locations(protocol_.ctx, caFile, nullptr) != 1) [[unlikely]]
                {
                    LOG_ERROR("Client::runSsl: CA bundle \"{}\" could not be loaded: {}", caFile, log::sslText());
                    reset();
                    return std::unexpected(ERR::SSL_CA_FAILED);
                }
            }
            ssl_ = SSL_new(protocol_.ctx);
            if (ssl_ == nullptr) [[unlikely]]
            {
                LOG_ERROR("Client::runSsl: SSL_new() failed: {}", log::sslText());
                reset();
                return std::unexpected(ERR::SSL_NEW_FAILED);
            }
            if (SSL_set_fd(ssl_, fd_) != 1) [[unlikely]]
            {
                LOG_ERROR("Client::runSsl: SSL_set_fd({}) failed: {}", fd_, log::sslText());
                reset();
                return std::unexpected(ERR::SSL_SET_FD_FAILED);
            }
            SSL_set_connect_state(ssl_);
            if (serverName != nullptr && SSL_set_tlsext_host_name(ssl_, serverName) != 1) [[unlikely]]
            {
                LOG_ERROR("Client::runSsl: SNI \"{}\" was refused: {}", serverName, log::sslText());
                reset();
                return std::unexpected(ERR::SSL_SNI_FAILED);
            }
            if (::connect(fd_, reinterpret_cast<const sockaddr *>(&addr_), sizeof(addr_)) < 0 && errno != EINPROGRESS)
                [[unlikely]]
            {
                LOG_ERROR("Client::runSsl: connect() to {}:{} failed: {}", ip, port, log::errnoText(errno));
                reset();
                return std::unexpected(ERR::CONNECT_FAILED);
            }
            state_ = PEER_STATE::CONNECTING;
            return runLoop();
        }

        /**
         * @brief Stop the peer event loop from any thread.
         */
        inline void stop() noexcept { stopSource_.request_stop(); }

        /**
         * @brief Reset peer state and clean up sockets/timers.
         */
        inline void reset() noexcept
        {
            loop_.quit();
            if (stopTimer_ != 0)
            {
                (void)loop_.cancelTimer(stopTimer_);
                stopTimer_ = 0;
            }
            stopSource_ = std::stop_source{};
            if (ssl_ != nullptr)
            {
                SSL_free(ssl_);
                ssl_ = nullptr;
            }
            if (stdinRegistered_ && !stdinPaused_)
            {
                (void)loop_.delFd(STDIN_FILENO);
            }
            stdinRegistered_ = false;
            stdinPaused_ = false;
            if (stdinFlags_ >= 0)
            {
                ::fcntl(STDIN_FILENO, F_SETFL, stdinFlags_);
                stdinFlags_ = -1;
            }
            if (fd_ != -1)
            {
                (void)loop_.delFd(fd_);
                ::close(fd_);
                fd_ = -1;
            }
            if constexpr (SslEvent<Event>)
            {
                if (protocol_.ctx != nullptr)
                {
                    SSL_CTX_free(protocol_.ctx);
                    protocol_.ctx = nullptr;
                }
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
            state_ = PEER_STATE::CLOSED;
        }

        [[nodiscard]] inline size_t sent() const noexcept { return sentTotal_; }

        [[nodiscard]] inline size_t received() const noexcept { return recvTotal_; }

        [[nodiscard]] inline int fd() const noexcept { return fd_; }

    private:
        [[nodiscard]] inline std::string peerText() const
        {
            char buf[64];
            std::snprintf(buf, sizeof(buf), "%s:%d", ::inet_ntoa(addr_.sin_addr),
                          static_cast<int>(::ntohs(addr_.sin_port)));
            return buf;
        }

        [[nodiscard]] inline Result<> setup(const char *ip, int port, int type, int bufSize)
        {
            reset();
            addr_.sin_family = AF_INET;
            if (::inet_pton(AF_INET, ip, &addr_.sin_addr) <= 0) [[unlikely]]
            {
                LOG_ERROR("Client::setup: \"{}\" is not an IPv4 address literal", ip);
                return std::unexpected(ERR::ADDR_INVALID);
            }
            addr_.sin_port = ::htons(static_cast<uint16_t>(port));
            fd_ = ::socket(AF_INET, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (fd_ < 0) [[unlikely]]
            {
                LOG_ERROR("Client::setup: socket() failed: {}", log::errnoText(errno));
                return std::unexpected(ERR::SOCKET_FAILED);
            }
            int opt = 1;
            if (::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) [[unlikely]]
            {
                LOG_ERROR("Client::setup: setsockopt(SO_REUSEADDR) failed: {}", log::errnoText(errno));
                reset();
                return std::unexpected(ERR::SETSOCKOPT_FAILED);
            }
            stdinFlags_ = ::fcntl(STDIN_FILENO, F_GETFL, 0);
            if (stdinFlags_ >= 0)
            {
                ::fcntl(STDIN_FILENO, F_SETFL, stdinFlags_ | O_NONBLOCK);
            }
            bufSize_ = bufSize;
            type_ = type;
            return {};
        }

        [[nodiscard]] inline Result<> runLoop()
        {
            sigset_t maskPipe{};
            sigset_t maskSaved{};
            ::sigemptyset(&maskPipe);
            ::sigaddset(&maskPipe, SIGPIPE);
            const bool maskBlocked = ::pthread_sigmask(SIG_BLOCK, &maskPipe, &maskSaved) == 0;
            if (auto err = loop_.init(); !err) [[unlikely]]
            {
                if (maskBlocked)
                {
                    ::pthread_sigmask(SIG_SETMASK, &maskSaved, nullptr);
                }
                reset();
                return err;
            }
            loop_.setEventCallback(
                [this](uint32_t events, void *ptr)
                {
                    if (ptr == &stdinTag_)
                    {
                        onStdinEvent();
                    }
                    else
                    {
                        onPeerEvent(events);
                    }
                });
            if (auto err = loop_.addFd(fd_, EPOLLIN | EPOLLOUT, this); !err) [[unlikely]]
            {
                if (maskBlocked)
                {
                    ::pthread_sigmask(SIG_SETMASK, &maskSaved, nullptr);
                }
                reset();
                return err;
            }
            if (!isRegularFile(STDIN_FILENO) && loop_.addFd(STDIN_FILENO, EPOLLIN, &stdinTag_).has_value())
            {
                stdinRegistered_ = true;
            }
            buf_.assign(static_cast<size_t>(bufSize_), '\0');
            stopTimer_ = loop_.runEvery(std::chrono::milliseconds(100),
                                        [this]()
                                        {
                                            if (stopSource_.stop_requested())
                                            {
                                                loop_.quit();
                                            }
                                            pumpStdin();
                                        });
            Result<> loopErr = loop_.run();
            if (maskBlocked)
            {
                restoreSigpipeMask(maskPipe, maskSaved);
            }
            std::optional<ERR> reason = failReason_;
            reset();
            if (!loopErr)
            {
                return loopErr;
            }
            if (reason)
            {
                return std::unexpected(*reason);
            }
            return {};
        }

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
            {
                peerEof_ = true;
            }
            if (state_ == PEER_STATE::CONNECTING || state_ == PEER_STATE::HANDSHAKE)
            {
                handshakeOrConnect();
            }
            if (state_ == PEER_STATE::OPEN)
            {
                if (events & EPOLLIN)
                {
                    drainPeer();
                }
                if (events & EPOLLOUT)
                {
                    flushToPeer();
                }
            }
            flushToOut();
            pumpStdin();
            updateInterest();
        }

        inline void pumpStdin()
        {
            if (!stdinRegistered_ && !stdinEof_ && backlog() < kHighWater)
            {
                onStdinEvent();
            }
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
                {
                    continue;
                }
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    break;
                }
                stdinEof_ = true;
                break;
            }
            if (stdinEof_)
            {
                pauseStdin();
                pendingShutdown_ = true;
            }
            else if (backlog() >= kHighWater)
            {
                pauseStdin();
            }
            flushToPeer();
            flushToOut();
            updateInterest();
        }

        inline void handshakeOrConnect()
        {
            if (state_ == PEER_STATE::CONNECTING)
            {
                int soError = 0;
                socklen_t len = sizeof(soError);
                if (::getsockopt(fd_, SOL_SOCKET, SO_ERROR, &soError, &len) < 0 || soError != 0) [[unlikely]]
                {
                    LOG_ERROR("Client::handshakeOrConnect: connect to {} failed: {}", peerText(),
                              soError != 0 ? log::errnoText(soError) : log::errnoText(errno));
                    fatal_ = true;
                    failReason_ = ERR::CONNECT_FAILED;
                    peerEof_ = true;
                    return;
                }
                state_ = ssl_ != nullptr ? PEER_STATE::HANDSHAKE : PEER_STATE::OPEN;
            }
            if (state_ == PEER_STATE::HANDSHAKE)
            {
                int e = SSL_connect(ssl_);
                if (e == 1)
                {
                    state_ = PEER_STATE::OPEN;
                }
                else
                {
                    int reason = SSL_get_error(ssl_, e);
                    if (reason != SSL_ERROR_WANT_READ && reason != SSL_ERROR_WANT_WRITE) [[unlikely]]
                    {
                        LOG_ERROR("Client::handshakeOrConnect: TLS handshake with {} failed: {}", peerText(),
                                  log::sslText());
                        fatal_ = true;
                        failReason_ = ERR::CONNECT_FAILED;
                        peerEof_ = true;
                    }
                }
            }
        }

        inline void drainPeer()
        {
            while (true)
            {
                std::expected<size_t, IO_END> n = readSome(buf_.data(), buf_.size());
                if (n)
                {
                    toOut_.append(buf_.data(), *n);
                    recvTotal_ += *n;
                    continue;
                }
                if (n.error() == IO_END::EOF_REACHED || n.error() == IO_END::FATAL)
                {
                    peerEof_ = true;
                }
                break;
            }
            flushToOut();
        }

        inline void flushToPeer()
        {
            if (state_ != PEER_STATE::OPEN)
            {
                return;
            }
            while (toPeerOffset_ < toPeer_.size())
            {
                std::expected<size_t, IO_END> n =
                    writeSome(toPeer_.data() + toPeerOffset_, toPeer_.size() - toPeerOffset_);
                if (n)
                {
                    toPeerOffset_ += *n;
                    sentTotal_ += *n;
                    continue;
                }
                if (n.error() == IO_END::WOULDBLOCK)
                {
                    break;
                }
                peerEof_ = true;
                break;
            }
            if (toPeerOffset_ == toPeer_.size())
            {
                toPeer_.clear();
                toPeerOffset_ = 0;
            }
            else if (toPeerOffset_ >= 4096 && toPeerOffset_ * 2 >= toPeer_.size())
            {
                toPeer_.erase(0, toPeerOffset_);
                toPeerOffset_ = 0;
            }
            if (pendingShutdown_)
            {
                halfClosePeer();
            }
            if (!stdinEof_ && stdinPaused_ && backlog() <= kLowWater)
            {
                resumeStdin();
            }
        }

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
                {
                    continue;
                }
                if (n < 0) [[unlikely]]
                {
                    LOG_ERROR("Client: writing to stdout failed: {}", log::errnoText(errno));
                    fatal_ = true;
                    failReason_ = ERR::STDOUT_FAILED;
                    peerEof_ = true;
                }
                break;
            }
            if (toOutOffset_ == toOut_.size())
            {
                toOut_.clear();
                toOutOffset_ = 0;
            }
            else if (toOutOffset_ >= 4096 && toOutOffset_ * 2 >= toOut_.size())
            {
                toOut_.erase(0, toOutOffset_);
                toOutOffset_ = 0;
            }
        }

        [[nodiscard]] static bool isRegularFile(int fd) noexcept
        {
            struct stat st;
            return ::fstat(fd, &st) == 0 && S_ISREG(st.st_mode);
        }

        inline void pauseStdin()
        {
            if (!stdinRegistered_ || stdinPaused_)
            {
                return;
            }
            (void)loop_.delFd(STDIN_FILENO);
            stdinPaused_ = true;
        }

        inline void resumeStdin()
        {
            if (!stdinRegistered_ || !stdinPaused_)
            {
                return;
            }
            if (loop_.addFd(STDIN_FILENO, EPOLLIN, &stdinTag_).has_value())
            {
                stdinPaused_ = false;
            }
        }

        inline void updateInterest()
        {
            if (fd_ == -1)
            {
                return;
            }
            uint32_t events = 0;
            if (!peerEof_)
            {
                events |= EPOLLIN;
            }
            if (state_ == PEER_STATE::CONNECTING || state_ == PEER_STATE::HANDSHAKE || toPeerOffset_ < toPeer_.size() ||
                pendingShutdown_)
            {
                events |= EPOLLOUT;
            }
            if (auto err = loop_.modFd(fd_, events, this); !err) [[unlikely]]
            {
                fatal_ = true;
                failReason_ = err.error();
                peerEof_ = true;
            }
            const bool udpAnswered =
                type_ == SOCK_DGRAM && stdinEof_ && backlog() == 0 && recvTotal_ > 0 && toOutOffset_ == toOut_.size();
            if (fatal_ || udpAnswered || (peerEof_ && toOutOffset_ == toOut_.size() && backlog() == 0))
            {
                loop_.quit();
            }
        }

        [[nodiscard]] inline size_t backlog() const noexcept { return toPeer_.size() - toPeerOffset_; }

        [[nodiscard]] inline std::expected<size_t, IO_END> readSome(char *p, size_t cap)
        {
            while (true)
            {
                if (state_ != PEER_STATE::OPEN)
                {
                    return std::unexpected(IO_END::WOULDBLOCK);
                }
                if (ssl_ != nullptr)
                {
                    int e = SSL_read(ssl_, p, static_cast<int>(cap));
                    if (e > 0)
                    {
                        return static_cast<size_t>(e);
                    }
                    int reason = SSL_get_error(ssl_, e);
                    if (reason == SSL_ERROR_WANT_READ || reason == SSL_ERROR_WANT_WRITE)
                    {
                        return std::unexpected(IO_END::WOULDBLOCK);
                    }
                    LOG_DEBUG("Client::readSome: fd {}: TLS stream ended: {}", fd_, log::sslText());
                    return std::unexpected(IO_END::EOF_REACHED);
                }
                ssize_t n = ::recv(fd_, p, cap, 0);
                if (n > 0)
                {
                    return static_cast<size_t>(n);
                }
                if (n == 0)
                {
                    return std::unexpected(IO_END::EOF_REACHED);
                }
                if (errno == EINTR)
                {
                    continue;
                }
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    return std::unexpected(IO_END::WOULDBLOCK);
                }
                LOG_WARN("Client::readSome: fd {}: recv() failed: {}", fd_, log::errnoText(errno));
                return std::unexpected(IO_END::FATAL);
            }
        }

        [[nodiscard]] inline std::expected<size_t, IO_END> writeSome(const char *p, size_t n)
        {
            while (true)
            {
                if (ssl_ != nullptr)
                {
                    int e = SSL_write(ssl_, p, static_cast<int>(n));
                    if (e > 0)
                    {
                        return static_cast<size_t>(e);
                    }
                    int reason = SSL_get_error(ssl_, e);
                    if (reason == SSL_ERROR_WANT_READ || reason == SSL_ERROR_WANT_WRITE)
                    {
                        return std::unexpected(IO_END::WOULDBLOCK);
                    }
                    if (reason == SSL_ERROR_SYSCALL && (errno == ECONNRESET || errno == EPIPE || errno == 0))
                    {
                        return std::unexpected(IO_END::EOF_REACHED);
                    }
                    LOG_WARN("Client::writeSome: fd {}: SSL_write() failed: {}", fd_, log::sslText());
                    return std::unexpected(IO_END::FATAL);
                }
                ssize_t r = ::send(fd_, p, n, MSG_NOSIGNAL);
                if (r > 0)
                {
                    return static_cast<size_t>(r);
                }
                if (r == 0)
                {
                    return std::unexpected(IO_END::WOULDBLOCK);
                }
                if (errno == EINTR)
                {
                    continue;
                }
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    return std::unexpected(IO_END::WOULDBLOCK);
                }
                if (errno == ECONNRESET || errno == EPIPE)
                {
                    return std::unexpected(IO_END::EOF_REACHED);
                }
                LOG_WARN("Client::writeSome: fd {}: send() failed: {}", fd_, log::errnoText(errno));
                return std::unexpected(IO_END::FATAL);
            }
        }

        [[no_unique_address]] Protocol<Event> protocol_{};
        EventLoop loop_{};
        sockaddr_in addr_{};
        SSL *ssl_ = nullptr;
        int fd_ = -1;
        int stdinFlags_ = -1;
        int bufSize_ = 16 << 10;
        uint64_t stopTimer_ = 0;
        char stdinTag_ = 0;
        bool stdinRegistered_ = false;
        bool stdinPaused_ = false;
        bool stdinEof_ = false;
        bool pendingShutdown_ = false;
        bool peerEof_ = false;
        int type_ = 0;
        bool fatal_ = false;
        std::optional<ERR> failReason_{};
        PEER_STATE state_ = PEER_STATE::CLOSED;
        std::string toPeer_{};
        size_t toPeerOffset_ = 0;
        std::string toOut_{};
        size_t toOutOffset_ = 0;
        size_t sentTotal_ = 0;
        size_t recvTotal_ = 0;
        std::vector<char> buf_{};
        std::stop_source stopSource_{};
    };

} // namespace mynet
