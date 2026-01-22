#pragma once

#include "myconcepts.hpp"
#include "event.hpp"
#include "handler.hpp"
#include <string>
#include <vector>
#include <stop_token>

template <typename Event>
    requires mustDerivedFromEventBase<Event> && mustResettable<Event>
class Peer // remember to add timers!
{
    [[no_unique_address]] Protocol<Event> protocol_;
    Event event_{};
    Event::Handler handler_{};
    std::stop_source stopSource_;

public:
    Peer() noexcept = default;
    ~Peer() noexcept = default;
    Peer(const Peer &) = delete;
    Peer &operator=(const Peer &) = delete;
    Peer(Peer &&) noexcept = delete;
    Peer &operator=(Peer &&) noexcept = delete;
    // 0 success
    // -1 ip error
    // -2 port error
    // -3 socket() error
    // -4 fcntl() error
    // -5 setsockopt() error
    // -6 connect() error
    // -7 select() error
    // -8 getsockopt() error
    int run_tcp(const char *ip, int port,
                int bufSize = 4096)
        requires mustEventSocket<Event>
    {
        if (ip == nullptr)
            return -1;
        event_.addr.sin_family = AF_INET;
        if (::inet_pton(AF_INET, ip, &event_.addr.sin_addr) <= 0)
        {
            reset();
            return -1;
        }
        if (port < 0 || port > 65535)
        {
            reset();
            return -2;
        }
        event_.addr.sin_port = ::htons(port);
        event_.fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (event_.fd < 0)
        {
            reset();
            return -3;
        }
        int flg;
        if ((flg = ::fcntl(event_.fd, F_GETFL, 0)) < 0)
        {
            reset();
            return -4;
        }
        if (::fcntl(event_.fd, F_SETFL, flg | O_NONBLOCK) < 0)
        {
            reset();
            return -4;
        }
        int opt = 1;
        if (::setsockopt(event_.fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        {
            reset();
            return -5;
        }
        if (::setsockopt(event_.fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0)
        {
            reset();
            return -5;
        }
        if (::connect(event_.fd, (const sockaddr *)&event_.addr, sizeof(event_.addr)) < 0 && errno != EINPROGRESS)
        {
            reset();
            return -6;
        }
        timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        std::vector<char> buf(bufSize, 0);
        while (!stopSource_.stop_requested())
        {
            fd_set readFds;
            fd_set writeFds;
            FD_ZERO(&readFds);
            FD_ZERO(&writeFds);
            FD_SET(event_.fd, &readFds);
            FD_SET(event_.fd, &writeFds);
            FD_SET(STDIN_FILENO, &readFds);
            int n = ::select(event_.fd + 1, &readFds, &writeFds, nullptr, &timeout);
            if (n < 0)
            {
                if (errno == EINTR)
                    continue;
                reset();
                return -7;
            }
            else if (n == 0)
            {
                timeout.tv_sec = 1;
                timeout.tv_usec = 0;
                int errno_lag = 0;
                socklen_t len = sizeof(errno_lag);
                if (::getsockopt(event_.fd, SOL_SOCKET, SO_ERROR, &errno_lag, &len) < 0 || errno_lag != 0)
                {
                    reset();
                    return -8;
                }
            }
            else
            {
                if (FD_ISSET(event_.fd, &readFds))
                {
                    while (true)
                    {
                        ssize_t rn = ::recv(event_.fd, buf.data(), buf.size(), 0);
                        if (rn < 0)
                        {
                            switch (errno)
                            {
                            case EAGAIN:
                                goto recvover;
                            case EINTR:
                                continue;
                            default:
                                fprintf(stderr, "Socket Error: %d\n", errno); ///
                                stop();
                                goto recvover;
                            }
                        }
                        else if (rn == 0)
                        {
                            printf("server closed\n"); ///
                            stop();
                            break;
                        }
                        else
                        {
                            handler_.appendRequest(buf.data(), rn);
                            handler_.process();
                        }
                    }
                recvover:;
                }
                if (FD_ISSET(event_.fd, &writeFds))
                {
                    if (FD_ISSET(STDIN_FILENO, &readFds))
                        handler_.stdin2response();
                    if (handler_.isResponse())
                    {
                        ssize_t sn = 0;
                        do
                        {
                            sn = ::send(event_.fd, handler_.responseBegin(), handler_.responseLength(), MSG_NOSIGNAL);
                            if (sn <= 0)
                            {
                                switch (errno)
                                {
                                case EAGAIN:
                                    goto sendlater;
                                case EINTR:
                                    continue;
                                default:
                                    fprintf(stderr, "Socket Error: %d\n", errno); ///
                                    stop();
                                    goto sendlater;
                                }
                            }
                        } while (handler_.isResponding(sn));
                    sendlater:;
                    }
                }
            }
        }
        reset();
        return 0;
    }
    // 0 success
    // -1 ip error
    // -2 port error
    // -3 socket() error
    // -4 fcntl() error
    // -5 setsockopt() error
    // -6 select() error
    // -7 getsockopt() error
    int run_udp(const char *ip, int port,
                int bufSize = 4096)
        requires mustEventSocket<Event>
    {
        if (ip == nullptr)
            return -1;
        event_.addr.sin_family = AF_INET;
        if (::inet_pton(AF_INET, ip, &event_.addr.sin_addr) <= 0)
        {
            reset();
            return -1;
        }
        if (port < 0 || port > 65535)
        {
            reset();
            return -2;
        }
        event_.addr.sin_port = ::htons(port);
        event_.fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (event_.fd < 0)
        {
            reset();
            return -3;
        }
        int flg;
        if ((flg = ::fcntl(event_.fd, F_GETFL, 0)) < 0)
        {
            reset();
            return -4;
        }
        if (::fcntl(event_.fd, F_SETFL, flg | O_NONBLOCK) < 0)
        {
            reset();
            return -4;
        }
        int opt = 1;
        if (::setsockopt(event_.fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        {
            reset();
            return -5;
        }
        if (::setsockopt(event_.fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0)
        {
            reset();
            return -5;
        }
        if (::setsockopt(event_.fd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt)) < 0)
        {
            reset();
            return -5;
        }
        timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        std::vector<char> buf(bufSize, 0);
        while (!stopSource_.stop_requested())
        {
            fd_set readFds;
            fd_set writeFds;
            FD_ZERO(&readFds);
            FD_ZERO(&writeFds);
            FD_SET(event_.fd, &readFds);
            FD_SET(event_.fd, &writeFds);
            FD_SET(STDIN_FILENO, &readFds);
            int n = ::select(event_.fd + 1, &readFds, &writeFds, nullptr, &timeout);
            if (n < 0)
            {
                if (errno == EINTR)
                    continue;
                reset();
                return -6;
            }
            else if (n == 0)
            {
                timeout.tv_sec = 1;
                timeout.tv_usec = 0;
                int errno_lag = 0;
                socklen_t len = sizeof(errno_lag);
                if (::getsockopt(event_.fd, SOL_SOCKET, SO_ERROR, &errno_lag, &len) < 0 || errno_lag != 0)
                {
                    reset();
                    return -7;
                }
            }
            else
            {
                socklen_t socklen = sizeof(event_.addr);
                if (FD_ISSET(event_.fd, &readFds))
                {
                    while (true)
                    {
                        ssize_t rn = ::recvfrom(event_.fd, buf.data(), buf.size(), 0, (sockaddr *)&event_.addr, &socklen);
                        if (rn < 0)
                        {
                            switch (errno)
                            {
                            case EAGAIN:
                                goto recvover;
                            case EINTR:
                                continue;
                            default:
                                fprintf(stderr, "Socket Error: %d\n", errno); ///
                                stop();
                                goto recvover;
                            }
                        }
                        else
                        {
                            handler_.appendRequest(buf.data(), rn);
                            handler_.process();
                        }
                    }
                recvover:;
                }
                if (FD_ISSET(event_.fd, &writeFds))
                {
                    if (FD_ISSET(STDIN_FILENO, &readFds))
                        handler_.stdin2response();
                    if (handler_.isResponse())
                    {
                        ssize_t sn = 0;
                        do
                        {
                            sn = ::sendto(event_.fd, handler_.responseBegin(), handler_.responseLength(), MSG_NOSIGNAL, (sockaddr *)&event_.addr, socklen);
                            if (sn < 0)
                            {
                                switch (errno)
                                {
                                case EAGAIN:
                                    goto sendlater;
                                case EINTR:
                                    continue;
                                default:
                                    fprintf(stderr, "Socket Error: %d\n", errno); ///
                                    stop();
                                    goto sendlater;
                                }
                            }
                        } while (handler_.isResponding(sn));
                    sendlater:;
                    }
                }
            }
        }
        reset();
        return 0;
    }
    // 0 success
    // -1 ip error
    // -2 port error
    // -3 socket() error
    // -4 fcntl() error
    // -5 setsockopt() error
    // -6 connect() error
    // -7 SSL_CTX_new() error
    // -8 SSL_CTX_set_default_verify_paths() error
    // -9 SSL_new() error
    // -10 SSL_set_fd() error
    // -11 SSL_CTX_load_verify_locations() error
    // -12 select() error
    // -13 getsockopt() error
    int run_ssl(const char *ip, int port,
                const char *crt = nullptr,
                int bufSize = 4096)
        requires mustEventSSL<Event>
    {
        if (ip == nullptr)
            return -1;
        event_.addr.sin_family = AF_INET;
        if (::inet_pton(AF_INET, ip, &event_.addr.sin_addr) <= 0)
        {
            reset();
            return -1;
        }
        if (port < 0 || port > 65535)
        {
            reset();
            return -2;
        }
        event_.addr.sin_port = ::htons(port);
        if ((event_.fd = ::socket(AF_INET, SOCK_STREAM, 0)) < 0)
        {
            reset();
            return -3;
        }
        int flg;
        if ((flg = ::fcntl(event_.fd, F_GETFL, 0)) < 0)
        {
            reset();
            return -4;
        }
        if (::fcntl(event_.fd, F_SETFL, flg | O_NONBLOCK) < 0)
        {
            reset();
            return -4;
        }
        int opt = 1;
        if (::setsockopt(event_.fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        {
            reset();
            return -5;
        }
        if (::setsockopt(event_.fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0)
        {
            reset();
            return -5;
        }
        if (::connect(event_.fd, (const sockaddr *)&event_.addr, sizeof(event_.addr)) < 0 && errno != EINPROGRESS)
        {
            reset();
            return -6;
        }
        if ((protocol_.ctx = SSL_CTX_new(TLS_client_method())) == nullptr)
        {
            reset();
            return -7;
        }
        if (SSL_CTX_set_default_verify_paths(protocol_.ctx) <= 0)
        {
            reset();
            return -8;
        }
        if (crt == nullptr)
            SSL_CTX_set_verify(protocol_.ctx, SSL_VERIFY_NONE, nullptr);
        else
            SSL_CTX_set_verify(protocol_.ctx, SSL_VERIFY_PEER, nullptr);
        if ((event_.ssl = SSL_new(protocol_.ctx)) == nullptr)
        {
            reset();
            return -9;
        }
        if (SSL_set_fd(event_.ssl, event_.fd) <= 0)
        {
            reset();
            return -10;
        }
        if (crt != nullptr && SSL_CTX_load_verify_locations(protocol_.ctx, crt, nullptr) <= 0)
        {
            reset();
            return -11;
        }
        timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        std::vector<char> buf(bufSize, 0);
        event_.type = 1;
        while (!stopSource_.stop_requested())
        {
            fd_set readFds;
            fd_set writeFds;
            FD_ZERO(&readFds);
            FD_ZERO(&writeFds);
            FD_SET(event_.fd, &readFds);
            FD_SET(event_.fd, &writeFds);
            FD_SET(STDIN_FILENO, &readFds);
            int n = ::select(event_.fd + 1, &readFds, &writeFds, nullptr, &timeout);
            if (n < 0)
            {
                if (errno == EINTR)
                    continue;
                reset();
                return -12;
            }
            else if (n == 0)
            {
                timeout.tv_sec = 1;
                timeout.tv_usec = 0;
                int errno_lag = 0;
                socklen_t len = sizeof(errno_lag);
                if (::getsockopt(event_.fd, SOL_SOCKET, SO_ERROR, &errno_lag, &len) < 0 || errno_lag != 0)
                {
                    reset();
                    return -13;
                }
            }
            else
            {
                switch (event_.type)
                {
                case 1:
                    if (FD_ISSET(event_.fd, &readFds))
                    {
                        goto error;
                    }
                    else if (FD_ISSET(event_.fd, &writeFds))
                    {
                        int e = SSL_connect(event_.ssl);
                        if (e < 0)
                        {
                            switch (SSL_get_error(event_.ssl, e))
                            {
                            case SSL_ERROR_WANT_READ:
                                event_.type = 3;
                                break;
                            case SSL_ERROR_WANT_WRITE:
                                event_.type = 3;
                                break;
                            default:
                                goto error;
                            }
                        }
                        else if (e == 0)
                        {
                            printf("server closed\n"); ///
                            stop();
                        }
                        else
                        {
                            event_.type = 2;
                        }
                    }
                    else
                    {
                        goto error;
                    }
                    break;
                case 2:
                    if (FD_ISSET(event_.fd, &readFds))
                    {
                        while (true)
                        {
                            ssize_t rn = ::SSL_read(event_.ssl, buf.data(), buf.size());
                            if (rn < 0)
                            {
                                switch (SSL_get_error(event_.ssl, rn))
                                {
                                case SSL_ERROR_WANT_READ:
                                    goto recvover;
                                default:
                                    goto error;
                                }
                            }
                            else if (rn == 0)
                            {
                                int e = SSL_shutdown(event_.ssl);
                                if (e <= 0)
                                {
                                    switch (SSL_get_error(event_.ssl, e))
                                    {
                                    case SSL_ERROR_WANT_READ:
                                        event_.type = 4;
                                        break;
                                    case SSL_ERROR_WANT_WRITE:
                                        event_.type = 4;
                                        break;
                                    default:
                                        goto error;
                                    }
                                }
                                else
                                {
                                    printf("server closed\n"); ///
                                    stop();
                                    goto recvover;
                                }
                            }
                            else
                            {
                                handler_.appendRequest(buf.data(), rn);
                                handler_.process();
                            }
                        }
                    recvover:;
                    }
                    if (FD_ISSET(event_.fd, &writeFds))
                    {
                        if (FD_ISSET(STDIN_FILENO, &readFds))
                            handler_.stdin2response();
                        if (handler_.isResponse())
                        {
                            ssize_t sn = 0;
                            do
                            {
                                sn = ::SSL_write(event_.ssl, handler_.responseBegin(), handler_.responseLength());
                                if (sn <= 0)
                                {
                                    switch (SSL_get_error(event_.ssl, sn))
                                    {
                                    case SSL_ERROR_WANT_WRITE:
                                        goto sendlater;
                                    default:
                                        goto error;
                                    }
                                }
                            } while (handler_.isResponding(sn));
                        sendlater:;
                        }
                    }
                    break;
                case 3:
                    if (FD_ISSET(event_.fd, &readFds))
                    {
                        int e = SSL_connect(event_.ssl);
                        if (e < 0)
                        {
                            switch (SSL_get_error(event_.ssl, e))
                            {
                            case SSL_ERROR_WANT_READ:
                                break;
                            case SSL_ERROR_WANT_WRITE:
                                break;
                            default:
                                goto error;
                            }
                        }
                        else if (e == 0)
                        {
                            printf("server closed\n"); ///
                            stop();
                        }
                        else
                        {
                            event_.type = 2;
                        }
                    }
                    else if (FD_ISSET(event_.fd, &writeFds))
                    {
                        int e = SSL_connect(event_.ssl);
                        if (e < 0)
                        {
                            switch (SSL_get_error(event_.ssl, e))
                            {
                            case SSL_ERROR_WANT_READ:
                                break;
                            case SSL_ERROR_WANT_WRITE:
                                break;
                            default:
                                goto error;
                            }
                        }
                        else if (e == 0)
                        {
                            printf("server closed\n"); ///
                            stop();
                        }
                        else
                        {
                            event_.type = 2;
                        }
                    }
                    else
                    {
                        goto error;
                    }
                    break;
                case 4:
                    if (FD_ISSET(event_.fd, &readFds))
                    {
                        int e = SSL_shutdown(event_.ssl);
                        if (e <= 0)
                        {
                            switch (SSL_get_error(event_.ssl, e))
                            {
                            case SSL_ERROR_WANT_READ:
                                break;
                            case SSL_ERROR_WANT_WRITE:
                                break;
                            default:
                                goto error;
                            }
                        }
                        else
                        {
                            stop();
                        }
                    }
                    else if (FD_ISSET(event_.fd, &writeFds))
                    {
                        int e = SSL_shutdown(event_.ssl);
                        if (e <= 0)
                        {
                            switch (SSL_get_error(event_.ssl, e))
                            {
                            case SSL_ERROR_WANT_READ:
                                break;
                            case SSL_ERROR_WANT_WRITE:
                                break;
                            default:
                                goto error;
                            }
                        }
                        else
                        {
                            stop();
                        }
                    }
                    else
                    {
                        goto error;
                    }
                    break;
                default:
                error:
                    fprintf(stderr, "%s", strerror(errno)); ///
                    int e = SSL_shutdown(event_.ssl);
                    if (e <= 0)
                    {
                        switch (SSL_get_error(event_.ssl, e))
                        {
                        case SSL_ERROR_WANT_READ:
                            event_.type = 4;
                            break;
                        case SSL_ERROR_WANT_WRITE:
                            event_.type = 4;
                            break;
                        default:
                            goto error;
                        }
                    }
                    else
                    {
                        stop();
                    }
                    break;
                }
            }
        }
        reset();
        return 0;
    }
    inline void stop() const noexcept { stopSource_.request_stop(); }
    inline void reset() noexcept
    {
        if constexpr (mustEventSSL<Event>)
        {
            if (protocol_.ctx != nullptr)
                SSL_CTX_free(protocol_.ctx);
            protocol_.ctx = nullptr;
        }
        handler_.reset();
        event_.reset();
    }
};
