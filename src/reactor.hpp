#pragma once

#include "myconcepts.hpp"
#include "event.hpp"
#include "objectPool.hpp"
#include <sys/epoll.h>
#include <string>
#include <cstring>
#include <stop_token>

template <typename Event>
    requires mustDerivedFromEventBase<Event> && mustResettable<Event>
class Reactor // remember to add timers!
{
    [[no_unique_address]] Protocol<Event> protocol_;
    int epollFd_ = -1;
    epoll_event *newEventBuf_ = nullptr;
    Event accEvent_{};
    ObjectPool<Event> eventPool_;
    ObjectPool<typename Event::Handler> handlerPool_;
    std::stop_source stopSource_;

public:
    Reactor() noexcept = default;
    ~Reactor() noexcept = default;
    Reactor(const Reactor &) = delete;
    Reactor &operator=(const Reactor &) = delete;
    Reactor(Reactor &&) noexcept = delete;
    Reactor &operator=(Reactor &&) noexcept = delete;
    // 0 success
    // -1 ip error
    // -2 port error
    // -3 socket() error
    // -4 fcntl() error
    // -5 setsockopt() error
    // -6 bind() error
    // -7 listen() error
    // -8 epoll_create1() error
    // -9 epoll_ctl() error
    // -10 epoll_wait() error
    int run_tcp(const char *ip, int port, int backlog = 511,
                size_t eventPoolSize = 1024, size_t handlerPoolSize = 256,
                int maxBufEntrs = 1024, int bufSize = 4096)
        requires mustEventSocket<Event>
    {
        int err = accEvent_.listen_tcp(ip, port, backlog);
        if (err < 0)
        {
            reset();
            return err;
        }
        if ((epollFd_ = epoll_create1(0)) < 0)
        {
            reset();
            return -8;
        }
        eventPool_.init(eventPoolSize);
        handlerPool_.init(handlerPoolSize);
        newEventBuf_ = new epoll_event[maxBufEntrs];
        accEvent_.type = 1;
        epoll_event acceptor;
        acceptor.events = EPOLLIN;
        acceptor.data.ptr = &accEvent_;
        if (epoll_ctl(epollFd_, EPOLL_CTL_ADD, accEvent_.fd, &acceptor) < 0)
        {
            reset();
            return -9;
        }
        while (!stopSource_.stop_requested())
        {
            int n = epoll_wait(epollFd_, newEventBuf_, maxBufEntrs, -1);
            if (n < 0)
            {
                if (errno == EINTR)
                    continue;
                reset();
                return -10;
            }
            for (int i = 0; i < n; ++i)
            {
                Event *event = reinterpret_cast<Event *>(newEventBuf_[i].data.ptr);
                if (event == nullptr)
                    goto error;
                switch (event->type)
                {
                case 1:
                    if (newEventBuf_[i].events & EPOLLIN)
                    {
                        Event *cliEvent = eventPool_.acquire();
                        if (cliEvent == nullptr)
                            goto error;
                        socklen_t socklen = sizeof(cliEvent->addr);
                        cliEvent->fd = ::accept4(accEvent_.fd, (sockaddr *)&cliEvent->addr, &socklen, SOCK_NONBLOCK | SOCK_CLOEXEC);
                        if (cliEvent->fd < 0)
                        {
                            switch (errno)
                            {
                            default:
                                goto error;
                            }
                        }

                        cliEvent->type = 2;
                        cliEvent->handler = handlerPool_.acquire();
                        if (cliEvent->handler == nullptr)
                            goto error;
                        epoll_event recver;
                        recver.events = EPOLLIN | EPOLLET;
                        recver.data.ptr = cliEvent;
                        if (epoll_ctl(epollFd_, EPOLL_CTL_ADD, cliEvent->fd, &recver) < 0)
                            goto error;
                    }
                    else if (newEventBuf_[i].events & EPOLLOUT)
                    {
                        goto error;
                    }
                    else
                    {
                        goto error;
                    }
                    break;
                case 2:
                    if (newEventBuf_[i].events & EPOLLIN)
                    {
                        if (event->handler == nullptr)
                            goto error;
                        std::vector<char> buf(bufSize, 0);
                        while (true)
                        {
                            ssize_t rn = ::recv(event->fd, buf.data(), buf.size(), 0);
                            if (rn < 0)
                            {
                                switch (errno)
                                {
                                case EAGAIN:
                                    goto breakout;
                                case EINTR:
                                    continue;
                                default:
                                    goto error;
                                }
                            }
                            else if (rn == 0)
                            {
                                printf("client left\n"); ///
                                epoll_ctl(epollFd_, EPOLL_CTL_DEL, event->fd, nullptr);
                                handlerPool_.release(event->handler);
                                eventPool_.release(event);
                                goto breakout;
                            }
                            else
                            {
                                event->handler->appendRequest(buf.data(), rn);
                                event->handler->process();
                                if (event->handler->isResponse())
                                {
                                    epoll_event sender;
                                    sender.events = EPOLLIN | EPOLLOUT | EPOLLET;
                                    sender.data.ptr = event;
                                    if (epoll_ctl(epollFd_, EPOLL_CTL_MOD, event->fd, &sender) < 0)
                                        goto error;
                                }
                            }
                        }
                    }
                    else if (newEventBuf_[i].events & EPOLLOUT)
                    {
                        if (event->handler == nullptr)
                            goto error;
                        ssize_t sn = 0;
                        do
                        {
                            sn = ::send(event->fd, event->handler->responseBegin(), event->handler->responseLength(), MSG_NOSIGNAL);
                            if (sn <= 0)
                            {
                                switch (errno)
                                {
                                case EAGAIN:
                                    goto breakout;
                                case EINTR:
                                    continue;
                                default:
                                    goto error;
                                }
                            }
                        } while (event->handler->isResponding(sn));

                        epoll_event sender;
                        sender.events = EPOLLIN | EPOLLET;
                        sender.data.ptr = event;
                        if (epoll_ctl(epollFd_, EPOLL_CTL_MOD, event->fd, &sender) < 0)
                            goto error;
                    }
                    else
                    {
                        goto error;
                    }
                breakout:
                    break;
                default:
                error:
                    fprintf(stderr, "%s", strerror(errno)); ///
                    epoll_ctl(epollFd_, EPOLL_CTL_DEL, event->fd, nullptr);
                    handlerPool_.release(event->handler);
                    eventPool_.release(event);
                    break;
                }
            }
        }
        reset();
        return 0;
    }
    // single pem format
    // 0 success
    // -1 ip error
    // -2 port error
    // -3 socket() error
    // -4 fcntl() error
    // -5 setsockopt() error
    // -6 bind() error
    // -7 listen() error
    // -8 SSL_CTX_new() error
    // -9 SSL_CTX_use_certificate_file() error
    // -10 SSL_CTX_use_PrivateKey_file() error
    // -11 SSL_CTX_check_private_key() error
    // -12 epoll_create1() error
    // -13 epoll_ctl() error
    // -14 epoll_wait() error
    int run_ssl(const char *ip, int port,
                const char *crt, const char *key,
                int backlog = 511,
                size_t eventPoolSize = 1024, size_t handlerPoolSize = 256,
                int maxBufEntrs = 1024, int bufSize = 4096)
        requires mustEventSSL<Event>
    {
        int err = accEvent_.listen_tcp(ip, port, backlog);
        if (err < 0)
        {
            reset();
            return err;
        }
        if ((protocol_.ctx = SSL_CTX_new(TLS_server_method())) == nullptr)
        {
            reset();
            return -8;
        }
        if (SSL_CTX_use_certificate_file(protocol_.ctx, crt, SSL_FILETYPE_PEM) <= 0)
        {
            reset();
            return -9;
        }
        if (SSL_CTX_use_PrivateKey_file(protocol_.ctx, key, SSL_FILETYPE_PEM) <= 0)
        {
            reset();
            return -10;
        }
        if (SSL_CTX_check_private_key(protocol_.ctx) <= 0)
        {
            reset();
            return -11;
        }
        if ((epollFd_ = epoll_create1(0)) < 0)
        {
            reset();
            return -12;
        }
        eventPool_.init(eventPoolSize);
        handlerPool_.init(handlerPoolSize);
        newEventBuf_ = new epoll_event[maxBufEntrs];
        accEvent_.type = 1;
        epoll_event acceptor;
        acceptor.events = EPOLLIN;
        acceptor.data.ptr = &accEvent_;
        if (epoll_ctl(epollFd_, EPOLL_CTL_ADD, accEvent_.fd, &acceptor) < 0)
        {
            reset();
            return -13;
        }
        while (!stopSource_.stop_requested())
        {
            int n = epoll_wait(epollFd_, newEventBuf_, maxBufEntrs, -1);
            if (n < 0)
            {
                if (errno == EINTR)
                    continue;
                reset();
                return -14;
            }
            for (int i = 0; i < n; ++i)
            {
                Event *event = reinterpret_cast<Event *>(newEventBuf_[i].data.ptr);
                if (event == nullptr)
                    goto error;
                switch (event->type)
                {
                case 1:
                    if (newEventBuf_[i].events & EPOLLIN)
                    {
                        Event *cliEvent = eventPool_.acquire();
                        if (cliEvent == nullptr)
                            goto error;
                        socklen_t socklen = sizeof(cliEvent->addr);
                        cliEvent->fd = ::accept4(accEvent_.fd, (sockaddr *)&cliEvent->addr, &socklen, SOCK_NONBLOCK | SOCK_CLOEXEC);
                        if (cliEvent->fd < 0)
                        {
                            switch (errno)
                            {
                            default:
                                goto error;
                            }
                        }
                        cliEvent->ssl = SSL_new(protocol_.ctx);
                        if (cliEvent->ssl == nullptr)
                            goto error;
                        if (SSL_set_fd(cliEvent->ssl, cliEvent->fd) <= 0)
                            goto error;
                        int e = SSL_accept(cliEvent->ssl);
                        if (e < 0)
                        {
                            switch (SSL_get_error(cliEvent->ssl, e))
                            {
                            case SSL_ERROR_WANT_READ:
                            {
                                cliEvent->type = 3;
                                epoll_event recver;
                                recver.events = EPOLLIN | EPOLLET;
                                recver.data.ptr = cliEvent;
                                if (epoll_ctl(epollFd_, EPOLL_CTL_ADD, cliEvent->fd, &recver) < 0)
                                    goto error;
                            }
                            break;
                            case SSL_ERROR_WANT_WRITE:
                            {
                                cliEvent->type = 3;
                                epoll_event sender;
                                sender.events = EPOLLOUT | EPOLLET;
                                sender.data.ptr = cliEvent;
                                if (epoll_ctl(epollFd_, EPOLL_CTL_ADD, cliEvent->fd, &sender) < 0)
                                    goto error;
                            }
                            break;
                            default:
                                goto error;
                            }
                        }
                        else if (e == 0)
                        {
                            printf("client left\n"); ///
                            eventPool_.release(cliEvent);
                        }
                        else
                        {
                            cliEvent->type = 2;
                            cliEvent->handler = handlerPool_.acquire();
                            if (cliEvent->handler == nullptr)
                                goto error;
                            epoll_event recver;
                            recver.events = EPOLLIN | EPOLLET;
                            recver.data.ptr = cliEvent;
                            if (epoll_ctl(epollFd_, EPOLL_CTL_ADD, cliEvent->fd, &recver) < 0)
                                goto error;
                        }
                    }
                    else if (newEventBuf_[i].events & EPOLLOUT)
                    {
                        goto error;
                    }
                    else
                    {
                        goto error;
                    }
                    break;
                case 2:
                    if (newEventBuf_[i].events & EPOLLIN)
                    {
                        if (event->handler == nullptr)
                            goto error;
                        std::vector<char> buf(bufSize, 0);
                        while (true)
                        {
                            ssize_t rn = ::SSL_read(event->ssl, buf.data(), buf.size());
                            if (rn < 0)
                            {
                                switch (SSL_get_error(event->ssl, rn))
                                {
                                case SSL_ERROR_WANT_READ:
                                    goto breakout;
                                default:
                                    goto error;
                                }
                            }
                            else if (rn == 0)
                            {
                                int e = SSL_shutdown(event->ssl);
                                if (e <= 0)
                                {
                                    switch (SSL_get_error(event->ssl, e))
                                    {
                                    case SSL_ERROR_WANT_READ:
                                    {
                                        event->type = 4;
                                        epoll_event recver;
                                        recver.events = EPOLLIN | EPOLLET;
                                        recver.data.ptr = event;
                                        if (epoll_ctl(epollFd_, EPOLL_CTL_MOD, event->fd, &recver) < 0)
                                            goto error;
                                    }
                                    break;
                                    case SSL_ERROR_WANT_WRITE:
                                    {
                                        event->type = 4;
                                        epoll_event sender;
                                        sender.events = EPOLLOUT | EPOLLET;
                                        sender.data.ptr = event;
                                        if (epoll_ctl(epollFd_, EPOLL_CTL_MOD, event->fd, &sender) < 0)
                                            goto error;
                                    }
                                    break;
                                    default:
                                        goto error;
                                    }
                                }
                                else
                                {
                                    printf("client left\n"); ///
                                    epoll_ctl(epollFd_, EPOLL_CTL_DEL, event->fd, nullptr);
                                    handlerPool_.release(event->handler);
                                    eventPool_.release(event);
                                    goto breakout;
                                }
                            }
                            else
                            {
                                event->handler->appendRequest(buf.data(), rn);
                                event->handler->process();
                                if (event->handler->isResponse())
                                {
                                    epoll_event sender;
                                    sender.events = EPOLLIN | EPOLLOUT | EPOLLET;
                                    sender.data.ptr = event;
                                    if (epoll_ctl(epollFd_, EPOLL_CTL_MOD, event->fd, &sender) < 0)
                                        goto error;
                                }
                            }
                        }
                    }
                    else if (newEventBuf_[i].events & EPOLLOUT)
                    {
                        if (event->handler == nullptr)
                            goto error;
                        ssize_t sn = 0;
                        do
                        {
                            sn = ::SSL_write(event->ssl, event->handler->responseBegin(), event->handler->responseLength());
                            if (sn <= 0)
                            {
                                switch (SSL_get_error(event->ssl, sn))
                                {
                                case SSL_ERROR_WANT_WRITE:
                                    goto breakout;
                                default:
                                    goto error;
                                }
                            }
                        } while (event->handler->isResponding(sn));

                        epoll_event sender;
                        sender.events = EPOLLIN | EPOLLET;
                        sender.data.ptr = event;
                        if (epoll_ctl(epollFd_, EPOLL_CTL_MOD, event->fd, &sender) < 0)
                            goto error;
                    }
                    else
                    {
                        goto error;
                    }
                breakout:
                    break;
                case 3:
                    if (newEventBuf_[i].events & EPOLLIN)
                    {
                        int e = SSL_accept(event->ssl);
                        if (e < 0)
                        {
                            switch (SSL_get_error(event->ssl, e))
                            {
                            case SSL_ERROR_WANT_READ:
                                break;
                            case SSL_ERROR_WANT_WRITE:
                            {
                                epoll_event sender;
                                sender.events = EPOLLOUT | EPOLLET;
                                sender.data.ptr = event;
                                if (epoll_ctl(epollFd_, EPOLL_CTL_MOD, event->fd, &sender) < 0)
                                    goto error;
                            }
                            break;
                            default:
                                goto error;
                            }
                        }
                        else if (e == 0)
                        {
                            printf("client left\n"); ///
                            eventPool_.release(event);
                        }
                        else
                        {
                            event->type = 2;
                            event->handler = handlerPool_.acquire();
                            if (event->handler == nullptr)
                                goto error;
                            epoll_event recver;
                            recver.events = EPOLLIN | EPOLLET;
                            recver.data.ptr = event;
                            if (epoll_ctl(epollFd_, EPOLL_CTL_MOD, event->fd, &recver) < 0)
                                goto error;
                        }
                    }
                    else if (newEventBuf_[i].events & EPOLLOUT)
                    {
                        int e = SSL_accept(event->ssl);
                        if (e < 0)
                        {
                            switch (SSL_get_error(event->ssl, e))
                            {
                            case SSL_ERROR_WANT_READ:
                            {
                                epoll_event recver;
                                recver.events = EPOLLIN | EPOLLET;
                                recver.data.ptr = event;
                                if (epoll_ctl(epollFd_, EPOLL_CTL_MOD, event->fd, &recver) < 0)
                                    goto error;
                            }
                            break;
                            case SSL_ERROR_WANT_WRITE:
                                break;
                            default:
                                goto error;
                            }
                        }
                        else if (e == 0)
                        {
                            printf("client left\n"); ///
                            eventPool_.release(event);
                        }
                        else
                        {
                            event->type = 2;
                            event->handler = handlerPool_.acquire();
                            if (event->handler == nullptr)
                                goto error;
                            epoll_event recver;
                            recver.events = EPOLLIN | EPOLLET;
                            recver.data.ptr = event;
                            if (epoll_ctl(epollFd_, EPOLL_CTL_MOD, event->fd, &recver) < 0)
                                goto error;
                        }
                    }
                    else
                    {
                        goto error;
                    }
                    break;
                case 4:
                    if (newEventBuf_[i].events & EPOLLIN)
                    {
                        int e = SSL_shutdown(event->ssl);
                        if (e <= 0)
                        {
                            switch (SSL_get_error(event->ssl, e))
                            {
                            case SSL_ERROR_WANT_READ:
                                break;
                            case SSL_ERROR_WANT_WRITE:
                            {
                                epoll_event sender;
                                sender.events = EPOLLOUT | EPOLLET;
                                sender.data.ptr = event;
                                if (epoll_ctl(epollFd_, EPOLL_CTL_MOD, event->fd, &sender) < 0)
                                    goto error;
                            }
                            break;
                            default:
                                goto error;
                            }
                        }
                        else
                        {
                            printf("client left\n"); ///
                            epoll_ctl(epollFd_, EPOLL_CTL_DEL, event->fd, nullptr);
                            handlerPool_.release(event->handler);
                            eventPool_.release(event);
                        }
                    }
                    else if (newEventBuf_[i].events & EPOLLOUT)
                    {
                        int e = SSL_shutdown(event->ssl);
                        if (e <= 0)
                        {
                            switch (SSL_get_error(event->ssl, e))
                            {
                            case SSL_ERROR_WANT_READ:
                            {
                                epoll_event recver;
                                recver.events = EPOLLIN | EPOLLET;
                                recver.data.ptr = event;
                                if (epoll_ctl(epollFd_, EPOLL_CTL_MOD, event->fd, &recver) < 0)
                                    goto error;
                            }
                            break;
                            case SSL_ERROR_WANT_WRITE:
                                break;
                            default:
                                goto error;
                            }
                        }
                        else
                        {
                            printf("client left\n"); ///
                            epoll_ctl(epollFd_, EPOLL_CTL_DEL, event->fd, nullptr);
                            handlerPool_.release(event->handler);
                            eventPool_.release(event);
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
                    if (event->ssl != nullptr)
                    {
                        int e = SSL_shutdown(event->ssl);
                        if (e <= 0)
                        {
                            switch (SSL_get_error(event->ssl, e))
                            {
                            case SSL_ERROR_WANT_READ:
                            {
                                event->type = 4;
                                epoll_event recver;
                                recver.events = EPOLLIN | EPOLLET;
                                recver.data.ptr = event;
                                if (epoll_ctl(epollFd_, EPOLL_CTL_MOD, event->fd, &recver) < 0)
                                    goto cleanup;
                            }
                            break;
                            case SSL_ERROR_WANT_WRITE:
                            {
                                event->type = 4;
                                epoll_event sender;
                                sender.events = EPOLLOUT | EPOLLET;
                                sender.data.ptr = event;
                                if (epoll_ctl(epollFd_, EPOLL_CTL_MOD, event->fd, &sender) < 0)
                                    goto cleanup;
                            }
                            break;
                            default:
                                goto cleanup;
                            }
                        }
                    }
                cleanup:
                    ERR_clear_error();
                    epoll_ctl(epollFd_, EPOLL_CTL_DEL, event->fd, nullptr);
                    handlerPool_.release(event->handler);
                    eventPool_.release(event);
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
        epoll_ctl(epollFd_, EPOLL_CTL_DEL, accEvent_.fd, nullptr);
        if (newEventBuf_ != nullptr)
            delete[] newEventBuf_;
        newEventBuf_ = nullptr;
        handlerPool_.reset();
        eventPool_.reset();
        if (epollFd_ != -1)
            ::close(epollFd_);
        epollFd_ = -1;
        accEvent_.reset();
    }
};