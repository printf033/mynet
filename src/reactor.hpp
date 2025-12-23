#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <string>
#include <vector>
#include <cstdlib>
#include <stop_token>
#include "concepts.hpp"

template <typename Peer>
struct TEvent
{
    static_assert(is_tcp<Peer> || is_tls<Peer>,
                  "Event<Peer>: Peer must satisfy is_tcp or is_tls");
};
template <is_tcp Peer>
struct TEvent<Peer>
{
    int fd = -1;
    uint32_t events = 0;
    Handler handler{};
    inline void reset() noexcept
    {
        fd = -1;
        events = 0;
        handler.reset();
    }
};
template <is_tls Peer>
struct TEvent<Peer>
{
    int fd = -1;
    SSL *ssl = nullptr;
    uint32_t events = 0;
    Handler handler{};
    inline void reset() noexcept
    {
        fd = -1;
        events = 0;
        handler.reset();
    }
};
template <typename Peer>
class Reactor : private Peer
{
    int epollFd_ = -1;
    epoll_event *newEventBuf_ = nullptr;
    using Event = TEvent<Peer>;
    Event accEvent_{};
    template <Resettable Obj>
    class ObjPool
    {
        std::vector<Obj> pool_;
        std::vector<Obj *> available_;

    public:
        ObjPool() noexcept = default;
        ~ObjPool() noexcept = default;
        ObjPool(const ObjPool &) = delete;
        ObjPool &operator=(const ObjPool &) = delete;
        ObjPool(ObjPool &&) noexcept = delete;
        ObjPool &operator=(ObjPool &&) noexcept = delete;
        inline void init(size_t capa)
        {
            pool_.resize(capa);
            available_.reserve(capa);
            for (auto &event : pool_)
                available_.push_back(&event);
        }
        inline Obj *acquire()
        {
            if (available_.empty())
                return nullptr;
            Obj *obj = available_.back();
            available_.pop_back();
            return obj;
        }
        inline void release(Obj *obj)
        {
            if (obj != nullptr)
            {
                obj->reset();
                available_.push_back(obj);
            }
        }
        inline std::vector<Obj> &myPool() noexcept { return pool_; }
    };
    ObjPool<Event> eventPool_;
    std::stop_source stopSource_;

public:
    Reactor() noexcept = default;
    ~Reactor() noexcept { stop(); }
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
    int run(const char *ip, int port, int backlog = 511,
            int recvTimeout_s = 3, int recvTimeout_us = 0,
            unsigned int eventPoolSize = 1024, unsigned int maxBufEntrs = 1024)
        requires is_tcp<Peer>
    {
        int n = Peer::listen(ip, port, backlog);
        if (n < 0)
            return n;
        accEvent_.fd = Peer::serInfo_.fd;
        epollFd_ = epoll_create1(0);
        if (epollFd_ < 0)
        {
            ::close(Peer::serInfo_.fd);
            Peer::serInfo_ = {};
            return -8;
        }
        epoll_event acceptor;
        acceptor.events = EPOLLIN;
        acceptor.data.ptr = &accEvent_;
        if (epoll_ctl(epollFd_, EPOLL_CTL_ADD, Peer::serInfo_.fd, &acceptor) < 0)
        {
            ::close(epollFd_);
            ::close(Peer::serInfo_.fd);
            Peer::serInfo_ = {};
            return -9;
        }
        newEventBuf_ = new epoll_event[maxBufEntrs];
        eventPool_.init(eventPoolSize);
        while (!stopSource_.stop_requested())
        {
            n = epoll_wait(epollFd_, newEventBuf_, maxBufEntrs, -1);
            if (n < 0)
            {
                if (errno == EINTR)
                    continue;
                ::close(epollFd_);
                ::close(Peer::serInfo_.fd);
                Peer::serInfo_ = {};
                return -10;
            }
            for (int i = 0; i < n; ++i)
            {
                Event *event = reinterpret_cast<Event *>(newEventBuf_[i].data.ptr);
                int e = 0;
                if (event->fd == Peer::serInfo_.fd)
                {
                    int fd = Peer::accept(recvTimeout_s, recvTimeout_us);
                    if (fd < 0)
                    {
                        fprintf(stderr, "Peer::accept() Error: %d\n", fd); //
                        continue;
                    }
                    Event *recvEvent = eventPool_.acquire();
                    if (recvEvent == nullptr)
                        continue;
                    recvEvent->fd = fd;
                    recvEvent->events |= (EPOLLIN | EPOLLET);
                    epoll_event recver;
                    recver.events = recvEvent->events;
                    recver.data.ptr = recvEvent;
                    if (epoll_ctl(epollFd_, EPOLL_CTL_ADD, recvEvent->fd, &recver) < 0)
                    {
                        ::close(recvEvent->fd);
                        eventPool_.release(recvEvent);
                        goto error;
                    }
                }
                else
                {
                    if (newEventBuf_[i].events & EPOLLIN)
                    {
                        int fd = event->fd;
                        Handler &handler = event->handler;
                        char buf[4096]{0};
                        ssize_t rn = 0;
                        do
                        {
                            rn = Peer::recv(fd, buf, sizeof(buf));
                            if (rn >= 0)
                            {
                                if (rn == 0)
                                    break;
                                handler.appendRecvStream(buf, rn);
                                handler.process_reflect();
                                if (handler.isResponse())
                                {
                                    event->events |= (EPOLLOUT | EPOLLET);
                                    epoll_event sender;
                                    sender.events = event->events;
                                    sender.data.ptr = event;
                                    if (epoll_ctl(epollFd_, EPOLL_CTL_MOD, event->fd, &sender) < 0)
                                    {
                                        epoll_ctl(epollFd_, EPOLL_CTL_DEL, fd, nullptr);
                                        eventPool_.release(event);
                                        goto error;
                                    }
                                }
                            }
                            else
                            {
                                epoll_ctl(epollFd_, EPOLL_CTL_DEL, fd, nullptr);
                                eventPool_.release(event);
                                if (rn != 0)
                                    fprintf(stderr, "Peer::recv() Error: %ld\n", rn); //
                                rn = 0;
                            }
                        } while (rn >= sizeof(buf));
                    }
                    else if (newEventBuf_[i].events & EPOLLOUT)
                    {
                        int fd = event->fd;
                        Handler &handler = event->handler;
                        ssize_t sn = 0;
                        do
                        {
                            sn = Peer::send(fd, handler.responseBegin(), handler.responseLength());
                            if (sn >= 0)
                            {
                                event->events &= ~EPOLLOUT;
                                epoll_event sender;
                                sender.events = event->events;
                                sender.data.ptr = event;
                                if (epoll_ctl(epollFd_, EPOLL_CTL_MOD, event->fd, &sender) < 0)
                                {
                                    epoll_ctl(epollFd_, EPOLL_CTL_DEL, fd, nullptr);
                                    eventPool_.release(event);
                                    goto error;
                                }
                            }
                            else
                            {
                                epoll_ctl(epollFd_, EPOLL_CTL_DEL, fd, nullptr);
                                eventPool_.release(event);
                                fprintf(stderr, "Peer::send() Error: %ld\n", sn); //
                            }
                        } while (handler.stillSending(sn));
                    }
                    else if (newEventBuf_[i].events & EPOLLERR)
                    {
                    error:
                        fprintf(stderr, "Event Error: %d\n", e); //
                    }
                }
            }
        }
        if (Peer::serInfo_.fd != -1)
        {
            epoll_ctl(epollFd_, EPOLL_CTL_DEL, Peer::serInfo_.fd, nullptr);
            ::close(Peer::serInfo_.fd);
            Peer::serInfo_.fd = -1;
        }
        if (epollFd_ != -1)
        {
            ::close(epollFd_);
            epollFd_ = -1;
        }
        if (newEventBuf_ != nullptr)
        {
            delete[] newEventBuf_;
            newEventBuf_ = nullptr;
        }
        for (auto &event : eventPool_.myPool())
            if (event.fd != -1)
            {
                ::close(event.fd);
                event.fd = -1;
            }
        return 0;
    }
    // single crt&pem format
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
    int run(const char *ip, int port, const char *crt, const char *key, int backlog = 511,
            int recvTimeout_s = 3, int recvTimeout_us = 0,
            unsigned int eventPoolSize = 1024, unsigned int maxBufEntrs = 1024)
        requires is_tls<Peer>
    {
        int n = Peer::listen(ip, port, crt, key, backlog);
        if (n < 0)
            return n;
        accEvent_.fd = Peer::serInfo_.fd;
        epollFd_ = epoll_create1(0);
        if (epollFd_ < 0)
        {
            ::close(Peer::serInfo_.fd);
            SSL_CTX_free(Peer::serInfo_.ctx);
            Peer::serInfo_ = {};
            return -12;
        }
        epoll_event acceptor;
        acceptor.events = EPOLLIN;
        acceptor.data.ptr = &accEvent_;
        if (epoll_ctl(epollFd_, EPOLL_CTL_ADD, Peer::serInfo_.fd, &acceptor) < 0)
        {
            ::close(epollFd_);
            ::close(Peer::serInfo_.fd);
            SSL_CTX_free(Peer::serInfo_.ctx);
            Peer::serInfo_ = {};
            return -13;
        }
        newEventBuf_ = new epoll_event[maxBufEntrs];
        eventPool_.init(eventPoolSize);
        while (!stopSource_.stop_requested())
        {
            n = epoll_wait(epollFd_, newEventBuf_, maxBufEntrs, -1);
            if (n < 0)
            {
                if (errno == EINTR)
                    continue;
                ::close(epollFd_);
                ::close(Peer::serInfo_.fd);
                SSL_CTX_free(Peer::serInfo_.ctx);
                Peer::serInfo_ = {};
                return -14;
            }
            for (int i = 0; i < n; ++i)
            {
                Event *event = reinterpret_cast<Event *>(newEventBuf_[i].data.ptr);
                int e = 0;
                if (event->fd == Peer::serInfo_.fd)
                {
                    SSL *ssl = Peer::accept(recvTimeout_s, recvTimeout_us);
                    if (ssl == nullptr)
                    {
                        fprintf(stderr, "Peer::accept() Error\n"); //
                        continue;
                    }
                    int fd = SSL_get_fd(ssl);
                    Event *recvEvent = eventPool_.acquire();
                    if (recvEvent == nullptr)
                        continue;
                    recvEvent->ssl = ssl;
                    recvEvent->fd = fd;
                    recvEvent->events |= (EPOLLIN | EPOLLET);
                    epoll_event recver;
                    recver.events = recvEvent->events;
                    recver.data.ptr = recvEvent;
                    if (epoll_ctl(epollFd_, EPOLL_CTL_ADD, fd, &recver) < 0)
                    {
                        SSL_shutdown(ssl);
                        SSL_free(ssl);
                        ::close(fd);
                        eventPool_.release(recvEvent);
                        goto error;
                    }
                }
                else
                {
                    if (newEventBuf_[i].events & EPOLLIN)
                    {
                        SSL *&ssl = event->ssl;
                        int fd = event->fd;
                        Handler &handler = event->handler;
                        char buf[4096]{0};
                        ssize_t rn = 0;
                        do
                        {
                            rn = Peer::recv(ssl, buf, sizeof(buf));
                            if (rn >= 0)
                            {
                                if (rn == 0)
                                    break;
                                handler.appendRecvStream(buf, rn);
                                handler.process_reflect();
                                if (handler.isResponse())
                                {
                                    event->events |= (EPOLLOUT | EPOLLET);
                                    epoll_event sender;
                                    sender.events = event->events;
                                    sender.data.ptr = event;
                                    if (epoll_ctl(epollFd_, EPOLL_CTL_MOD, event->fd, &sender) < 0)
                                    {
                                        epoll_ctl(epollFd_, EPOLL_CTL_DEL, fd, nullptr);
                                        eventPool_.release(event);
                                        goto error;
                                    }
                                }
                            }
                            else
                            {
                                epoll_ctl(epollFd_, EPOLL_CTL_DEL, fd, nullptr);
                                eventPool_.release(event);
                                if (rn != 0)
                                    fprintf(stderr, "Peer::recv() Error: %ld\n", rn); //
                                rn = 0;
                            }
                        } while (rn >= sizeof(buf));
                    }
                    else if (newEventBuf_[i].events & EPOLLOUT)
                    {
                        SSL *&ssl = event->ssl;
                        int fd = event->fd;
                        Handler &handler = event->handler;
                        ssize_t sn = 0;
                        do
                        {
                            sn = Peer::send(ssl, handler.responseBegin(), handler.responseLength());
                            if (sn >= 0)
                            {
                                event->events &= ~EPOLLOUT;
                                epoll_event sender;
                                sender.events = event->events;
                                sender.data.ptr = event;
                                if (epoll_ctl(epollFd_, EPOLL_CTL_MOD, event->fd, &sender) < 0)
                                {
                                    epoll_ctl(epollFd_, EPOLL_CTL_DEL, fd, nullptr);
                                    eventPool_.release(event);
                                    goto error;
                                }
                            }
                            else
                            {
                                epoll_ctl(epollFd_, EPOLL_CTL_DEL, fd, nullptr);
                                eventPool_.release(event);
                                fprintf(stderr, "Peer::send() Error: %ld\n", sn); //
                            }
                        } while (handler.stillSending(sn));
                    }
                    else if (newEventBuf_[i].events & EPOLLERR)
                    {
                    error:
                        fprintf(stderr, "Event Error: %d\n", e); //
                    }
                }
            }
        }
        if (Peer::cliInfo_.fd != -1)
        {
            epoll_ctl(epollFd_, EPOLL_CTL_DEL, Peer::cliInfo_.fd, nullptr);
            SSL_shutdown(Peer::cliInfo_.ssl);
            SSL_free(Peer::cliInfo_.ssl);
            ::close(Peer::cliInfo_.fd);
            SSL_CTX_free(Peer::cliInfo_.ctx);
            Peer::cliInfo_ = {};
        }
        if (Peer::serInfo_.fd != -1)
        {
            epoll_ctl(epollFd_, EPOLL_CTL_DEL, Peer::serInfo_.fd, nullptr);
            SSL_shutdown(Peer::serInfo_.ssl);
            SSL_free(Peer::serInfo_.ssl);
            ::close(Peer::serInfo_.fd);
            SSL_CTX_free(Peer::serInfo_.ctx);
            Peer::serInfo_ = {};
        }
        if (epollFd_ != -1)
        {
            ::close(epollFd_);
            epollFd_ = -1;
        }
        if (newEventBuf_ != nullptr)
        {
            delete[] newEventBuf_;
            newEventBuf_ = nullptr;
        }
        for (auto &event : eventPool_.myPool())
            if (event.fd != -1)
            {
                ::close(event.fd);
                event.fd = -1;
            }
        return 0;
    }
    inline void stop() const noexcept { stopSource_.request_stop(); }
};