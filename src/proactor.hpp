#pragma once

#include "myconcepts.hpp"
#include "event.hpp"
#include "objectPool.hpp"
#include <liburing.h>
#include <string>
#include <cstdlib>
#include <cstring>
#include <stop_token>

template <typename Event>
    requires mustDerivedFromEventBase<Event> && mustResettable<Event>
class Proactor // remember to add timers!
{
    io_uring uring_;
    int bgid_ = 1;
    io_uring_buf_ring *bufRing_ = nullptr;
    int maxBufEntrs_ = 0;
    void *bufBase_ = nullptr;
    Event acceptor_;
    ObjectPool<Event> eventPool_;
    ObjectPool<typename Event::Handler> handlerPool_;
    std::stop_source stopSource_;

public:
    Proactor() noexcept = default;
    ~Proactor() noexcept = default;
    Proactor(const Proactor &) = delete;
    Proactor &operator=(const Proactor &) = delete;
    Proactor(Proactor &&) noexcept = delete;
    Proactor &operator=(Proactor &&) noexcept = delete;
    // 0 success
    // -1 ip error
    // -2 port error
    // -3 socket() error
    // -4 fcntl() error
    // -5 setsockopt() error
    // -6 bind() error
    // -7 listen() error
    // -8 io_uring_queue_init_params() error
    // -9 posix_memalign() error
    // -10 io_uring_setup_buf_ring() error
    // -11 eventPool_.acquire() error
    // -12 io_uring_get_sqe() error
    // -13 io_uring_submit() error
    // -14 io_uring_wait_cqe() error
    int run_tcp(const char *ip, int port, int backlog = 511,
                unsigned int sqEntries = 512, unsigned int cqEntries = 1024,
                int maxAcceptEvents = 256, size_t eventPoolSize = 512, size_t handlerPoolSize = 256,
                int maxBufEntrs = 1024, int bufSize = 4096)
        requires mustEventSocket<Event>
    {
        int err = acceptor_.listen_tcp(ip, port, backlog);
        if (err < 0)
        {
            reset();
            return err;
        }
        io_uring_params params = {};
        params.flags = IORING_SETUP_CQSIZE;
        params.cq_entries = cqEntries;
        if (io_uring_queue_init_params(sqEntries, &uring_, &params) < 0)
        {
            reset();
            return -8;
        }
        eventPool_.init(eventPoolSize);
        handlerPool_.init(handlerPoolSize);
        maxBufEntrs_ = maxBufEntrs;
        if (maxBufEntrs_ != 0 && posix_memalign(&bufBase_, 4096, maxBufEntrs_ * bufSize) != 0)
        {
            reset();
            return -9;
        }
        int e = 0;
        if ((bufRing_ = io_uring_setup_buf_ring(&uring_, maxBufEntrs_, bgid_, 0, &e)) == nullptr)
        {
            reset();
            return -10;
        }
        for (int i = 0; i < maxBufEntrs_; ++i)
            io_uring_buf_ring_add(bufRing_, (char *)bufBase_ + i * bufSize, bufSize, i, io_uring_buf_ring_mask(maxBufEntrs_), i);
        io_uring_buf_ring_advance(bufRing_, maxBufEntrs_);
        for (int i = 0; i < maxAcceptEvents; ++i)
        {
            Event *recvEvent = eventPool_.acquire();
            if (recvEvent == nullptr)
            {
                reset();
                return -11;
            }
            recvEvent->type = 1;
            io_uring_sqe *sqe = io_uring_get_sqe(&uring_);
            if (sqe == nullptr)
            {
                reset();
                return -12;
            }
            socklen_t socklen = sizeof(recvEvent->addr);
            io_uring_prep_accept(sqe, acceptor_.fd, (sockaddr *)&recvEvent->addr, &socklen, SOCK_NONBLOCK | SOCK_CLOEXEC);
            io_uring_sqe_set_data(sqe, recvEvent);
        }
        if (io_uring_submit(&uring_) < 0)
        {
            reset();
            return -13;
        }
        while (!stopSource_.stop_requested())
        {
            io_uring_cqe *cqe;
            int e = io_uring_wait_cqe(&uring_, &cqe);
            if (e < 0)
            {
                if (e == -EINTR)
                    continue;
                reset();
                return -14;
            }
            unsigned int head = 0;
            unsigned int count = 0;
            io_uring_for_each_cqe(&uring_, head, cqe)
            {
                ++count;
                Event *event = reinterpret_cast<Event *>(io_uring_cqe_get_data(cqe));
                if (event == nullptr)
                    goto error;
                if (cqe->res < 0)
                {
                    switch (-cqe->res)
                    {
                    case ECANCELED:
                        continue;
                    default:
                        goto error;
                    }
                }
                switch (event->type)
                {
                case 1:
                {
                    event->fd = cqe->res;

                    event->type = 2;
                    event->handler = handlerPool_.acquire();
                    if (event->handler == nullptr)
                        goto error;
                    io_uring_sqe *sqe = io_uring_get_sqe(&uring_);
                    if (sqe == nullptr)
                        goto error;
                    io_uring_prep_recv_multishot(sqe, event->fd, nullptr, 0, 0);
                    sqe->buf_group = bgid_;
                    sqe->flags |= IOSQE_BUFFER_SELECT;
                    io_uring_sqe_set_data(sqe, event);

                    Event *recvEvent = eventPool_.acquire();
                    if (recvEvent == nullptr)
                        goto error;
                    recvEvent->type = 1;
                    sqe = io_uring_get_sqe(&uring_);
                    if (sqe == nullptr)
                        goto error;
                    socklen_t socklen = sizeof(recvEvent->addr);
                    io_uring_prep_accept(sqe, acceptor_.fd, (sockaddr *)&recvEvent->addr, &socklen, SOCK_NONBLOCK | SOCK_CLOEXEC);
                    io_uring_sqe_set_data(sqe, recvEvent);
                }
                break;
                case 2:
                    if (cqe->res == 0)
                    {
                        printf("client left\n"); ///
                        handlerPool_.release(event->handler);
                        eventPool_.release(event);
                    }
                    else
                    {
                        if (cqe->flags & IORING_CQE_F_BUFFER)
                        {
                            unsigned short bid = cqe->flags >> 16;
                            char *buf = (char *)bufBase_ + (bid * bufSize);
                            if (event->handler == nullptr)
                            {
                                io_uring_buf_ring_add(bufRing_, buf, bufSize, bid, io_uring_buf_ring_mask(maxBufEntrs_), 0);
                                io_uring_buf_ring_advance(bufRing_, 1);
                                goto error;
                            }
                            event->handler->appendRequest(buf, cqe->res);
                            event->handler->process();
                            if (event->handler->isResponse())
                            {
                                Event *sendEvent = eventPool_.acquire();
                                if (sendEvent == nullptr)
                                {
                                    io_uring_buf_ring_add(bufRing_, buf, bufSize, bid, io_uring_buf_ring_mask(maxBufEntrs_), 0);
                                    io_uring_buf_ring_advance(bufRing_, 1);
                                    goto error;
                                }
                                sendEvent->type = 3;
                                sendEvent->fd = event->fd;
                                sendEvent->handler = event->handler;
                                io_uring_sqe *sqe = io_uring_get_sqe(&uring_);
                                if (sqe == nullptr)
                                {
                                    io_uring_buf_ring_add(bufRing_, buf, bufSize, bid, io_uring_buf_ring_mask(maxBufEntrs_), 0);
                                    io_uring_buf_ring_advance(bufRing_, 1);
                                    goto error;
                                }
                                io_uring_prep_send(sqe, sendEvent->fd, sendEvent->handler->responseBegin(), sendEvent->handler->responseLength(), MSG_NOSIGNAL);
                                io_uring_sqe_set_data(sqe, sendEvent);
                            }
                            io_uring_buf_ring_add(bufRing_, buf, bufSize, bid, io_uring_buf_ring_mask(maxBufEntrs_), 0);
                            io_uring_buf_ring_advance(bufRing_, 1);
                        }
                        if (!(cqe->flags & IORING_CQE_F_MORE))
                        {
                            handlerPool_.release(event->handler);
                            eventPool_.release(event);
                        }
                    }
                    break;
                case 3:
                {
                    if (event->handler == nullptr)
                        goto error;
                    if (!event->handler->isResponding(cqe->res))
                    {
                        event->fd = -1;
                        eventPool_.release(event);
                    }
                    else
                    {
                        io_uring_sqe *sqe = io_uring_get_sqe(&uring_);
                        if (sqe == nullptr)
                            goto error;
                        io_uring_prep_send(sqe, event->fd, event->handler->responseBegin(), event->handler->responseLength(), MSG_NOSIGNAL);
                        io_uring_sqe_set_data(sqe, event);
                    }
                }
                break;
                default:
                error:
                    fprintf(stderr, "%s", strerror(-cqe->res)); ///
                    handlerPool_.release(event->handler);
                    eventPool_.release(event);
                    break;
                }
            }
            io_uring_cq_advance(&uring_, count);
            io_uring_submit(&uring_);
        }
        reset();
        return 0;
    }
    inline void stop() const noexcept { stopSource_.request_stop(); }
    inline void reset() noexcept
    {
        if (bufRing_ != nullptr)
        {
            io_uring_free_buf_ring(&uring_, bufRing_, maxBufEntrs_, bgid_);
            bufRing_ = nullptr;
        }
        if (bufBase_ != nullptr)
        {
            ::free(bufBase_);
            bufBase_ = nullptr;
        }
        maxBufEntrs_ = 0;
        handlerPool_.reset();
        eventPool_.reset();
        io_uring_queue_exit(&uring_);
        uring_ = {};
        acceptor_.reset();
    }
};