#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <liburing.h>
#include <string>
#include <vector>
#include <cstdlib>
#include <stop_token>
#include "concepts.hpp"

class Proactor
{
    struct Info
    {
        sockaddr_in sockaddr{};
        const char *ip = nullptr;
        int port = -1;
        int fd = -1;
    } serInfo_;
    io_uring uring_;
    int bgid_ = 1;
    io_uring_buf_ring *bufRing_ = nullptr;
    int maxBufEntrs_ = 0;
    void *bufBase_ = nullptr;
    struct Event
    {
        int type = -1;
        int fd = -1;
        Handler *handler = nullptr;
        inline void reset() noexcept
        {
            type = -1;
            fd = -1;
            handler = nullptr;
        }
    } accEvent_ = {.type = 0};
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
        std::vector<Obj> &myPool() noexcept { return pool_; }
    };
    ObjPool<Event> eventPool_;
    ObjPool<Handler> handlerPool_;
    std::stop_source stopSource_;

public:
    Proactor() noexcept = default;
    ~Proactor() noexcept { stop(); }
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
    // -11 io_uring_submit() error
    // -12 io_uring_wait_cqe() error
    int run(const char *ip, int port, int backlog = 511,
            unsigned int sqEntries = 512, unsigned int cqEntries = 1024,
            int maxAccepts = 256, size_t eventPoolSize = 256, size_t handlerPoolSize = 256,
            int maxBufEntrs = 1024,  int bufSize = 4096)
    {
        if (ip == nullptr)
            return -1;
        serInfo_.sockaddr.sin_family = AF_INET;
        if (::inet_pton(AF_INET, ip, &serInfo_.sockaddr.sin_addr) <= 0)
        {
            serInfo_ = {};
            return -1;
        }
        serInfo_.ip = ip;
        if (port < 0 || port > 65535)
        {
            serInfo_ = {};
            return -2;
        }
        serInfo_.sockaddr.sin_port = ::htons(port);
        serInfo_.port = port;
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0)
        {
            serInfo_ = {};
            return -3;
        }
        serInfo_.fd = fd;
        int flags;
        if ((flags = ::fcntl(serInfo_.fd, F_GETFL, 0)) < 0)
        {
            ::close(serInfo_.fd);
            serInfo_ = {};
            return -4;
        }
        if (::fcntl(serInfo_.fd, F_SETFL, flags | O_NONBLOCK) < 0)
        {
            ::close(serInfo_.fd);
            serInfo_ = {};
            return -4;
        }
        int opt = 1;
        if (::setsockopt(serInfo_.fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        {
            ::close(serInfo_.fd);
            serInfo_ = {};
            return -5;
        }
        if (::setsockopt(serInfo_.fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0)
        {
            ::close(serInfo_.fd);
            serInfo_ = {};
            return -5;
        }
        if (::bind(fd, (const sockaddr *)&serInfo_.sockaddr, sizeof(sockaddr_in)) < 0)
        {
            ::close(serInfo_.fd);
            serInfo_ = {};
            return -6;
        }
        if (::listen(fd, backlog) < 0)
        {
            ::close(serInfo_.fd);
            serInfo_ = {};
            return -7;
        }
        io_uring_params params = {};
        params.flags = IORING_SETUP_CQSIZE;
        params.cq_entries = cqEntries;
        if (io_uring_queue_init_params(sqEntries, &uring_, &params) < 0)
        {
            ::close(serInfo_.fd);
            serInfo_ = {};
            return -8;
        }
        maxBufEntrs_ = maxBufEntrs;
        if (maxBufEntrs_ != 0 && posix_memalign(&bufBase_, 4096, maxBufEntrs_ * bufSize) != 0)
        {
            ::close(serInfo_.fd);
            serInfo_ = {};
            return -9;
        }
        int err = 0;
        if ((bufRing_ = io_uring_setup_buf_ring(&uring_, maxBufEntrs_, bgid_, 0, &err)) == nullptr)
        {
            ::close(serInfo_.fd);
            serInfo_ = {};
            return -10;
        }
        for (int i = 0; i < maxBufEntrs_; ++i)
            io_uring_buf_ring_add(bufRing_, (char *)bufBase_ + i * bufSize, bufSize, i, io_uring_buf_ring_mask(maxBufEntrs_), i);
        io_uring_buf_ring_advance(bufRing_, maxBufEntrs_);
        for (int i = 0; i < maxAccepts; ++i)
            addAccept();
        eventPool_.init(eventPoolSize);
        handlerPool_.init(handlerPoolSize);
        if (io_uring_submit(&uring_) < 0)
        {
            ::close(serInfo_.fd);
            serInfo_ = {};
            return -11;
        }
        while (!stopSource_.stop_requested())
        {
            io_uring_cqe *cqe;
            int e = io_uring_wait_cqe(&uring_, &cqe);
            if (e < 0)
            {
                if (e == -EINTR)
                    continue;
                ::close(serInfo_.fd);
                serInfo_ = {};
                return -12;
            }
            unsigned int head = 0;
            unsigned int count = 0;
            io_uring_for_each_cqe(&uring_, head, cqe)
            {
                ++count;
                Event *event = reinterpret_cast<Event *>(io_uring_cqe_get_data(cqe));
                int n = cqe->res;
                if (n < 0)
                    switch (-n)
                    {
                    case ENOBUFS:
                        fprintf(stderr, "No Buffers\n"); //
                        if (event->type == 1)
                        {
                            ::close(event->fd);
                            handlerPool_.release(event->handler);
                            eventPool_.release(event);
                        }
                        break;
                    default:
                        fprintf(stderr, "Unhandle Error: %d\n", -n); //
                        ::close(event->fd);
                        handlerPool_.release(event->handler);
                        eventPool_.release(event);
                        break;
                    }
                int e = 0;
                switch (event->type)
                {
                case 0:
                    e = addAccept();
                    if (e < 0)
                        goto error;
                    e = addRecv_multishot(n);
                    if (e < 0)
                        goto error;
                    break;
                case 1:
                {
                    int fd = event->fd;
                    Handler *handler = event->handler;
                    if (cqe->flags & IORING_CQE_F_BUFFER)
                    {
                        unsigned short bid = cqe->flags >> 16;
                        char *buf = (char *)bufBase_ + (bid * bufSize);
                        handler->appendRecvStream(buf, n);
                        handler->process_reflect();
                        if (handler->isResponse())
                        {
                            e = addSend(fd, handler);
                            if (e < 0)
                                goto error;
                        }
                        io_uring_buf_ring_add(bufRing_, buf, bufSize, bid, io_uring_buf_ring_mask(maxBufEntrs_), 0);
                        io_uring_buf_ring_advance(bufRing_, 1);
                    }
                    if (!(cqe->flags & IORING_CQE_F_MORE))
                    {
                        ::close(fd);
                        handlerPool_.release(handler);
                        eventPool_.release(event);
                    }
                    break;
                }
                case 2:
                {
                    int fd = event->fd;
                    Handler *handler = event->handler;
                    if (handler->stillSending(n))
                    {
                        e = addSend(fd, handler);
                        if (e < 0)
                            goto error;
                    }
                    else
                        eventPool_.release(event);
                    break;
                }
                default:
                error:
                    fprintf(stderr, "Event Error: %d\n", e); //
                    break;
                }
            }
            io_uring_cq_advance(&uring_, count);
            io_uring_submit(&uring_);
        }
        if (serInfo_.fd != -1)
        {
            ::close(serInfo_.fd);
            serInfo_.fd = -1;
        }
        if (bufRing_ != nullptr)
        {
            io_uring_free_buf_ring(&uring_, bufRing_, maxBufEntrs_, bgid_);
            bufRing_ = nullptr;
        }
        if (bufBase_ != nullptr)
        {
            std::free(bufBase_);
            bufBase_ = nullptr;
        }
        io_uring_queue_exit(&uring_);
        for (auto &event : eventPool_.myPool())
            if (event.fd != -1)
            {
                ::close(event.fd);
                event.fd = -1;
            }
        return 0;
    }
    inline void stop() const noexcept { stopSource_.request_stop(); }

private:
    int addAccept()
    {
        io_uring_sqe *sqe = io_uring_get_sqe(&uring_);
        if (sqe == nullptr)
            return -1;
        io_uring_prep_accept(sqe, serInfo_.fd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
        io_uring_sqe_set_data(sqe, &accEvent_);
        return 0;
    }
    int addRecv_multishot(int fd)
    {
        Handler *handler = handlerPool_.acquire();
        if (handler == nullptr)
        {
            ::close(fd);
            return -1;
        }
        Event *event = eventPool_.acquire();
        if (event == nullptr)
        {
            ::close(fd);
            handlerPool_.release(handler);
            return -2;
        }
        event->type = 1;
        event->fd = fd;
        event->handler = handler;
        io_uring_sqe *sqe = io_uring_get_sqe(&uring_);
        if (sqe == nullptr)
        {
            ::close(fd);
            handlerPool_.release(handler);
            eventPool_.release(event);
            return -3;
        }
        io_uring_prep_recv_multishot(sqe, fd, nullptr, 0, 0);
        sqe->buf_group = bgid_;
        sqe->flags |= IOSQE_BUFFER_SELECT;
        io_uring_sqe_set_data(sqe, event);
        return 0;
    }
    int addSend(int fd, Handler *handler)
    {
        if (handler == nullptr)
        {
            ::close(fd);
            return -1;
        }
        Event *event = eventPool_.acquire();
        if (event == nullptr)
        {
            ::close(fd);
            handlerPool_.release(handler);
            return -2;
        }
        event->type = 2;
        event->fd = fd;
        event->handler = handler;
        io_uring_sqe *sqe = io_uring_get_sqe(&uring_);
        if (sqe == nullptr)
        {
            ::close(fd);
            handlerPool_.release(handler);
            eventPool_.release(event);
            return -3;
        }
        const char *data = handler->responseBegin();
        size_t length = handler->responseLength();
        io_uring_prep_send(sqe, fd, data, length, MSG_NOSIGNAL);
        io_uring_sqe_set_data(sqe, event);
        return 0;
    }
};