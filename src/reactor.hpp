#ifndef MYNET_SRC_REACTOR_HPP
#define MYNET_SRC_REACTOR_HPP

#include "peer.hpp"
#include "cryptor.hpp"
#include "syncQueue_nonblocking.hpp"
#include "atomQueue_nonblocking.hpp"
#include "handler.hpp"
#include <sys/epoll.h>
#include <fcntl.h>
#include <thread>
#include <stop_token>
#include <vector>
#include <type_traits>

template <typename Peer_ser>
concept is_tcp_ser = std::is_same_v<Peer_ser, Peer_tcp_ser>;
template <typename Peer_ser>
concept is_tls_ser = std::is_same_v<Peer_ser, Cryptor_tls_ser>;
template <typename Peer_ser, template <typename> typename TaskQueue_nonblocking>
class Reactor_linux : public Peer_ser
{
    int mainreactor_fd_ = -1;
    epoll_event acceptor_;
    std::vector<std::jthread> subReactorVec_;
    std::stop_source stop_source_;
    using TaskType = std::conditional_t<std::is_same_v<Peer_ser, Cryptor_tls_ser>, SSL *, int>;
    TaskQueue_nonblocking<TaskType> clientQue_;

public:
    Reactor_linux(size_t taskQueue_capacity = 1024)
        : clientQue_(TaskQueue_nonblocking<TaskType>(taskQueue_capacity)) {}
    ~Reactor_linux()
    {
        stop();
        ::close(mainreactor_fd_);
    }
    Reactor_linux(const Reactor_linux &) = delete;
    Reactor_linux &operator=(const Reactor_linux &) = delete;
    Reactor_linux(Reactor_linux &&) = delete;
    Reactor_linux &operator=(Reactor_linux &&) = delete;
    // epoll_wait 0 millisecond timeout is high cost
    // 0 success
    // -1 socket() error
    // -2 inet_pton() error
    // -3 port error
    // -4 bind() error
    // -5 listen() error
    // -6 fcntl() error
    // -7 epoll_create1() error
    // -8 epoll_ctl() error
    int run(const std::string &ip, int port, int wait_queue_size = 5,
            int sub_reactor_num = 4, int max_client_num = 100, int epoll_wait_time_ms = 10)
        requires is_tcp_ser<Peer_ser>
    {
        auto n = Peer_ser::listen(ip, port, wait_queue_size);
        if (0 != n)
            return n;
        if (-1 == fcntl(Peer_ser::getFd(), F_SETFL, fcntl(Peer_ser::getFd(), F_GETFL, 0) | O_NONBLOCK))
            return -6;
        mainreactor_fd_ = epoll_create1(0);
        if (-1 == mainreactor_fd_)
            return -7;
        acceptor_.events = EPOLLIN | EPOLLET;
        acceptor_.data.fd = Peer_ser::getFd();
        if (-1 == epoll_ctl(mainreactor_fd_, EPOLL_CTL_ADD, Peer_ser::getFd(), &acceptor_))
            return -8;
        subReactorVec_.reserve(sub_reactor_num);
        for (int i = 0; i < sub_reactor_num; ++i)
            subReactorVec_.emplace_back(
                std::jthread([this, max_client_num, epoll_wait_time_ms](std::stop_token st)
                             {
                                 auto subReactor_fd = epoll_create1(0);
                                 if (-1 == subReactor_fd)
                                 {
                                     perror("epoll_create1");
                                     return;
                                 }
                                 int cli_fd = -1;
                                 epoll_event accept_event = {};
                                 accept_event.events = EPOLLIN | EPOLLET;
                                 epoll_event *recv_events = new epoll_event[max_client_num]();
                                 std::string data;
                                 Handler handler;
                                 while (!st.stop_requested())
                                 {
                                     if (0 == myClientQue().take(cli_fd))
                                     {
                                         accept_event.data.fd = cli_fd;
                                         if (-1 == epoll_ctl(subReactor_fd, EPOLL_CTL_ADD, cli_fd, &accept_event))
                                         {
                                             perror("epoll_ctl");
                                             ::close(cli_fd);
                                         }
                                     }
                                     int n = epoll_wait(subReactor_fd, recv_events, max_client_num, epoll_wait_time_ms);
                                     if (-1 == n)
                                     {
                                         perror("epoll_wait");
                                         break;
                                     }
                                     for (int i = 0; i < n; ++i)
                                     {
                                         cli_fd = recv_events[i].data.fd;
                                         auto n = Peer_ser::recv(cli_fd, data);
                                         if (n <= 0)
                                         {
                                             epoll_ctl(subReactor_fd, EPOLL_CTL_DEL, cli_fd, nullptr);
                                             printf("A client left, cli_fd: %d\n", cli_fd); //
                                             continue;
                                         }
                                         n = Peer_ser::send(cli_fd, handler.process(data));
                                         data.clear();
                                         if (n < 0)
                                         {
                                             epoll_ctl(subReactor_fd, EPOLL_CTL_DEL, cli_fd, nullptr);
                                             printf("send failed, cli_fd: %d\n", cli_fd); //
                                             continue;
                                         }
                                     }
                                 }
                                 ::close(subReactor_fd);
                                 delete[] recv_events;
                                 printf("subReactor thread exit\n"); //
                             },
                             stop_source_.get_token()));
        int cli_fd = -1;
        epoll_event accept_event = {};
        while (!stop_source_.stop_requested())
            if (1 == epoll_wait(mainreactor_fd_, &accept_event, 1, epoll_wait_time_ms))
            {
                cli_fd = Peer_ser::accept();
                if (cli_fd < 0)
                    continue;
                printf("A new client was accepted, cli_fd: %d\n", cli_fd); //
                if (clientQue_.put(cli_fd) < 0)
                    Peer_ser::send(cli_fd, "\0"); // error code
            }
        return 0;
    }
    // epoll_wait 0 millisecond timeout is high cost
    // !!! single crt & pem format !!!
    // 0 success
    // -1 socket() error
    // -2 inet_pton() error
    // -3 port error
    // -4 bind() error
    // -5 listen() error
    // -6 SSL_CTX_new() error
    // -7 SSL_CTX_use_certificate_file() error
    // -8 SSL_CTX_use_PrivateKey_file() error
    // -9 SSL_CTX_check_private_key() error
    // -10 fcntl() error
    // -11 epoll_create1() error
    // -12 epoll_ctl() error
    int run(const std::string &ip, int port, const std::string &crt, const std::string &key, int wait_queue_size = 5,
            int sub_reactor_num = 4, int max_client_num = 100, int epoll_wait_time_ms = 10)
        requires is_tls_ser<Peer_ser>
    {
        auto n = Peer_ser::listen(ip, port, crt, key, wait_queue_size);
        if (0 != n)
            return n;
        if (-1 == fcntl(Peer_ser::getFd(), F_SETFL, fcntl(Peer_ser::getFd(), F_GETFL, 0) | O_NONBLOCK))
            return -10;
        mainreactor_fd_ = epoll_create1(0);
        if (-1 == mainreactor_fd_)
            return -11;
        acceptor_.events = EPOLLIN | EPOLLET;
        acceptor_.data.fd = Peer_ser::getFd();
        if (-1 == epoll_ctl(mainreactor_fd_, EPOLL_CTL_ADD, Peer_ser::getFd(), &acceptor_))
            return -12;
        subReactorVec_.reserve(sub_reactor_num);
        for (int i = 0; i < sub_reactor_num; ++i)
            subReactorVec_.emplace_back(
                std::jthread([this, max_client_num, epoll_wait_time_ms](std::stop_token st)
                             {
                                 auto subReactor_fd = epoll_create1(0);
                                 if (-1 == subReactor_fd)
                                 {
                                     perror("epoll_create1");
                                     return;
                                 }
                                 int cli_fd = -1;
                                 SSL *cli_ssl = nullptr;
                                 epoll_event accept_event = {};
                                 accept_event.events = EPOLLIN | EPOLLET;
                                 epoll_event *recv_events = new epoll_event[max_client_num]();
                                 std::string data;
                                 Handler handler;
                                 while (!st.stop_requested())
                                 {
                                     if (0 == myClientQue().take(cli_ssl))
                                     {
                                         cli_fd = SSL_get_fd(cli_ssl);
                                         accept_event.data.ptr = cli_ssl;
                                         if (-1 == epoll_ctl(subReactor_fd, EPOLL_CTL_ADD, cli_fd, &accept_event))
                                         {
                                             perror("epoll_ctl");
                                             SSL_shutdown(cli_ssl);
                                             SSL_free(cli_ssl);
                                             cli_ssl = nullptr;
                                             ::close(cli_fd);
                                         }
                                     }
                                     int n = epoll_wait(subReactor_fd, recv_events, max_client_num, epoll_wait_time_ms);
                                     if (-1 == n)
                                     {
                                         perror("epoll_wait");
                                         break;
                                     }
                                     for (int i = 0; i < n; ++i)
                                     {
                                         cli_ssl = reinterpret_cast<SSL *>(recv_events[i].data.ptr);
                                         cli_fd = SSL_get_fd(cli_ssl);
                                         auto n = Peer_ser::recv(cli_ssl, data);
                                         if (n <= 0)
                                         {
                                             epoll_ctl(subReactor_fd, EPOLL_CTL_DEL, cli_fd, nullptr);
                                             printf("A client left, cli_fd: %d\n", cli_fd); //
                                             continue;
                                         }
                                         n = Peer_ser::send(cli_ssl, handler.process(data));
                                         data.clear();
                                         if (n < 0)
                                         {
                                             epoll_ctl(subReactor_fd, EPOLL_CTL_DEL, cli_fd, nullptr);
                                             printf("send failed, cli_fd: %d\n", cli_fd); //
                                             continue;
                                         }
                                     }
                                 }
                                 ::close(subReactor_fd);
                                 delete[] recv_events;
                                 printf("subReactor thread exit\n"); //
                             },
                             stop_source_.get_token()));
        int cli_fd = -1;
        SSL *cli_ssl = nullptr;
        epoll_event accept_event = {};
        while (!stop_source_.stop_requested())
            if (1 == epoll_wait(mainreactor_fd_, &accept_event, 1, epoll_wait_time_ms))
            {
                cli_fd = Peer_ser::accept(cli_ssl);
                if (cli_fd < 0)
                    continue;
                printf("A new client was accepted, cli_fd: %d\n", cli_fd); //
                if (clientQue_.put(cli_ssl) < 0)
                    Peer_ser::send(cli_ssl, "\0"); // error code
            }
        return 0;
    }
    inline void stop() const { stop_source_.request_stop(); }
    inline TaskQueue_nonblocking<TaskType> &myClientQue() { return clientQue_; }
};

#endif