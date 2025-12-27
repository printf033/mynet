#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>
#include <fcntl.h>
#include <string>
#include <cstring>
#include <unordered_map>
#include "handler.hpp"

class Peer_tcp
{
protected:
    struct Info
    {
        sockaddr_in sockaddr{};
        const char *ip = nullptr;
        int port = -1;
        int fd = -1;
    } serInfo_, cliInfo_;

public:
    Peer_tcp() noexcept = default;
    ~Peer_tcp() noexcept
    {
        ::close(serInfo_.fd);
        ::close(cliInfo_.fd);
    }
    Peer_tcp(const Peer_tcp &) = delete;
    Peer_tcp &operator=(const Peer_tcp &) = delete;
    Peer_tcp(Peer_tcp &&) noexcept = delete;
    Peer_tcp &operator=(Peer_tcp &&) noexcept = delete;
    // 0 success
    // -1 ip error
    // -2 port error
    // -3 socket() error
    // -4 fcntl() error
    // -5 setsockopt() error
    // -6 bind() error
    // -7 listen() error
    int listen(const char *ip, int port, int backlog = 511)
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
        return 0;
    }
    // n cli socket descriptor
    // -1 accept() error
    // -2 setsockopt() error
    int accept(int recvTimeout_s = 3, int recvTimeout_us = 0)
    {
        Info accInfo{};
        socklen_t socklen = sizeof(sockaddr_in);
        if ((accInfo.fd = ::accept4(serInfo_.fd, (sockaddr *)&accInfo.sockaddr, &socklen, SOCK_NONBLOCK | SOCK_CLOEXEC)) < 0)
        {
            accInfo = {};
            return -1;
        }
        timeval timeout;
        timeout.tv_sec = recvTimeout_s;
        timeout.tv_usec = recvTimeout_us;
        if (::setsockopt(accInfo.fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
        {
            ::close(accInfo.fd);
            accInfo = {};
            return -2;
        }
        return accInfo.fd;
    }
    // user space blocking
    // 0 success
    // -1 ip error
    // -2 port error
    // -3 socket() error
    // -4 fcntl() error
    // -5 setsockopt() error
    // -6 connect() error
    // -7 timeout
    int connect(const char *ip, int port, int recvTimeout_s = 60, int recvTimeout_us = 0)
    {
        if (cliInfo_.fd != -1)
        {
            ::close(cliInfo_.fd);
            cliInfo_ = {};
        }
        if (ip == nullptr)
            return -1;
        cliInfo_.sockaddr.sin_family = AF_INET;
        if (::inet_pton(AF_INET, ip, &cliInfo_.sockaddr.sin_addr) <= 0)
        {
            cliInfo_ = {};
            return -1;
        }
        cliInfo_.ip = ip;
        if (port < 0 || port > 65535)
        {
            cliInfo_ = {};
            return -2;
        }
        cliInfo_.sockaddr.sin_port = ::htons(port);
        cliInfo_.port = port;
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0)
        {
            cliInfo_ = {};
            return -3;
        }
        cliInfo_.fd = fd;
        int flags;
        if ((flags = ::fcntl(cliInfo_.fd, F_GETFL, 0)) < 0)
        {
            ::close(cliInfo_.fd);
            cliInfo_ = {};
            return -4;
        }
        if (::fcntl(cliInfo_.fd, F_SETFL, flags | O_NONBLOCK) < 0)
        {
            ::close(cliInfo_.fd);
            cliInfo_ = {};
            return -4;
        }
        timeval timeout;
        timeout.tv_sec = recvTimeout_s;
        timeout.tv_usec = recvTimeout_us;
        if (::setsockopt(cliInfo_.fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
        {
            ::close(cliInfo_.fd);
            cliInfo_ = {};
            return -5;
        }
        int n = ::connect(cliInfo_.fd, (const sockaddr *)&cliInfo_.sockaddr, sizeof(sockaddr_in));
        if (n < 0)
        {
            if (errno != EINPROGRESS)
            {
                ::close(cliInfo_.fd);
                cliInfo_ = {};
                return -6;
            }
            fd_set writeFds;
            FD_ZERO(&writeFds);
            FD_SET(cliInfo_.fd, &writeFds);
            n = ::select(cliInfo_.fd + 1, nullptr, &writeFds, nullptr, &timeout);
            if (n < 0)
            {
                ::close(cliInfo_.fd);
                cliInfo_ = {};
                return -6;
            }
            else if (n == 0)
            {
                ::close(cliInfo_.fd);
                cliInfo_ = {};
                return -7;
            }
            else
            {
                n = 0;
                socklen_t len = sizeof(n);
                if (::getsockopt(cliInfo_.fd, SOL_SOCKET, SO_ERROR, &n, &len) < 0 || n != 0)
                {
                    ::close(cliInfo_.fd);
                    cliInfo_ = {};
                    return -6;
                }
            }
        }
        return 0;
    }
    // n the bytes sent
    // -1 data == nullptr || len == 0
    // -2 send() error
    ssize_t send(int fd, const char *data, size_t len)
    {
        if (data == nullptr || len == 0)
            return -1;
        size_t sum = 0;
        while (sum < len)
        {
            ssize_t n = ::send(fd, data + sum, len - sum, MSG_NOSIGNAL);
            if (n < 0)
            {
                if (errno == EAGAIN)
                    break;
                if (errno == EINTR)
                    continue;
                ::close(fd);
                return -2;
            }
            sum += static_cast<size_t>(n);
        }
        return sum;
    }
    // n the bytes received
    // 0 EAGAIN
    // -1 buf == nullptr || len == 0
    // -2 recv() error
    ssize_t recv(int fd, char *buf, size_t len)
    {
        if (buf == nullptr || len == 0)
            return -1;
        size_t sum = 0;
        while (sum < len)
        {
            ssize_t n = ::recv(fd, buf + sum, len - sum, 0);
            if (n <= 0)
            {
                if (errno == EAGAIN)
                    break;
                if (errno == EINTR)
                    continue;
                ::close(fd);
                return -2;
            }
            sum += static_cast<size_t>(n);
        }
        return sum;
    }
    // 0 success
    // -1 ip error
    // -2 port error
    // -3 socket() error
    // -4 fcntl() error
    // -5 setsockopt() error
    // -6 bind() error
    // -7 listen() error
    int run_ser(const char *ip, int port, int backlog = 511,
                int recvTimeout_s = 3, int recvTimeout_us = 0)
    {
        int n = listen(ip, port, backlog);
        if (n < 0)
            return n;
        std::unordered_map<int, Handler> accMap;
        while (true)
        {
            int fd = accept(recvTimeout_s, recvTimeout_us);
            if (fd > 0)
                accMap.emplace(fd, Handler());
            for (auto it = accMap.begin(); it != accMap.end();)
            {
                int fd = it->first;
                Handler &handler = it->second;
                bool isClose = false;
                {
                    char buf[4096]{0};
                    ssize_t rn = recv(fd, buf, sizeof(buf));
                    if (rn > 0)
                    {
                        handler.appendRecvStream(buf, rn);
                        handler.process_reflect();
                        if (handler.isResponse())
                        {
                            ssize_t sn = send(fd, handler.responseBegin(), handler.responseLength());
                            if (sn >= 0)
                                handler.stillSending(sn);
                            else
                                isClose = true;
                        }
                    }
                    else
                    {
                        if (rn != 0)
                            isClose = true;
                    }
                }
                if (!isClose && handler.stillSending(0))
                {
                    ssize_t sn = send(fd, handler.responseBegin(), handler.responseLength());
                    if (sn >= 0)
                        handler.stillSending(sn);
                    else
                        isClose = true;
                }
                if (isClose)
                    it = accMap.erase(it);
                else
                    ++it;
            }
        }
        return 0;
    }
    // user space blocking
    // 0 success
    // -1 ip error
    // -2 port error
    // -3 socket() error
    // -4 fcntl() error
    // -5 setsockopt() error
    // -6 connect() error
    // -7 timeout
    int run_cli(const char *ip, int port,
                int recvTimeout_s = 60, int recvTimeout_us = 0)
    {
        int n = connect(ip, port, recvTimeout_s, recvTimeout_us);
        if (n < 0)
            return n;
        int fd = cliInfo_.fd;
        Handler handler;
        while (true)
        {
            handler.process_stdin();
            if (handler.isResponse())
            {
                ssize_t sn = 0;
                do
                {
                    sn = send(fd, handler.responseBegin(), handler.responseLength());
                    if (sn < 0)
                    {
                        n = connect(ip, port, recvTimeout_s, recvTimeout_us);
                        if (n < 0)
                            return n;
                    }
                } while (handler.stillSending(sn));
            }
            char buf[4096]{0};
            ssize_t rn = 0;
            do
            {
                rn = recv(fd, buf, sizeof(buf));
                if (rn < 0)
                {
                    n = connect(ip, port, recvTimeout_s, recvTimeout_us);
                    if (n < 0)
                        return n;
                    continue;
                }
                if (rn > 0)
                {
                    handler.appendRecvStream(buf, rn);
                    handler.process_stdout();
                }
            } while (rn <= 0);
        }
        return 0;
    }
};

class Peer_udp
{
protected:
    struct Info
    {
        sockaddr_in sockaddr{};
        const char *ip = nullptr;
        int port = -1;
        int fd = -1;
    } myInfo_;

public:
    Peer_udp() noexcept = default;
    ~Peer_udp() noexcept { ::close(myInfo_.fd); }
    Peer_udp(const Peer_udp &) = delete;
    Peer_udp &operator=(const Peer_udp &) = delete;
    Peer_udp(Peer_udp &&) noexcept = delete;
    Peer_udp &operator=(Peer_udp &&) noexcept = delete;
    // 0 success
    // -1 ip error
    // -2 port error
    // -3 socket() error
    // -4 fcntl() error
    // -5 setsockopt() error
    // -6 bind() error
    int listen(const char *ip, int port)
    {
        if (ip == nullptr)
            return -1;
        myInfo_.sockaddr.sin_family = AF_INET;
        if (::inet_pton(AF_INET, ip, &myInfo_.sockaddr.sin_addr) <= 0)
        {
            myInfo_ = {};
            return -1;
        }
        myInfo_.ip = ip;
        if (port < 0 || port > 65535)
        {
            myInfo_ = {};
            return -2;
        }
        myInfo_.sockaddr.sin_port = ::htons(port);
        myInfo_.port = port;
        int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0)
        {
            myInfo_ = {};
            return -3;
        }
        myInfo_.fd = fd;
        int flags;
        if ((flags = ::fcntl(myInfo_.fd, F_GETFL, 0)) < 0)
        {
            ::close(myInfo_.fd);
            myInfo_ = {};
            return -4;
        }
        if (::fcntl(myInfo_.fd, F_SETFL, flags | O_NONBLOCK) < 0)
        {
            ::close(myInfo_.fd);
            myInfo_ = {};
            return -4;
        }
        int opt = 1;
        if (::setsockopt(myInfo_.fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        {
            ::close(myInfo_.fd);
            myInfo_ = {};
            return -5;
        }
        if (::setsockopt(myInfo_.fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0)
        {
            ::close(myInfo_.fd);
            myInfo_ = {};
            return -5;
        }
        if (::setsockopt(myInfo_.fd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt)) < 0)
        {
            ::close(myInfo_.fd);
            myInfo_ = {};
            return -5;
        }
        if (::bind(fd, (const sockaddr *)&myInfo_.sockaddr, sizeof(sockaddr_in)) < 0)
        {
            ::close(myInfo_.fd);
            myInfo_ = {};
            return -6;
        }
        return 0;
    }
    // n the bytes received
    // 0 EAGAIN
    // -1 buf == nullptr || len == 0
    // -2 recvfrom() error
    ssize_t recv(sockaddr_in &ur_sockaddr, char *buf, size_t len)
    {
        if (buf == nullptr || len == 0)
            return -1;
        socklen_t socklen = sizeof(sockaddr_in);
        size_t sum = 0;
        while (sum < len)
        {
            ssize_t n = ::recvfrom(myInfo_.fd, buf, len, 0, (sockaddr *)&ur_sockaddr, &socklen);
            if (n <= 0)
            {
                if (errno == EAGAIN)
                    break;
                if (errno == EINTR)
                    continue;
                return -2;
            }
            sum += static_cast<size_t>(n);
        }
        return sum;
    }
    // n the bytes sent
    // -1 data == nullptr || len == 0
    // -2 sendto() error
    ssize_t send(sockaddr_in &ur_sockaddr, const char *data, size_t len)
    {
        if (data == nullptr || len == 0)
            return -1;
        socklen_t socklen = sizeof(sockaddr_in);
        size_t sum = 0;
        while (sum < len)
        {
            ssize_t n = ::sendto(myInfo_.fd, data, len, 0, (const sockaddr *)&ur_sockaddr, socklen);
            if (n < 0)
            {
                if (errno == EAGAIN)
                    break;
                if (errno == EINTR)
                    continue;
                return -2;
            }
            sum += static_cast<size_t>(n);
        }
        return sum;
    }
    // n the bytes sent
    // -1 data == nullptr || len == 0
    // -2 sendto() error
    // -3 ip error
    // -4 port error
    ssize_t send(const char *ip, int port, const char *data, size_t len)
    {
        if (ip == nullptr)
            return -3;
        sockaddr_in ur_sockaddr{};
        ur_sockaddr.sin_family = AF_INET;
        if (::inet_pton(AF_INET, ip, &ur_sockaddr.sin_addr) <= 0)
        {
            ur_sockaddr = {};
            return -3;
        }
        if (port < 0 || port > 65535)
        {
            ur_sockaddr = {};
            return -4;
        }
        ur_sockaddr.sin_port = ::htons(port);
        return send(ur_sockaddr, data, len);
    }
    // 0 success
    // -1 ip error
    // -2 port error
    // -3 socket() error
    // -4 fcntl() error
    // -5 setsockopt() error
    // -6 bind() error
    int run_ser(const char *ip, int port)
    {
        int n = listen(ip, port);
        if (n < 0)
            return n;
        Handler handler;
        while (true)
        {
            char buf[4096]{0};
            sockaddr_in ur_sockaddr{};
            ssize_t rn = recv(ur_sockaddr, buf, sizeof(buf));
            if (rn > 0)
            {
                handler.appendRecvStream(buf, rn);
                handler.process_reflect();
                if (handler.isResponse())
                {
                    ssize_t sn = 0;
                    do
                    {
                        sn = send(ur_sockaddr, handler.responseBegin(), handler.responseLength());
                        if (sn < 0)
                            break;
                    } while (handler.stillSending(sn));
                }
            }
        }
        return 0;
    }
    // 0 success
    // -1 ip error
    // -2 port error
    // -3 socket() error
    // -4 fcntl() error
    // -5 setsockopt() error
    int run_cli(const char *ip, int port)
    {
        if (ip == nullptr)
            return -1;
        myInfo_.sockaddr.sin_family = AF_INET;
        if (::inet_pton(AF_INET, ip, &myInfo_.sockaddr.sin_addr) <= 0)
        {
            myInfo_ = {};
            return -1;
        }
        myInfo_.ip = ip;
        if (port < 0 || port > 65535)
        {
            myInfo_ = {};
            return -2;
        }
        myInfo_.sockaddr.sin_port = ::htons(port);
        myInfo_.port = port;
        int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0)
        {
            myInfo_ = {};
            return -3;
        }
        myInfo_.fd = fd;
        int flags;
        if ((flags = ::fcntl(myInfo_.fd, F_GETFL, 0)) < 0)
        {
            ::close(myInfo_.fd);
            myInfo_ = {};
            return -4;
        }
        if (::fcntl(myInfo_.fd, F_SETFL, flags | O_NONBLOCK) < 0)
        {
            ::close(myInfo_.fd);
            myInfo_ = {};
            return -4;
        }
        int opt = 1;
        if (::setsockopt(myInfo_.fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        {
            ::close(myInfo_.fd);
            myInfo_ = {};
            return -5;
        }
        if (::setsockopt(myInfo_.fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0)
        {
            ::close(myInfo_.fd);
            myInfo_ = {};
            return -5;
        }
        if (::setsockopt(myInfo_.fd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt)) < 0)
        {
            ::close(myInfo_.fd);
            myInfo_ = {};
            return -5;
        }
        Handler handler;
        while (true)
        {
            handler.process_stdin();
            if (handler.isResponse())
            {
                ssize_t sn = 0;
                do
                {
                    sn = send(myInfo_.sockaddr, handler.responseBegin(), handler.responseLength());
                    if (sn < 0)
                        break;
                } while (handler.stillSending(sn));
            }
            char buf[4096]{0};
            ssize_t rn = 0;
            do
            {
                rn = recv(myInfo_.sockaddr, buf, sizeof(buf));
                if (rn > 0)
                {
                    handler.appendRecvStream(buf, rn);
                    handler.process_stdout();
                }
            } while (rn <= 0);
        }
        return 0;
    }
};

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>

class Peer_tls
{
protected:
    struct Info
    {
        sockaddr_in sockaddr{};
        const char *ip = nullptr;
        int port = -1;
        int fd = -1;
        SSL_CTX *ctx = nullptr;
        SSL *ssl = nullptr;
    } serInfo_, cliInfo_;

public:
    Peer_tls() noexcept { signal(SIGPIPE, SIG_IGN); }
    ~Peer_tls() noexcept
    {
        SSL_shutdown(serInfo_.ssl);
        SSL_free(serInfo_.ssl);
        ::close(serInfo_.fd);
        SSL_CTX_free(serInfo_.ctx);
        SSL_shutdown(cliInfo_.ssl);
        SSL_free(cliInfo_.ssl);
        ::close(cliInfo_.fd);
        SSL_CTX_free(cliInfo_.ctx);
    }
    Peer_tls(const Peer_tls &) = delete;
    Peer_tls &operator=(const Peer_tls &) = delete;
    Peer_tls(Peer_tls &&) noexcept = delete;
    Peer_tls &operator=(Peer_tls &&) noexcept = delete;
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
    int listen(const char *ip, int port, const char *crt, const char *key, int backlog = 511)
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
        serInfo_.ctx = SSL_CTX_new(TLS_server_method());
        if (serInfo_.ctx == nullptr)
        {
            ::close(serInfo_.fd);
            serInfo_ = {};
            return -8;
        }
        if (SSL_CTX_use_certificate_file(serInfo_.ctx, crt, SSL_FILETYPE_PEM) <= 0)
        {
            ::close(serInfo_.fd);
            SSL_CTX_free(serInfo_.ctx);
            serInfo_ = {};
            return -9;
        }
        if (SSL_CTX_use_PrivateKey_file(serInfo_.ctx, key, SSL_FILETYPE_PEM) <= 0)
        {
            ::close(serInfo_.fd);
            SSL_CTX_free(serInfo_.ctx);
            serInfo_ = {};
            return -10;
        }
        if (SSL_CTX_check_private_key(serInfo_.ctx) <= 0)
        {
            ::close(serInfo_.fd);
            SSL_CTX_free(serInfo_.ctx);
            serInfo_ = {};
            return -11;
        }
        return 0;
    }
    // pointer cli ssl pointer
    // nullptr accept() error
    // nullptr setsockopt() error
    // nullptr SSL_new() error
    // nullptr SSL_set_fd() error
    // nullptr SSL_accept() error
    SSL *accept(int recvTimeout_s = 3, int recvTimeout_us = 0)
    {
        Info accInfo{};
        socklen_t socklen = sizeof(sockaddr_in);
        if ((accInfo.fd = ::accept4(serInfo_.fd, (sockaddr *)&accInfo.sockaddr, &socklen, SOCK_NONBLOCK | SOCK_CLOEXEC)) < 0)
        {
            accInfo = {};
            return nullptr;
        }
        timeval timeout;
        timeout.tv_sec = recvTimeout_s;
        timeout.tv_usec = recvTimeout_us;
        if (::setsockopt(accInfo.fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
        {
            ::close(accInfo.fd);
            accInfo = {};
            return nullptr;
        }
        accInfo.ssl = SSL_new(serInfo_.ctx);
        if (accInfo.ssl == nullptr)
        {
            ::close(accInfo.fd);
            accInfo = {};
            return nullptr;
        }
        if (SSL_set_fd(accInfo.ssl, accInfo.fd) <= 0)
        {
            SSL_free(accInfo.ssl);
            ::close(accInfo.fd);
            accInfo = {};
            return nullptr;
        }
        int e;
        while ((e = SSL_accept(accInfo.ssl)) <= 0)
        {
            e = SSL_get_error(accInfo.ssl, e);
            if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE)
            {
                SSL_free(accInfo.ssl);
                ::close(accInfo.fd);
                accInfo = {};
                return nullptr;
            }
        }
        return accInfo.ssl;
    }
    // user space blocking
    // 0 success
    // -1 ip error
    // -2 port error
    // -3 socket() error
    // -4 fcntl() error
    // -5 setsockopt() error
    // -6 connect() error
    // -7 timeout
    // -8 SSL_CTX_new() error
    // -9 SSL_CTX_set_default_verify_paths() error
    // -10 SSL_new() error
    // -11 SSL_set_fd() error
    // -12 SSL_CTX_load_verify_locations() error
    // -13 SSL_connect() error
    int connect(const char *ip, int port, const char *crt = nullptr, int recvTimeout_s = 60, int recvTimeout_us = 0)
    {
        if (cliInfo_.fd != -1)
        {
            ::close(cliInfo_.fd);
            cliInfo_ = {};
        }
        if (ip == nullptr)
            return -1;
        cliInfo_.sockaddr.sin_family = AF_INET;
        if (::inet_pton(AF_INET, ip, &cliInfo_.sockaddr.sin_addr) <= 0)
        {
            cliInfo_ = {};
            return -1;
        }
        cliInfo_.ip = ip;
        if (port < 0 || port > 65535)
        {
            cliInfo_ = {};
            return -2;
        }
        cliInfo_.sockaddr.sin_port = ::htons(port);
        cliInfo_.port = port;
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0)
        {
            cliInfo_ = {};
            return -3;
        }
        cliInfo_.fd = fd;
        int flags;
        if ((flags = ::fcntl(cliInfo_.fd, F_GETFL, 0)) < 0)
        {
            ::close(cliInfo_.fd);
            cliInfo_ = {};
            return -4;
        }
        if (::fcntl(cliInfo_.fd, F_SETFL, flags | O_NONBLOCK) < 0)
        {
            ::close(cliInfo_.fd);
            cliInfo_ = {};
            return -4;
        }
        timeval timeout;
        timeout.tv_sec = recvTimeout_s;
        timeout.tv_usec = recvTimeout_us;
        if (::setsockopt(cliInfo_.fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
        {
            ::close(cliInfo_.fd);
            cliInfo_ = {};
            return -5;
        }
        int n = ::connect(cliInfo_.fd, (const sockaddr *)&cliInfo_.sockaddr, sizeof(sockaddr_in));
        if (n < 0)
        {
            if (errno != EINPROGRESS)
            {
                ::close(cliInfo_.fd);
                cliInfo_ = {};
                return -6;
            }
            fd_set writeFds;
            FD_ZERO(&writeFds);
            FD_SET(cliInfo_.fd, &writeFds);
            n = ::select(cliInfo_.fd + 1, nullptr, &writeFds, nullptr, &timeout);
            if (n < 0)
            {
                ::close(cliInfo_.fd);
                cliInfo_ = {};
                return -6;
            }
            else if (n == 0)
            {
                ::close(cliInfo_.fd);
                cliInfo_ = {};
                return -7;
            }
            else
            {
                n = 0;
                socklen_t len = sizeof(n);
                if (::getsockopt(cliInfo_.fd, SOL_SOCKET, SO_ERROR, &n, &len) < 0 || n != 0)
                {
                    ::close(cliInfo_.fd);
                    cliInfo_ = {};
                    return -6;
                }
            }
        }
        if (cliInfo_.ctx == nullptr)
        {
            cliInfo_.ctx = SSL_CTX_new(TLS_client_method());
            if (cliInfo_.ctx == nullptr)
            {
                ::close(cliInfo_.fd);
                cliInfo_ = {};
                return -8;
            }
            if (SSL_CTX_set_default_verify_paths(cliInfo_.ctx) <= 0)
            {
                ::close(cliInfo_.fd);
                SSL_CTX_free(cliInfo_.ctx);
                cliInfo_ = {};
                return -9;
            }
            if (crt == nullptr)
                SSL_CTX_set_verify(cliInfo_.ctx, SSL_VERIFY_NONE, nullptr);
            else
                SSL_CTX_set_verify(cliInfo_.ctx, SSL_VERIFY_PEER, nullptr);
        }
        cliInfo_.ssl = SSL_new(cliInfo_.ctx);
        if (cliInfo_.ssl == nullptr)
        {
            ::close(cliInfo_.fd);
            cliInfo_.fd = {};
            return -10;
        }
        if (SSL_set_fd(cliInfo_.ssl, cliInfo_.fd) <= 0)
        {
            SSL_free(cliInfo_.ssl);
            ::close(cliInfo_.fd);
            cliInfo_ = {};
            return -11;
        }
        if (crt != nullptr && SSL_CTX_load_verify_locations(cliInfo_.ctx, crt, nullptr) <= 0)
        {
            SSL_free(cliInfo_.ssl);
            ::close(cliInfo_.fd);
            cliInfo_ = {};
            return -12;
        }
        int e;
        while ((e = SSL_connect(cliInfo_.ssl)) <= 0)
        {
            e = SSL_get_error(cliInfo_.ssl, e);
            if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE)
            {
                SSL_free(cliInfo_.ssl);
                ::close(cliInfo_.fd);
                cliInfo_ = {};
                return -13;
            }
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(cliInfo_.fd, &fds);
            if (e == SSL_ERROR_WANT_READ)
                ::select(cliInfo_.fd + 1, &fds, nullptr, nullptr, &timeout);
            else
                ::select(cliInfo_.fd + 1, nullptr, &fds, nullptr, &timeout);
        }
        return 0;
    }
    // n the bytes sent
    // -1 ssl == nullptr || data == nullptr || len == 0
    // -2 SSL_write() error
    ssize_t send(SSL *&ssl, const char *data, size_t len)
    {
        if (ssl == nullptr || data == nullptr || len == 0)
            return -1;
        size_t sum = 0;
        while (sum < len)
        {
            ssize_t n = SSL_write(ssl, data + sum, len - sum);
            if (n < 0)
            {
                n = SSL_get_error(ssl, n);
                if (n == SSL_ERROR_WANT_READ ||
                    n == SSL_ERROR_WANT_WRITE)
                    break;
                else
                {
                    int fd = SSL_get_fd(ssl);
                    SSL_shutdown(ssl);
                    SSL_free(ssl);
                    ::close(fd);
                    ssl = nullptr;
                    ERR_clear_error();
                    return -2;
                }
            }
            sum += static_cast<size_t>(n);
        }
        return sum;
    }
    // n the bytes received
    // 0 EAGAIN
    // -1 ssl == nullptr || buf == nullptr || len == 0
    // -2 SSL_read() error
    ssize_t recv(SSL *&ssl, char *buf, size_t len)
    {
        if (ssl == nullptr || buf == nullptr || len == 0)
            return -1;
        size_t sum = 0;
        while (sum < len)
        {
            ssize_t n = ::SSL_read(ssl, buf + sum, len - sum);
            if (n <= 0)
            {
                n = SSL_get_error(ssl, n);
                if (n == SSL_ERROR_WANT_READ ||
                    n == SSL_ERROR_WANT_WRITE)
                    break;
                else
                {
                    int fd = SSL_get_fd(ssl);
                    SSL_shutdown(ssl);
                    SSL_free(ssl);
                    ::close(fd);
                    ssl = nullptr;
                    ERR_clear_error();
                    return -2;
                }
            }
            sum += static_cast<size_t>(n);
        }
        return sum;
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
    int run_ser(const char *ip, int port, const char *crt, const char *key, int backlog = 511,
                int recvTimeout_s = 3, int recvTimeout_us = 0)
    {
        int n = listen(ip, port, crt, key, backlog);
        if (n < 0)
            return n;
        std::unordered_map<SSL *, Handler> accMap;
        while (true)
        {
            SSL *ssl = accept(recvTimeout_s, recvTimeout_us);
            if (ssl != nullptr)
                accMap.emplace(ssl, Handler());
            for (auto it = accMap.begin(); it != accMap.end();)
            {
                SSL *ssl = it->first;
                Handler &handler = it->second;
                bool isClose = false;
                {
                    char buf[4096]{0};
                    ssize_t rn = recv(ssl, buf, sizeof(buf));
                    if (rn > 0 && ssl != nullptr)
                    {
                        handler.appendRecvStream(buf, rn);
                        handler.process_reflect();
                        if (handler.isResponse())
                        {
                            ssize_t sn = send(ssl, handler.responseBegin(), handler.responseLength());
                            if (ssl != nullptr)
                                handler.stillSending(sn);
                            else
                                isClose = true;
                        }
                    }
                    else
                    {
                        if (rn != 0)
                            isClose = true;
                    }
                }
                if (!isClose && handler.stillSending(0))
                {
                    ssize_t sn = send(ssl, handler.responseBegin(), handler.responseLength());
                    if (ssl != nullptr)
                        handler.stillSending(sn);
                    else
                        isClose = true;
                }
                if (isClose)
                    it = accMap.erase(it);
                else
                    ++it;
            }
        }
        return 0;
    }
    // user space blocking
    // 0 success
    // -1 ip error
    // -2 port error
    // -3 socket() error
    // -4 fcntl() error
    // -5 setsockopt() error
    // -6 connect() error
    // -7 timeout
    // -8 SSL_CTX_new() error
    // -9 SSL_CTX_set_default_verify_paths() error
    // -10 SSL_new() error
    // -11 SSL_set_fd() error
    // -12 SSL_CTX_load_verify_locations() error
    // -13 SSL_connect() error
    int run_cli(const char *ip, int port, const char *crt = nullptr,
                int recvTimeout_s = 60, int recvTimeout_us = 0)
    {
        int n = connect(ip, port, crt, recvTimeout_s, recvTimeout_us);
        if (n < 0)
            return n;
        SSL *&ssl = cliInfo_.ssl;
        Handler handler;
        while (true)
        {
            handler.process_stdin();
            if (handler.isResponse())
            {
                ssize_t sn = 0;
                do
                {
                    sn = send(ssl, handler.responseBegin(), handler.responseLength());
                    if (sn < 0)
                    {
                        n = connect(ip, port, crt, recvTimeout_s, recvTimeout_us);
                        if (n < 0)
                            return n;
                    }
                } while (handler.stillSending(sn));
            }
            char buf[4096]{0};
            ssize_t rn = 0;
            do
            {
                rn = recv(ssl, buf, sizeof(buf));
                if (rn < 0)
                {
                    n = connect(ip, port, crt, recvTimeout_s, recvTimeout_us);
                    if (n < 0)
                        return n;
                    continue;
                }
                if (rn > 0)
                {
                    handler.appendRecvStream(buf, rn);
                    handler.process_stdout();
                }
            } while (rn <= 0);
        }
        return 0;
    }
};
