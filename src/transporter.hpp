#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>

struct Transporter_base
{
    sockaddr_in addr{};
    int fd = -1;

public:
    inline void reset() noexcept
    {
        if (fd != -1)
            ::close(fd);
        fd = -1;
        addr = {};
    }
    // 0 success
    // -1 ip error
    // -2 port error
    // -3 socket() error
    // -4 fcntl() error
    // -5 setsockopt() error
    // -6 bind() error
    // -7 listen() error
    int listen_tcp(const char *ip, int port,
                   int backlog = 511) noexcept
    {
        if (ip == nullptr)
            return -1;
        addr.sin_family = AF_INET;
        if (::inet_pton(AF_INET, ip, &addr.sin_addr) <= 0)
        {
            reset();
            return -1;
        }
        if (port < 0 || port > 65535)
        {
            reset();
            return -2;
        }
        addr.sin_port = ::htons(port);
        fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0)
        {
            reset();
            return -3;
        }
        int flg;
        if ((flg = ::fcntl(fd, F_GETFL, 0)) < 0)
        {
            reset();
            return -4;
        }
        if (::fcntl(fd, F_SETFL, flg | O_NONBLOCK) < 0)
        {
            reset();
            return -4;
        }
        int opt = 1;
        if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        {
            reset();
            return -5;
        }
        if (::setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0)
        {
            reset();
            return -5;
        }
        if (::bind(fd, (const sockaddr *)&addr, sizeof(sockaddr_in)) < 0)
        {
            reset();
            return -6;
        }
        if (::listen(fd, backlog) < 0)
        {
            reset();
            return -7;
        }
        return 0;
    }
    // 0 success
    // -1 ip error
    // -2 port error
    // -3 socket() error
    // -4 fcntl() error
    // -5 setsockopt() error
    // -6 bind() error
    int listen_udp(const char *ip, int port) noexcept
    {
        if (ip == nullptr)
            return -1;
        addr.sin_family = AF_INET;
        if (::inet_pton(AF_INET, ip, &addr.sin_addr) <= 0)
        {
            reset();
            return -1;
        }
        if (port < 0 || port > 65535)
        {
            reset();
            return -2;
        }
        addr.sin_port = ::htons(port);
        fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0)
        {
            reset();
            return -3;
        }
        int flg;
        if ((flg = ::fcntl(fd, F_GETFL, 0)) < 0)
        {
            reset();
            return -4;
        }
        if (::fcntl(fd, F_SETFL, flg | O_NONBLOCK) < 0)
        {
            reset();
            return -4;
        }
        int opt = 1;
        if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        {
            reset();
            return -5;
        }
        if (::setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0)
        {
            reset();
            return -5;
        }
        if (::setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt)) < 0)
        {
            reset();
            return -5;
        }
        if (::bind(fd, (const sockaddr *)&addr, sizeof(sockaddr_in)) < 0)
        {
            reset();
            return -6;
        }
        return 0;
    }
};

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>

struct Transporter_ssl : public Transporter_base
{
    SSL *ssl = nullptr;

public:
    inline void reset() noexcept
    {
        if (ssl != nullptr)
            SSL_free(ssl);
        ssl = nullptr;
        Transporter_base::reset();
    }
};
