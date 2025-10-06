#ifndef MYNET_SRC_VIEWER_HPP
#define MYNET_SRC_VIEWER_HPP

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <signal.h>
#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>

class Viewer_web_cli // binding socket is not supported
{
    struct Info
    {
        sockaddr_in sockaddr{};
        std::string ip{};
        int port = -1;
        int fd = -1;
    } ser_info_;
    SSL_CTX *ctx_ = nullptr;
    SSL *ssl_ = nullptr;
    std::string crt_ = "";

public:
    Viewer_web_cli()
    {
        signal(SIGPIPE, SIG_IGN);
        ctx_ = SSL_CTX_new(TLS_client_method());
        if (nullptr == ctx_)
            printf("SSL_CTX_new() error\n");
        SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, nullptr);
        if (SSL_CTX_set_default_verify_paths(ctx_) <= 0)
            printf("SSL_CTX_set_default_verify_paths() error\n");
    }
    ~Viewer_web_cli()
    {
        SSL_shutdown(ssl_);
        SSL_free(ssl_);
        ::close(ser_info_.fd);
        SSL_CTX_free(ctx_);
    }
    Viewer_web_cli(const Viewer_web_cli &) = delete;
    Viewer_web_cli &operator=(const Viewer_web_cli &) = delete;
    Viewer_web_cli(Viewer_web_cli &&) = delete;
    Viewer_web_cli &operator=(Viewer_web_cli &&) = delete;
    // 0 success
    // -1 socket() error
    // -2 inet_pton() error
    // -3 port error
    // -4 connect() error
    // -5 setsockopt() error
    // -6 SSL_new() error
    // -7 SSL_set_fd() error
    // -8 SSL_CTX_load_verify_locations() error
    // -9 SSL_connect() error
    int connect(const std::string &ip, int port, const std::string &crt = "", int recv_overtime_sec = 60, int recv_overtime_usec = 0)
    {
        if (ssl_ != nullptr)
        {
            SSL_shutdown(ssl_);
            SSL_free(ssl_);
        }
        ssl_ = nullptr;
        if (ser_info_.fd != -1)
            ::close(ser_info_.fd);
        ser_info_.fd = -1;
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (-1 == fd)
            return -1;
        ser_info_.fd = fd;
        ser_info_.sockaddr.sin_family = AF_INET;
        if (1 != ::inet_pton(AF_INET, ip.c_str(), &ser_info_.sockaddr.sin_addr))
        {
            ::close(ser_info_.fd);
            ser_info_.fd = -1;
            return -2;
        }
        ser_info_.ip = ip;
        if (port < 0 || port > 65535)
        {
            ::close(ser_info_.fd);
            ser_info_.fd = -1;
            return -3;
        }
        ser_info_.sockaddr.sin_port = ::htons(port);
        ser_info_.port = port;
        if (-1 == ::connect(ser_info_.fd, (const sockaddr *)&ser_info_.sockaddr, sizeof(sockaddr_in)))
        {
            ::close(ser_info_.fd);
            ser_info_.fd = -1;
            return -4;
        }
        timeval tv;
        tv.tv_sec = recv_overtime_sec;
        tv.tv_usec = recv_overtime_usec;
        if (-1 == ::setsockopt(ser_info_.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)))
        {
            ::close(ser_info_.fd);
            ser_info_.fd = -1;
            return -5;
        }
        ssl_ = SSL_new(ctx_);
        if (nullptr == ssl_)
        {
            ::close(ser_info_.fd);
            ser_info_.fd = -1;
            return -6;
        }
        if (SSL_set_fd(ssl_, ser_info_.fd) <= 0)
        {
            SSL_free(ssl_);
            ssl_ = nullptr;
            ::close(ser_info_.fd);
            ser_info_.fd = -1;
            return -7;
        }
        if (crt != "" && SSL_CTX_load_verify_locations(ctx_, crt.c_str(), nullptr) <= 0)
        {
            SSL_free(ssl_);
            ssl_ = nullptr;
            ::close(ser_info_.fd);
            ser_info_.fd = -1;
            return -8;
        }
        crt_ = crt;
        if (SSL_connect(ssl_) <= 0)
        {
            SSL_free(ssl_);
            ssl_ = nullptr;
            ::close(ser_info_.fd);
            ser_info_.fd = -1;
            crt_ = "";
            return -9;
        }
        return 0;
    }
    // if length == -1, send with data size()
    // n the number sent
    // -1 SSL_write() data error & closed the connection
    ssize_t send(const std::string &data, size_t breakpoint = 0, ssize_t length = -1) // blocking send
    {
        if (data.empty())
            return 0;
        if (nullptr == ssl_)
            return -1;
        ssize_t n = SSL_write(ssl_, data.c_str(), data.size());
        return n;
    }
    // n the number read
    // 0 closed the connection
    // -1 SSL_read() data error
    ssize_t recv(std::string &data, size_t breakpoint = 0) // blocking recv
    {
        if (nullptr == ssl_)
            return -1;
        ssize_t n = SSL_read(ssl_, data.data(), data.size());
        return n;
    }
};

#endif