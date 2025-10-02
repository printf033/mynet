#ifndef MYNET_SRC_CRYPTOR_HPP
#define MYNET_SRC_CRYPTOR_HPP

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string>
#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>

class Cryptor_tls_ser
{
    struct Info
    {
        sockaddr_in sockaddr{};
        std::string ip{};
        int port = -1;
        int fd = -1;
    } my_info_;
    SSL_CTX *ctx_ = nullptr;

public:
    Cryptor_tls_ser() = default;
    ~Cryptor_tls_ser()
    {
        ::close(my_info_.fd);
        SSL_CTX_free(ctx_);
    }
    Cryptor_tls_ser(const Cryptor_tls_ser &) = delete;
    Cryptor_tls_ser &operator=(const Cryptor_tls_ser &) = delete;
    Cryptor_tls_ser(Cryptor_tls_ser &&) = delete;
    Cryptor_tls_ser &operator=(Cryptor_tls_ser &&) = delete;
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
    int listen(const std::string &ip, int port, const std::string &crt, const std::string &key, int wait_queue_size = 5)
    {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (-1 == fd)
            return -1;
        my_info_.fd = fd;
        my_info_.sockaddr.sin_family = AF_INET;
        if (1 != ::inet_pton(AF_INET, ip.c_str(), &my_info_.sockaddr.sin_addr))
        {
            ::close(my_info_.fd);
            my_info_.fd = -1;
            return -2;
        }
        my_info_.ip = ip;
        if (port < 0 || port > 65535)
        {
            ::close(my_info_.fd);
            my_info_.fd = -1;
            return -3;
        }
        my_info_.sockaddr.sin_port = ::htons(port);
        my_info_.port = port;
        if (-1 == ::bind(fd, (const sockaddr *)&my_info_.sockaddr, sizeof(sockaddr_in)))
        {
            ::close(my_info_.fd);
            my_info_.fd = -1;
            return -4;
        }
        if (-1 == ::listen(fd, wait_queue_size))
        {
            ::close(my_info_.fd);
            my_info_.fd = -1;
            return -5;
        }
        ctx_ = SSL_CTX_new(TLS_server_method());
        if (nullptr == ctx_)
        {
            ::close(my_info_.fd);
            my_info_.fd = -1;
            return -6;
        }
        if (SSL_CTX_use_certificate_file(ctx_, crt.c_str(), SSL_FILETYPE_PEM) <= 0)
        {
            ::close(my_info_.fd);
            my_info_.fd = -1;
            SSL_CTX_free(ctx_);
            return -7;
        }
        if (SSL_CTX_use_PrivateKey_file(ctx_, key.c_str(), SSL_FILETYPE_PEM) <= 0)
        {
            ::close(my_info_.fd);
            my_info_.fd = -1;
            SSL_CTX_free(ctx_);
            return -8;
        }
        if (SSL_CTX_check_private_key(ctx_) <= 0)
        {
            ::close(my_info_.fd);
            my_info_.fd = -1;
            SSL_CTX_free(ctx_);
            return -9;
        }
        return 0;
    }
    // n cli's socket descriptor
    // -1 accept() error
    // -2 setsockopt() error
    // -3 SSL_new() error
    // -4 SSL_set_fd() error
    // -5 SSL_accept() error
    int accept(SSL *&ssl, int recv_overtime_sec = 3, int recv_overtime_usec = 0) // blocking accept
    {
        Info cli_info{};
        socklen_t socklen = sizeof(sockaddr_in);
        cli_info.fd = ::accept(my_info_.fd, (sockaddr *)&cli_info.sockaddr, &socklen);
        if (-1 == cli_info.fd)
            return -1;
        timeval tv;
        tv.tv_sec = recv_overtime_sec;
        tv.tv_usec = recv_overtime_usec;
        if (-1 == ::setsockopt(cli_info.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)))
        {
            ::close(cli_info.fd);
            return -2;
        }
        ssl = SSL_new(ctx_);
        if (nullptr == ssl)
        {
            ::close(cli_info.fd);
            return -3;
        }
        if (SSL_set_fd(ssl, cli_info.fd) <= 0)
        {
            SSL_free(ssl);
            ssl = nullptr;
            ::close(cli_info.fd);
            return -4;
        }
        if (SSL_accept(ssl) <= 0)
        {
            SSL_free(ssl);
            ssl = nullptr;
            ::close(cli_info.fd);
            return -5;
        }
        return cli_info.fd;
    }
    // 0 success
    // -1 SSL_write() error
    // n SSL_write() data error & the number sent
    ssize_t send(SSL *&ssl, const std::string &data, size_t breakpoint = 0) // blocking send
    {
        if (data.empty())
            return 0;
        if (nullptr == ssl)
            return -1;
        uint32_t len = data.size();
        size_t sum = 0;
        while (sum < 4)
        {
            ssize_t n = SSL_write(ssl, reinterpret_cast<char *>(&len) + sum, 4 - sum);
            if (n < 0)
            {
                if (errno == EINTR)
                    continue;
                SSL_shutdown(ssl);
                int fd = SSL_get_fd(ssl);
                SSL_free(ssl);
                ssl = nullptr;
                ::close(fd);
                return -1;
            }
            sum += static_cast<size_t>(n);
        }
        sum = breakpoint;
        while (sum < len)
        {
            ssize_t n = SSL_write(ssl, data.c_str() + sum, len - sum);
            if (n < 0)
            {
                if (errno == EINTR)
                    continue;
                SSL_shutdown(ssl);
                int fd = SSL_get_fd(ssl);
                SSL_free(ssl);
                ssl = nullptr;
                ::close(fd);
                return sum;
            }
            sum += static_cast<size_t>(n);
        }
        return 0;
    }
    // 0 success
    // -1 SSL_read() error & closed the connection
    // n SSL_read() data error & the number read
    ssize_t recv(SSL *&ssl, std::string &&data, size_t breakpoint = 0) // blocking recv
    {
        if (nullptr == ssl)
            return -1;
        uint32_t len = 0;
        size_t sum = 0;
        while (sum < 4)
        {
            ssize_t n = SSL_read(ssl, reinterpret_cast<char *>(&len) + sum, 4 - sum);
            if (n <= 0)
            {
                if (n < 0 && errno == EINTR)
                    continue;
                SSL_shutdown(ssl);
                int fd = SSL_get_fd(ssl);
                SSL_free(ssl);
                ssl = nullptr;
                ::close(fd);
                return -1;
            }
            sum += static_cast<size_t>(n);
        }
        if (0 == breakpoint)
            data.resize(len);
        sum = breakpoint;
        while (sum < len)
        {
            ssize_t n = SSL_read(ssl, data.data() + sum, len - sum);
            if (n <= 0)
            {
                if (n < 0 && errno == EINTR)
                    continue;
                SSL_shutdown(ssl);
                int fd = SSL_get_fd(ssl);
                SSL_free(ssl);
                ssl = nullptr;
                ::close(fd);
                return sum;
            }
            sum += static_cast<size_t>(n);
        }
        return 0;
    }
};

class Cryptor_tls_cli // binding socket is not supported
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
    Cryptor_tls_cli()
    {
        ctx_ = SSL_CTX_new(TLS_client_method());
        if (nullptr == ctx_)
            std::cerr << "SSL_CTX_new() error\n";
        SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, nullptr);
        if (SSL_CTX_set_default_verify_paths(ctx_) <= 0)
            std::cerr << "SSL_CTX_set_default_verify_paths() error\n";
    }
    ~Cryptor_tls_cli()
    {
        SSL_shutdown(ssl_);
        SSL_free(ssl_);
        ::close(ser_info_.fd);
        SSL_CTX_free(ctx_);
    }
    Cryptor_tls_cli(const Cryptor_tls_cli &) = delete;
    Cryptor_tls_cli &operator=(const Cryptor_tls_cli &) = delete;
    Cryptor_tls_cli(Cryptor_tls_cli &&) = delete;
    Cryptor_tls_cli &operator=(Cryptor_tls_cli &&) = delete;
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
    // 0 success
    // -1 SSL_write() len error
    // n SSL_write() data error & the number sent
    ssize_t send(const std::string &data, size_t breakpoint = 0) // blocking send
    {
        if (data.empty())
            return 0;
        if (nullptr == ssl_)
            return -1;
        uint32_t len = data.size();
        size_t sum = 0;
        while (sum < 4)
        {
            ssize_t n = SSL_write(ssl_, reinterpret_cast<char *>(&len) + sum, 4 - sum);
            if (n < 0)
            {
                if (errno == EINTR)
                    continue;
                connect(ser_info_.ip, ser_info_.port, crt_);
                return -1;
            }
            sum += static_cast<size_t>(n);
        }
        sum = breakpoint;
        while (sum < len)
        {
            ssize_t n = SSL_write(ssl_, data.c_str() + sum, len - sum);
            if (n < 0)
            {
                if (errno == EINTR)
                    continue;
                connect(ser_info_.ip, ser_info_.port, crt_);
                return sum;
            }
            sum += static_cast<size_t>(n);
        }
        return 0;
    }
    // 0 success
    // -1 SSL_read() error & closed the connection
    // n SSL_read() data error & the number read
    ssize_t recv(std::string &&data, size_t breakpoint = 0) // blocking recv
    {
        if (nullptr == ssl_)
            return -1;
        uint32_t len = 0;
        size_t sum = 0;
        while (sum < 4)
        {
            ssize_t n = SSL_read(ssl_, reinterpret_cast<char *>(&len) + sum, 4 - sum);
            if (n <= 0)
            {
                if (n < 0 && errno == EINTR)
                    continue;
                connect(ser_info_.ip, ser_info_.port, crt_);
                return -1;
            }
            sum += static_cast<size_t>(n);
        }
        if (0 == breakpoint)
            data.resize(len);
        sum = breakpoint;
        while (sum < len)
        {
            ssize_t n = SSL_read(ssl_, data.data() + sum, len - sum);
            if (n <= 0)
            {
                if (n < 0 && errno == EINTR)
                    continue;
                connect(ser_info_.ip, ser_info_.port, crt_);
                return sum;
            }
            sum += static_cast<size_t>(n);
        }
        return 0;
    }
};

#endif