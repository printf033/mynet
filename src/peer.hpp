#ifndef MYNET_SRC_PEER_HPP
#define MYNET_SRC_PEER_HPP

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string>

class Peer_tcp_based_ser
{
    struct Info
    {
        sockaddr_in sockaddr{};
        std::string ip{};
        int port = -1;
        int fd = -1;
    } my_info_;

public:
    Peer_tcp_based_ser() = default;
    ~Peer_tcp_based_ser() { ::close(my_info_.fd); }
    Peer_tcp_based_ser(const Peer_tcp_based_ser &) = delete;
    Peer_tcp_based_ser &operator=(const Peer_tcp_based_ser &) = delete;
    Peer_tcp_based_ser(Peer_tcp_based_ser &&) = delete;
    Peer_tcp_based_ser &operator=(Peer_tcp_based_ser &&) = delete;
    // 0 success
    // -1 socket() error
    // -2 inet_pton() error
    // -3 port error
    // -4 bind() error
    // -5 listen() error
    int listen(const std::string &ip, int port, int wait_queue_size = 5)
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
        return 0;
    }
    // n cli's socket descriptor
    // -1 accept() error
    // -2 setsockopt() error
    int accept(int recv_overtime_sec = 3, int recv_overtime_usec = 0) // blocking accept
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
        return cli_info.fd;
    }
    // if length == -1, send with data size()
    // n the number sent
    // -1 send() total error & closed the connection
    // -2 send() data error
    ssize_t send(int cli_fd, const std::string &data, size_t breakpoint = 0, ssize_t length = -1) // blocking send
    {
        if (data.empty())
            return 0;
        uint32_t total = length == -1 ? data.size() : std::min(breakpoint + length, data.size());
        size_t sum = 0;
        while (sum < 4)
        {
            ssize_t n = ::send(cli_fd, reinterpret_cast<char *>(&total) + sum, 4 - sum, 0);
            if (n < 0)
            {
                if (errno == EINTR)
                    continue;
                ::close(cli_fd);
                return -1;
            }
            sum += static_cast<size_t>(n);
        }
        sum = breakpoint;
        while (sum < total)
        {
            ssize_t n = ::send(cli_fd, data.c_str() + sum, total - sum, 0);
            if (n < 0)
            {
                if (errno == EINTR)
                    continue;
                ::close(cli_fd);
                return -2;
            }
            sum += static_cast<size_t>(n);
        }
        return sum;
    }
    // n the number read
    // 0 closed the connection
    // -1 recv() total error
    // -2 recv() data error
    ssize_t recv(int cli_fd, std::string &data, size_t breakpoint = 0) // blocking recv
    {
        uint32_t total = 0;
        size_t sum = 0;
        while (sum < 4)
        {
            ssize_t n = ::recv(cli_fd, reinterpret_cast<char *>(&total) + sum, 4 - sum, 0);
            if (n <= 0)
            {
                if (n < 0 && errno == EINTR)
                    continue;
                ::close(cli_fd);
                return 0 == n ? 0 : -1;
            }
            sum += static_cast<size_t>(n);
        }
        if (data.size() < total)
            data.resize(total);
        sum = breakpoint;
        while (sum < total)
        {
            ssize_t n = ::recv(cli_fd, data.data() + sum, total - sum, 0);
            if (n <= 0)
            {
                if (n < 0 && errno == EINTR)
                    continue;
                ::close(cli_fd);
                return -2;
            }
            sum += static_cast<size_t>(n);
        }
        return sum;
    }
    inline int getFd() const { return my_info_.fd; }
};

class Peer_tcp_based_cli // binding socket is not supported
{
    struct Info
    {
        sockaddr_in sockaddr{};
        std::string ip{};
        int port = -1;
        int fd = -1;
    } ser_info_;

public:
    Peer_tcp_based_cli() = default;
    ~Peer_tcp_based_cli() { ::close(ser_info_.fd); }
    Peer_tcp_based_cli(const Peer_tcp_based_cli &) = delete;
    Peer_tcp_based_cli &operator=(const Peer_tcp_based_cli &) = delete;
    Peer_tcp_based_cli(Peer_tcp_based_cli &&) = delete;
    Peer_tcp_based_cli &operator=(Peer_tcp_based_cli &&) = delete;
    // 0 success
    // -1 socket() error
    // -2 inet_pton() error
    // -3 port error
    // -4 connect() error
    // -5 setsockopt() error
    int connect(const std::string &ip, int port, int recv_overtime_sec = 60, int recv_overtime_usec = 0)
    {
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
        return 0;
    }
    // if length == -1, send with data size()
    // n the number sent
    // -1 send() total error & closed the connection
    // -2 send() data error
    ssize_t send(const std::string &data, size_t breakpoint = 0, ssize_t length = -1) // blocking send
    {
        if (data.empty())
            return 0;
        uint32_t total = length == -1 ? data.size() : std::min(breakpoint + length, data.size());
        size_t sum = 0;
        while (sum < 4)
        {
            ssize_t n = ::send(ser_info_.fd, reinterpret_cast<char *>(&total) + sum, 4 - sum, 0);
            if (n < 0)
            {
                if (errno == EINTR)
                    continue;
                connect(ser_info_.ip, ser_info_.port);
                return -1;
            }
            sum += static_cast<size_t>(n);
        }
        sum = breakpoint;
        while (sum < total)
        {
            ssize_t n = ::send(ser_info_.fd, data.c_str() + sum, total - sum, 0);
            if (n < 0)
            {
                if (errno == EINTR)
                    continue;
                connect(ser_info_.ip, ser_info_.port);
                return -2;
            }
            sum += static_cast<size_t>(n);
        }
        return sum;
    }
    // n the number read
    // 0 closed the connection
    // -1 recv() total error
    // -2 recv() data error
    ssize_t recv(std::string &data, size_t breakpoint = 0) // blocking recv
    {
        uint32_t total = 0;
        size_t sum = 0;
        while (sum < 4)
        {
            ssize_t n = ::recv(ser_info_.fd, reinterpret_cast<char *>(&total) + sum, 4 - sum, 0);
            if (n <= 0)
            {
                if (n < 0 && errno == EINTR)
                    continue;
                connect(ser_info_.ip, ser_info_.port);
                return 0 == n ? 0 : -1;
            }
            sum += static_cast<size_t>(n);
        }
        if (data.size() < total)
            data.resize(total);
        sum = breakpoint;
        while (sum < total)
        {
            ssize_t n = ::recv(ser_info_.fd, data.data() + sum, total - sum, 0);
            if (n <= 0)
            {
                if (n < 0 && errno == EINTR)
                    continue;
                connect(ser_info_.ip, ser_info_.port);
                return -2;
            }
            sum += static_cast<size_t>(n);
        }
        return sum;
    }
};

class Peer_udp
{
    struct Info
    {
        sockaddr_in sockaddr{};
        std::string ip{};
        int port = -1;
        int fd = -1;
    } my_info_;
    socklen_t socklen_ = sizeof(sockaddr_in);

public:
    Peer_udp() = default;
    ~Peer_udp() { ::close(my_info_.fd); }
    Peer_udp(const Peer_udp &) = delete;
    Peer_udp &operator=(const Peer_udp &) = delete;
    Peer_udp(Peer_udp &&) = delete;
    Peer_udp &operator=(Peer_udp &&) = delete;
    // 0 success
    // -1 socket() error
    // -2 inet_pton() error
    // -3 port error
    // -4 bind() error
    // -5 setsockopt() error
    int init(const std::string &ip, int port)
    {
        int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
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
        int broadcastEnable = 1;
        if (-1 == ::setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable)))
            return -5;
        return 0;
    }
    void send(sockaddr_in &ur_sockaddr_in, const std::string &data)
    {
        ::sendto(my_info_.fd, data.c_str(), data.size(), 0, (const sockaddr *)&ur_sockaddr_in, socklen_);
    }
    void send(const std::string &ur_ip, int ur_port, const std::string &data)
    {
        sockaddr_in ur_sockaddr_in{};
        ur_sockaddr_in.sin_family = AF_INET;
        if (1 != ::inet_pton(AF_INET, ur_ip.c_str(), &ur_sockaddr_in.sin_addr))
            return;
        if (ur_port < 0 || ur_port > 65535)
            return;
        ur_sockaddr_in.sin_port = ::htons(ur_port);
        send(ur_sockaddr_in, data);
    }
#define MAX_RECV_SIZE 65536
    std::string recv(sockaddr_in &ur_sockaddr_in) // blocking recv & max recv size 65536
    {
        char buf[MAX_RECV_SIZE]{};
        if (::recvfrom(my_info_.fd, buf, MAX_RECV_SIZE, 0, (sockaddr *)&ur_sockaddr_in, &socklen_) <= 0)
            return {};
        return std::string(buf);
    }
    std::string recv(int ur_port, const std::string &ur_ip = "255.255.255.255") // blocking recv & max recv size 65536
    {
        sockaddr_in ur_sockaddr_in{};
        ur_sockaddr_in.sin_family = AF_INET;
        if (1 != ::inet_pton(AF_INET, ur_ip.c_str(), &ur_sockaddr_in.sin_addr))
            return {};
        if (ur_port < 0 || ur_port > 65535)
            return {};
        ur_sockaddr_in.sin_port = ::htons(ur_port);
        return recv(ur_sockaddr_in);
    }
#undef MAX_RECV_SIZE
};

#endif