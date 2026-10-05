#pragma once

#include "error.hpp"
#include "handler.hpp"
#include "log.hpp"
#include "myconcepts.hpp"
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <optional>
#include <sys/socket.h>
#include <unistd.h>

template <typename HandlerType>
    requires mustDerivedFromHandlerBase<HandlerType> && mustResettable<HandlerType>
struct EventBase
{
    int fd = -1;
    using Handler = HandlerType;
    Handler *handler = nullptr;

public:
    inline void reset() noexcept
    {
        if (fd != -1)
        {
            ::close(fd);
            fd = -1;
        }
        handler = nullptr;
    }
};

template <typename HandlerType>
    requires mustDerivedFromHandlerBase<HandlerType> && mustResettable<HandlerType>
struct EventSocket : public EventBase<HandlerType>
{
    sockaddr_in addr{};

public:
    inline void reset() noexcept
    {
        addr = {};
        EventBase<HandlerType>::reset();
    }

    // std::nullopt on success, otherwise the call that failed. The address
    // text and the port range are contract preconditions rather than error
    // codes: a null pointer or a port outside the 16-bit range is a bug in the
    // caller, and failing the contract here is honest about that where a
    // returned number the caller may ignore is not. What is left as an Err is
    // only what the kernel can refuse at run time.
    [[nodiscard]] std::optional<Err> listen_tcp(const char *ip, int port, int backlog = 511) noexcept
    {
        contract_assert(ip != nullptr);
        contract_assert(port >= 0 && port <= 65535);
        addr.sin_family = AF_INET;
        if (::inet_pton(AF_INET, ip, &addr.sin_addr) <= 0)
        {
            LOG_ERROR("listen_tcp {}:{}: not an IPv4 address literal", ip, port);
            reset();
            return Err::addr_invalid;
        }
        addr.sin_port = ::htons(port);
        EventBase<HandlerType>::fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (EventBase<HandlerType>::fd < 0)
        {
            LOG_ERROR("listen_tcp {}:{}: socket() failed: {}", ip, port, mynetlog::errnoText(errno));
            reset();
            return Err::socket_failed;
        }
        const int flg = ::fcntl(EventBase<HandlerType>::fd, F_GETFL, 0);
        if (flg < 0)
        {
            LOG_ERROR("listen_tcp {}:{}: fcntl(F_GETFL) on fd {} failed: {}", ip, port,
                      EventBase<HandlerType>::fd, mynetlog::errnoText(errno));
            reset();
            return Err::fcntl_failed;
        }
        if (::fcntl(EventBase<HandlerType>::fd, F_SETFL, flg | O_NONBLOCK) < 0)
        {
            LOG_ERROR("listen_tcp {}:{}: fcntl(F_SETFL, O_NONBLOCK) on fd {} failed: {}", ip, port,
                      EventBase<HandlerType>::fd, mynetlog::errnoText(errno));
            reset();
            return Err::fcntl_failed;
        }
        int opt = 1;
        if (::setsockopt(EventBase<HandlerType>::fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        {
            LOG_ERROR("listen_tcp {}:{}: setsockopt(SO_REUSEADDR) failed: {}", ip, port,
                      mynetlog::errnoText(errno));
            reset();
            return Err::setsockopt_failed;
        }
        if (::setsockopt(EventBase<HandlerType>::fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0)
        {
            LOG_ERROR("listen_tcp {}:{}: setsockopt(SO_REUSEPORT) failed: {}", ip, port,
                      mynetlog::errnoText(errno));
            reset();
            return Err::setsockopt_failed;
        }
        if (::bind(EventBase<HandlerType>::fd, reinterpret_cast<const sockaddr *>(&addr), sizeof(sockaddr_in)) < 0)
        {
            LOG_ERROR("listen_tcp {}:{}: bind() failed: {}", ip, port, mynetlog::errnoText(errno));
            reset();
            return Err::bind_failed;
        }
        if (::listen(EventBase<HandlerType>::fd, backlog) < 0)
        {
            LOG_ERROR("listen_tcp {}:{}: listen(backlog={}) failed: {}", ip, port, backlog,
                      mynetlog::errnoText(errno));
            reset();
            return Err::listen_failed;
        }
        return std::nullopt;
    }

    // The same contract as listen_tcp, minus the listen() -- a datagram socket
    // is bound but never listening, and asks for SO_BROADCAST instead.
    [[nodiscard]] std::optional<Err> listen_udp(const char *ip, int port) noexcept
    {
        contract_assert(ip != nullptr);
        contract_assert(port >= 0 && port <= 65535);
        addr.sin_family = AF_INET;
        if (::inet_pton(AF_INET, ip, &addr.sin_addr) <= 0)
        {
            LOG_ERROR("listen_udp {}:{}: not an IPv4 address literal", ip, port);
            reset();
            return Err::addr_invalid;
        }
        addr.sin_port = ::htons(port);
        EventBase<HandlerType>::fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (EventBase<HandlerType>::fd < 0)
        {
            LOG_ERROR("listen_udp {}:{}: socket() failed: {}", ip, port, mynetlog::errnoText(errno));
            reset();
            return Err::socket_failed;
        }
        const int flg = ::fcntl(EventBase<HandlerType>::fd, F_GETFL, 0);
        if (flg < 0)
        {
            LOG_ERROR("listen_udp {}:{}: fcntl(F_GETFL) on fd {} failed: {}", ip, port,
                      EventBase<HandlerType>::fd, mynetlog::errnoText(errno));
            reset();
            return Err::fcntl_failed;
        }
        if (::fcntl(EventBase<HandlerType>::fd, F_SETFL, flg | O_NONBLOCK) < 0)
        {
            LOG_ERROR("listen_udp {}:{}: fcntl(F_SETFL, O_NONBLOCK) on fd {} failed: {}", ip, port,
                      EventBase<HandlerType>::fd, mynetlog::errnoText(errno));
            reset();
            return Err::fcntl_failed;
        }
        int opt = 1;
        if (::setsockopt(EventBase<HandlerType>::fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        {
            LOG_ERROR("listen_udp {}:{}: setsockopt(SO_REUSEADDR) failed: {}", ip, port,
                      mynetlog::errnoText(errno));
            reset();
            return Err::setsockopt_failed;
        }
        if (::setsockopt(EventBase<HandlerType>::fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0)
        {
            LOG_ERROR("listen_udp {}:{}: setsockopt(SO_REUSEPORT) failed: {}", ip, port,
                      mynetlog::errnoText(errno));
            reset();
            return Err::setsockopt_failed;
        }
        if (::setsockopt(EventBase<HandlerType>::fd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt)) < 0)
        {
            LOG_ERROR("listen_udp {}:{}: setsockopt(SO_BROADCAST) failed: {}", ip, port,
                      mynetlog::errnoText(errno));
            reset();
            return Err::setsockopt_failed;
        }
        if (::bind(EventBase<HandlerType>::fd, reinterpret_cast<const sockaddr *>(&addr), sizeof(sockaddr_in)) < 0)
        {
            LOG_ERROR("listen_udp {}:{}: bind() failed: {}", ip, port, mynetlog::errnoText(errno));
            reset();
            return Err::bind_failed;
        }
        return std::nullopt;
    }
};

// A pure tag, not a handle. Choosing EventSsl<H> is what picks the one
// Protocol<> specialisation that carries an SSL_CTX, and nothing else about
// the type changes. The per-connection SSL object lives in Connection::ssl_
// -- an SSL* cached on the listener was never assigned by anyone, so the
// SSL_free() this type used to run was a double free waiting to be wired up.
template <typename HandlerType>
    requires mustDerivedFromHandlerBase<HandlerType> && mustResettable<HandlerType>
struct EventSsl : public EventSocket<HandlerType>
{
};
