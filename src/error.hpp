#pragma once

#include <cstdint>
#include <string_view>
#include <utility>

// Every way this library can fail, named once.
//
// What this replaces: a call returned 0 for success or one of a couple of
// dozen negative ints whose meaning lived in a comment beside the return
// statement. The worst part was not the magic numbers, it was that the same
// number meant different things in different files -- -8 was "SSL_CTX_new
// failed" in the reactor and "the CA bundle would not load" in the peer, so a
// single printed error code could not be read back without knowing who
// produced it. An enum gives every failure exactly one name with one meaning
// library-wide, and it is the payload of the std::optional the public API
// returns: nullopt is success, a value is why not.
//
// Deliberately absent: argument validation. A null address or a port outside
// the 16-bit range is a programming error, not a runtime failure, and is
// stated as a contract_assert precondition on the function that requires it.
// What remains here is only what the kernel, OpenSSL or io_uring can refuse at
// run time and no amount of correct calling can prevent.
enum class Err : uint8_t
{
    addr_invalid,           // inet_pton() rejected the text address
    socket_failed,          // socket()
    fcntl_failed,           // fcntl(): read or set O_NONBLOCK
    setsockopt_failed,      // setsockopt()
    bind_failed,            // bind()
    listen_failed,          // listen()
    connect_failed,         // connect()
    epoll_create_failed,    // epoll_create1()
    epoll_ctl_failed,       // epoll_ctl(): add, modify or delete
    epoll_wait_failed,      // epoll_wait() returned a real error, not EINTR
    eventfd_failed,         // eventfd(): the cross-thread wakeup channel
    ssl_ctx_failed,         // SSL_CTX_new()
    ssl_cert_failed,        // SSL_CTX_use_certificate_file()
    ssl_key_failed,         // SSL_CTX_use_PrivateKey_file()
    ssl_key_mismatch,       // SSL_CTX_check_private_key()
    ssl_ca_failed,          // SSL_CTX_load_verify_locations() on the client
    ssl_new_failed,         // SSL_new()
    ssl_set_fd_failed,      // SSL_set_fd()
    ssl_sni_failed,         // SSL_set_tlsext_host_name()
    uring_queue_failed,     // io_uring_queue_init_params()
    uring_memalign_failed,  // posix_memalign() for the buffer ring
    uring_buf_ring_failed,  // io_uring_setup_buf_ring()
    uring_accept_exhausted, // the accept-op pool had nothing left to post
    uring_sqe_failed,       // io_uring_get_sqe(): submission queue full
    uring_submit_failed,    // io_uring_submit()
    uring_wait_failed,      // io_uring_wait_cqe()
    accept_failed,          // accept4()
    stdout_failed,          // write() to stdout in the peer
    timer_not_found,        // cancelTimer() for an id that already fired
    not_initialised,        // run() before the loop was initialised
};

// Why one recv() or send() moved no bytes.
//
// None of these is an error. A socket that has nothing yet, a peer that said
// goodbye and a signal that cut a call short are the three ordinary outcomes
// of a non-blocking transfer, and each asks the caller for something
// different. Naming them ends the "-1 means retry here and teardown there"
// that a bare int forced every reader to re-derive from a comment.
//
// It lives here rather than beside the code that first needed it because both
// transports -- the server's Connection and the client's Peer -- answer the
// same question, and a caller that reads the reason should not care which one
// produced it.
enum class IoEnd : uint8_t
{
    wouldblock,  // not ready yet: come back when the loop reports readiness
    interrupted, // a signal cut the call short: retry immediately
    eof,         // the peer closed its side: an orderly end of stream
    fatal,       // the transport is unusable
};

// One line, lowercase, for a log line or a stderr print -- the same text
// whichever module produced the failure.
[[nodiscard]] constexpr std::string_view to_string(Err err) noexcept
{
    switch (err)
    {
    case Err::addr_invalid:
        return "the address could not be parsed";
    case Err::socket_failed:
        return "socket() failed";
    case Err::fcntl_failed:
        return "fcntl() failed";
    case Err::setsockopt_failed:
        return "setsockopt() failed";
    case Err::bind_failed:
        return "bind() failed";
    case Err::listen_failed:
        return "listen() failed";
    case Err::connect_failed:
        return "connect() failed";
    case Err::epoll_create_failed:
        return "epoll_create1() failed";
    case Err::epoll_ctl_failed:
        return "epoll_ctl() failed";
    case Err::epoll_wait_failed:
        return "epoll_wait() failed";
    case Err::eventfd_failed:
        return "eventfd() failed";
    case Err::ssl_ctx_failed:
        return "SSL_CTX_new() failed";
    case Err::ssl_cert_failed:
        return "the certificate file could not be loaded";
    case Err::ssl_key_failed:
        return "the private key file could not be loaded";
    case Err::ssl_key_mismatch:
        return "the private key does not match the certificate";
    case Err::ssl_ca_failed:
        return "the CA bundle could not be loaded";
    case Err::ssl_new_failed:
        return "SSL_new() failed";
    case Err::ssl_set_fd_failed:
        return "SSL_set_fd() failed";
    case Err::ssl_sni_failed:
        return "SSL_set_tlsext_host_name() failed";
    case Err::uring_queue_failed:
        return "io_uring_queue_init_params() failed";
    case Err::uring_memalign_failed:
        return "posix_memalign() failed";
    case Err::uring_buf_ring_failed:
        return "io_uring_setup_buf_ring() failed";
    case Err::uring_accept_exhausted:
        return "the accept queue had no op left to post";
    case Err::uring_sqe_failed:
        return "io_uring_get_sqe() returned nothing";
    case Err::uring_submit_failed:
        return "io_uring_submit() failed";
    case Err::uring_wait_failed:
        return "io_uring_wait_cqe() failed";
    case Err::accept_failed:
        return "accept4() failed";
    case Err::stdout_failed:
        return "write() to stdout failed";
    case Err::timer_not_found:
        return "no timer with that id is armed";
    case Err::not_initialised:
        return "the event loop was not initialised";
    }
    return "unknown error";
}

// The integer form, for the one place a raw number is still what is wanted:
// turning a failure into a process exit status in main().
[[nodiscard]] constexpr int to_exit_code(Err err) noexcept
{
    return static_cast<int>(std::to_underlying(err)) + 1;
}
