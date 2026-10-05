#include "error.hpp"
#include "handler.hpp"
#include "log.hpp"
#include "multiplexer.hpp"
#include "proactor.hpp"
#include <netdb.h>

// Same framed, multiplexed stream port as multiplex_tcp, on the io_uring
// front end instead of epoll.
//
// Nothing below the multiplexer changes with the engine: the multiplexer is a
// HandlerBase, so it is the same layer boundary in both samples, and the
// read/write path that hands it bytes is the only thing that differs.
int main(int argc, char *argv[])
{
    // Send mylog's output to stderr before anything can log: the data this
    // program streams over stdout must stay untouched.
    mynetlog::init();
    const char *name = "0.0.0.0";
    const char *service = "8888";
    switch (argc)
    {
    case 3:
        service = argv[2];
        [[fallthrough]];
    case 2:
        name = argv[1];
        [[fallthrough]];
    default:
        LOG_INFO("resolving {}:{}", name, service);
    }
    struct addrinfo hints{}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    int e = getaddrinfo(name, service, &hints, &res);
    if (e != 0)
    {
        LOG_ERROR("cannot resolve {}:{}: {}", name, service, gai_strerror(e));
        return EXIT_FAILURE;
    }
    auto *addr = reinterpret_cast<sockaddr_in *>(res->ai_addr);
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(addr->sin_addr), ip, INET_ADDRSTRLEN);
    int port = ntohs(addr->sin_port);
    freeaddrinfo(res);
    LOG_INFO("listening to {}:{} (multiplexed streams)", ip, port);
    if (std::optional<Err> err = Proactor<EventSocket<Multiplexer<HandlerTrace>>>().run_tcp(ip, port))
    {
        LOG_ERROR("mynet: {}", to_string(*err));
        return to_exit_code(*err);
    }
    return 0;
}
