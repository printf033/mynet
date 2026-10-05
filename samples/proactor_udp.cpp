#include "error.hpp"
#include "log.hpp"
#include "proactor.hpp"
#include "udp_echo.hpp"
#include <netdb.h>

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
    hints.ai_socktype = SOCK_DGRAM;
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
    LOG_INFO("listening to {}:{} (udp)", ip, port);
    // Same front end as reactor_udp, driven by io_uring instead of epoll. One
    // recvmsg is armed at a time because the sender's address is part of the
    // message and there is no connection to key a per-session buffer on; the
    // read is re-armed as each completion is retired.
    UdpEcho handler;
    if (std::optional<Err> err = Proactor<EventSocket<UdpEcho>>().run_udp(ip, port, handler))
    {
        LOG_ERROR("mynet: {}", to_string(*err));
        return to_exit_code(*err);
    }
    return 0;
}
