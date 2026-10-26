#include "error.hpp"
#include "http/v3/handler.hpp"
#include "log.hpp"
#include "reactor.hpp"
#include <netdb.h>

int main(int argc, char *argv[])
{
    mynet::log::init();
    const char *name = "0.0.0.0";
    const char *service = "4433";
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
    hints.ai_socktype = SOCK_DGRAM; // HTTP/3 基于 QUIC/UDP
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
    LOG_INFO("listening to {}:{} (HTTP/3 over QUIC/UDP)", ip, port);

    using namespace mynet;
    HandlerHttp3 handler;
    if (auto res = Reactor<EventSocket<HandlerHttp3>>().runUdp(ip, port, handler); !res)
    {
        LOG_ERROR("mynet HTTP/3: {}", toString(res.error()));
        return toExitCode(res.error());
    }
    return 0;
}
