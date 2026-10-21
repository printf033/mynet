#include "error.hpp"
#include "handler.hpp"
#include "log.hpp"
#include "proactor.hpp"
#include <netdb.h>

int main(int argc, char *argv[])
{
    // Send mylog's output to stderr before anything can log: the data this
    // program streams over stdout must stay untouched.
    mynet::log::init();
    const char *name = "0.0.0.0";
    const char *service = "8888";
    const char *crt = "../certs/ser.crt";
    const char *key = "../certs/ser.key";
    switch (argc)
    {
    case 5:
        key = argv[4];
        [[fallthrough]];
    case 4:
        crt = argv[3];
        [[fallthrough]];
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
    LOG_INFO("listening to {}:{}", ip, port);
    // Same front end as reactor_ssl: echo, plus what arrived written down --
    using namespace mynet;
    if (auto res = Proactor<EventSsl<HandlerBase>>().runSsl(ip, port, crt, key); !res)
    {
        LOG_ERROR("mynet: {}", toString(res.error()));
        return toExitCode(res.error());
    }
    return 0;
}
