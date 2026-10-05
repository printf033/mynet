#include "error.hpp"
#include "handler.hpp"
#include "log.hpp"
#include "multiplexer.hpp"
#include "reactor.hpp"
#include <netdb.h>

// A TCP port that speaks framed, multiplexed streams rather than HTTP.
//
// The point of the sample is where the layer boundary sits: the multiplexer
// owns framing, stream identifiers, flow control and teardown, and hands each
// stream a plain byte stream -- here HandlerTrace, which writes down whatever
// its client sent and echoes it back. A stream handler never sees a frame
// header, and the multiplexer never sees an application message.
//
// The admission limit is 128 concurrent streams (mynetmux::kDefaultMaxStreams,
// advertised as SETTINGS_MAX_CONCURRENT_STREAMS and settable through
// Multiplexer::setMaxConcurrentStreams). A peer that opens past it is refused
// with RST_STREAM rather than queued, because holding the frames would only
// move the backlog somewhere less visible.
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
    if (std::optional<Err> err = Reactor<EventSocket<Multiplexer<HandlerTrace>>>().run_tcp(ip, port))
    {
        LOG_ERROR("mynet: {}", to_string(*err));
        return to_exit_code(*err);
    }
    return 0;
}
