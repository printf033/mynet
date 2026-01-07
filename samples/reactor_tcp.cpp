#include "reactor.hpp"
#include "handler.hpp"

int main()
{
    Reactor<Peer_tcp, Handler_base> reactor;
    int n = reactor.run("0.0.0.0", 8080);
    return n;
}
