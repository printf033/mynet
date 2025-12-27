#include "reactor.hpp"

int main()
{
    Reactor<Peer_tcp> reactor;
    int n = reactor.run("0.0.0.0", 8080);
    return n;
}
