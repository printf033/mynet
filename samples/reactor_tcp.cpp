#include "reactor.hpp"

int main()
{
    Reactor<Peer_tcp> reactor;
    int n = reactor.run("127.0.0.1", 8080);
    return n;
}
