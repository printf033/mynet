#include "reactor.hpp"

int main()
{
    Reactor<Peer_tls> reactor;
    int n = reactor.run("0.0.0.0", 4433, "../certs/ser.crt", "../certs/ser.key");
    return n;
}