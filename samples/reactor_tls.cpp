#include "reactor.hpp"

int main()
{
    Reactor<Peer_tls> reactor;
    int n = reactor.run("127.0.0.1", 4433, "/home/aaa/code/mynet/certs/ser.crt", "/home/aaa/code/mynet/certs/ser.key");
    return n;
}