#include "peer.hpp"

int main()
{
    Peer_tcp peer;
    int n = peer.run_cli("127.0.0.1", 8080);
    return n;
}