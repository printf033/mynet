#include "peer.hpp"

int main()
{
    Peer_udp peer;
    int n = peer.run_cli("127.0.0.1", 9999);
    return n;
}