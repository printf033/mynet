#include "peer.hpp"

int main()
{
    Peer_udp peer;
    int n = peer.run_ser("0.0.0.0", 9999);
    return n;
}