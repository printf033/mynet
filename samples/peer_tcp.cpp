#include "peer.hpp"

int main()
{
    Peer_tcp peer;
    int n = peer.run_ser("0.0.0.0", 8080);
    return n;
}