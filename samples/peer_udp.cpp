#include "peer.hpp"
#include "handler.hpp"

int main()
{
    Peer_udp peer;
    int n = peer.run_ser<Handler_base>("0.0.0.0", 9999);
    return n;
}