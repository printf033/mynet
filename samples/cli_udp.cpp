#include "peer.hpp"
#include "handler.hpp"

int main()
{
    Peer_udp peer;
    int n = peer.run_cli<Handler_base>("127.0.0.1", 9999);
    return n;
}