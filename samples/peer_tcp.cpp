#include "peer.hpp"
#include "handler.hpp"

int main()
{
    Peer_tcp peer;
    int n = peer.run_ser<Handler_base>("0.0.0.0", 8080);
    return n;
}