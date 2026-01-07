#include "peer.hpp"
#include "handler.hpp"

int main()
{
    Peer_tls peer;
    int n = peer.run_cli<Handler_base>("127.0.0.1", 4433, nullptr);
    return n;
}