#include "peer.hpp"

int main()
{
    Peer_tls peer;
    int n = peer.run_cli("127.0.0.1", 4433, nullptr);
    return n;
}