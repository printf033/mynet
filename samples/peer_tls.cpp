#include "peer.hpp"

int main()
{
    Peer_tls peer;
    int n = peer.run_ser("0.0.0.0", 4433, "../certs/ser.crt", "../certs/ser.key");
    return n;
}