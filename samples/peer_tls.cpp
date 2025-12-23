#include "peer.hpp"

int main()
{
    Peer_tls peer;
    int n = peer.run_ser("127.0.0.1", 4433, "../certs/ser.crt", "../certs/ser.key");
    return n;
}