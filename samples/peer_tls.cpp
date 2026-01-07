#include "peer.hpp"
#include "handler.hpp"

int main()
{
    Peer_tls peer;
    int n = peer.run_ser<Handler_base>("0.0.0.0", 4433, "../certs/ser.crt", "../certs/ser.key");
    return n;
}