#include "reactor.hpp"

int main()
{
    Reactor_linux<Peer_tcp_based_ser, AtomQueue_nonblocking> ser;
    ser.run("0.0.0.0", 9999);
}