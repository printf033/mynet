#include "reactor.hpp"
#include <iostream>

int main()
{
    Reactor_linux<Peer_tcp_ser, AtomQueue_nonblocking> ser;
    ser.run("0.0.0.0", 9999);
}