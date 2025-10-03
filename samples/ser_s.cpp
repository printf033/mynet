#include "reactor.hpp"
#include <iostream>

int main()
{
    Reactor_linux<Cryptor_tls_ser, AtomQueue_nonblocking> ser;
    ser.run("0.0.0.0", 9999, "../../certs/myser.crt", "../../certs/myser.key");
}