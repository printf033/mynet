#include "reactor.hpp"

int main()
{
    Reactor_linux<Cryptor_tls_ser, AtomQueue_nonblocking> ser;
    ser.run("0.0.0.0", 9998, "../../certs/myser.crt", "../../certs/myser.key");
}