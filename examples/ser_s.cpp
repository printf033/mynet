#include "cryptor.hpp"

int main()
{
    Cryptor_tls_ser ser;
    int n = ser.listen("0.0.0.0", 9999, "/home/aaa/code/mynet/certs/myser.crt", "/home/aaa/code/mynet/certs/myser.key");
    std::cerr << n << "listen\n";
    SSL *ssl;
    n = ser.accept(ssl, 99999);
    std::cerr << n << "accept\n";
    while (true)
    {
        std::string data{};
        data.resize(65536); // pre-allocate max recv size
        if (0 == ser.recv(ssl, std::move(data)))
            std::cout << data << std::endl;
        else
            std::cout << "no connection" << std::endl;
        ser.send(ssl, data);
    }
}