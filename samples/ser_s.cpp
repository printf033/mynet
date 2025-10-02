#include "cryptor.hpp"

int main()
{
    Cryptor_tls_ser ser;
    int n = ser.listen("0.0.0.0", 9999, "../../certs/myser.crt", "../../certs/myser.key");
    SSL *ssl;
    n = ser.accept(ssl, 99999);
    while (true)
    {
        std::string data{};
        if (0 == ser.recv(ssl, std::move(data)))
        {
            std::cout << data << std::endl;
            ser.send(ssl, data);
        }
    }
}