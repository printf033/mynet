#include "cryptor.hpp"

int main()
{
    Cryptor_tls_cli cli;
    int n = cli.connect("127.0.0.1", 9999, "/home/aaa/code/mynet/certs/myser.crt");
    std::cerr << n << "connect\n";
    while (true)
    {
        std::string data{};
        std::getline(std::cin, data);
        cli.send(data);
        std::string recv_data{};
        recv_data.resize(65536); // pre-allocate max recv size
        if (0 == cli.recv(std::move(recv_data)))
            std::cout << recv_data << std::endl;
        else
            std::cout << "recv error" << std::endl;
    }
}