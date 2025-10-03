#include "cryptor.hpp"
#include <netdb.h>

int main()
{
    Cryptor_tls_cli cli;
    int n = cli.connect("127.0.0.1", 9999, "../../certs/myser.crt");
    while (true)
    {
        std::string data{};
        std::cin >> data;
        cli.send(data);
        std::string recv_data{};
        if (cli.recv(recv_data) > 0)
            std::cout << recv_data << std::endl;
        else
            std::cout << "recv error" << std::endl;
    }
}