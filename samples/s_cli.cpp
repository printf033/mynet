#include "peer_s.hpp"
#include <iostream>

int main()
{
    Peer_s_tls_based_cli cli;
    cli.connect("127.0.0.1", 9998, "../../certs/myser.crt");
    while (true)
    {
        std::string data{};
        std::cin >> data;
        cli.send(data);
        std::string recv_data{};
        if (cli.recv(recv_data) > 0)
            std::cout << recv_data << std::endl;
        else
            std::cout << "the other side left..." << std::endl;
    }
}