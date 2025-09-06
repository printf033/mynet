#include "peer.hpp"
#include <iostream>

int main()
{
    Peer_tcp_cli cli;
    cli.connect("127.0.0.1", 9999);
    while (true)
    {
        std::string data{};
        std::getline(std::cin, data);
        cli.send(data);
        std::string recv_data{};
        if (0 == cli.recv(std::move(recv_data)))
            std::cout << recv_data << std::endl;
        else
            std::cout << "recv error" << std::endl;
    }
}