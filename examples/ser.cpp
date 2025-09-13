#include "peer.hpp"
#include <iostream>

int main()
{
    Peer_tcp_ser ser;
    int n = ser.listen("0.0.0.0", 9999);
    int cli_fd = ser.accept(99999);
    while (true)
    {
        std::string data{};
        if (0 == ser.recv(cli_fd, std::move(data)))
        {
            std::cout << data << std::endl;
            ser.send(cli_fd, data);
        }
    }
}