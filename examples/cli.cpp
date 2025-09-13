#include "peer.hpp"
#include <iostream>
#include <netdb.h>

int main()
{
    struct hostent *he = gethostbyname("switchyard.proxy.rlwy.net");
    if (he == nullptr)
    {
        std::cerr << "gethostbyname error\n";
        return -1;
    }
    std::string ip = inet_ntoa(*(struct in_addr *)he->h_addr_list[0]);
    char ipstr[INET_ADDRSTRLEN]; // IPv4 长度
    int i = 0;
    while (he->h_addr_list[i] != nullptr)
    {
        if (inet_ntop(AF_INET, he->h_addr_list[i], ipstr, sizeof(ipstr)) != nullptr)
            std::cout << "IP " << i << ": " << ipstr << std::endl;
        else
            perror("inet_ntop");
        i++;
    }
    /////////////////////////////////////////////////////////////////
    Peer_tcp_cli cli;
    cli.connect(ip, 15548); // 127.0.0.1 9999
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