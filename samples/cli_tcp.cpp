#include "peer.hpp"
#include <netdb.h>

int main(int argc, char *argv[])
{
    const char *ip = "127.0.0.1";
    int port = 8080;
    switch (argc)
    {
    case 3:
        port = std::stoi(argv[2]);
    case 2:
        ip = argv[1];
    default:
        std::cout << "Connecting to " << ip << ":" << port << std::endl;
        break;
    }
    Peer_tcp peer;
    int n = peer.run_cli(ip, port);
    if (n < 0)
    {
        struct addrinfo hints{}, *res;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        int status = getaddrinfo(ip, nullptr, &hints, &res);
        if (status != 0)
            return -1;
        char ip_str[INET_ADDRSTRLEN];
        ip = ip_str;
        auto *ipv4 = reinterpret_cast<struct sockaddr_in *>(res->ai_addr);
        inet_ntop(AF_INET, &(ipv4->sin_addr), ip_str, INET_ADDRSTRLEN);
        freeaddrinfo(res);
        std::cout << "Connecting to " << ip << ":" << port << std::endl;
        int n = peer.run_cli(ip, port);
        std::cout << "error:" << n << std::endl;
    }
    return n;
}