#include "peer.hpp"
#include "handler.hpp"
#include <netdb.h>

int main(int argc, char *argv[])
{
    const char *name = "0.0.0.0";
    const char *service = "4433";
    const char *crt = "../certs/ser.crt";
    switch (argc)
    {
    case 4:
        crt = argv[3];
        [[fallthrough]];
    case 3:
        service = argv[2];
        [[fallthrough]];
    case 2:
        name = argv[1];
        [[fallthrough]];
    default:
        std::cout << "Resolving " << name << ":" << service << std::endl;
    }
    struct addrinfo hints{}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    int e = getaddrinfo(name, service, &hints, &res);
    if (e != 0)
    {
        std::cerr << "Error: " << gai_strerror(e) << std::endl;
        return -1;
    }
    auto *addr = reinterpret_cast<sockaddr_in *>(res->ai_addr);
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(addr->sin_addr), ip, INET_ADDRSTRLEN);
    int port = ntohs(addr->sin_port);
    freeaddrinfo(res);
    std::cout << "Connecting to " << ip << ":" << port << std::endl;
    return Peer<Transporter_ssl, Handler_base>().run_ssl(ip, port, crt);
}
