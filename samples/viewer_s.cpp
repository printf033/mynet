#include "viewer.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <netdb.h>

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        std::cerr << "哪个网站？" << std::endl;
        return -1;
    }
    struct hostent *host = gethostbyname(argv[1]);
    if (host == nullptr)
    {
        std::cerr << "something wrong with this hostname: " << argv[1] << std::endl;
        return -2;
    }
    std::string host_name = host->h_name;
    std::cout << "Official name: " << host_name << std::endl;
    std::vector<std::string> host_alias;
    int i = 0;
    while (host->h_aliases[i] != nullptr)
    {
        host_alias.push_back(host->h_aliases[i]);
        std::cout << "Alias " << i << ": " << host->h_aliases[i] << std::endl;
        ++i;
    }
    int host_address_type = host->h_addrtype;
    std::cout << "Address type: " << (host_address_type == AF_INET ? "IPv4" : (host_address_type == AF_INET6 ? "IPv6" : "unknown")) << std::endl;
    int host_length = host->h_length;
    std::cout << "Address length: " << host_length << std::endl;
    std::vector<std::string> ip;
    i = 0;
    while (host->h_addr_list[i] != nullptr)
    {
        ip.push_back(inet_ntoa(*(struct in_addr *)host->h_addr_list[i]));
        std::cout << "IP " << i << ": " << ip[i] << std::endl;
        ++i;
    }
    /////////////////////////////////////////////////////////////////
    Viewer_web_cli cli;
    int n = cli.connect(ip.front(), 443);
    std::cout << "connect result: " << n << std::endl;
    while (true)
    {
        std::string data{};
        std::cin >> data;
        cli.send(data);
        std::string recv_data{};
        recv_data.resize(1024 * 1024, 0); ///////////////
        n = cli.recv(recv_data);
        if (n > 0)
            std::cout << recv_data << std::endl;
        else
            std::cout << "recv result: " << n << std::endl;
    }
}
