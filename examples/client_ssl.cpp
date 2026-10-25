#include "client.hpp"
#include "error.hpp"
#include "handler.hpp"
#include "log.hpp"
#include <netdb.h>

int main(int argc, char *argv[])
{
    // 在产生任何日志之前将 mylog 的输出重定向到 stderr：
    // 本程序在 stdout 上流式传输的数据必须保持纯净且不受污染。
    mynet::log::init();
    const char *name = "127.0.0.1";
    const char *service = "8888";
    const char *serverName = nullptr;
    const char *caFile = nullptr;
    switch (argc)
    {
    case 5:
        caFile = argv[4];
        [[fallthrough]];
    case 4:
        serverName = argv[3];
        [[fallthrough]];
    case 3:
        service = argv[2];
        [[fallthrough]];
    case 2:
        name = argv[1];
        [[fallthrough]];
    default:
        LOG_INFO("resolving {}:{}", name, service);
    }
    struct addrinfo hints{}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    int e = getaddrinfo(name, service, &hints, &res);
    if (e != 0)
    {
        LOG_ERROR("cannot resolve {}:{}: {}", name, service, gai_strerror(e));
        return EXIT_FAILURE;
    }
    auto *addr = reinterpret_cast<sockaddr_in *>(res->ai_addr);
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(addr->sin_addr), ip, INET_ADDRSTRLEN);
    int port = ntohs(addr->sin_port);
    freeaddrinfo(res);
    LOG_INFO("connecting to {}:{}", ip, port);
    // 客户端自身无需持有证书，因此第 3 个参数为 SNI 中请求的服务器名称，
    // 第 4 个参数为用于校验服务端证书的 CA 根证书包路径（若不提供则跳过校验）。
    using namespace mynet;
    if (auto res = Client<EventSsl<HandlerBase>>().runSsl(ip, port, serverName != nullptr ? serverName : name, caFile);
        !res)
    {
        LOG_ERROR("mynet: {}", toString(res.error()));
        return toExitCode(res.error());
    }
    return 0;
}
