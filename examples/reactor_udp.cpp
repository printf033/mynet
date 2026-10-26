#include "error.hpp"
#include "log.hpp"
#include "reactor.hpp"
#include <netdb.h>

int main(int argc, char *argv[])
{
    // 在产生任何日志之前将 mylog 的输出重定向到 stderr：
    // 本程序在 stdout 上流式传输的数据必须保持纯净且不受污染。
    mynet::log::init();
    const char *name = "0.0.0.0";
    const char *service = "8888";
    switch (argc)
    {
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
    // UDP 监听器绑定的套接字类型，与流式示例通过相同的路径解析，
    // 因此 /etc/services 中的服务名称依然适用。
    hints.ai_socktype = SOCK_DGRAM;
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
    LOG_INFO("listening to {}:{} (udp)", ip, port);
    // 整个套接字共享一个处理器：数据报套接字是所有对端共享的单一端点，
    // 无需池化连接级状态，处理器的生命周期贯穿所有消息，而非随单个套接字连接回收。
    using namespace mynet;
    HandlerEcho handler;
    if (auto res = Reactor<EventSocket<HandlerEcho>>().runUdp(ip, port, handler); !res)
    {
        LOG_ERROR("mynet: {}", toString(res.error()));
        return toExitCode(res.error());
    }
    return 0;
}
