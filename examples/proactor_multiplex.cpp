#include "error.hpp"
#include "handler.hpp"
#include "http/v2/multiplexer.hpp"
#include "log.hpp"
#include "proactor.hpp"
#include <netdb.h>

// 与 reactor_multiplex 相同的分帧多路复用流端口，基于 io_uring 前端引擎实现而非 epoll。
//
// Multiplexer 之下的逻辑不随底层引擎改变：Multiplexer 继承自 HandlerBase，因此在两个示例中
// 具有相同的分层边界，唯一的区别仅在于向其递送字节的读写路径。
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
    LOG_INFO("listening to {}:{} (multiplexed streams)", ip, port);
    using namespace mynet;
    if (auto res = Proactor<EventSocket<Multiplexer<HandlerBase>>>().runTcp(ip, port); !res)
    {
        LOG_ERROR("mynet: {}", toString(res.error()));
        return toExitCode(res.error());
    }
    return 0;
}
