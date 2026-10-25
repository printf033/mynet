#include "error.hpp"
#include "handler.hpp"
#include "http/v2/multiplexer.hpp"
#include "log.hpp"
#include "reactor.hpp"
#include <netdb.h>

// 支持分帧与多路复用流（而非普通 HTTP）的 TCP 服务端示例。
//
// 本示例的核心在于清晰的分层边界：Multiplexer 负责分帧、流标识符管理、流控与连接拆除，
// 并为每条流提供透明的纯字节流——此处为 HandlerBase，它记录客户端发送的数据并进行回显。
// 流处理器完全感知不到帧首部，而 Multiplexer 也无需理解上层应用协议报文。
//
// 准入上限为 128 条并发流（mux::kDefaultMaxStreams，通过 SETTINGS_MAX_CONCURRENT_STREAMS
// 宣告并通过 Multiplexer::setMaxConcurrentStreams 配置）。超出限制的新建流将被发送
// RST_STREAM 拒绝而非排队缓冲，因为强行缓存帧只会将积压转移到隐蔽位置。
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
    if (auto res = Reactor<EventSocket<Multiplexer<HandlerBase>>>().runTcp(ip, port); !res)
    {
        LOG_ERROR("mynet: {}", toString(res.error()));
        return toExitCode(res.error());
    }
    return 0;
}
