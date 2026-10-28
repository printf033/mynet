#include "common/endpoint.hpp"
#include "common/handlers.hpp"
#include "error.hpp"
#include "log_config.hpp"
#include "reactor.hpp"

// epoll 驱动的流式回显服务端。用法：
//
//     ./reactor_tcp              # 监听 0.0.0.0:8888
//     ./reactor_tcp 127.0.0.1:9000
//
// SpliceEchoHandler 在明文 TCP 下自动走 Linux splice 内核零拷贝环回通道。

int main(int argc, char *argv[])
{
    // 在产生任何日志之前把 mylog 输出重定向到 stderr：
    // 本程序在 stdout 上流式传输的数据必须保持纯净且不受污染。
    mynet::log::init();

    mynet::example::Endpoint listen;
    if (!mynet::example::resolveEndpoint(argc > 1 ? argv[1] : nullptr, "0.0.0.0:8888", SOCK_STREAM, listen))
    {
        LOG_ERROR("mynet: cannot resolve endpoint '{}' (expected host:port)", argc > 1 ? argv[1] : "0.0.0.0:8888");
        return EXIT_FAILURE;
    }
    LOG_INFO("listening on {} (tcp, reactor)", listen.text);

    using namespace mynet;
    if (auto res = Reactor<EventSocket<example::SpliceEchoHandler>>().runTcp(listen.ip, listen.port()); !res)
    {
        LOG_ERROR("mynet: {}", toString(res.error()));
        return toExitCode(res.error());
    }
    return 0;
}
