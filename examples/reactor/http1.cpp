#include "common/endpoint.hpp"
#include "error.hpp"
#include "http/v1/handler.hpp"
#include "log_config.hpp"
#include "reactor.hpp"

// epoll 驱动的 HTTP/1.x 服务端。用法：
//
//     ./reactor_http1              # 监听 0.0.0.0:8888
//     ./reactor_http1 0.0.0.0:9000
//
// HandlerHttp<REQUEST> 基于 llhttp 解析请求，并把请求体原样装进 200 OK 响应
// （Content-Length + Keep-Alive 语义由 llhttp 的解析结论决定）。它演示的是
// "协议处理器 = 状态机 + 响应队列" 的最小闭环，可作为替换业务逻辑的起点。

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
    LOG_INFO("listening on {} (http/1.x, reactor)", listen.text);

    using namespace mynet;
    using Handler = http::v1::HandlerHttp<http::v1::HTTP_MODE::REQUEST>;
    if (auto res = Reactor<EventSocket<Handler>>().runTcp(listen.ip, listen.port()); !res)
    {
        LOG_ERROR("mynet: {}", toString(res.error()));
        return toExitCode(res.error());
    }
    return 0;
}
