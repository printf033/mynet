#include "common/endpoint.hpp"
#include "connection.hpp"
#include "error.hpp"
#include "http/v2/handler.hpp"
#include "log_config.hpp"
#include "reactor.hpp"

// epoll 驱动的 HTTP/2 流多路复用服务端。用法：
//
//     ./reactor_http2              # 监听 0.0.0.0:8888
//     ./reactor_http2 0.0.0.0:9000
//
// 分层边界是本示例的重点：HandlerHttp2 负责分帧、流标识符管理、流控与连接拆除，
// 并为每条流提供透明的纯字节流——此处为 HandlerConnection，它把流内字节原样回显。
// 流处理器完全感知不到帧首部，HandlerHttp2 也不理解上层应用协议报文。
//
// 准入上限 128 条并发流（mux::kDefaultMaxStreams，通过 SETTINGS_MAX_CONCURRENT_STREAMS
// 宣告）。超限的新建流被 RST_STREAM 拒绝而非排队缓冲——强行缓存帧只会把积压藏起来。

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
    LOG_INFO("listening on {} (http/2, reactor)", listen.text);

    using namespace mynet;
    using Handler = HandlerHttp2<HandlerConnection>;
    if (auto res = Reactor<EventSocket<Handler>>().runTcp(listen.ip, listen.port()); !res)
    {
        LOG_ERROR("mynet: {}", toString(res.error()));
        return toExitCode(res.error());
    }
    return 0;
}
