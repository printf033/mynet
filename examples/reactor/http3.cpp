#include "common/endpoint.hpp"
#include "error.hpp"
#include "http/v3/handler.hpp"
#include "log_config.hpp"
#include "reactor.hpp"

// epoll 驱动的 HTTP/3 (QUIC over UDP) 服务端。用法：
//
//     ./reactor_http3              # 监听 0.0.0.0:4433
//     ./reactor_http3 0.0.0.0:4443
//
// HTTP/3 走数据报路径：HandlerHttp3 同时继承 HandlerConnection 与 HandlerDatagram，
// 但只有报文侧被引擎驱动——每个 QUIC 短首部报文携带连接 ID，HandlerHttp3 按
// (peer, dcid) 维护会话表并原路回写。默认端口 4433 避开明文 HTTP 的 8888。

int main(int argc, char *argv[])
{
    // 在产生任何日志之前把 mylog 输出重定向到 stderr：
    // 本程序在 stdout 上流式传输的数据必须保持纯净且不受污染。
    mynet::log::init();

    mynet::example::Endpoint listen;
    if (!mynet::example::resolveEndpoint(argc > 1 ? argv[1] : nullptr, "0.0.0.0:4433", SOCK_DGRAM, listen))
    {
        LOG_ERROR("mynet: cannot resolve endpoint '{}' (expected host:port)", argc > 1 ? argv[1] : "0.0.0.0:4433");
        return EXIT_FAILURE;
    }
    LOG_INFO("listening on {} (http/3 over quic, reactor)", listen.text);

    using namespace mynet;
    http::v3::HandlerHttp3 handler;
    if (auto res = Reactor<EventSocket<http::v3::HandlerHttp3>>().runUdp(listen.ip, listen.port(), handler); !res)
    {
        LOG_ERROR("mynet: {}", toString(res.error()));
        return toExitCode(res.error());
    }
    return 0;
}
