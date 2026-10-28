#include "common/endpoint.hpp"
#include "error.hpp"
#include "http/v3/handler.hpp"
#include "log_config.hpp"
#include "proactor.hpp"

// io_uring 驱动的 HTTP/3 (QUIC over UDP) 服务端。用法：
//
//     ./proactor_http3              # 监听 0.0.0.0:4433
//     ./proactor_http3 0.0.0.0:4443
//
// 数据报路径在 Proactor 上以单次 recvmsg 驱动（每次完成后立即重新装填），
// 与 reactor_http3 共享同一个 HandlerHttp3：按 (peer, dcid) 维护 QUIC 会话表。

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
    LOG_INFO("listening on {} (http/3 over quic, proactor)", listen.text);

    using namespace mynet;
    http::v3::HandlerHttp3 handler;
    if (auto res = Proactor<EventSocket<http::v3::HandlerHttp3>>().runUdp(listen.ip, listen.port(), handler); !res)
    {
        LOG_ERROR("mynet: {}", toString(res.error()));
        return toExitCode(res.error());
    }
    return 0;
}
