#include "common/endpoint.hpp"
#include "error.hpp"
#include "http/v3/handler.hpp"
#include "log_config.hpp"
#include "reactor/reactor.hpp"
#include <csignal>

// 基于 QUIC/UDP 的 HTTP/3 标准服务端（Reactor 驱动）。用法：
//
//     ./reactor_http3              # 监听 0.0.0.0:4433
//     ./reactor_http3 0.0.0.0:4443
//
// 支持与标准 curl --http3 完全互通：
//     curl -v --http3 https://127.0.0.1:4433/ -k
//     curl -v --http3 https://127.0.0.1:4433/echo -d "hello http3" -k
//
// 传输层由 Reactor<AcceptorQuic<HandlerHttp3>> 统一驱动，业务逻辑由
// HandlerHttp3::onRequest 解耦处理并分发响应。

namespace
{
    mynet::Reactor<mynet::AcceptorQuic<mynet::http::v3::HandlerHttp3>> *g_reactor = nullptr;

    void handleSignal(int)
    {
        if (g_reactor != nullptr)
        {
            g_reactor->stop();
        }
    }
} // namespace

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
    Reactor<AcceptorQuic<http::v3::HandlerHttp3>> reactor;
    g_reactor = &reactor;
    std::signal(SIGINT, handleSignal);
    std::signal(SIGTERM, handleSignal);

    if (auto res = reactor.runQuic(listen.ip, listen.port(), handler); !res)
    {
        LOG_ERROR("mynet: {}", toString(res.error()));
        return toExitCode(res.error());
    }
    return 0;
}
