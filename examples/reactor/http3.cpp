#include "common/endpoint.hpp"
#include "error.hpp"
#include "http/v3/handler.hpp"
#include "http/v3/server.hpp"
#include "log_config.hpp"
#include <csignal>

// 基于 QUIC/UDP 的 HTTP/3 标准服务端。用法：
//
//     ./reactor_http3              # 监听 0.0.0.0:4433
//     ./reactor_http3 0.0.0.0:4443
//
// 支持与标准 curl --http3 完全互通：
//     curl -v --http3 https://127.0.0.1:4433/ -k
//     curl -v --http3 https://127.0.0.1:4433/echo -d "hello http3" -k
//
// 底层由 OpenSSL 3.6 QUIC (TLS 1.3 + ALPN "h3") 驱动，业务逻辑由
// HandlerHttp3::onRequest 解耦处理并分发响应。

namespace
{
    mynet::http::v3::ServerHttp3 *g_server = nullptr;

    void handleSignal(int)
    {
        if (g_server != nullptr)
        {
            g_server->stop();
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
    LOG_INFO("listening on {} (http/3 over quic, server)", listen.text);

    using namespace mynet;
    http::v3::HandlerHttp3 handler;
    http::v3::ServerHttp3 server;
    g_server = &server;
    std::signal(SIGINT, handleSignal);
    std::signal(SIGTERM, handleSignal);

    if (auto res = server.run(listen.ip, listen.port(), handler); !res)
    {
        LOG_ERROR("mynet: {}", toString(res.error()));
        return toExitCode(res.error());
    }
    return 0;
}
