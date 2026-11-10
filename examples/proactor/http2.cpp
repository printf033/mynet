#include "common/http2.hpp"
#include "common/endpoint.hpp"
#include "connection.hpp"
#include "error.hpp"
#include "log_config.hpp"
#include "proactor.hpp"
#include "handler/http/v2/handler.hpp"

// io_uring 驱动的 HTTP/2 流多路复用服务端。用法：
//
//     ./proactor_http2              # 监听 0.0.0.0:8888
//     ./proactor_http2 0.0.0.0:9000
//
// HandlerHttp2 之下的逻辑不随底层引擎改变：连接前言、HPACK、分帧与流控都在
// 协议层完成，因此在 reactor_http2 与本示例中可用同样的标准客户端验证：
//     curl --http2-prior-knowledge -d hello http://127.0.0.1:8888/

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
    LOG_INFO("listening on {} (http/2, proactor)", listen.text);

    using namespace mynet;
    using Handler = example::Http2EchoHandler;
    if (auto res = Proactor<AcceptorBase<Handler>>().runTcp(listen.ip, listen.port()); !res)
    {
        LOG_ERROR("mynet: {}", toString(res.error()));
        return toExitCode(res.error());
    }
    return 0;
}
