#include "common/endpoint.hpp"
#include "error.hpp"
#include "http/v1/handler.hpp"
#include "log_config.hpp"
#include "proactor.hpp"

// io_uring 驱动的 HTTP/1.x 服务端。用法：
//
//     ./proactor_http1              # 监听 0.0.0.0:8888
//     ./proactor_http1 0.0.0.0:9000
//
// 与 reactor_http1 共用 HandlerHttp<REQUEST>：解析状态机与响应生成完全一致，
// 区别仅在于把已解析字节送进处理器的读写路径。

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
    LOG_INFO("listening on {} (http/1.x, proactor)", listen.text);

    using namespace mynet;
    using Handler = http::v1::HandlerHttp<http::v1::HTTP_MODE::REQUEST>;
    if (auto res = Proactor<EventSocket<Handler>>().runTcp(listen.ip, listen.port()); !res)
    {
        LOG_ERROR("mynet: {}", toString(res.error()));
        return toExitCode(res.error());
    }
    return 0;
}
