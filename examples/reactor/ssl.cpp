#include "common/endpoint.hpp"
#include "connection.hpp"
#include "error.hpp"
#include "log_config.hpp"
#include "reactor.hpp"

// epoll 驱动的 TLS 回显服务端。用法：
//
//     ./reactor_ssl                                   # 0.0.0.0:8888 + 默认证书
//     ./reactor_ssl 0.0.0.0:8443 ../certs/ser.crt ../certs/ser.key
//
// HandlerConnection 收到的是解密后的明文；TLS 握手由 Connection 内部驱动。

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
    const char *crt = argc > 2 ? argv[2] : "../certs/ser.crt";
    const char *key = argc > 3 ? argv[3] : "../certs/ser.key";
    LOG_INFO("listening on {} (tls, reactor)", listen.text);

    using namespace mynet;
    if (auto res = Reactor<EventSsl<HandlerConnection>>().runSsl(listen.ip, listen.port(), crt, key); !res)
    {
        LOG_ERROR("mynet: {}", toString(res.error()));
        return toExitCode(res.error());
    }
    return 0;
}
