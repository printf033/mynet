#include "client.hpp"
#include "common/endpoint.hpp"
#include "connection.hpp"
#include "error.hpp"
#include "log_config.hpp"

// TLS 传输级客户端示例。用法：
//
//     echo "hello" | ./cli_ssl 127.0.0.1:8443 localhost ../certs/ser.crt
//
// 位置参数：<host:port> [SNI 服务器名] [CA 根证书]
// SNI 省略时用 host 部分的原始文本；CA 省略时校验系统默认证书库。

int main(int argc, char *argv[])
{
    // 在产生任何日志之前把 mylog 输出重定向到 stderr：
    // 本程序在 stdout 上流式传输的数据必须保持纯净且不受污染。
    mynet::log::init();

    mynet::example::Endpoint target;
    const char *spec = argc > 1 ? argv[1] : "127.0.0.1:8888";
    if (!mynet::example::resolveEndpoint(spec, "127.0.0.1:8888", SOCK_STREAM, target))
    {
        LOG_ERROR("mynet: cannot resolve endpoint '{}' (expected host:port)", spec);
        return EXIT_FAILURE;
    }

    // SNI 默认回退到端点文本的 host 段（不含端口），与浏览器的行为一致。
    const char *serverName = argc > 2 ? argv[2] : nullptr;
    const char *caFile = argc > 3 ? argv[3] : nullptr;
    LOG_INFO("connecting to {} (sni={}, ca={})", target.text, serverName != nullptr ? serverName : target.ip,
             caFile != nullptr ? caFile : "system");

    using namespace mynet;
    if (auto res = Client<EventSsl<HandlerConnection>>().runSsl(
            target.ip, target.port(), serverName != nullptr ? serverName : target.ip, caFile);
        !res)
    {
        LOG_ERROR("mynet: {}", toString(res.error()));
        return toExitCode(res.error());
    }
    return 0;
}
