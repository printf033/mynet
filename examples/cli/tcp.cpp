#include "client.hpp"
#include "common/endpoint.hpp"
#include "connection.hpp"
#include "error.hpp"
#include "log_config.hpp"

// 传输级客户端示例：把 stdin 流式发往服务端，并把服务端回包写到 stdout。
//
// Client 是纯字节管道，不解析任何应用协议——它演示的是"标准流 <-> 套接字"的
// Unix 管道哲学。用法：
//
//     echo "hello" | ./cli_tcp 127.0.0.1:8888
//
// TLS 与 UDP 变体分别在 cli/ssl.cpp 与 cli/udp.cpp 中。

int main(int argc, char *argv[])
{
    // 在产生任何日志之前把 mylog 输出重定向到 stderr：
    // 本程序在 stdout 上流式传输的数据必须保持纯净且不受污染。
    mynet::log::init();

    mynet::example::Endpoint target;
    if (!mynet::example::resolveEndpoint(argc > 1 ? argv[1] : nullptr, "127.0.0.1:8888", SOCK_STREAM, target))
    {
        LOG_ERROR("mynet: cannot resolve endpoint '{}' (expected host:port)", argc > 1 ? argv[1] : "127.0.0.1:8888");
        return EXIT_FAILURE;
    }
    LOG_INFO("connecting to {}", target.text);

    using namespace mynet;
    if (auto res = Client<EventSocket<HandlerConnection>>().runTcp(target.ip, target.port()); !res)
    {
        LOG_ERROR("mynet: {}", toString(res.error()));
        return toExitCode(res.error());
    }
    return 0;
}
