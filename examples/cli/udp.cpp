#include "client.hpp"
#include "common/endpoint.hpp"
#include "datagram.hpp"
#include "error.hpp"
#include "log_config.hpp"

// UDP 客户端示例。用法：
//
//     echo "ping" | ./cli_udp 127.0.0.1:9999
//
// 注意 UDP 下一次性的语义：无连接协议没有 FIN，若 Client 等待回包，单向发送
// （fire-and-forget、对端宕机或丢包）时会永远挂起。因此 Client 在 UDP 下的完成
// 条件是「stdin 已关闭且待发数据已全部写出」，收完 stdin 就退出，不保证回包已到达。
// 需要严格的请求-响应语义时，用 reactor_udp / proactor_udp 配合自带截止时间的
// 客户端（如 python 的 socket.settimeout）。

int main(int argc, char *argv[])
{
    // 在产生任何日志之前把 mylog 输出重定向到 stderr：
    // 本程序在 stdout 上流式传输的数据必须保持纯净且不受污染。
    mynet::log::init();

    mynet::example::Endpoint target;
    if (!mynet::example::resolveEndpoint(argc > 1 ? argv[1] : nullptr, "127.0.0.1:8888", SOCK_DGRAM, target))
    {
        LOG_ERROR("mynet: cannot resolve endpoint '{}' (expected host:port)", argc > 1 ? argv[1] : "127.0.0.1:8888");
        return EXIT_FAILURE;
    }
    LOG_INFO("connecting to {} (udp)", target.text);

    using namespace mynet;
    if (auto res = Client<EventSocket<HandlerDatagram>>().runUdp(target.ip, target.port()); !res)
    {
        LOG_ERROR("mynet: {}", toString(res.error()));
        return toExitCode(res.error());
    }
    return 0;
}
