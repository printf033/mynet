#include "common/endpoint.hpp"
#include "common/handlers.hpp"
#include "datagram.hpp"
#include "error.hpp"
#include "log_config.hpp"
#include "proactor.hpp"

// io_uring 驱动的 UDP 数据报回显服务端。用法：
//
//     ./proactor_udp              # 监听 0.0.0.0:8888
//     ./proactor_udp 0.0.0.0:9999
//
// 每次只下发单个 recvmsg：发送端地址是消息的一部分，不存在可关联的连接级
// 会话缓冲；每次接收完成后立即重新装填读取操作。

int main(int argc, char *argv[])
{
    // 在产生任何日志之前把 mylog 输出重定向到 stderr：
    // 本程序在 stdout 上流式传输的数据必须保持纯净且不受污染。
    mynet::log::init();

    mynet::example::Endpoint listen;
    if (!mynet::example::resolveEndpoint(argc > 1 ? argv[1] : nullptr, "0.0.0.0:8888", SOCK_DGRAM, listen))
    {
        LOG_ERROR("mynet: cannot resolve endpoint '{}' (expected host:port)", argc > 1 ? argv[1] : "0.0.0.0:8888");
        return EXIT_FAILURE;
    }
    LOG_INFO("listening on {} (udp, proactor)", listen.text);

    using namespace mynet;
    example::UdpEchoHandler handler;
    if (auto res = Proactor<EventSocket<example::UdpEchoHandler>>().runUdp(listen.ip, listen.port(), handler); !res)
    {
        LOG_ERROR("mynet: {}", toString(res.error()));
        return toExitCode(res.error());
    }
    return 0;
}
