#pragma once

/**
 * @file common/handlers.hpp
 * @brief 示例程序共用的协议处理器。
 *
 * 两个引擎（Reactor / Proactor）的 tcp 与 udp 示例使用完全相同的处理器定义：
 * 传输引擎的差异只体现在递送字节的读写路径上，与处理器无关。把定义集中在此，
 * 避免四个示例文件各自复制一份，也能保证它们的行为严格一致。
 */

#include "connection.hpp"
#include "datagram.hpp"
#include <cstddef>

namespace mynet::example
{

    /**
     * @brief 流式回显处理器
     *
     * process() 显式实现字节流回显。
     * 声明 kEnableSplice 后，明文 TCP 上由 handler 在 onConnect(fd) 钩子中
     * 将零拷贝目标设定为对端套接字（socket -> pipe -> socket），数据不进入用户态；
     * TLS 下自动退回用户态回显。
     */
    class SpliceEchoHandler : public HandlerConnection
    {
    public:
        static constexpr bool kEnableSplice = true;

        void onConnect(int fd) noexcept override { setSpliceTarget(fd); }

        void process()
        {
            const size_t n = requestBytes();
            if (n == 0)
            {
                return;
            }
            if (!pushResponse(std::string_view(requestBegin(), n)))
            {
                LOG_WARN("SpliceEchoHandler: response queue full, echoing dropped");
            }
            requestClear();
        }

        void reset() noexcept override { HandlerConnection::reset(); }
    };

    /**
     * @brief 数据报回显处理器
     *
     * 业务协议级回显：在 onDatagram 中自主将接收到的报文通过 sendTo 推入外发队列。
     */
    class UdpEchoHandler : public HandlerDatagram
    {
    public:
        void onDatagram(const sockaddr_in &peer, const char *data, size_t n) noexcept override
        {
            if (data != nullptr && n > 0)
            {
                sendTo(peer, data, n);
            }
        }
    };

} // namespace mynet::example
