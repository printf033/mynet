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
     * HandlerConnection::process() 本身即字节流回显，无需额外代码。
     * 声明 kEnableSplice 后，明文 TCP 上会走 Linux 内核零拷贝环回
     * （socket -> pipe -> socket），数据不进入用户态；TLS 下自动退回用户态回显。
     */
    class SpliceEchoHandler : public HandlerConnection
    {
    public:
        static constexpr bool kEnableSplice = true;

        SpliceEchoHandler() noexcept { setSpliceEnabled(true); }

        void reset() noexcept override
        {
            HandlerConnection::reset();
            setSpliceEnabled(true);
        }
    };

    /**
     * @brief 数据报回显处理器
     *
     * 只需偏报文的 HandlerDatagram：数据报路径不经过 Connection，不要求任何
     * 流式设施。HandlerDatagram 自带对端地址标签化的回复队列。
     */
    class UdpEchoHandler : public HandlerDatagram
    {
    public:
        void onDatagram(const sockaddr_in &peer, const char *data, size_t n) noexcept override
        {
            pushReply(peer, data, n);
        }
    };

} // namespace mynet::example
