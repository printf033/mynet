#pragma once

#include "connection.hpp"

namespace mynet::hysteria2
{
    /**
     * @brief Hysteria 2 专属流式连接会话实现
     *
     * 继承自统一的 ConnectionBase，在连接层管理 Hysteria 2 代理会话流式传输与状态。
     */
    class ConnectionHysteria2 : public Connection
    {
    public:
        using Connection::Connection;
    };

    using Hysteria2Connection = ConnectionHysteria2;
} // namespace mynet::hysteria2
