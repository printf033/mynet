#pragma once

#include "connection.hpp"

namespace mynet::socks
{
    /**
     * @brief Socks 专属流式连接会话实现
     *
     * 继承自统一的 ConnectionBase，在连接层管理 Socks 代理会话流式传输与状态。
     */
    class ConnectionSocks : public Connection
    {
    public:
        using Connection::Connection;
    };

    using SocksConnection = ConnectionSocks;
} // namespace mynet::socks
