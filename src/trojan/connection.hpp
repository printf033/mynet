#pragma once

#include "connection.hpp"

namespace mynet::trojan
{
    /**
     * @brief Trojan 专属流式连接会话实现
     *
     * 继承自统一的 ConnectionBase，在连接层管理 Trojan 代理会话流式传输与状态。
     */
    class ConnectionTrojan : public Connection
    {
    public:
        using Connection::Connection;
    };

    using TrojanConnection = ConnectionTrojan;
} // namespace mynet::trojan
