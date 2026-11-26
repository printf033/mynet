#pragma once

#include "connection.hpp"

namespace mynet::vless
{
    /**
     * @brief VLESS 专属流式连接会话实现
     *
     * 继承自统一的 ConnectionBase，在连接层管理 VLESS 代理会话流式传输与状态。
     */
    class ConnectionVless : public Connection
    {
    public:
        using Connection::Connection;
    };

    using VlessConnection = ConnectionVless;
} // namespace mynet::vless
