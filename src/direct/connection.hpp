#pragma once

#include "connection.hpp"

namespace mynet::direct
{
    /**
     * @brief Direct 直连专属流式连接会话实现
     *
     * 继承自统一的 ConnectionBase，在连接层管理 Direct 直连会话流式传输与状态。
     */
    class ConnectionDirect : public Connection
    {
    public:
        using Connection::Connection;
    };

    using DirectConnection = ConnectionDirect;
} // namespace mynet::direct
