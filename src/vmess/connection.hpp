#pragma once

#include "connection.hpp"

namespace mynet::vmess
{
    /**
     * @brief VMess 专属流式连接会话实现
     *
     * 继承自统一的 ConnectionBase，在连接层管理 VMess 代理会话流式传输与状态。
     */
    class ConnectionVmess : public ConnectionBase
    {
    public:
        using ConnectionBase::ConnectionBase;
    };

    using VmessConnection = ConnectionVmess;
} // namespace mynet::vmess
