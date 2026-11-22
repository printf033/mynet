#pragma once

#include "connection.hpp"

namespace mynet::http
{
    /**
     * @brief HTTP 专属流式连接会话实现
     *
     * 继承自统一的 ConnectionBase，在连接层管理 HTTP 会话流式传输与状态。
     */
    class ConnectionHttp : public ConnectionBase
    {
    public:
        using ConnectionBase::ConnectionBase;
    };

    using HttpConnection = ConnectionHttp;
} // namespace mynet::http
