#pragma once

#include "connection.hpp"

namespace mynet::shadowsocks
{
    /**
     * @brief Shadowsocks 专属流式连接会话实现
     *
     * 继承自统一的 ConnectionBase，在连接层管理 Shadowsocks 代理会话流式传输与状态。
     */
    class ConnectionShadowsocks : public ConnectionBase
    {
    public:
        using ConnectionBase::ConnectionBase;
    };

    using ShadowsocksConnection = ConnectionShadowsocks;
} // namespace mynet::shadowsocks
