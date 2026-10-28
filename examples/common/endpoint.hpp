#pragma once

/**
 * @file common/endpoint.hpp
 * @brief 示例程序共用的端点解析：把单个 "host:port" 参数解析为 sockaddr_in。
 *
 * 所有示例统一接受一个位置参数 `<host>:<port>`，而不是过去分开的 host 与 port
 * 两个参数。省略时回退到各自传入的默认值，因此 `./reactor_tcp` 与
 * `./reactor_tcp 0.0.0.0:8888` 等价。
 *
 * 端口既可以是十进制数字，也可以是 /etc/services 中的服务名（如 "http"），
 * 因为它最终交给 getaddrinfo() 解析。
 */

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <cstddef>
#include <cstdio>
#include <cstring>
#include <string_view>

namespace mynet::example
{

    /// host 与 port 两段的最大长度：IPv4 字面量最长 15 字符，域名留足余量。
    inline constexpr size_t kHostCapacity = 256;
    inline constexpr size_t kPortCapacity = 32;

    /**
     * @brief 拆分后的端点文本
     */
    struct HostPort
    {
        char host[kHostCapacity]{};
        char port[kPortCapacity]{};
    };

    /**
     * @brief 把 "host:port" 拆成两段
     *
     * 规则：
     * - 以最后一个 ':' 为界，左侧是 host、右侧是 port；
     * - 省略 host（如 ":8888"）时使用 fallbackHost；
     * - 省略 port（如 "127.0.0.1"）时使用 "8888"；
     * - 完全没有 ':' 时整串视为 host。
     *
     * 不抛异常：超长片段直接判为失败，由调用方回退到默认值。
     *
     * @param spec 形如 "127.0.0.1:8888" 的文本
     * @param out 拆分结果
     * @param fallbackHost host 为空时采用的地址
     * @return 拆分成功返回 true
     */
    [[nodiscard]] inline bool splitHostPort(std::string_view spec, HostPort &out, const char *fallbackHost) noexcept
    {
        if (spec.empty())
        {
            return false;
        }

        const size_t colon = spec.rfind(':');
        std::string_view host = spec;
        std::string_view port = "8888";
        if (colon != std::string_view::npos)
        {
            host = spec.substr(0, colon);
            port = spec.substr(colon + 1);
            if (port.empty())
            {
                port = "8888";
            }
        }
        if (host.empty())
        {
            host = fallbackHost;
        }

        if (host.size() >= kHostCapacity || port.size() >= kPortCapacity)
        {
            return false;
        }
        std::memcpy(out.host, host.data(), host.size());
        out.host[host.size()] = '\0';
        std::memcpy(out.port, port.data(), port.size());
        out.port[port.size()] = '\0';
        return true;
    }

    /**
     * @brief 解析后的端点
     */
    struct Endpoint
    {
        sockaddr_in addr{};               ///< 解析出的 IPv4 地址
        char ip[INET_ADDRSTRLEN]{};       ///< 点分十进制地址，直接喂给 runTcp / runSsl / runUdp
        char text[INET_ADDRSTRLEN + 8]{}; ///< 便于日志输出的 "ip:port"

        [[nodiscard]] int port() const noexcept { return static_cast<int>(::ntohs(addr.sin_port)); }
        [[nodiscard]] const sockaddr_in *sockaddr() const noexcept { return &addr; }
    };

    /**
     * @brief 把 "host:port" 解析成 IPv4 端点
     *
     * @param spec 命令行给出的端点文本；为 nullptr 时整段采用 defaultSpec
     * @param defaultSpec 默认端点（如 "0.0.0.0:8888"）
     * @param socktype SOCK_STREAM 或 SOCK_DGRAM，决定服务名的解析结果
     * @param out 解析结果
     * @return 成功返回 true；地址非法或无法解析时返回 false
     */
    [[nodiscard]] inline bool resolveEndpoint(const char *spec, const char *defaultSpec, int socktype,
                                              Endpoint &out) noexcept
    {
        HostPort hp{};
        if (!splitHostPort(spec != nullptr ? std::string_view{spec} : std::string_view{defaultSpec}, hp, "0.0.0.0"))
        {
            return false;
        }

        struct addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = socktype;
        struct addrinfo *res = nullptr;
        if (::getaddrinfo(hp.host, hp.port, &hints, &res) != 0 || res == nullptr)
        {
            return false;
        }
        out.addr = *reinterpret_cast<const sockaddr_in *>(res->ai_addr);
        ::freeaddrinfo(res);

        if (::inet_ntop(AF_INET, &out.addr.sin_addr, out.ip, sizeof out.ip) == nullptr)
        {
            return false;
        }
        std::snprintf(out.text, sizeof out.text, "%s:%d", out.ip, static_cast<int>(::ntohs(out.addr.sin_port)));
        return true;
    }

} // namespace mynet::example
