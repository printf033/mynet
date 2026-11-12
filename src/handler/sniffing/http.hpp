#pragma once

#include "common.hpp"
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <utility>

namespace mynet::handler::sniffing
{

    /**
     * @brief 嗅探 HTTP 1.0 / 1.1 请求中的 Host 首部
     *
     * @param data 报文字节切片
     * @return std::optional<std::pair<std::string_view, uint16_t>> 域名与可选端口
     */
    [[nodiscard]] inline std::optional<std::pair<std::string_view, uint16_t>>
    sniffHttpHost(std::span<const uint8_t> data) noexcept
    {
        if (data.size() < 14) // 最小请求 "GET / HTTP/1.1\r\n"
        {
            return std::nullopt;
        }

        // 校验首部 HTTP 动词
        static constexpr std::string_view kMethods[] = {
            "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "CONNECT ", "OPTIONS ", "PATCH ", "TRACE "};

        std::string_view headerView(reinterpret_cast<const char *>(data.data()), data.size());
        bool validMethod = false;
        for (auto m : kMethods)
        {
            if (headerView.starts_with(m))
            {
                validMethod = true;
                break;
            }
        }
        if (!validMethod)
        {
            return std::nullopt;
        }

        // 按行扫描（单字节 '\n' 分割）
        size_t start = 0;
        // 跳过请求行
        auto nlPos = headerView.find('\n');
        if (nlPos == std::string_view::npos)
        {
            return std::nullopt;
        }
        start = nlPos + 1;

        while (start < headerView.size())
        {
            auto nextNl = headerView.find('\n', start);
            std::string_view line = (nextNl != std::string_view::npos)
                                        ? headerView.substr(start, nextNl - start)
                                        : headerView.substr(start);
            start = (nextNl != std::string_view::npos) ? nextNl + 1 : headerView.size();

            if (!line.empty() && line.back() == '\r')
            {
                line.remove_suffix(1);
            }
            if (line.empty())
            {
                // 空行表示头部结束
                break;
            }

            // 匹配 "Host:" 或 "host:"
            if (line.size() >= 5)
            {
                const char c0 = line[0];
                const char c1 = line[1];
                const char c2 = line[2];
                const char c3 = line[3];
                const char c4 = line[4];
                const bool isHost = (c0 == 'H' || c0 == 'h') && (c1 == 'O' || c1 == 'o') &&
                                    (c2 == 'S' || c2 == 's') && (c3 == 'T' || c3 == 't') && (c4 == ':');
                if (isHost)
                {
                    std::string_view val = line.substr(5);
                    // 裁剪前后空白
                    while (!val.empty() && (val.front() == ' ' || val.front() == '\t'))
                    {
                        val.remove_prefix(1);
                    }
                    while (!val.empty() && (val.back() == ' ' || val.back() == '\t'))
                    {
                        val.remove_suffix(1);
                    }

                    if (val.empty())
                    {
                        return std::nullopt;
                    }

                    // 检查是否包含端口: host:port 或 [ipv6]:port
                    uint16_t port = 0;
                    if (val.front() == '[')
                    {
                        auto closeBracket = val.find(']');
                        if (closeBracket != std::string_view::npos && closeBracket + 1 < val.size() &&
                            val[closeBracket + 1] == ':')
                        {
                            auto portStr = val.substr(closeBracket + 2);
                            uint32_t p = 0;
                            for (char pc : portStr)
                            {
                                if (pc >= '0' && pc <= '9')
                                {
                                    p = p * 10 + (pc - '0');
                                }
                                else
                                {
                                    break;
                                }
                            }
                            port = static_cast<uint16_t>(p);
                            val = val.substr(0, closeBracket + 1);
                        }
                    }
                    else
                    {
                        auto portColon = val.rfind(':');
                        if (portColon != std::string_view::npos)
                        {
                            auto portStr = val.substr(portColon + 1);
                            uint32_t p = 0;
                            bool ok = true;
                            for (char pc : portStr)
                            {
                                if (pc >= '0' && pc <= '9')
                                {
                                    p = p * 10 + (pc - '0');
                                }
                                else
                                {
                                    ok = false;
                                    break;
                                }
                            }
                            if (ok && p > 0 && p <= 65535)
                            {
                                port = static_cast<uint16_t>(p);
                                val = val.substr(0, portColon);
                            }
                        }
                    }

                    return std::pair{val, port};
                }
            }
        }

        return std::nullopt;
    }

} // namespace mynet::handler::sniffing
