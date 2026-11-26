#pragma once

/**
 * @file handler/address.hpp
 * @brief 通用代理目标网络地址抽象，兼容 SOCKS5 / Trojan / VLESS 规范。
 */

#include "encoding.hpp"
#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <linux/netfilter_ipv4.h>
#include <netinet/in.h>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <vector>

#ifndef SO_ORIGINAL_DST
#define SO_ORIGINAL_DST 80
#endif
#ifndef IP6T_SO_ORIGINAL_DST
#define IP6T_SO_ORIGINAL_DST 80
#endif

namespace mynet::handler
{

    /**
     * @brief 判定是否为 RFC 1918 私网/回环/链路本地/保留地址 (Single Source of Truth)
     */
    [[nodiscard]] constexpr bool isPrivateAddress(in_addr ip) noexcept
    {
        const uint32_t h = ntohl(ip.s_addr);
        // 10.0.0.0/8
        if ((h & 0xFF000000) == 0x0A000000)
            return true;
        // 172.16.0.0/12
        if ((h & 0xFFF00000) == 0xAC100000)
            return true;
        // 192.168.0.0/16
        if ((h & 0xFFFF0000) == 0xC0A80000)
            return true;
        // 127.0.0.0/8 (Loopback)
        if ((h & 0xFF000000) == 0x7F000000)
            return true;
        // 100.64.0.0/10 (CGNAT)
        if ((h & 0xFFC00000) == 0x64400000)
            return true;
        // 169.254.0.0/16 (Link Local)
        if ((h & 0xFFFF0000) == 0xA9FE0000)
            return true;
        // 198.18.0.0/15 (FakeIP / Benchmark)
        if ((h & 0xFFFE0000) == 0xC6120000)
            return true;
        // 0.0.0.0/8
        if ((h & 0xFF000000) == 0x00000000)
            return true;
        return false;
    }

    /**
     * @brief IPv4 CIDR 网段掩码与地址匹配结构体 (Single Source of Truth)
     */
    class IpCidr
    {
    public:
        uint32_t networkBe{0}; // 网络字节序网络地址
        uint32_t maskBe{0};    // 网络字节序子网掩码
        uint8_t prefixLen{32}; // 前缀长度 (0~32)

        constexpr IpCidr() noexcept = default;

        constexpr IpCidr(uint32_t ipBe, uint8_t prefix) noexcept
            : networkBe(ipBe),
              prefixLen(prefix > 32 ? 32 : prefix)
        {
            if (prefixLen == 0)
            {
                maskBe = 0;
            }
            else
            {
                const uint32_t hostMask = (prefixLen == 32) ? 0xFFFFFFFFU : ~((1U << (32 - prefixLen)) - 1U);
                maskBe = htonl(hostMask);
            }
            networkBe &= maskBe;
        }

        [[nodiscard]] constexpr uint32_t networkBeVal() const noexcept { return networkBe; }
        [[nodiscard]] constexpr uint32_t maskBeVal() const noexcept { return maskBe; }
        [[nodiscard]] constexpr uint8_t prefix() const noexcept { return prefixLen; }

        [[nodiscard]] constexpr bool matches(uint32_t ipBe) const noexcept { return (ipBe & maskBe) == networkBe; }

        [[nodiscard]] constexpr bool matches(in_addr ip) const noexcept { return matches(ip.s_addr); }

        /**
         * @brief 从标准 CIDR 格式字符串解析（如 "192.168.1.0/24" 或单 IP "10.0.0.1"）
         */
        static std::optional<IpCidr> parse(std::string_view cidrStr) noexcept
        {
            if (cidrStr.empty())
                return std::nullopt;

            size_t slashPos = cidrStr.find('/');
            std::string ipPart(cidrStr.substr(0, slashPos));
            in_addr addr{};
            if (::inet_pton(AF_INET, ipPart.c_str(), &addr) != 1)
            {
                return std::nullopt;
            }

            uint8_t prefix = 32;
            if (slashPos != std::string_view::npos)
            {
                std::string_view prefixPart = cidrStr.substr(slashPos + 1);
                if (prefixPart.empty())
                    return std::nullopt;
                uint32_t val = 0;
                for (char c : prefixPart)
                {
                    if (c < '0' || c > '9')
                        return std::nullopt;
                    val = val * 10 + static_cast<uint32_t>(c - '0');
                    if (val > 32)
                        return std::nullopt;
                }
                prefix = static_cast<uint8_t>(val);
            }

            return IpCidr(addr.s_addr, prefix);
        }

        [[nodiscard]] static bool isPrivate(in_addr ip) noexcept { return isPrivateAddress(ip); }
    };

    /**
     * @brief IPv6 CIDR 网段掩码与地址匹配结构体 (Single Source of Truth)
     */
    struct Ip6Cidr
    {
        in6_addr network{};
        uint8_t prefix{128};

        static std::optional<Ip6Cidr> parse(std::string_view cidrStr) noexcept
        {
            if (cidrStr.empty())
                return std::nullopt;

            size_t slashPos = cidrStr.find('/');
            std::string ipPart(cidrStr.substr(0, slashPos));
            in6_addr addr{};
            if (::inet_pton(AF_INET6, ipPart.c_str(), &addr) != 1)
            {
                return std::nullopt;
            }

            uint8_t prefix = 128;
            if (slashPos != std::string_view::npos)
            {
                std::string_view prefixPart = cidrStr.substr(slashPos + 1);
                if (prefixPart.empty())
                    return std::nullopt;
                uint32_t val = 0;
                for (char c : prefixPart)
                {
                    if (c < '0' || c > '9')
                        return std::nullopt;
                    val = val * 10 + static_cast<uint32_t>(c - '0');
                    if (val > 128)
                        return std::nullopt;
                }
                prefix = static_cast<uint8_t>(val);
            }

            return Ip6Cidr{addr, prefix};
        }
    };

    /**
     * @brief 6字节 IEEE 802.3 以太网 MAC 地址抽象 (Single Source of Truth)
     */
    struct MacAddress
    {
        uint8_t bytes[6]{0};

        static std::optional<MacAddress> parse(std::string_view str) noexcept
        {
            if (str.size() != 17)
                return std::nullopt;
            MacAddress mac{};
            for (size_t i = 0; i < 6; ++i)
            {
                size_t offset = i * 3;
                if (i < 5 && str[offset + 2] != ':' && str[offset + 2] != '-')
                {
                    return std::nullopt;
                }
                int hi = encoding::hexCharToNibble(str[offset]);
                int lo = encoding::hexCharToNibble(str[offset + 1]);
                if (hi < 0 || lo < 0)
                    return std::nullopt;
                mac.bytes[i] = static_cast<uint8_t>((hi << 4) | lo);
            }
            return mac;
        }

        [[nodiscard]] std::string toString() const
        {
            char buf[18];
            std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", bytes[0], bytes[1], bytes[2], bytes[3],
                          bytes[4], bytes[5]);
            return std::string(buf);
        }

        constexpr bool operator==(const MacAddress &other) const noexcept
        {
            for (size_t i = 0; i < 6; ++i)
            {
                if (bytes[i] != other.bytes[i])
                    return false;
            }
            return true;
        }

        [[nodiscard]] constexpr bool isZero() const noexcept
        {
            for (size_t i = 0; i < 6; ++i)
            {
                if (bytes[i] != 0)
                    return false;
            }
            return true;
        }
    };

    /**
     * @brief 目标地址类型定义（与 RFC 1928 SOCKS5 规范 ATYP 字节一致）
     */
    enum class AddressType : uint8_t
    {
        IPV4 = 0x01,
        DOMAIN = 0x03,
        IPV6 = 0x04
    };

    /**
     * @brief 代理通用目标网络地址
     *
     * 支持表示 IPv4、IPv6 与域名地址，并提供与 RFC 1928 兼容的二进制反序列化与序列化。
     */
    class ProxyAddress
    {
    public:
        AddressType type{AddressType::IPV4};
        std::string host{};
        uint16_t port{0};

        in_addr ipv4_{};
        in6_addr ipv6_{};

        ProxyAddress() noexcept
        {
            std::memset(&ipv4_, 0, sizeof(ipv4_));
            std::memset(&ipv6_, 0, sizeof(ipv6_));
        }

        /**
         * @brief 从 IPv4 二进制网络字节序构造
         */
        static ProxyAddress fromIPv4(uint32_t be32, uint16_t port) noexcept
        {
            ProxyAddress addr;
            addr.type = AddressType::IPV4;
            addr.ipv4_.s_addr = be32;
            addr.port = port;

            char buf[INET_ADDRSTRLEN]{};
            if (::inet_ntop(AF_INET, &addr.ipv4_, buf, sizeof(buf)) != nullptr)
            {
                addr.host = buf;
            }
            return addr;
        }

        /**
         * @brief 从 IPv4 文本和端口构造
         */
        static std::optional<ProxyAddress> fromIPv4String(std::string_view ipStr, uint16_t port) noexcept
        {
            ProxyAddress addr;
            addr.type = AddressType::IPV4;
            addr.port = port;
            std::string tmp(ipStr);
            if (::inet_pton(AF_INET, tmp.c_str(), &addr.ipv4_) != 1)
            {
                return std::nullopt;
            }
            addr.host = tmp;
            return addr;
        }

        /**
         * @brief 从域名与端口构造
         */
        static ProxyAddress fromDomain(std::string_view domain, uint16_t port)
        {
            ProxyAddress addr;
            addr.type = AddressType::DOMAIN;
            addr.host = domain;
            addr.port = port;
            return addr;
        }

        /**
         * @brief 从 IPv6 16字节网络字节序构造
         */
        static ProxyAddress fromIPv6(const uint8_t *be128, uint16_t port) noexcept
        {
            ProxyAddress addr;
            addr.type = AddressType::IPV6;
            std::memcpy(&addr.ipv6_, be128, 16);
            addr.port = port;

            char buf[INET6_ADDRSTRLEN]{};
            if (::inet_ntop(AF_INET6, &addr.ipv6_, buf, sizeof(buf)) != nullptr)
            {
                addr.host = buf;
            }
            return addr;
        }

        /**
         * @brief 从 RFC 1928 SOCKS5 二进制字节流解析目标地址
         *
         * 格式：
         * - IPv4: [0x01 (1B)][IPv4 (4B)][Port (2B BE)] -> 总计 7 字节
         * - 域名: [0x03 (1B)][Len (1B)][Domain (Len B)][Port (2B BE)] -> 总计 1+1+Len+2 字节
         * - IPv6: [0x04 (1B)][IPv6 (16B)][Port (2B BE)] -> 总计 19 字节
         *
         * @param bytes 待解析的二进制缓冲区切片
         * @param consumed 成功时回填实际消费的字节数
         * @return std::optional<ProxyAddress> 成功返回地址，缓冲区不足或非法返回 nullopt
         */
        static std::optional<ProxyAddress> decodeSocks5(std::span<const uint8_t> bytes, size_t &consumed)
        {
            if (bytes.empty())
            {
                return std::nullopt;
            }

            const uint8_t atyp = bytes[0];
            switch (atyp)
            {
            case static_cast<uint8_t>(AddressType::IPV4):
            {
                constexpr size_t kTotalLen = 1 + 4 + 2;
                if (bytes.size() < kTotalLen)
                {
                    return std::nullopt;
                }
                uint32_t ipBe = 0;
                std::memcpy(&ipBe, bytes.data() + 1, 4);
                const uint16_t port = (static_cast<uint16_t>(bytes[5]) << 8) | static_cast<uint16_t>(bytes[6]);
                consumed = kTotalLen;
                return fromIPv4(ipBe, port);
            }
            case static_cast<uint8_t>(AddressType::DOMAIN):
            {
                if (bytes.size() < 2)
                {
                    return std::nullopt;
                }
                const uint8_t domainLen = bytes[1];
                const size_t kTotalLen = 1 + 1 + domainLen + 2;
                if (bytes.size() < kTotalLen)
                {
                    return std::nullopt;
                }
                std::string_view domain(reinterpret_cast<const char *>(bytes.data() + 2), domainLen);
                const size_t portOffset = 1 + 1 + domainLen;
                const uint16_t port =
                    (static_cast<uint16_t>(bytes[portOffset]) << 8) | static_cast<uint16_t>(bytes[portOffset + 1]);
                consumed = kTotalLen;
                return fromDomain(domain, port);
            }
            case static_cast<uint8_t>(AddressType::IPV6):
            {
                constexpr size_t kTotalLen = 1 + 16 + 2;
                if (bytes.size() < kTotalLen)
                {
                    return std::nullopt;
                }
                const uint16_t port = (static_cast<uint16_t>(bytes[17]) << 8) | static_cast<uint16_t>(bytes[18]);
                consumed = kTotalLen;
                return fromIPv6(bytes.data() + 1, port);
            }
            default:
                return std::nullopt;
            }
        }

        /**
         * @brief 编码为 SOCKS5 二进制字节格式（供响应或外发代理使用）
         */
        void encodeSocks5(std::vector<uint8_t> &out) const
        {
            out.push_back(static_cast<uint8_t>(type));
            switch (type)
            {
            case AddressType::IPV4:
            {
                const auto *p = reinterpret_cast<const uint8_t *>(&ipv4_.s_addr);
                out.insert(out.end(), p, p + 4);
                break;
            }
            case AddressType::DOMAIN:
            {
                const uint8_t len = static_cast<uint8_t>(std::min<size_t>(host.size(), 255));
                out.push_back(len);
                out.insert(out.end(), host.begin(), host.begin() + len);
                break;
            }
            case AddressType::IPV6:
            {
                const auto *p = reinterpret_cast<const uint8_t *>(&ipv6_);
                out.insert(out.end(), p, p + 16);
                break;
            }
            }
            out.push_back(static_cast<uint8_t>((port >> 8) & 0xFF));
            out.push_back(static_cast<uint8_t>(port & 0xFF));
        }

        /**
         * @brief 转换为易读字符串形式（如 "127.0.0.1:8080" 或 "example.com:443"）
         */
        [[nodiscard]] std::string toString() const
        {
            if (type == AddressType::IPV6)
            {
                return "[" + host + "]:" + std::to_string(port);
            }
            return host + ":" + std::to_string(port);
        }

        /**
         * @brief 转换为 Linux sockaddr_in（仅当地址类型为 IPv4 时有效）
         */
        [[nodiscard]] std::optional<sockaddr_in> toSockAddrIn() const noexcept
        {
            if (type != AddressType::IPV4 || ipv4_.s_addr == 0)
            {
                return std::nullopt;
            }
            sockaddr_in sin{};
            sin.sin_family = AF_INET;
            sin.sin_addr = ipv4_;
            sin.sin_port = ::htons(port);
            return sin;
        }

        /**
         * @brief 从主机名/IP字符串与端口自适应构造
         */
        static ProxyAddress fromHostPort(std::string_view hostStr, uint16_t port)
        {
            if (hostStr.empty())
            {
                return fromDomain("", port);
            }

            // 尝试 IPv4
            if (auto ipv4 = fromIPv4String(hostStr, port); ipv4.has_value())
            {
                return *ipv4;
            }

            // 尝试 IPv6
            std::string tmp(hostStr);
            if (!tmp.empty() && tmp.front() == '[' && tmp.back() == ']')
            {
                tmp = tmp.substr(1, tmp.size() - 2);
            }
            in6_addr sin6{};
            if (::inet_pton(AF_INET6, tmp.c_str(), &sin6) == 1)
            {
                return fromIPv6(reinterpret_cast<const uint8_t *>(&sin6), port);
            }

            // 默认为域名
            return fromDomain(hostStr, port);
        }

        /**
         * @brief 解析 VLESS 格式目标地址
         *
         * VLESS 规范：Port (2B BE) 先行，后接 ATYP 与对应地址字节：
         * - 0x01: IPv4 (4B)
         * - 0x02: 域名 (1B 长度 + 域名字符)
         * - 0x03: IPv6 (16B)
         *
         * @param atyp 地址类型字节
         * @param bytes 待解析切片（从地址内容开始）
         * @param port 预先解析到的端口
         * @param consumed 成功时回填地址占用的字节数
         */
        static std::optional<ProxyAddress> decodeVlessAddress(uint8_t atyp, std::span<const uint8_t> bytes,
                                                              uint16_t port, size_t &consumed)
        {
            switch (atyp)
            {
            case 0x01: // IPv4
            {
                if (bytes.size() < 4)
                {
                    return std::nullopt;
                }
                uint32_t ipBe = 0;
                std::memcpy(&ipBe, bytes.data(), 4);
                consumed = 4;
                return fromIPv4(ipBe, port);
            }
            case 0x02: // Domain
            {
                if (bytes.size() < 1)
                {
                    return std::nullopt;
                }
                const uint8_t domainLen = bytes[0];
                if (bytes.size() < 1 + static_cast<size_t>(domainLen))
                {
                    return std::nullopt;
                }
                std::string_view domain(reinterpret_cast<const char *>(bytes.data() + 1), domainLen);
                consumed = 1 + domainLen;
                return fromDomain(domain, port);
            }
            case 0x03: // IPv6
            {
                if (bytes.size() < 16)
                {
                    return std::nullopt;
                }
                consumed = 16;
                return fromIPv6(bytes.data(), port);
            }
            default:
                return std::nullopt;
            }
        }

        /**
         * @brief 编码为 VLESS / VMess 格式目标地址：[Port 2B BE][ATYP 1B (0x01/0x02/0x03)][Address]
         */
        void encodeVless(std::vector<uint8_t> &out) const
        {
            out.push_back(static_cast<uint8_t>((port >> 8) & 0xFF));
            out.push_back(static_cast<uint8_t>(port & 0xFF));
            switch (type)
            {
            case AddressType::IPV4:
            {
                out.push_back(0x01);
                const auto *p = reinterpret_cast<const uint8_t *>(&ipv4_.s_addr);
                out.insert(out.end(), p, p + 4);
                break;
            }
            case AddressType::DOMAIN:
            {
                out.push_back(0x02);
                const uint8_t len = static_cast<uint8_t>(std::min<size_t>(host.size(), 255));
                out.push_back(len);
                out.insert(out.end(), host.begin(), host.begin() + len);
                break;
            }
            case AddressType::IPV6:
            {
                out.push_back(0x03);
                const auto *p = reinterpret_cast<const uint8_t *>(&ipv6_);
                out.insert(out.end(), p, p + 16);
                break;
            }
            }
        }

        /**
         * @brief 从 UoT 格式二进制解析目标地址：[ATYP (0x00=IPv4, 0x01=IPv6, 0x02=Domain)][Addr][Port 2B BE]
         */
        static std::optional<ProxyAddress> decodeUot(std::span<const uint8_t> bytes, size_t &consumed)
        {
            if (bytes.empty())
            {
                return std::nullopt;
            }
            const uint8_t atyp = bytes[0];
            switch (atyp)
            {
            case 0x00: // IPv4
            {
                constexpr size_t kLen = 1 + 4 + 2;
                if (bytes.size() < kLen)
                {
                    return std::nullopt;
                }
                uint32_t ipBe = 0;
                std::memcpy(&ipBe, bytes.data() + 1, 4);
                const uint16_t p = (static_cast<uint16_t>(bytes[5]) << 8) | bytes[6];
                consumed = kLen;
                return fromIPv4(ipBe, p);
            }
            case 0x01: // IPv6
            {
                constexpr size_t kLen = 1 + 16 + 2;
                if (bytes.size() < kLen)
                {
                    return std::nullopt;
                }
                const uint16_t p = (static_cast<uint16_t>(bytes[17]) << 8) | bytes[18];
                consumed = kLen;
                return fromIPv6(bytes.data() + 1, p);
            }
            case 0x02: // Domain
            {
                if (bytes.size() < 2)
                {
                    return std::nullopt;
                }
                const uint8_t domainLen = bytes[1];
                const size_t kLen = 1 + 1 + domainLen + 2;
                if (bytes.size() < kLen)
                {
                    return std::nullopt;
                }
                std::string_view domain(reinterpret_cast<const char *>(bytes.data() + 2), domainLen);
                const size_t pOff = 2 + domainLen;
                const uint16_t p = (static_cast<uint16_t>(bytes[pOff]) << 8) | bytes[pOff + 1];
                consumed = kLen;
                return fromDomain(domain, p);
            }
            default:
                return std::nullopt;
            }
        }

        /**
         * @brief 编码为 UoT 地址格式：[ATYP 1B][Addr][Port 2B BE]
         */
        void encodeUot(std::vector<uint8_t> &out) const
        {
            switch (type)
            {
            case AddressType::IPV4:
            {
                out.push_back(0x00);
                const auto *p = reinterpret_cast<const uint8_t *>(&ipv4_.s_addr);
                out.insert(out.end(), p, p + 4);
                break;
            }
            case AddressType::IPV6:
            {
                out.push_back(0x01);
                const auto *p = reinterpret_cast<const uint8_t *>(&ipv6_);
                out.insert(out.end(), p, p + 16);
                break;
            }
            case AddressType::DOMAIN:
            {
                out.push_back(0x02);
                const uint8_t len = static_cast<uint8_t>(std::min<size_t>(host.size(), 255));
                out.push_back(len);
                out.insert(out.end(), host.begin(), host.begin() + len);
                break;
            }
            }
            out.push_back(static_cast<uint8_t>((port >> 8) & 0xFF));
            out.push_back(static_cast<uint8_t>(port & 0xFF));
        }

        /**
         * @brief 从已连接套接字提取透明代理原始目的地址 (Linux Netfilter SO_ORIGINAL_DST)
         *
         * @param fd 套接字描述符
         * @return std::optional<ProxyAddress> 提取成功返回目的地址，未重定向或失败返回 nullopt
         */
        static std::optional<ProxyAddress> fromOriginalDst(int fd) noexcept
        {
            if (fd < 0)
            {
                return std::nullopt;
            }

            sockaddr_in sin{};
            socklen_t slen = sizeof(sin);
            if (::getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, &sin, &slen) == 0 && sin.sin_family == AF_INET)
            {
                const uint16_t port = ntohs(sin.sin_port);
                return fromIPv4(sin.sin_addr.s_addr, port);
            }

            sockaddr_in6 sin6{};
            socklen_t slen6 = sizeof(sin6);
            if (::getsockopt(fd, SOL_IPV6, IP6T_SO_ORIGINAL_DST, &sin6, &slen6) == 0 && sin6.sin6_family == AF_INET6)
            {
                const uint16_t port = ntohs(sin6.sin6_port);
                return fromIPv6(reinterpret_cast<const uint8_t *>(&sin6.sin6_addr), port);
            }

            return std::nullopt;
        }

        /**
         * @brief 从已连接套接字提取 Linux TProxy 原始目的地址 (getsockname 或 SO_ORIGINAL_DST 回落)
         */
        static std::optional<ProxyAddress> fromTProxyDst(int fd) noexcept
        {
            if (fd < 0)
            {
                return std::nullopt;
            }

            sockaddr_storage ss{};
            socklen_t slen = sizeof(ss);
            if (::getsockname(fd, reinterpret_cast<sockaddr *>(&ss), &slen) == 0)
            {
                if (ss.ss_family == AF_INET)
                {
                    const auto *sin = reinterpret_cast<const sockaddr_in *>(&ss);
                    if (sin->sin_addr.s_addr != INADDR_ANY)
                    {
                        return fromIPv4(sin->sin_addr.s_addr, ntohs(sin->sin_port));
                    }
                }
                else if (ss.ss_family == AF_INET6)
                {
                    const auto *sin6 = reinterpret_cast<const sockaddr_in6 *>(&ss);
                    if (!IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr))
                    {
                        return fromIPv6(reinterpret_cast<const uint8_t *>(&sin6->sin6_addr), ntohs(sin6->sin6_port));
                    }
                }
            }

            return fromOriginalDst(fd);
        }
    };

} // namespace mynet::handler

namespace mynet
{
    using MacAddress = handler::MacAddress;
    using ProxyAddress = handler::ProxyAddress;

    /**
     * @brief 格式化 IPv4 对端套接字地址文本 ("192.0.2.7:5353")
     *
     * @param peer 对端 sockaddr_in 地址结构
     * @return std::string 人类可读地址字符串
     */
    [[nodiscard]] inline std::string datagramPeerText(const sockaddr_in &peer)
    {
        char host[INET_ADDRSTRLEN] = {};
        if (::inet_ntop(AF_INET, &peer.sin_addr, host, sizeof host) == nullptr) [[unlikely]]
        {
            return std::string("<unnamed>:") + std::to_string(::ntohs(peer.sin_port));
        }
        return std::string(host) + ":" + std::to_string(::ntohs(peer.sin_port));
    }
} // namespace mynet

namespace mynet::handler
{
    using mynet::datagramPeerText;
} // namespace mynet::handler
