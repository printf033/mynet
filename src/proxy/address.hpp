#pragma once

/**
 * @file proxy/address.hpp
 * @brief 通用代理目标网络地址抽象，兼容 SOCKS5 / Trojan / VLESS 规范。
 */

#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <netinet/in.h>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mynet::proxy
{

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
    };

} // namespace mynet::proxy
