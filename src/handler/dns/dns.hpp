#pragma once

/**
 * @file handler/dns/dns.hpp
 * @brief RFC 1035 / RFC 3596 DNS 协议报文编解码器与数据结构
 *
 * 满足零异常 (-fno-exceptions)，支持标准 DNS 查询构建、响应解包、
 * 指针压缩解算 (0xC0xx)、A/AAAA/CNAME 解析以及通用 DNS 消息结构抽象。
 */

#include "error.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mynet::handler::dns
{
    // =========================================================================
    // 常量定义
    // =========================================================================
    inline constexpr uint16_t kTypeA = 1;       ///< IPv4 地址
    inline constexpr uint16_t kTypeNS = 2;      ///< 权威域名服务器
    inline constexpr uint16_t kTypeCNAME = 5;   ///< 规范名称
    inline constexpr uint16_t kTypeSOA = 6;     ///< 起始授权机构
    inline constexpr uint16_t kTypePTR = 12;    ///< 指针记录
    inline constexpr uint16_t kTypeMX = 15;     ///< 邮件交换
    inline constexpr uint16_t kTypeTXT = 16;    ///< 文本记录
    inline constexpr uint16_t kTypeAAAA = 28;   ///< IPv6 地址
    inline constexpr uint16_t kTypeANY = 255;   ///< 通配查询

    inline constexpr uint16_t kClassIN = 1;     ///< 互联网类别 (Internet)
    inline constexpr uint16_t kDefaultPort = 53;

    namespace rcode
    {
        inline constexpr uint8_t NOERROR = 0;   ///< 成功
        inline constexpr uint8_t FORMERR = 1;   ///< 格式错误
        inline constexpr uint8_t SERVFAIL = 2;  ///< 服务器失败
        inline constexpr uint8_t NXDOMAIN = 3;  ///< 域名不存在
        inline constexpr uint8_t NOTIMP = 4;    ///< 功能不支持
        inline constexpr uint8_t REFUSED = 5;   ///< 拒绝查询
    } // namespace rcode

    // =========================================================================
    // DNS 报文头部结构 (12 字节固定长度)
    // =========================================================================
    struct DnsHeader
    {
        uint16_t id{0};
        uint16_t flags{0x0100}; // 默认标准递归查询 (RD=1)
        uint16_t qdcount{0};
        uint16_t ancount{0};
        uint16_t nscount{0};
        uint16_t arcount{0};

        [[nodiscard]] bool isResponse() const noexcept { return (flags & 0x8000) != 0; }
        void setResponse(bool v) noexcept
        {
            if (v) flags |= 0x8000;
            else flags &= ~0x8000;
        }

        [[nodiscard]] uint8_t opcode() const noexcept { return static_cast<uint8_t>((flags >> 11) & 0x0F); }
        void setOpcode(uint8_t op) noexcept { flags = static_cast<uint16_t>((flags & ~0x7800) | ((op & 0x0F) << 11)); }

        [[nodiscard]] bool authoritative() const noexcept { return (flags & 0x0400) != 0; }
        void setAuthoritative(bool v) noexcept
        {
            if (v) flags |= 0x0400;
            else flags &= ~0x0400;
        }

        [[nodiscard]] bool truncated() const noexcept { return (flags & 0x0200) != 0; }
        void setTruncated(bool v) noexcept
        {
            if (v) flags |= 0x0200;
            else flags &= ~0x0200;
        }

        [[nodiscard]] bool recursionDesired() const noexcept { return (flags & 0x0100) != 0; }
        void setRecursionDesired(bool v) noexcept
        {
            if (v) flags |= 0x0100;
            else flags &= ~0x0100;
        }

        [[nodiscard]] bool recursionAvailable() const noexcept { return (flags & 0x0080) != 0; }
        void setRecursionAvailable(bool v) noexcept
        {
            if (v) flags |= 0x0080;
            else flags &= ~0x0080;
        }

        [[nodiscard]] uint8_t rcode() const noexcept { return static_cast<uint8_t>(flags & 0x0F); }
        void setRcode(uint8_t code) noexcept { flags = static_cast<uint16_t>((flags & ~0x0F) | (code & 0x0F)); }
    };

    // =========================================================================
    // DNS 查询段 (Question)
    // =========================================================================
    struct DnsQuestion
    {
        std::string qname{};
        uint16_t qtype{kTypeA};
        uint16_t qclass{kClassIN};
    };

    // =========================================================================
    // DNS 资源记录 (Resource Record)
    // =========================================================================
    struct DnsRecord
    {
        std::string name{};
        uint16_t type{kTypeA};
        uint16_t rclass{kClassIN};
        uint32_t ttl{300};
        std::vector<uint8_t> rdata{};

        static DnsRecord createA(std::string name, in_addr ip, uint32_t ttl = 300)
        {
            DnsRecord rec;
            rec.name = std::move(name);
            rec.type = kTypeA;
            rec.rclass = kClassIN;
            rec.ttl = ttl;
            rec.rdata.resize(4);
            std::memcpy(rec.rdata.data(), &ip.s_addr, 4);
            return rec;
        }

        static DnsRecord createAAAA(std::string name, in6_addr ip6, uint32_t ttl = 300)
        {
            DnsRecord rec;
            rec.name = std::move(name);
            rec.type = kTypeAAAA;
            rec.rclass = kClassIN;
            rec.ttl = ttl;
            rec.rdata.resize(16);
            std::memcpy(rec.rdata.data(), &ip6, 16);
            return rec;
        }

        [[nodiscard]] std::optional<in_addr> asIpv4() const noexcept
        {
            if (type == kTypeA && rdata.size() == 4)
            {
                in_addr addr{};
                std::memcpy(&addr.s_addr, rdata.data(), 4);
                return addr;
            }
            return std::nullopt;
        }

        [[nodiscard]] std::optional<in6_addr> asIpv6() const noexcept
        {
            if (type == kTypeAAAA && rdata.size() == 16)
            {
                in6_addr addr{};
                std::memcpy(&addr, rdata.data(), 16);
                return addr;
            }
            return std::nullopt;
        }

        [[nodiscard]] std::string ipString() const
        {
            if (auto v4 = asIpv4(); v4.has_value())
            {
                char buf[INET_ADDRSTRLEN]{};
                ::inet_ntop(AF_INET, &v4->s_addr, buf, sizeof(buf));
                return buf;
            }
            if (auto v6 = asIpv6(); v6.has_value())
            {
                char buf[INET6_ADDRSTRLEN]{};
                ::inet_ntop(AF_INET6, &*v6, buf, sizeof(buf));
                return buf;
            }
            return {};
        }
    };

    // =========================================================================
    // 基础编解码辅助函数
    // =========================================================================

    /**
     * @brief 编码 QNAME 标签式域名（如 "example.com" -> 7example3com0）
     */
    inline void encodeDomainLabels(std::string_view domain, std::vector<uint8_t> &out)
    {
        size_t start = 0;
        while (start < domain.size())
        {
            size_t dot = domain.find('.', start);
            if (dot == std::string_view::npos)
            {
                dot = domain.size();
            }
            const size_t labelLen = dot - start;
            if (labelLen > 0 && labelLen <= 63)
            {
                out.push_back(static_cast<uint8_t>(labelLen));
                for (size_t i = start; i < dot; ++i)
                {
                    out.push_back(static_cast<uint8_t>(domain[i]));
                }
            }
            start = dot + 1;
        }
        out.push_back(0x00); // 终止空标签
    }

    /**
     * @brief 解码 QNAME 标签（支持 0xC0xx 指针压缩与跳转深度限制）
     */
    inline bool decodeDomainLabels(std::span<const uint8_t> packet, size_t &offset, std::string &outDomain)
    {
        outDomain.clear();
        size_t curr = offset;
        bool jumped = false;
        size_t jumpCount = 0;
        static constexpr size_t kMaxJumps = 16;

        while (curr < packet.size())
        {
            const uint8_t len = packet[curr++];
            if (len == 0)
            {
                break;
            }
            if ((len & 0xC0) == 0xC0)
            {
                if (curr >= packet.size())
                {
                    return false;
                }
                const uint16_t ptr = ((static_cast<uint16_t>(len & 0x3F) << 8) | packet[curr++]);
                if (ptr >= packet.size() || ++jumpCount > kMaxJumps)
                {
                    return false; // 非法指针或环路
                }
                if (!jumped)
                {
                    offset = curr;
                    jumped = true;
                }
                curr = ptr;
                continue;
            }

            if (curr + len > packet.size())
            {
                return false;
            }

            if (!outDomain.empty())
            {
                outDomain.push_back('.');
            }
            outDomain.append(reinterpret_cast<const char *>(packet.data() + curr), len);
            curr += len;
        }

        if (!jumped)
        {
            offset = curr;
        }
        return true;
    }

    // =========================================================================
    // 完整 DNS 报文模型 (DnsMessage)
    // =========================================================================
    struct DnsMessage
    {
        DnsHeader header{};
        std::vector<DnsQuestion> questions{};
        std::vector<DnsRecord> answers{};
        std::vector<DnsRecord> authorities{};
        std::vector<DnsRecord> additionals{};

        /**
         * @brief 序列化 DNS 报文为网络二进制切片
         */
        [[nodiscard]] std::vector<uint8_t> encode() const
        {
            std::vector<uint8_t> buf;
            buf.reserve(512);

            // 1. Header (12 字节)
            buf.push_back(static_cast<uint8_t>(header.id >> 8));
            buf.push_back(static_cast<uint8_t>(header.id & 0xFF));
            buf.push_back(static_cast<uint8_t>(header.flags >> 8));
            buf.push_back(static_cast<uint8_t>(header.flags & 0xFF));
            buf.push_back(static_cast<uint8_t>(questions.size() >> 8));
            buf.push_back(static_cast<uint8_t>(questions.size() & 0xFF));
            buf.push_back(static_cast<uint8_t>(answers.size() >> 8));
            buf.push_back(static_cast<uint8_t>(answers.size() & 0xFF));
            buf.push_back(static_cast<uint8_t>(authorities.size() >> 8));
            buf.push_back(static_cast<uint8_t>(authorities.size() & 0xFF));
            buf.push_back(static_cast<uint8_t>(additionals.size() >> 8));
            buf.push_back(static_cast<uint8_t>(additionals.size() & 0xFF));

            // 2. Questions
            for (const auto &q : questions)
            {
                encodeDomainLabels(q.qname, buf);
                buf.push_back(static_cast<uint8_t>(q.qtype >> 8));
                buf.push_back(static_cast<uint8_t>(q.qtype & 0xFF));
                buf.push_back(static_cast<uint8_t>(q.qclass >> 8));
                buf.push_back(static_cast<uint8_t>(q.qclass & 0xFF));
            }

            // 3. Answers
            auto encodeRecords = [&buf](const std::vector<DnsRecord> &records) {
                for (const auto &r : records)
                {
                    encodeDomainLabels(r.name, buf);
                    buf.push_back(static_cast<uint8_t>(r.type >> 8));
                    buf.push_back(static_cast<uint8_t>(r.type & 0xFF));
                    buf.push_back(static_cast<uint8_t>(r.rclass >> 8));
                    buf.push_back(static_cast<uint8_t>(r.rclass & 0xFF));
                    buf.push_back(static_cast<uint8_t>(r.ttl >> 24));
                    buf.push_back(static_cast<uint8_t>(r.ttl >> 16));
                    buf.push_back(static_cast<uint8_t>(r.ttl >> 8));
                    buf.push_back(static_cast<uint8_t>(r.ttl & 0xFF));
                    buf.push_back(static_cast<uint8_t>(r.rdata.size() >> 8));
                    buf.push_back(static_cast<uint8_t>(r.rdata.size() & 0xFF));
                    buf.insert(buf.end(), r.rdata.begin(), r.rdata.end());
                }
            };

            encodeRecords(answers);
            encodeRecords(authorities);
            encodeRecords(additionals);

            return buf;
        }

        /**
         * @brief 反序列化解析二进制切片为 DnsMessage
         */
        static std::optional<DnsMessage> decode(std::span<const uint8_t> data)
        {
            if (data.size() < 12)
            {
                return std::nullopt;
            }

            DnsMessage msg;
            msg.header.id = (static_cast<uint16_t>(data[0]) << 8) | data[1];
            msg.header.flags = (static_cast<uint16_t>(data[2]) << 8) | data[3];
            msg.header.qdcount = (static_cast<uint16_t>(data[4]) << 8) | data[5];
            msg.header.ancount = (static_cast<uint16_t>(data[6]) << 8) | data[7];
            msg.header.nscount = (static_cast<uint16_t>(data[8]) << 8) | data[9];
            msg.header.arcount = (static_cast<uint16_t>(data[10]) << 8) | data[11];

            size_t offset = 12;

            // 1. Questions
            for (uint16_t i = 0; i < msg.header.qdcount; ++i)
            {
                DnsQuestion q;
                if (!decodeDomainLabels(data, offset, q.qname))
                {
                    return std::nullopt;
                }
                if (offset + 4 > data.size())
                {
                    return std::nullopt;
                }
                q.qtype = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
                q.qclass = (static_cast<uint16_t>(data[offset + 2]) << 8) | data[offset + 3];
                offset += 4;
                msg.questions.push_back(std::move(q));
            }

            // 2. Records 解析闭包
            auto decodeRecords = [&](uint16_t count, std::vector<DnsRecord> &records) -> bool {
                for (uint16_t i = 0; i < count; ++i)
                {
                    DnsRecord r;
                    if (!decodeDomainLabels(data, offset, r.name))
                    {
                        return false;
                    }
                    if (offset + 10 > data.size())
                    {
                        return false;
                    }
                    r.type = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
                    r.rclass = (static_cast<uint16_t>(data[offset + 2]) << 8) | data[offset + 3];
                    r.ttl = (static_cast<uint32_t>(data[offset + 4]) << 24) |
                            (static_cast<uint32_t>(data[offset + 5]) << 16) |
                            (static_cast<uint32_t>(data[offset + 6]) << 8) | data[offset + 7];
                    const uint16_t rdlen = (static_cast<uint16_t>(data[offset + 8]) << 8) | data[offset + 9];
                    offset += 10;

                    if (offset + rdlen > data.size())
                    {
                        return false;
                    }
                    r.rdata.assign(data.begin() + static_cast<ptrdiff_t>(offset),
                                   data.begin() + static_cast<ptrdiff_t>(offset + rdlen));
                    offset += rdlen;
                    records.push_back(std::move(r));
                }
                return true;
            };

            if (!decodeRecords(msg.header.ancount, msg.answers) ||
                !decodeRecords(msg.header.nscount, msg.authorities) ||
                !decodeRecords(msg.header.arcount, msg.additionals))
            {
                return std::nullopt;
            }

            return msg;
        }

        /**
         * @brief 快速创建针对本查询的响应消息模板
         */
        [[nodiscard]] DnsMessage makeResponse(uint8_t rcode = rcode::NOERROR) const
        {
            DnsMessage resp;
            resp.header.id = header.id;
            resp.header.flags = 0;
            resp.header.setResponse(true);
            resp.header.setRecursionDesired(header.recursionDesired());
            resp.header.setRecursionAvailable(true);
            resp.header.setRcode(rcode);
            resp.questions = questions;
            return resp;
        }
    };

    // =========================================================================
    // 兼容与便捷全局函数 (RFC 1035 Fast Codec)
    // =========================================================================

    /**
     * @brief 快速编码单个域名查询包
     */
    inline std::vector<uint8_t> encodeQuery(std::string_view domain, uint16_t qtype = kTypeA,
                                            uint16_t txid = 0x1234)
    {
        DnsMessage msg;
        msg.header.id = txid;
        msg.header.setRecursionDesired(true);
        msg.questions.push_back(DnsQuestion{
            .qname = std::string(domain),
            .qtype = qtype,
            .qclass = kClassIN,
        });
        return msg.encode();
    }

    /**
     * @brief 快速解码响应报文中的 A / AAAA 记录与最小 TTL
     */
    inline bool decodeResponse(std::span<const uint8_t> buffer, std::vector<in_addr> &outIpv4,
                               std::vector<in6_addr> &outIpv6, uint32_t &outTtl)
    {
        auto msg = DnsMessage::decode(buffer);
        if (!msg.has_value() || msg->header.rcode() != rcode::NOERROR)
        {
            return false;
        }

        outTtl = 3600;
        for (const auto &ans : msg->answers)
        {
            if (ans.ttl > 0 && ans.ttl < outTtl)
            {
                outTtl = ans.ttl;
            }
            if (auto v4 = ans.asIpv4(); v4.has_value())
            {
                outIpv4.push_back(*v4);
            }
            else if (auto v6 = ans.asIpv6(); v6.has_value())
            {
                outIpv6.push_back(*v6);
            }
        }
        return !outIpv4.empty() || !outIpv6.empty();
    }

} // namespace mynet::handler::dns
