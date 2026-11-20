#pragma once

/**
 * @file uot.hpp
 * @brief UoT (UDP over TCP) v1/v2 协议编解码与隧道封装引擎 (借鉴 sing-box common/uot)
 *
 * 核心设计原理：
 * 1. 突破 ISP 针对 UDP 的 QoS 劣化、高丢包、限速及阻断；
 * 2. 借助 TCP 高可靠流式通道、BBR 拥塞控制和连接复用能力承载 UDP 数据报；
 * 3. 采用特定魔法保留地址：
 *    - "sp.v2.udp-over-tcp.arpa" (UoT v2)
 *    - "sp.udp-over-tcp.arpa" (UoT v1)
 * 4. 模式：
 *    - Connected 模式 (单目标流式)：报文头仅 2 字节 uint16_t 长度，配合 writev 零拷贝发送；
 *    - Packet 模式 (多目标数据报)：报文头携带 [地址族 + IP/域名 + 端口 + 长度 + 载荷]。
 */

#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <netinet/in.h>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <vector>

namespace mynet::transport
{

    inline constexpr std::string_view UOT_V2_MAGIC_ADDRESS = "sp.v2.udp-over-tcp.arpa";
    inline constexpr std::string_view UOT_V1_MAGIC_ADDRESS = "sp.udp-over-tcp.arpa";

    enum class UotVersion : uint8_t
    {
        V1 = 1,
        V2 = 2
    };

    enum class UotAddressType : uint8_t
    {
        IPV4 = 0x00,
        IPV6 = 0x01,
        FQDN = 0x02
    };

    struct UotEndpoint
    {
        UotAddressType type{UotAddressType::IPV4};
        uint32_t ipv4{0}; ///< 主机字节序
        uint8_t ipv6[16]{};
        std::string domain{};
        uint16_t port{0}; ///< 主机字节序

        [[nodiscard]] bool isIpv4() const noexcept { return type == UotAddressType::IPV4; }
        [[nodiscard]] bool isIpv6() const noexcept { return type == UotAddressType::IPV6; }
        [[nodiscard]] bool isDomain() const noexcept { return type == UotAddressType::FQDN; }
    };

    struct UotRequest
    {
        bool isConnect{true}; ///< 是否为绑定单一目标的连接模式
        UotEndpoint destination{};
    };

    class UotProtocol
    {
    public:
        /**
         * @brief 检查目标域名是否属于 UoT 隧道魔法握手地址
         */
        [[nodiscard]] static constexpr bool isUotMagicAddress(std::string_view fqdn) noexcept
        {
            return fqdn == UOT_V2_MAGIC_ADDRESS || fqdn == UOT_V1_MAGIC_ADDRESS;
        }

        /**
         * @brief 编码 UoT 请求头 (握手阶段)
         */
        [[nodiscard]] static std::vector<uint8_t> encodeRequest(const UotRequest &req) noexcept
        {
            std::vector<uint8_t> buf;
            buf.push_back(req.isConnect ? 0x01 : 0x00);

            // 写入目标地址族
            buf.push_back(static_cast<uint8_t>(req.destination.type));

            switch (req.destination.type)
            {
            case UotAddressType::IPV4:
            {
                buf.push_back(static_cast<uint8_t>((req.destination.ipv4 >> 24) & 0xFF));
                buf.push_back(static_cast<uint8_t>((req.destination.ipv4 >> 16) & 0xFF));
                buf.push_back(static_cast<uint8_t>((req.destination.ipv4 >> 8) & 0xFF));
                buf.push_back(static_cast<uint8_t>(req.destination.ipv4 & 0xFF));
                break;
            }
            case UotAddressType::IPV6:
            {
                buf.insert(buf.end(), req.destination.ipv6, req.destination.ipv6 + 16);
                break;
            }
            case UotAddressType::FQDN:
            {
                const uint8_t len = static_cast<uint8_t>(req.destination.domain.size());
                buf.push_back(len);
                buf.insert(buf.end(), req.destination.domain.begin(), req.destination.domain.end());
                break;
            }
            }

            // 写入端口 (2B Big-Endian)
            buf.push_back(static_cast<uint8_t>((req.destination.port >> 8) & 0xFF));
            buf.push_back(static_cast<uint8_t>(req.destination.port & 0xFF));

            return buf;
        }

        /**
         * @brief 解码 UoT 初始请求头
         */
        [[nodiscard]] static std::optional<std::pair<UotRequest, size_t>>
        decodeRequest(std::span<const uint8_t> data) noexcept
        {
            if (data.size() < 4)
                return std::nullopt;

            UotRequest req{};
            req.isConnect = (data[0] != 0);

            const uint8_t addrType = data[1];
            size_t offset = 2;

            if (addrType == static_cast<uint8_t>(UotAddressType::IPV4))
            {
                if (data.size() < offset + 4 + 2)
                    return std::nullopt;
                req.destination.type = UotAddressType::IPV4;
                req.destination.ipv4 =
                    (static_cast<uint32_t>(data[offset]) << 24) | (static_cast<uint32_t>(data[offset + 1]) << 16) |
                    (static_cast<uint32_t>(data[offset + 2]) << 8) | static_cast<uint32_t>(data[offset + 3]);
                offset += 4;
            }
            else if (addrType == static_cast<uint8_t>(UotAddressType::IPV6))
            {
                if (data.size() < offset + 16 + 2)
                    return std::nullopt;
                req.destination.type = UotAddressType::IPV6;
                std::memcpy(req.destination.ipv6, data.data() + offset, 16);
                offset += 16;
            }
            else if (addrType == static_cast<uint8_t>(UotAddressType::FQDN))
            {
                if (data.size() < offset + 1)
                    return std::nullopt;
                const uint8_t fqdnLen = data[offset++];
                if (data.size() < offset + fqdnLen + 2)
                    return std::nullopt;
                req.destination.type = UotAddressType::FQDN;
                req.destination.domain = std::string(reinterpret_cast<const char *>(data.data() + offset), fqdnLen);
                offset += fqdnLen;
            }
            else
            {
                return std::nullopt;
            }

            req.destination.port = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
            offset += 2;

            return std::make_pair(req, offset);
        }

        /**
         * @brief 构建 Connected 模式下的数据帧 (2 字节长度 + 载荷)
         */
        [[nodiscard]] static std::vector<uint8_t> encodeConnectedFrame(std::span<const uint8_t> payload) noexcept
        {
            if (payload.size() > 0xFFFF)
                return {};
            const size_t len = payload.size();
            std::vector<uint8_t> frame(2 + len);
            frame[0] = static_cast<uint8_t>((len >> 8) & 0xFF);
            frame[1] = static_cast<uint8_t>(len & 0xFF);
            if (len > 0)
            {
                std::memcpy(frame.data() + 2, payload.data(), len);
            }
            return frame;
        }

        /**
         * @brief 使用 writev 矢量化写入 Connected 模式数据帧 (免内存拷贝拼接)
         */
        static ssize_t writeVectorisedConnectedFrame(int tcpFd, std::span<const uint8_t> payload) noexcept
        {
            if (tcpFd < 0 || payload.size() > 0xFFFF)
                return -1;

            uint8_t header[2];
            const uint16_t len = static_cast<uint16_t>(payload.size());
            header[0] = static_cast<uint8_t>((len >> 8) & 0xFF);
            header[1] = static_cast<uint8_t>(len & 0xFF);

            struct iovec iov[2];
            iov[0].iov_base = header;
            iov[0].iov_len = sizeof(header);
            iov[1].iov_base = const_cast<uint8_t *>(payload.data());
            iov[1].iov_len = payload.size();

            return ::writev(tcpFd, iov, 2);
        }

        /**
         * @brief 解码 Connected 模式数据帧
         * @return std::pair<载荷span, 消耗的总字节数(含2字节头)>
         */
        [[nodiscard]] static std::optional<std::pair<std::span<const uint8_t>, size_t>>
        decodeConnectedFrame(std::span<const uint8_t> data) noexcept
        {
            if (data.size() < 2)
                return std::nullopt;

            const size_t payloadLen = (static_cast<size_t>(data[0]) << 8) | data[1];
            if (data.size() < 2 + payloadLen)
                return std::nullopt;

            return std::make_pair(data.subspan(2, payloadLen), 2 + payloadLen);
        }

        /**
         * @brief 编码 Packet 模式下的数据帧 (携带对端目的地址)
         */
        [[nodiscard]] static std::vector<uint8_t> encodePacketFrame(const UotEndpoint &endpoint,
                                                                    std::span<const uint8_t> payload) noexcept
        {
            if (payload.size() > 0xFFFF)
                return {};
            std::vector<uint8_t> frame;
            frame.push_back(static_cast<uint8_t>(endpoint.type));

            switch (endpoint.type)
            {
            case UotAddressType::IPV4:
            {
                frame.push_back(static_cast<uint8_t>((endpoint.ipv4 >> 24) & 0xFF));
                frame.push_back(static_cast<uint8_t>((endpoint.ipv4 >> 16) & 0xFF));
                frame.push_back(static_cast<uint8_t>((endpoint.ipv4 >> 8) & 0xFF));
                frame.push_back(static_cast<uint8_t>(endpoint.ipv4 & 0xFF));
                break;
            }
            case UotAddressType::IPV6:
            {
                frame.insert(frame.end(), endpoint.ipv6, endpoint.ipv6 + 16);
                break;
            }
            case UotAddressType::FQDN:
            {
                const uint8_t len = static_cast<uint8_t>(endpoint.domain.size());
                frame.push_back(len);
                frame.insert(frame.end(), endpoint.domain.begin(), endpoint.domain.end());
                break;
            }
            }

            frame.push_back(static_cast<uint8_t>((endpoint.port >> 8) & 0xFF));
            frame.push_back(static_cast<uint8_t>(endpoint.port & 0xFF));

            const uint16_t len = static_cast<uint16_t>(payload.size());
            frame.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
            frame.push_back(static_cast<uint8_t>(len & 0xFF));

            frame.insert(frame.end(), payload.begin(), payload.end());
            return frame;
        }

        /**
         * @brief 解码 Packet 模式数据帧
         */
        [[nodiscard]] static std::optional<std::pair<UotEndpoint, std::vector<uint8_t>>>
        decodePacketFrame(std::span<const uint8_t> data, size_t &outBytesConsumed) noexcept
        {
            if (data.size() < 5)
                return std::nullopt;

            UotEndpoint ep{};
            const uint8_t addrType = data[0];
            size_t offset = 1;

            if (addrType == static_cast<uint8_t>(UotAddressType::IPV4))
            {
                if (data.size() < offset + 4 + 2 + 2)
                    return std::nullopt;
                ep.type = UotAddressType::IPV4;
                ep.ipv4 = (static_cast<uint32_t>(data[offset]) << 24) |
                          (static_cast<uint32_t>(data[offset + 1]) << 16) |
                          (static_cast<uint32_t>(data[offset + 2]) << 8) | static_cast<uint32_t>(data[offset + 3]);
                offset += 4;
            }
            else if (addrType == static_cast<uint8_t>(UotAddressType::IPV6))
            {
                if (data.size() < offset + 16 + 2 + 2)
                    return std::nullopt;
                ep.type = UotAddressType::IPV6;
                std::memcpy(ep.ipv6, data.data() + offset, 16);
                offset += 16;
            }
            else if (addrType == static_cast<uint8_t>(UotAddressType::FQDN))
            {
                const uint8_t fqdnLen = data[offset++];
                if (data.size() < offset + fqdnLen + 2 + 2)
                    return std::nullopt;
                ep.type = UotAddressType::FQDN;
                ep.domain = std::string(reinterpret_cast<const char *>(data.data() + offset), fqdnLen);
                offset += fqdnLen;
            }
            else
            {
                return std::nullopt;
            }

            ep.port = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
            offset += 2;

            const size_t len = (static_cast<size_t>(data[offset]) << 8) | data[offset + 1];
            offset += 2;

            if (data.size() < offset + len)
                return std::nullopt;

            std::vector<uint8_t> payload(data.data() + offset, data.data() + offset + len);
            outBytesConsumed = offset + len;

            return std::make_pair(ep, std::move(payload));
        }
    };

} // namespace mynet::transport
