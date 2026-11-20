#pragma once

/**
 * @file spoof.hpp
 * @brief TCP Desync 与 TLS 伪装注入引擎 (借鉴 sing-box common/tlsspoof)
 *
 * 核心原理：
 * 骨干网 DPI 中间件通常工作在旁路嗅探或快速路径过滤模式。为了降低延迟，DPI 经常
 * 忽略 TCP 校验和检查、忽视 RFC 7323 PAWS 时间戳保护、或仅根据流首包放行连接。
 *
 * 本模块在真实 TLS ClientHello 发送前，通过原始套接字向目标四元组注入带有伪造 SNI 的报文：
 * 1. WRONG_CHECKSUM (反转校验和)：DPI 忽略校验和直接解析出伪造白名单 SNI，将流放行白名单缓存；
 *    真实服务端内核由于 TCP 校验和损坏静默丢弃该虚假报文。
 * 2. WRONG_SEQUENCE (过期序列号)：发送已确认的序列号。
 * 3. WRONG_ACK (窗口外确认号)：服务端检测到 ACK 错位而丢弃。
 * 4. WRONG_TIMESTAMP (时间戳回溯)：生成一个比当前时间戳大幅落后的 TS 选项，真实内核由于 PAWS 静默丢包。
 * 5. WRONG_MD5 (非法 MD5 签名选项)：触发内核 RFC 2385 签名校验失败丢弃。
 */

#include "../checksum.hpp"
#include <arpa/inet.h>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#ifndef TCP_REPAIR
#define TCP_REPAIR 19
#endif
#ifndef TCP_REPAIR_QUEUE
#define TCP_REPAIR_QUEUE 20
#endif
#ifndef TCP_QUEUE_SEQ
#define TCP_QUEUE_SEQ 21
#endif
#ifndef TCP_RECV_QUEUE
#define TCP_RECV_QUEUE 1
#endif
#ifndef TCP_SEND_QUEUE
#define TCP_SEND_QUEUE 2
#endif

namespace mynet::tls
{

    enum class SpoofMethod : uint8_t
    {
        WRONG_CHECKSUM = 0,  ///< 校验和反转 (DPI 旁路放行，服务端校验和错误丢弃)
        WRONG_SEQUENCE = 1,  ///< 过期序列号 (DPI 解析，服务端因过时包丢弃)
        WRONG_ACK = 2,       ///< 非法 ACK (服务端丢弃)
        WRONG_TIMESTAMP = 3, ///< PAWS 时间戳倒退 (服务端因 PAWS 机制静默丢弃)
        WRONG_MD5 = 4        ///< 注入非法 TCP MD5 签名 (RFC 2385)
    };

    struct TcpEndpoints
    {
        uint32_t srcIp{0};   ///< 主机字节序 IPv4
        uint16_t srcPort{0}; ///< 主机字节序
        uint32_t dstIp{0};   ///< 主机字节序 IPv4
        uint16_t dstPort{0}; ///< 主机字节序
    };

    struct SpoofPacketInfo
    {
        uint32_t seqNum{0};
        uint32_t ackNum{0};
        bool corruptChecksum{false};
        std::vector<uint8_t> tcpOptions{};
    };

    class TlsSpoofer
    {
    public:
        static constexpr uint8_t DEFAULT_TTL = 64;
        static constexpr uint16_t DEFAULT_WINDOW_SIZE = 0xFFFF;
        static constexpr uint32_t TIMESTAMP_BACKDATE = 3600000; // 倒退 1 小时

        /**
         * @brief 纯内存计算 IP/TCP 校验和 (复用 mynet::rfc1071Checksum 单一真实源)
         */
        [[nodiscard]] static uint16_t calculateChecksum(std::span<const uint8_t> data, uint32_t initialSum = 0) noexcept
        {
            return mynet::rfc1071Checksum(data, initialSum);
        }

        /**
         * @brief 构建 IPv4 伪首部并计算 TCP 报文校验和
         */
        [[nodiscard]] static uint16_t calculateTcpChecksum(uint32_t srcIp, uint32_t dstIp,
                                                           std::span<const uint8_t> tcpHeaderAndPayload) noexcept
        {
            uint32_t sum = 0;
            // 伪头部: 源IP (4B) + 目的IP (4B) + 零/协议号 (2B) + TCP长度 (2B)
            sum += (srcIp >> 16) & 0xFFFF;
            sum += srcIp & 0xFFFF;
            sum += (dstIp >> 16) & 0xFFFF;
            sum += dstIp & 0xFFFF;
            sum += IPPROTO_TCP;
            sum += static_cast<uint16_t>(tcpHeaderAndPayload.size());

            return calculateChecksum(tcpHeaderAndPayload, sum);
        }

        /**
         * @brief 构建伪造的 ClientHello 报文载荷（携带伪造的白名单 SNI）
         */
        [[nodiscard]] static std::vector<uint8_t> buildFakeClientHello(std::string_view fakeSni) noexcept
        {
            if (fakeSni.empty())
                fakeSni = "www.microsoft.com";

            // 构造一个标准 TLS 1.2/1.3 ClientHello 框架
            std::vector<uint8_t> ch;
            // 预留 5 字节 TLS Record Layer
            ch.resize(5);
            ch[0] = 0x16; // Handshake
            ch[1] = 0x03; // TLS 1.0/1.2 Record Version
            ch[2] = 0x01;

            // Handshake 头部: Type=1 (ClientHello), Length (3 bytes)
            ch.push_back(0x01);
            size_t hsLenOffset = ch.size();
            ch.push_back(0x00);
            ch.push_back(0x00);
            ch.push_back(0x00); // 占位

            // Client Version: TLS 1.2 (0x0303)
            ch.push_back(0x03);
            ch.push_back(0x03);

            // Random: 32 bytes
            for (size_t i = 0; i < 32; ++i)
                ch.push_back(static_cast<uint8_t>(0xAA + (i % 7)));

            // Session ID: 0 (len=0)
            ch.push_back(0x00);

            // Cipher Suites (2 suites: TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256)
            ch.push_back(0x00);
            ch.push_back(0x04);
            ch.push_back(0x13);
            ch.push_back(0x01);
            ch.push_back(0x13);
            ch.push_back(0x03);

            // Compression Methods: 1 (null=0)
            ch.push_back(0x01);
            ch.push_back(0x00);

            // Extensions
            size_t extLenOffset = ch.size();
            ch.push_back(0x00);
            ch.push_back(0x00); // extensions total len 占位
            size_t extStart = ch.size();

            // SNI Extension: Type=0x0000
            ch.push_back(0x00);
            ch.push_back(0x00);
            const uint16_t sniExtLen = static_cast<uint16_t>(5 + fakeSni.size());
            ch.push_back(static_cast<uint8_t>((sniExtLen >> 8) & 0xFF));
            ch.push_back(static_cast<uint8_t>(sniExtLen & 0xFF));

            const uint16_t sniListLen = static_cast<uint16_t>(3 + fakeSni.size());
            ch.push_back(static_cast<uint8_t>((sniListLen >> 8) & 0xFF));
            ch.push_back(static_cast<uint8_t>(sniListLen & 0xFF));
            ch.push_back(0x00); // host_name

            const uint16_t nameLen = static_cast<uint16_t>(fakeSni.size());
            ch.push_back(static_cast<uint8_t>((nameLen >> 8) & 0xFF));
            ch.push_back(static_cast<uint8_t>(nameLen & 0xFF));
            ch.insert(ch.end(), fakeSni.begin(), fakeSni.end());

            // 补充 extensions 长度
            const size_t extTotalLen = ch.size() - extStart;
            ch[extLenOffset] = static_cast<uint8_t>((extTotalLen >> 8) & 0xFF);
            ch[extLenOffset + 1] = static_cast<uint8_t>(extTotalLen & 0xFF);

            // 补充 Handshake 长度
            const size_t hsLen = ch.size() - (hsLenOffset + 3);
            ch[hsLenOffset] = static_cast<uint8_t>((hsLen >> 16) & 0xFF);
            ch[hsLenOffset + 1] = static_cast<uint8_t>((hsLen >> 8) & 0xFF);
            ch[hsLenOffset + 2] = static_cast<uint8_t>(hsLen & 0xFF);

            // 补充 Record Layer 长度
            const size_t recLen = ch.size() - 5;
            ch[3] = static_cast<uint8_t>((recLen >> 8) & 0xFF);
            ch[4] = static_cast<uint8_t>(recLen & 0xFF);

            return ch;
        }

        /**
         * @brief 解析欺骗参数并生成对应欺骗策略的报文信息
         */
        [[nodiscard]] static SpoofPacketInfo resolveSpoofPacketInfo(SpoofMethod method, uint32_t sendNext,
                                                                    uint32_t receiveNext, uint32_t timestamp,
                                                                    size_t payloadLen) noexcept
        {
            SpoofPacketInfo info{.seqNum = sendNext, .ackNum = receiveNext, .corruptChecksum = false, .tcpOptions = {}};

            switch (method)
            {
            case SpoofMethod::WRONG_CHECKSUM:
                info.corruptChecksum = true;
                break;
            case SpoofMethod::WRONG_SEQUENCE:
                // 序号倒退 payloadLen 字节 (使服务端判断为重复包丢弃)
                info.seqNum = sendNext - static_cast<uint32_t>(payloadLen > 0 ? payloadLen : 1);
                break;
            case SpoofMethod::WRONG_ACK:
                // ACK 序号超出当前滑动窗口
                info.ackNum = receiveNext - static_cast<uint32_t>(DEFAULT_WINDOW_SIZE / 2);
                break;
            case SpoofMethod::WRONG_TIMESTAMP:
            {
                // 构建 PAWS 冲突时间戳选项 (Kind=8, Len=10, TSVal, TSEcr)
                uint32_t spoofedTs = timestamp > TIMESTAMP_BACKDATE ? timestamp - TIMESTAMP_BACKDATE : 0;
                info.tcpOptions.resize(12);
                info.tcpOptions[0] = 0x01; // NOP
                info.tcpOptions[1] = 0x01; // NOP
                info.tcpOptions[2] = 0x08; // Kind = 8 (Timestamp)
                info.tcpOptions[3] = 0x0A; // Length = 10
                // TSVal
                info.tcpOptions[4] = static_cast<uint8_t>((spoofedTs >> 24) & 0xFF);
                info.tcpOptions[5] = static_cast<uint8_t>((spoofedTs >> 16) & 0xFF);
                info.tcpOptions[6] = static_cast<uint8_t>((spoofedTs >> 8) & 0xFF);
                info.tcpOptions[7] = static_cast<uint8_t>(spoofedTs & 0xFF);
                // TSEcr (Echo 0)
                info.tcpOptions[8] = 0;
                info.tcpOptions[9] = 0;
                info.tcpOptions[10] = 0;
                info.tcpOptions[11] = 0;
                break;
            }
            case SpoofMethod::WRONG_MD5:
            {
                // TCP MD5 签名选项 (Kind=19, Len=18)
                info.tcpOptions.resize(20);
                info.tcpOptions[0] = 0x01; // NOP
                info.tcpOptions[1] = 0x01; // NOP
                info.tcpOptions[2] = 19;   // Kind = 19 (MD5 Signature)
                info.tcpOptions[3] = 18;   // Length = 18
                for (size_t i = 4; i < 20; ++i)
                    info.tcpOptions[i] = static_cast<uint8_t>(0xDE + i);
                break;
            }
            }
            return info;
        }

        /**
         * @brief 组装完整的 IPv4 + TCP 欺骗数据帧 (可以直接注入 SOCK_RAW)
         */
        [[nodiscard]] static std::vector<uint8_t> buildSpoofFrame(SpoofMethod method, const TcpEndpoints &endpoints,
                                                                  uint32_t sendNext, uint32_t receiveNext,
                                                                  uint32_t timestamp,
                                                                  std::span<const uint8_t> payload) noexcept
        {
            auto packetInfo = resolveSpoofPacketInfo(method, sendNext, receiveNext, timestamp, payload.size());

            const size_t ipHeaderLen = 20;
            const size_t tcpHeaderLen = 20 + packetInfo.tcpOptions.size();
            const size_t totalLen = ipHeaderLen + tcpHeaderLen + payload.size();

            std::vector<uint8_t> frame(totalLen, 0);

            // 1. 构建 IPv4 首部
            frame[0] = 0x45; // Version 4, IHL 5 (20 bytes)
            frame[1] = 0x00; // TOS
            frame[2] = static_cast<uint8_t>((totalLen >> 8) & 0xFF);
            frame[3] = static_cast<uint8_t>(totalLen & 0xFF);
            frame[4] = 0x00;
            frame[5] = 0x00; // ID
            frame[6] = 0x40;
            frame[7] = 0x00; // DF flag
            frame[8] = DEFAULT_TTL;
            frame[9] = IPPROTO_TCP;
            frame[10] = 0x00;
            frame[11] = 0x00; // Checksum 占位

            // 源 IP
            frame[12] = static_cast<uint8_t>((endpoints.srcIp >> 24) & 0xFF);
            frame[13] = static_cast<uint8_t>((endpoints.srcIp >> 16) & 0xFF);
            frame[14] = static_cast<uint8_t>((endpoints.srcIp >> 8) & 0xFF);
            frame[15] = static_cast<uint8_t>(endpoints.srcIp & 0xFF);

            // 目的 IP
            frame[16] = static_cast<uint8_t>((endpoints.dstIp >> 24) & 0xFF);
            frame[17] = static_cast<uint8_t>((endpoints.dstIp >> 16) & 0xFF);
            frame[18] = static_cast<uint8_t>((endpoints.dstIp >> 8) & 0xFF);
            frame[19] = static_cast<uint8_t>(endpoints.dstIp & 0xFF);

            // 计算 IPv4 校验和
            uint16_t ipCksum = calculateChecksum(std::span<const uint8_t>(frame.data(), ipHeaderLen));
            frame[10] = static_cast<uint8_t>((ipCksum >> 8) & 0xFF);
            frame[11] = static_cast<uint8_t>(ipCksum & 0xFF);

            // 2. 构建 TCP 首部
            uint8_t *tcp = frame.data() + ipHeaderLen;
            tcp[0] = static_cast<uint8_t>((endpoints.srcPort >> 8) & 0xFF);
            tcp[1] = static_cast<uint8_t>(endpoints.srcPort & 0xFF);
            tcp[2] = static_cast<uint8_t>((endpoints.dstPort >> 8) & 0xFF);
            tcp[3] = static_cast<uint8_t>(endpoints.dstPort & 0xFF);

            // Sequence Number
            tcp[4] = static_cast<uint8_t>((packetInfo.seqNum >> 24) & 0xFF);
            tcp[5] = static_cast<uint8_t>((packetInfo.seqNum >> 16) & 0xFF);
            tcp[6] = static_cast<uint8_t>((packetInfo.seqNum >> 8) & 0xFF);
            tcp[7] = static_cast<uint8_t>(packetInfo.seqNum & 0xFF);

            // Acknowledgment Number
            tcp[8] = static_cast<uint8_t>((packetInfo.ackNum >> 24) & 0xFF);
            tcp[9] = static_cast<uint8_t>((packetInfo.ackNum >> 16) & 0xFF);
            tcp[10] = static_cast<uint8_t>((packetInfo.ackNum >> 8) & 0xFF);
            tcp[11] = static_cast<uint8_t>(packetInfo.ackNum & 0xFF);

            // Data Offset (4-bit words) + Flags (ACK | PSH)
            const uint8_t dataOffsetWords = static_cast<uint8_t>(tcpHeaderLen / 4);
            tcp[12] = static_cast<uint8_t>(dataOffsetWords << 4);
            tcp[13] = 0x18; // ACK (0x10) | PSH (0x08)

            // Window Size
            tcp[14] = static_cast<uint8_t>((DEFAULT_WINDOW_SIZE >> 8) & 0xFF);
            tcp[15] = static_cast<uint8_t>(DEFAULT_WINDOW_SIZE & 0xFF);

            // Checksum 占位
            tcp[16] = 0;
            tcp[17] = 0;
            // Urgent Pointer
            tcp[18] = 0;
            tcp[19] = 0;

            // 写入 TCP Options
            if (!packetInfo.tcpOptions.empty())
            {
                std::memcpy(tcp + 20, packetInfo.tcpOptions.data(), packetInfo.tcpOptions.size());
            }

            // 写入载荷 Payload
            if (!payload.empty())
            {
                std::memcpy(tcp + tcpHeaderLen, payload.data(), payload.size());
            }

            // 3. 计算 TCP 校验和
            std::span<const uint8_t> tcpSegment(tcp, tcpHeaderLen + payload.size());
            uint16_t tcpCksum = calculateTcpChecksum(endpoints.srcIp, endpoints.dstIp, tcpSegment);

            // 若策略要求破坏校验和，进行位反转 (DPI 不验校验和直接放行，服务端内核由于无效校验和静默丢弃)
            if (packetInfo.corruptChecksum)
            {
                tcpCksum ^= 0xFFFF;
            }

            tcp[16] = static_cast<uint8_t>((tcpCksum >> 8) & 0xFF);
            tcp[17] = static_cast<uint8_t>(tcpCksum & 0xFF);

            return frame;
        }

        /**
         * @brief 通过 Linux TCP_REPAIR 读取套接字当前内核维护的 snd_nxt 与 rcv_nxt
         *
         * @param tcpFd 活跃已连接的 TCP 套接字
         * @param outSendNext 输出下一个待发序列号
         * @param outRecvNext 输出期望接收的序列号
         * @return 是否成功读取
         */
        static bool loadSequenceNumbers(int tcpFd, uint32_t &outSendNext, uint32_t &outRecvNext) noexcept
        {
#if defined(__linux__)
            int on = 1;
            int off = 0;
            // 尝试进入 TCP_REPAIR 模式 (需 CAP_NET_ADMIN 权限)
            if (::setsockopt(tcpFd, IPPROTO_TCP, TCP_REPAIR, &on, sizeof(on)) != 0)
            {
                return false;
            }

            bool ok = false;
            int queue = TCP_SEND_QUEUE;
            if (::setsockopt(tcpFd, IPPROTO_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue)) == 0)
            {
                uint32_t seq = 0;
                socklen_t len = sizeof(seq);
                if (::getsockopt(tcpFd, IPPROTO_TCP, TCP_QUEUE_SEQ, &seq, &len) == 0)
                {
                    outSendNext = seq;
                    queue = TCP_RECV_QUEUE;
                    if (::setsockopt(tcpFd, IPPROTO_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue)) == 0)
                    {
                        if (::getsockopt(tcpFd, IPPROTO_TCP, TCP_QUEUE_SEQ, &seq, &len) == 0)
                        {
                            outRecvNext = seq;
                            ok = true;
                        }
                    }
                }
            }

            // 无论如何必须退出 TCP_REPAIR 模式，否则套接字无法继续发送数据
            ::setsockopt(tcpFd, IPPROTO_TCP, TCP_REPAIR, &off, sizeof(off));
            return ok;
#else
            (void)tcpFd;
            (void)outSendNext;
            (void)outRecvNext;
            return false;
#endif
        }

        /**
         * @brief 向指定连接注入伪造的 ClientHello 帧 (TCP Desync)
         */
        static bool injectSpoof(int rawFd, SpoofMethod method, const TcpEndpoints &endpoints, uint32_t sendNext,
                                uint32_t receiveNext, std::string_view fakeSni = "www.microsoft.com",
                                uint32_t timestamp = 0) noexcept
        {
            if (rawFd < 0)
                return false;

            if (timestamp == 0)
            {
                timestamp = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                      std::chrono::steady_clock::now().time_since_epoch())
                                                      .count());
            }

            auto fakeHello = buildFakeClientHello(fakeSni);
            auto frame = buildSpoofFrame(method, endpoints, sendNext, receiveNext, timestamp, fakeHello);

            struct sockaddr_in sin{};
            sin.sin_family = AF_INET;
            sin.sin_port = htons(endpoints.dstPort);
            sin.sin_addr.s_addr = htonl(endpoints.dstIp);

            ssize_t sent =
                ::sendto(rawFd, frame.data(), frame.size(), 0, reinterpret_cast<struct sockaddr *>(&sin), sizeof(sin));
            return sent == static_cast<ssize_t>(frame.size());
        }
    };

} // namespace mynet::tls
