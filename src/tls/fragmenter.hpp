#pragma once

/**
 * @file fragmenter.hpp
 * @brief TLS ClientHello 智能分片与抗 DPI 深度重组引擎 (借鉴 sing-box common/tlsfragment)
 *
 * 核心机制：
 * 1. 精准解析 TLS ClientHello 结构，定位 Server Name Indication (SNI) 字段偏移；
 * 2. 逐级解析域名点号或标签并实施切割，破坏 DPI 基于字符串/正则规则库的特征匹配；
 * 3. 支持 SplitRecord 模式：将 ClientHello 切割为多个标准合法的 TLS 记录层 (ContentType=0x16)，
 *    目标服务端 TLS 引擎可无感合规重组；
 * 4. 支持 SplitPacket 模式：利用 Linux getsockopt(TCP_INFO) 检测 tcpi_unacked == 0，
 *    确保前序分片已被远端或中间件物理 ACK 确认后再发射后续分片，彻底破坏 DPI 滑动流重组。
 */

#include <span>
#include <vector>
#include <string>
#include <string_view>
#include <optional>
#include <cstdint>
#include <cstring>
#include <chrono>
#include <thread>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <unistd.h>
#include <poll.h>

namespace mynet::tls
{

    enum class FragmentMode : uint8_t
    {
        PACKET_ONLY = 1,  ///< 仅 TCP 分节发送并同步 ACK
        RECORD_ONLY = 2,  ///< 仅切分为多个合规 TLS Record
        HYBRID = 3        ///< 既拆分 TLS Record，又在 TCP 层分包同步 ACK
    };

    struct SniIndexInfo
    {
        size_t sniOffset{0};      ///< SNI 字符串在整个报文中的起始偏移
        size_t sniLength{0};      ///< SNI 字符串字节长度
        std::string_view serverName{};
    };

    class TlsFragmenter
    {
    public:
        static constexpr size_t RECORD_HEADER_LEN = 5;
        static constexpr uint8_t CONTENT_TYPE_HANDSHAKE = 0x16;
        static constexpr uint8_t HANDSHAKE_CLIENT_HELLO = 0x01;

        /**
         * @brief 定位 TLS ClientHello 中的 SNI 字段 (支持 0x16 记录层报文与 0x01 裸 ClientHello)
         * @param data 原始 TLS 数据包（记录层报文或裸 ClientHello 握手报文）
         */
        [[nodiscard]] static std::optional<SniIndexInfo> findSni(std::span<const uint8_t> data) noexcept
        {
            if (data.empty()) return std::nullopt;

            const uint8_t* p = nullptr;
            const uint8_t* end = nullptr;

            if (data[0] == CONTENT_TYPE_HANDSHAKE)
            {
                if (data.size() < RECORD_HEADER_LEN + 4) return std::nullopt;
                const size_t recordLen = (static_cast<size_t>(data[3]) << 8) | data[4];
                if (data.size() < RECORD_HEADER_LEN + recordLen) return std::nullopt;
                p = data.data() + RECORD_HEADER_LEN;
                end = p + recordLen;
            }
            else if (data[0] == HANDSHAKE_CLIENT_HELLO)
            {
                if (data.size() < 4) return std::nullopt;
                p = data.data();
                end = data.data() + data.size();
            }
            else
            {
                return std::nullopt;
            }

            // 握手类型必须为 ClientHello (1)
            if (p >= end || *p != HANDSHAKE_CLIENT_HELLO) return std::nullopt;
            p += 1;

            if (p + 3 > end) return std::nullopt;
            const size_t handshakeLen = (static_cast<size_t>(p[0]) << 16) | (static_cast<size_t>(p[1]) << 8) | p[2];
            p += 3;
            if (p + handshakeLen > end) return std::nullopt;

            // Client Version (2 bytes) + Random (32 bytes)
            if (p + 2 + 32 > end) return std::nullopt;
            p += 2 + 32;

            // Session ID
            if (p + 1 > end) return std::nullopt;
            const uint8_t sessionIdLen = *p;
            p += 1 + sessionIdLen;
            if (p > end) return std::nullopt;

            // Cipher Suites
            if (p + 2 > end) return std::nullopt;
            const size_t csLen = (static_cast<size_t>(p[0]) << 8) | p[1];
            p += 2 + csLen;
            if (p > end) return std::nullopt;

            // Compression Methods
            if (p + 1 > end) return std::nullopt;
            const uint8_t compLen = *p;
            p += 1 + compLen;
            if (p > end) return std::nullopt;

            // Extensions Length
            if (p + 2 > end) return std::nullopt;
            const size_t extTotalLen = (static_cast<size_t>(p[0]) << 8) | p[1];
            p += 2;
            const uint8_t* extEnd = p + extTotalLen;
            if (extEnd > end) return std::nullopt;

            // 遍历扩展寻找 server_name (0x0000)
            while (p + 4 <= extEnd)
            {
                const uint16_t extType = (static_cast<uint16_t>(p[0]) << 8) | p[1];
                const size_t extLen = (static_cast<size_t>(p[2]) << 8) | p[3];
                p += 4;
                if (p + extLen > extEnd) return std::nullopt;

                if (extType == 0x0000) // server_name extension
                {
                    if (extLen < 5) return std::nullopt;
                    // server_name_list_length (2) + name_type (1) + name_length (2)
                    const uint8_t nameType = p[2];
                    if (nameType == 0x00) // host_name
                    {
                        const size_t nameLen = (static_cast<size_t>(p[3]) << 8) | p[4];
                        if (5 + nameLen > extLen) return std::nullopt;

                        const uint8_t* namePtr = p + 5;
                        const size_t offset = static_cast<size_t>(namePtr - data.data());
                        std::string_view name(reinterpret_cast<const char*>(namePtr), nameLen);
                        return SniIndexInfo{
                            .sniOffset = offset,
                            .sniLength = nameLen,
                            .serverName = name
                        };
                    }
                }
                p += extLen;
            }

            return std::nullopt;
        }

        /**
         * @brief 计算切分点序列（在 SNI 点号或子域名内部进行切割）
         */
        [[nodiscard]] static std::vector<size_t> computeSplitOffsets(
            std::span<const uint8_t> /* data */,
            const SniIndexInfo& sniInfo) noexcept
        {
            std::vector<size_t> splitOffsets;
            if (sniInfo.sniLength <= 1)
            {
                splitOffsets.push_back(sniInfo.sniOffset + 1);
                return splitOffsets;
            }

            // 在 SNI 中寻找每个 '.' 的位置进行拆分
            size_t dotPos = sniInfo.serverName.find('.');
            if (dotPos != std::string_view::npos && dotPos > 0 && dotPos + 1 < sniInfo.sniLength)
            {
                // 在点号前后进行切分，比如在点号本身切割
                splitOffsets.push_back(sniInfo.sniOffset + dotPos);
                splitOffsets.push_back(sniInfo.sniOffset + dotPos + 1);
            }
            else
            {
                // 没有点号或为单标签，则在中间二分切分
                splitOffsets.push_back(sniInfo.sniOffset + sniInfo.sniLength / 2);
            }

            return splitOffsets;
        }

        /**
         * @brief 将原始 ClientHello 切分为多个合法的 TLS 记录层报文
         *
         * 每个分片均带有合法的 5 字节记录层头部：ContentType=0x16, Version=0x0301, Length=分片载荷长
         */
        [[nodiscard]] static std::vector<std::vector<uint8_t>> buildSplitRecords(
            std::span<const uint8_t> data,
            const std::vector<size_t>& splitOffsets) noexcept
        {
            std::vector<std::vector<uint8_t>> records;
            if (data.size() <= RECORD_HEADER_LEN || splitOffsets.empty())
            {
                records.emplace_back(data.begin(), data.end());
                return records;
            }

            const uint8_t contentType = data[0];
            const uint8_t vMajor = data[1];
            const uint8_t vMinor = data[2];

            // 原始有效载荷 (去掉前 5 字节头部)
            const uint8_t* payload = data.data() + RECORD_HEADER_LEN;
            const size_t totalPayloadLen = data.size() - RECORD_HEADER_LEN;

            // 转换切分偏移为相对于握手载荷的偏移
            std::vector<size_t> offsets;
            for (auto off : splitOffsets)
            {
                if (off > RECORD_HEADER_LEN && off < data.size())
                {
                    offsets.push_back(off - RECORD_HEADER_LEN);
                }
            }

            if (offsets.empty())
            {
                records.emplace_back(data.begin(), data.end());
                return records;
            }

            std::sort(offsets.begin(), offsets.end());
            offsets.erase(std::unique(offsets.begin(), offsets.end()), offsets.end());

            size_t prev = 0;
            for (size_t next : offsets)
            {
                if (next <= prev || next > totalPayloadLen) continue;
                const size_t chunkLen = next - prev;

                std::vector<uint8_t> rec(RECORD_HEADER_LEN + chunkLen);
                rec[0] = contentType;
                rec[1] = vMajor;
                rec[2] = vMinor;
                rec[3] = static_cast<uint8_t>((chunkLen >> 8) & 0xFF);
                rec[4] = static_cast<uint8_t>(chunkLen & 0xFF);
                std::memcpy(rec.data() + RECORD_HEADER_LEN, payload + prev, chunkLen);

                records.push_back(std::move(rec));
                prev = next;
            }

            if (prev < totalPayloadLen)
            {
                const size_t chunkLen = totalPayloadLen - prev;
                std::vector<uint8_t> rec(RECORD_HEADER_LEN + chunkLen);
                rec[0] = contentType;
                rec[1] = vMajor;
                rec[2] = vMinor;
                rec[3] = static_cast<uint8_t>((chunkLen >> 8) & 0xFF);
                rec[4] = static_cast<uint8_t>(chunkLen & 0xFF);
                std::memcpy(rec.data() + RECORD_HEADER_LEN, payload + prev, chunkLen);
                records.push_back(std::move(rec));
            }

            return records;
        }

        /**
         * @brief 写入指定数据段并等待对端 TCP ACK 确认 (Linux getsockopt TCP_INFO)
         *
         * @param fd 套接字文件描述符
         * @param payload 待发送载荷
         * @param fallbackDelay 等待 ACK 超时或透明代理回退延时
         * @return 实际发送成功的字节数，出错返回 -1
         */
        static ssize_t writeAndWaitAck(
            int fd,
            std::span<const uint8_t> payload,
            std::chrono::milliseconds fallbackDelay = std::chrono::milliseconds(50)) noexcept
        {
            if (fd < 0 || payload.empty()) return 0;

            // 发送数据 (处理非阻塞部分写入)
            size_t totalSent = 0;
            while (totalSent < payload.size())
            {
                const ssize_t n = ::send(fd, payload.data() + totalSent, payload.size() - totalSent, MSG_NOSIGNAL);
                if (n > 0)
                {
                    totalSent += static_cast<size_t>(n);
                }
                else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                {
                    struct pollfd pfd{ .fd = fd, .events = POLLOUT, .revents = 0 };
                    int pr = ::poll(&pfd, 1, 50);
                    if (pr <= 0) break;
                }
                else
                {
                    if (totalSent == 0) return n;
                    break;
                }
            }
            if (totalSent == 0) return 0;

#if defined(__linux__)
            const auto start = std::chrono::steady_clock::now();
            constexpr auto maxWait = std::chrono::milliseconds(500);

            while (true)
            {
                struct tcp_info info{};
                socklen_t len = sizeof(info);
                if (::getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &len) == 0)
                {
                    // 当且仅当所有发出的数据已被对端 ACK (tcpi_unacked == 0)
                    if (info.tcpi_unacked == 0)
                    {
                        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - start);
                        // 若 ACK 返回时间极短 (<= 15ms，说明命中了本机回路或透明代理)，实施额外延时以保证中间件物理间隔
                        if (elapsed <= std::chrono::milliseconds(15))
                        {
                            std::this_thread::sleep_for(fallbackDelay);
                        }
                        break;
                    }
                }
                else
                {
                    std::this_thread::sleep_for(fallbackDelay);
                    break;
                }

                if (std::chrono::steady_clock::now() - start > maxWait)
                {
                    // 超过最大等待限制，继续执行避免死锁
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
#else
            std::this_thread::sleep_for(fallbackDelay);
#endif
            return totalSent;
        }

        /**
         * @brief 一站式发送带有智能分片的 ClientHello 报文
         */
        static bool sendFragmentedClientHello(
            int fd,
            std::span<const uint8_t> clientHelloData,
            FragmentMode mode = FragmentMode::HYBRID,
            std::chrono::milliseconds fallbackDelay = std::chrono::milliseconds(30)) noexcept
        {
            if (fd < 0 || clientHelloData.empty()) return false;

            auto sniInfo = findSni(clientHelloData);
            if (!sniInfo)
            {
                // 无法解析 SNI，直接整包发送
                ssize_t n = ::send(fd, clientHelloData.data(), clientHelloData.size(), MSG_NOSIGNAL);
                return n == static_cast<ssize_t>(clientHelloData.size());
            }

            auto splitOffsets = computeSplitOffsets(clientHelloData, *sniInfo);

            // 临时开启 TCP_NODELAY，强制内核立即发射小包
            int one = 1;
            int prevNoDelay = 0;
            socklen_t optLen = sizeof(prevNoDelay);
            ::getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &prevNoDelay, &optLen);
            ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

            bool success = true;

            if (mode == FragmentMode::RECORD_ONLY)
            {
                auto records = buildSplitRecords(clientHelloData, splitOffsets);
                for (const auto& rec : records)
                {
                    ssize_t n = ::send(fd, rec.data(), rec.size(), MSG_NOSIGNAL);
                    if (n != static_cast<ssize_t>(rec.size()))
                    {
                        success = false;
                        break;
                    }
                }
            }
            else if (mode == FragmentMode::PACKET_ONLY)
            {
                size_t prev = 0;
                for (size_t next : splitOffsets)
                {
                    if (next <= prev || next > clientHelloData.size()) continue;
                    auto chunk = clientHelloData.subspan(prev, next - prev);
                    if (writeAndWaitAck(fd, chunk, fallbackDelay) <= 0)
                    {
                        success = false;
                        break;
                    }
                    prev = next;
                }
                if (success && prev < clientHelloData.size())
                {
                    auto chunk = clientHelloData.subspan(prev, clientHelloData.size() - prev);
                    ssize_t n = ::send(fd, chunk.data(), chunk.size(), MSG_NOSIGNAL);
                    if (n <= 0) success = false;
                }
            }
            else // HYBRID
            {
                auto records = buildSplitRecords(clientHelloData, splitOffsets);
                for (size_t i = 0; i < records.size(); ++i)
                {
                    const auto& rec = records[i];
                    if (i + 1 < records.size())
                    {
                        if (writeAndWaitAck(fd, rec, fallbackDelay) <= 0)
                        {
                            success = false;
                            break;
                        }
                    }
                    else
                    {
                        ssize_t n = ::send(fd, rec.data(), rec.size(), MSG_NOSIGNAL);
                        if (n <= 0) success = false;
                    }
                }
            }

            // 恢复原有的 TCP_NODELAY 设置
            ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &prevNoDelay, sizeof(prevNoDelay));
            return success;
        }
    };

} // namespace mynet::tls
