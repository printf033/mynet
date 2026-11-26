#pragma once

/**
 * @file tun.hpp
 * @brief Linux TUN 虚拟网卡用户态 L3/L4 报文转发引擎 (TunEngine)。
 *
 * 核心架构与职责：
 * 1. 原生接管 TUN 字符设备描述符 (/dev/net/tun)，支持双向非阻塞 L3 IP 报文收发；
 * 2. 内置用户态 ICMP 状态机：拦截 Echo Request 并直接以 0-RTT 响应 Echo Reply，保证 Ping 保活与测速畅通；
 * 3. 内置用户态 UDP NAT 会话转发表：自动维护 (client <-> target) 双向映射，非阻塞代发出站与回包隧道封装；
 * 4. 内置用户态 TCP 轻量流控与三次握手处理：自适应处理 SYN / SYN-ACK / ACK / PSH / FIN / RST，
 *    无缝桥接操作系统与用户态代理核心；
 * 5. 零异常 (-fno-exceptions)，完备 RAII 资源回收与空闲会话超时排空。
 */

#include "tunPacket.hpp"
#include "address.hpp"
#include "config/log.hpp"
#include "sniffer.hpp"
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <mutex>
#include <poll.h>
#include <span>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

namespace mynet::tun
{

    enum class TunProcessResult : uint8_t
    {
        DROP,
        ICMP_REPLIED,
        UDP_FORWARDED,
        TCP_HANDLED
    };

    /**
     * @brief 会话唯一标识 (四元组: Client IP:Port <-> Target IP:Port)
     */
    struct FlowKey
    {
        uint32_t clientIp{0};
        uint16_t clientPort{0};
        uint32_t targetIp{0};
        uint16_t targetPort{0};

        bool operator==(const FlowKey &other) const noexcept
        {
            return clientIp == other.clientIp && clientPort == other.clientPort && targetIp == other.targetIp &&
                   targetPort == other.targetPort;
        }
    };

    struct FlowKeyHash
    {
        size_t operator()(const FlowKey &k) const noexcept
        {
            const size_t h1 = std::hash<uint32_t>{}(k.clientIp);
            const size_t h2 = std::hash<uint32_t>{}(k.targetIp);
            const size_t h3 = (static_cast<size_t>(k.clientPort) << 16) | k.targetPort;
            return h1 ^ (h2 << 1) ^ (h3 << 2);
        }
    };

    /**
     * @brief 用户态 UDP 会话描述符
     */
    struct TunUdpSession
    {
        FlowKey key{};
        int outboundFd{-1};
        std::chrono::steady_clock::time_point lastActive{std::chrono::steady_clock::now()};

        ~TunUdpSession() noexcept
        {
            if (outboundFd >= 0)
            {
                ::close(outboundFd);
                outboundFd = -1;
            }
        }
    };

    /**
     * @brief 用户态 TCP 状态机状态
     */
    enum class TcpState : uint8_t
    {
        CLOSED,
        SYN_RECEIVED,
        ESTABLISHED,
        FIN_WAIT
    };

    /**
     * @brief 用户态 TCP 会话描述符
     */
    struct TunTcpSession
    {
        FlowKey key{};
        TcpState state{TcpState::CLOSED};
        uint32_t clientSeq{0};
        uint32_t serverSeq{0};
        int outboundFd{-1};
        std::chrono::steady_clock::time_point lastActive{std::chrono::steady_clock::now()};

        ~TunTcpSession() noexcept
        {
            if (outboundFd >= 0)
            {
                ::close(outboundFd);
                outboundFd = -1;
            }
        }
    };

    /**
     * @brief Linux TUN 用户态网络数据面引擎 (TunEngine)
     */
    class TunEngine
    {
    private:
        int tunFd_{-1};
        uint32_t mtu_{1500};
        bool enableSniffing_{true};

        mutable std::mutex mutex_{};
        std::unordered_map<FlowKey, std::shared_ptr<TunUdpSession>, FlowKeyHash> udpSessions_{};
        std::unordered_map<FlowKey, std::shared_ptr<TunTcpSession>, FlowKeyHash> tcpSessions_{};

        std::atomic<bool> running_{false};
        std::thread workerThread_{};

        std::atomic<uint64_t> packetsIn_{0};
        std::atomic<uint64_t> packetsOut_{0};
        std::atomic<uint64_t> bytesIn_{0};
        std::atomic<uint64_t> bytesOut_{0};

    public:
        explicit TunEngine(int tunFd = -1, uint32_t mtu = 1500, bool enableSniffing = true) noexcept
            : tunFd_(tunFd), mtu_(mtu), enableSniffing_(enableSniffing)
        {
        }

        ~TunEngine() noexcept { stop(); }

        TunEngine(const TunEngine &) = delete;
        TunEngine &operator=(const TunEngine &) = delete;
        TunEngine(TunEngine &&) = delete;
        TunEngine &operator=(TunEngine &&) = delete;

        void setTunFd(int fd) noexcept { tunFd_ = fd; }
        [[nodiscard]] int tunFd() const noexcept { return tunFd_; }
        [[nodiscard]] uint32_t mtu() const noexcept { return mtu_; }
        void setMtu(uint32_t mtu) noexcept { mtu_ = mtu; }
        [[nodiscard]] bool isRunning() const noexcept { return running_.load(std::memory_order_acquire); }

        [[nodiscard]] uint64_t packetsIn() const noexcept { return packetsIn_.load(std::memory_order_relaxed); }
        [[nodiscard]] uint64_t packetsOut() const noexcept { return packetsOut_.load(std::memory_order_relaxed); }
        [[nodiscard]] uint64_t bytesIn() const noexcept { return bytesIn_.load(std::memory_order_relaxed); }
        [[nodiscard]] uint64_t bytesOut() const noexcept { return bytesOut_.load(std::memory_order_relaxed); }

        /**
         * @brief 向 TUN 接口写入一个原始 L3 IP 报文
         */
        bool writeTun(std::span<const uint8_t> packet) noexcept
        {
            if (tunFd_ < 0 || packet.empty())
            {
                return false;
            }
            const ssize_t written = ::write(tunFd_, packet.data(), packet.size());
            if (written > 0)
            {
                packetsOut_.fetch_add(1, std::memory_order_relaxed);
                bytesOut_.fetch_add(static_cast<uint64_t>(written), std::memory_order_relaxed);
                return static_cast<size_t>(written) == packet.size();
            }
            return false;
        }

        /**
         * @brief 处理由 TUN 接口摄入的一个裸 L3 IP 报文
         */
        TunProcessResult processPacket(std::span<const uint8_t> packet)
        {
            if (packet.size() < 20)
            {
                return TunProcessResult::DROP;
            }

            packetsIn_.fetch_add(1, std::memory_order_relaxed);
            bytesIn_.fetch_add(packet.size(), std::memory_order_relaxed);

            const uint8_t ver = packet[0] >> 4;
            if (ver != 4)
            {
                // 目前重点加速 IPv4，其它协议按需忽略
                return TunProcessResult::DROP;
            }

            Ipv4View ip{packet.data(), packet.size()};
            if (!ip.valid())
            {
                return TunProcessResult::DROP;
            }

            // 1. ICMP 协议处理 (Echo Request -> Echo Reply)
            if (ip.protocol() == 1) // IPPROTO_ICMP
            {
                auto reply = buildIcmpEchoReply(packet.subspan(0, ip.totalLength()));
                if (!reply.empty())
                {
                    writeTun(reply);
                    return TunProcessResult::ICMP_REPLIED;
                }
                return TunProcessResult::DROP;
            }

            // 2. UDP 数据报协议处理
            if (ip.protocol() == 17) // IPPROTO_UDP
            {
                const auto udpSpan = ip.payload();
                UdpView udp{udpSpan.data(), udpSpan.size()};
                if (!udp.valid())
                {
                    return TunProcessResult::DROP;
                }

                const FlowKey key{
                    .clientIp = ip.srcIp(),
                    .clientPort = udp.srcPort(),
                    .targetIp = ip.dstIp(),
                    .targetPort = udp.dstPort(),
                };

                const auto payload = udp.payload();
                handleUdpPacket(key, payload);
                return TunProcessResult::UDP_FORWARDED;
            }

            // 3. TCP 流协议处理
            if (ip.protocol() == 6) // IPPROTO_TCP
            {
                const auto tcpSpan = ip.payload();
                TcpView tcp{tcpSpan.data(), tcpSpan.size()};
                if (!tcp.valid())
                {
                    return TunProcessResult::DROP;
                }

                const FlowKey key{
                    .clientIp = ip.srcIp(),
                    .clientPort = tcp.srcPort(),
                    .targetIp = ip.dstIp(),
                    .targetPort = tcp.dstPort(),
                };

                handleTcpPacket(key, tcp);
                return TunProcessResult::TCP_HANDLED;
            }

            return TunProcessResult::DROP;
        }

        /**
         * @brief 单次无阻塞/限时驱动轮询 (Poll Once)
         *
         * 同时检查 TUN 描述符可读报文与各活动会话的出站套接字回包
         */
        size_t pumpOnce(int timeoutMs = 0)
        {
            if (tunFd_ < 0)
            {
                return 0;
            }

            std::vector<pollfd> pfds;
            pfds.reserve(16);

            // 1. 监测 TUN 设备入站
            pfds.push_back(pollfd{.fd = tunFd_, .events = POLLIN, .revents = 0});

            // 2. 监测所有活动的 UDP 与 TCP 出站回包描述符
            struct FdMeta
            {
                int fd{-1};
                bool isUdp{false};
                FlowKey key{};
            };
            std::vector<FdMeta> metas;

            {
                std::lock_guard<std::mutex> lock(mutex_);
                for (const auto &pair : udpSessions_)
                {
                    if (pair.second && pair.second->outboundFd >= 0)
                    {
                        pfds.push_back(pollfd{.fd = pair.second->outboundFd, .events = POLLIN, .revents = 0});
                        metas.push_back(FdMeta{.fd = pair.second->outboundFd, .isUdp = true, .key = pair.first});
                    }
                }
                for (const auto &pair : tcpSessions_)
                {
                    if (pair.second && pair.second->outboundFd >= 0)
                    {
                        pfds.push_back(pollfd{.fd = pair.second->outboundFd, .events = POLLIN, .revents = 0});
                        metas.push_back(FdMeta{.fd = pair.second->outboundFd, .isUdp = false, .key = pair.first});
                    }
                }
            }

            const int ret = ::poll(pfds.data(), static_cast<nfds_t>(pfds.size()), timeoutMs);
            if (ret <= 0)
            {
                return 0;
            }

            size_t handled = 0;

            // 处理 TUN 可读
            if (pfds[0].revents & (POLLIN | POLLPRI))
            {
                std::vector<uint8_t> readBuf(mtu_ + 64, 0);
                for (size_t i = 0; i < 32; ++i)
                {
                    const ssize_t n = ::read(tunFd_, readBuf.data(), readBuf.size());
                    if (n <= 0)
                    {
                        break;
                    }
                    processPacket(std::span<const uint8_t>(readBuf.data(), static_cast<size_t>(n)));
                    ++handled;
                }
            }

            // 处理各出站套接字回包
            std::vector<uint8_t> outBuf(mtu_ + 64, 0);
            for (size_t i = 1; i < pfds.size(); ++i)
            {
                if (pfds[i].revents & (POLLIN | POLLPRI))
                {
                    const auto &meta = metas[i - 1];
                    if (meta.isUdp)
                    {
                        const ssize_t n = ::recv(meta.fd, outBuf.data(), outBuf.size(), 0);
                        if (n > 0)
                        {
                            // 构造 UDP 回包：源地址为 Target，目标地址为 Client
                            const uint8_t *srcIpBytes = reinterpret_cast<const uint8_t *>(&meta.key.targetIp);
                            const uint8_t *dstIpBytes = reinterpret_cast<const uint8_t *>(&meta.key.clientIp);
                            auto reply = buildIpv4UdpPacket(srcIpBytes, dstIpBytes, meta.key.targetPort,
                                                           meta.key.clientPort,
                                                           std::span<const uint8_t>(outBuf.data(), static_cast<size_t>(n)));
                            writeTun(reply);
                            ++handled;
                        }
                    }
                    else
                    {
                        // TCP 回包
                        handleTcpOutboundReadable(meta.key, meta.fd);
                        ++handled;
                    }
                }
            }

            return handled;
        }

        /**
         * @brief 启动后台守护工作线程
         */
        void start()
        {
            if (running_.exchange(true, std::memory_order_acq_rel))
            {
                return;
            }
            workerThread_ = std::thread([this]() {
                while (running_.load(std::memory_order_acquire))
                {
                    pumpOnce(50);
                    sweepSessions(std::chrono::seconds(60));
                }
            });
        }

        /**
         * @brief 停止后台守护工作线程并释放所有会话
         */
        void stop() noexcept
        {
            if (running_.exchange(false, std::memory_order_acq_rel))
            {
                if (workerThread_.joinable())
                {
                    workerThread_.join();
                }
                clearSessions();
            }
        }

        /**
         * @brief 排空超时的空闲会话资源
         */
        size_t sweepSessions(std::chrono::seconds timeout = std::chrono::seconds(60))
        {
            const auto now = std::chrono::steady_clock::now();
            std::lock_guard<std::mutex> lock(mutex_);
            const size_t origUdp = udpSessions_.size();
            const size_t origTcp = tcpSessions_.size();

            std::erase_if(udpSessions_, [&](const auto &pair) {
                return (now - pair.second->lastActive) >= timeout;
            });
            std::erase_if(tcpSessions_, [&](const auto &pair) {
                return pair.second->state == TcpState::CLOSED || (now - pair.second->lastActive) >= timeout;
            });

            return (origUdp - udpSessions_.size()) + (origTcp - tcpSessions_.size());
        }

        void clearSessions() noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            udpSessions_.clear();
            tcpSessions_.clear();
        }

    private:
        void handleUdpPacket(const FlowKey &key, std::span<const uint8_t> payload)
        {
            std::shared_ptr<TunUdpSession> session;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                auto it = udpSessions_.find(key);
                if (it != udpSessions_.end())
                {
                    session = it->second;
                    session->lastActive = std::chrono::steady_clock::now();
                }
                else
                {
                    session = std::make_shared<TunUdpSession>();
                    session->key = key;

                    int fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
                    if (fd >= 0)
                    {
                        sockaddr_in sin{};
                        sin.sin_family = AF_INET;
                        sin.sin_port = htons(key.targetPort);
                        sin.sin_addr.s_addr = key.targetIp;

                        // 连接到目的对端以锁定路由与简化收发
                        if (::connect(fd, reinterpret_cast<const sockaddr *>(&sin), sizeof(sin)) == 0)
                        {
                            session->outboundFd = fd;
                            udpSessions_[key] = session;
                        }
                        else
                        {
                            ::close(fd);
                            session = nullptr;
                        }
                    }
                }
            }

            if (session != nullptr && session->outboundFd >= 0 && !payload.empty())
            {
                ::send(session->outboundFd, payload.data(), payload.size(), 0);
            }
        }

        void handleTcpPacket(const FlowKey &key, const TcpView &tcp)
        {
            std::shared_ptr<TunTcpSession> session;
            const uint8_t *srcIpBytes = reinterpret_cast<const uint8_t *>(&key.targetIp);
            const uint8_t *dstIpBytes = reinterpret_cast<const uint8_t *>(&key.clientIp);

            // 1. SYN 握手发起
            if (tcp.syn() && !tcp.ack())
            {
                session = std::make_shared<TunTcpSession>();
                session->key = key;
                session->clientSeq = tcp.seq() + 1;
                // 生成初始序列号 ISN
                session->serverSeq =
                    (key.clientIp ^ key.targetIp) + (static_cast<uint32_t>(key.clientPort) << 16 | key.targetPort);
                session->state = TcpState::SYN_RECEIVED;
                session->lastActive = std::chrono::steady_clock::now();

                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    tcpSessions_[key] = session;
                }

                // 立即向客户端回送 SYN-ACK (Flags = 0x12)
                auto synAck = buildIpv4TcpPacket(srcIpBytes, dstIpBytes, key.targetPort, key.clientPort,
                                                session->serverSeq, session->clientSeq, 0x12, 65535);
                writeTun(synAck);
                return;
            }

            {
                std::lock_guard<std::mutex> lock(mutex_);
                auto it = tcpSessions_.find(key);
                if (it != tcpSessions_.end())
                {
                    session = it->second;
                    session->lastActive = std::chrono::steady_clock::now();
                }
            }

            if (session == nullptr)
            {
                return;
            }

            // 2. RST 复位
            if (tcp.rst())
            {
                session->state = TcpState::CLOSED;
                std::lock_guard<std::mutex> lock(mutex_);
                tcpSessions_.erase(key);
                return;
            }

            // 3. 握手第三阶段 ACK 完成建连
            if (session->state == TcpState::SYN_RECEIVED && tcp.ack())
            {
                session->state = TcpState::ESTABLISHED;
                session->serverSeq++; // SYN-ACK 消耗 1 序列号

                // 非阻塞连接远端目标真实套接字
                int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
                if (fd >= 0)
                {
                    sockaddr_in sin{};
                    sin.sin_family = AF_INET;
                    sin.sin_port = htons(key.targetPort);
                    sin.sin_addr.s_addr = key.targetIp;

                    int ret = ::connect(fd, reinterpret_cast<const sockaddr *>(&sin), sizeof(sin));
                    if (ret < 0 && errno != EINPROGRESS)
                    {
                        ::close(fd);
                        fd = -1;
                    }
                    session->outboundFd = fd;
                }
            }

            // 4. 数据报载荷传输
            const auto payload = tcp.payload();
            if (!payload.empty())
            {
                session->clientSeq = tcp.seq() + static_cast<uint32_t>(payload.size());

                // 回送 ACK 确认收到客户端数据 (Flags = 0x10)
                auto ackPkt = buildIpv4TcpPacket(srcIpBytes, dstIpBytes, key.targetPort, key.clientPort,
                                                session->serverSeq, session->clientSeq, 0x10, 65535);
                writeTun(ackPkt);

                // 转发数据至出站真实套接字
                if (session->outboundFd >= 0)
                {
                    ::send(session->outboundFd, payload.data(), payload.size(), MSG_NOSIGNAL);
                }
            }

            // 5. FIN 断开连接
            if (tcp.fin())
            {
                session->clientSeq = tcp.seq() + 1;
                auto finAck = buildIpv4TcpPacket(srcIpBytes, dstIpBytes, key.targetPort, key.clientPort,
                                                session->serverSeq, session->clientSeq, 0x11, 65535);
                writeTun(finAck);
                session->serverSeq++;
                session->state = TcpState::FIN_WAIT;

                if (session->outboundFd >= 0)
                {
                    ::shutdown(session->outboundFd, SHUT_WR);
                }
            }
        }

        void handleTcpOutboundReadable(const FlowKey &key, int fd)
        {
            std::shared_ptr<TunTcpSession> session;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                auto it = tcpSessions_.find(key);
                if (it != tcpSessions_.end())
                {
                    session = it->second;
                }
            }

            if (session == nullptr || session->outboundFd != fd)
            {
                return;
            }

            std::vector<uint8_t> buf(1460, 0);
            const ssize_t n = ::recv(fd, buf.data(), buf.size(), 0);

            const uint8_t *srcIpBytes = reinterpret_cast<const uint8_t *>(&key.targetIp);
            const uint8_t *dstIpBytes = reinterpret_cast<const uint8_t *>(&key.clientIp);

            if (n > 0)
            {
                // 构建 TCP PSH-ACK 数据推送给客户端
                auto pshAck =
                    buildIpv4TcpPacket(srcIpBytes, dstIpBytes, key.targetPort, key.clientPort, session->serverSeq,
                                       session->clientSeq, 0x18, 65535,
                                       std::span<const uint8_t>(buf.data(), static_cast<size_t>(n)));
                session->serverSeq += static_cast<uint32_t>(n);
                session->lastActive = std::chrono::steady_clock::now();
                writeTun(pshAck);
            }
            else if (n == 0)
            {
                // 远端正常关闭，向客户端发送 FIN-ACK
                auto finAck = buildIpv4TcpPacket(srcIpBytes, dstIpBytes, key.targetPort, key.clientPort,
                                                session->serverSeq, session->clientSeq, 0x11, 65535);
                session->serverSeq++;
                session->state = TcpState::FIN_WAIT;
                writeTun(finAck);
                ::close(session->outboundFd);
                session->outboundFd = -1;
            }
            else
            {
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                {
                    // 异常出错，发送 RST
                    auto rstPkt = buildIpv4TcpPacket(srcIpBytes, dstIpBytes, key.targetPort, key.clientPort,
                                                    session->serverSeq, session->clientSeq, 0x04, 0);
                    writeTun(rstPkt);
                    session->state = TcpState::CLOSED;
                }
            }
        }
    };

} // namespace mynet::tun
