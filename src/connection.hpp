#pragma once

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "address.hpp"
#include "config/log.hpp"
#include "configHolder.hpp"
#include "constraints.hpp"
#include "error.hpp"
#include "requestBuffer.hpp"
#include "responseQueue.hpp"
#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <deque>
#include <expected>
#include <fcntl.h>
#include <functional>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <optional>
#include <string>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

namespace mynet
{

    /**
     * @brief 零拷贝管道控制与生命周期状态枚举
     */
    enum class SPLICE_CONTROL : uint8_t
    {
        DISABLED = 0, ///< 禁用 / 初始状态（走常规用户态缓冲读取与协议解析）
        ACTIVE = 1,   ///< 活跃直通（内核 splice 管道建立，数据直通目标描述符）
        PAUSED = 2,   ///< 暂停挂起（背压保护或流控限制，暂时暂停管道读写）
        DRAINING = 3, ///< 管道排空（停止摄入新数据，等待管道内剩余字节完全刷入目标）
        CLOSED = 4    ///< 隧道关闭（目标描述符关闭或传输完成）
    };

    [[nodiscard]] constexpr std::string_view toString(SPLICE_CONTROL ctrl) noexcept
    {
        switch (ctrl)
        {
        case SPLICE_CONTROL::DISABLED:
            return "DISABLED";
        case SPLICE_CONTROL::ACTIVE:
            return "ACTIVE";
        case SPLICE_CONTROL::PAUSED:
            return "PAUSED";
        case SPLICE_CONTROL::DRAINING:
            return "DRAINING";
        case SPLICE_CONTROL::CLOSED:
            return "CLOSED";
        }
        return "UNKNOWN";
    }

    /**
     * @brief TCP 路由策略决断与实际出站传输绑定的解耦模型 (借鉴 dae TcpFlowBinding, 机制 72)
     *
     * 将连接状态明确解耦为两层：
     * 1. TcpRouteBinding: 高层策略决断（不可变版本号 Policy Epoch、出站组、Mark、Must 强制标记）
     * 2. TcpEgressBinding: 底层物理传输实例（Dialer 标签、解析的目标端点、嗅探到的 SNI 目标）
     * 在出站节点发生自动故障转移时，既有活跃长连接的策略决断保持冻结，仅新建连接应用新 Egress 绑定，
     * 彻底杜绝正在通信的活跃长连接被强行切断或重置。
     */
    struct TcpRouteBinding
    {
        uint32_t policyEpoch{0};
        std::string outboundGroup{};
        uint32_t fwmark{0};
        bool must{false};
        std::string matchedRule{};
    };

    struct TcpEgressBinding
    {
        std::string dialerTag{};
        std::string remoteEndpoint{};
        std::string sniffedSni{};
        bool isDirect{false};
    };

    struct TcpFlowBinding
    {
        TcpRouteBinding route{};
        TcpEgressBinding egress{};
        uint64_t flowId{0};
        std::chrono::steady_clock::time_point boundAt{std::chrono::steady_clock::now()};

        [[nodiscard]] bool isFrozen() const noexcept { return flowId != 0; }
        void freeze(uint64_t id) noexcept { flowId = id; }
    };

    namespace handler
    {
        enum class InboundStage : uint8_t
        {
            HANDSHAKE, ///< 正在接收并解析入站握手报文/鉴权/提取目标地址
            STREAMING, ///< 握手完成，进入数据流式透传/内核零拷贝转发阶段
            ERROR      ///< 鉴权失败或协议格式畸变
        };

        enum class OutboundStage : uint8_t
        {
            INITIAL,    ///< 初始未握手状态
            CONNECTING, ///< 正在发送出站协议头部或等待对端认证回执
            STREAMING,  ///< 握手完成，进入流式数据透传/内核零拷贝转发
            ERROR       ///< 出站协议握手失败或对端报错
        };

        enum class ProxyStage : uint8_t
        {
            INITIAL,
            HANDSHAKE,
            CONNECTING,
            STREAMING,
            ERROR
        };
    } // namespace handler

    class HandlerConnection;

    /**
     * @brief 流式连接协议外发参数包特化
     *
     * 包含待外发字节载荷 std::string bytes。提供与 std::string 互相隐式转换与兼容接口，
     * 保证上层零适配成本无缝复用。
     */
    template <>
    struct Protocol<HandlerConnection>
    {
        std::string bytes{};

        Protocol() noexcept = default;
        Protocol(std::string s) noexcept
            : bytes(std::move(s))
        {
        }
        Protocol(std::string_view sv)
            : bytes(sv)
        {
        }
        Protocol(const char *buf, size_t n)
            : bytes(buf, n)
        {
        }
        Protocol(const char *s)
            : bytes(s != nullptr ? s : "")
        {
        }

        void clear() noexcept { bytes.clear(); }
        [[nodiscard]] bool empty() const noexcept { return bytes.empty(); }
        [[nodiscard]] size_t size() const noexcept { return bytes.size(); }
        [[nodiscard]] size_t capacity() const noexcept { return bytes.capacity(); }
        [[nodiscard]] const char *data() const noexcept { return bytes.data(); }

        operator std::string &() & noexcept { return bytes; }
        operator const std::string &() const & noexcept { return bytes; }
        operator std::string() && noexcept { return std::move(bytes); }
        operator std::string_view() const noexcept { return bytes; }

        Protocol &operator=(std::string s) noexcept
        {
            bytes = std::move(s);
            return *this;
        }

        Protocol &operator=(std::string_view sv)
        {
            bytes.assign(sv);
            return *this;
        }

        bool operator==(const Protocol &other) const noexcept { return bytes == other.bytes; }
        bool operator==(std::string_view sv) const noexcept { return bytes == sv; }
        bool operator==(const char *s) const noexcept { return bytes == s; }

        friend std::ostream &operator<<(std::ostream &os, const Protocol &p) { return os << p.bytes; }
    };

    struct EmptyProtocol
    {
    };

    enum class TransportType : uint8_t
    {
        TCP,
        UDP
    };

    /**
     * @brief 真实传输套接字端点（封装基础套接字系统调用与地址状态）
     */
    struct SocketEndpoint
    {
        int fd{-1};
        sockaddr_in addr{};

        [[nodiscard]] constexpr bool valid() const noexcept { return fd >= 0; }
        [[nodiscard]] constexpr int getFd() const noexcept { return fd; }
        [[nodiscard]] constexpr const sockaddr_in &getAddr() const noexcept { return addr; }

        inline void reset() noexcept
        {
            if (fd >= 0)
            {
                ::close(fd);
                fd = -1;
            }
            addr = {};
        }

        [[nodiscard]] inline Result<int> listenTcp(const char *ip, int port, int backlog = 128, bool reuseAddr = true,
                                                   bool reusePort = true) noexcept
        {
            reset();
            if (ip == nullptr || port < 0 || port > 65535) [[unlikely]]
            {
                return std::unexpected(ERR::ADDR_INVALID);
            }

            ::signal(SIGPIPE, SIG_IGN);

            addr.sin_family = AF_INET;
            if (::inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) [[unlikely]]
            {
                LOG_ERROR("SocketEndpoint::listenTcp {}:{}: not an IPv4 address literal", ip, port);
                return std::unexpected(ERR::ADDR_INVALID);
            }
            addr.sin_port = ::htons(static_cast<uint16_t>(port));

            fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (fd < 0) [[unlikely]]
            {
                LOG_ERROR("SocketEndpoint::listenTcp {}:{}: socket() failed: {}", ip, port, errnoText(errno));
                return std::unexpected(ERR::SOCKET_FAILED);
            }

            constexpr int opt = 1;
            if (reuseAddr)
            {
                if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) [[unlikely]]
                {
                    LOG_ERROR("SocketEndpoint::listenTcp {}:{}: setsockopt(SO_REUSEADDR) failed: {}", ip, port,
                              errnoText(errno));
                    reset();
                    return std::unexpected(ERR::SETSOCKOPT_FAILED);
                }
            }
            if (reusePort)
            {
                if (::setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) [[unlikely]]
                {
                    LOG_ERROR("SocketEndpoint::listenTcp {}:{}: setsockopt(SO_REUSEPORT) failed: {}", ip, port,
                              errnoText(errno));
                    reset();
                    return std::unexpected(ERR::SETSOCKOPT_FAILED);
                }
            }

            if (::bind(fd, reinterpret_cast<const sockaddr *>(&addr), sizeof(sockaddr_in)) < 0) [[unlikely]]
            {
                LOG_ERROR("SocketEndpoint::listenTcp {}:{}: bind() failed: {}", ip, port, errnoText(errno));
                reset();
                return std::unexpected(ERR::BIND_FAILED);
            }

            if (::listen(fd, backlog) < 0) [[unlikely]]
            {
                LOG_ERROR("SocketEndpoint::listenTcp {}:{}: listen() failed: {}", ip, port, errnoText(errno));
                reset();
                return std::unexpected(ERR::LISTEN_FAILED);
            }

            if (port == 0)
            {
                socklen_t len = sizeof(addr);
                ::getsockname(fd, reinterpret_cast<sockaddr *>(&addr), &len);
            }

            return fd;
        }

        [[nodiscard]] inline Result<int> listenUdp(const char *ip, int port, bool reuseAddr = true,
                                                   bool reusePort = true) noexcept
        {
            reset();
            if (ip == nullptr || port < 0 || port > 65535) [[unlikely]]
            {
                return std::unexpected(ERR::ADDR_INVALID);
            }

            addr.sin_family = AF_INET;
            if (::inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) [[unlikely]]
            {
                LOG_ERROR("SocketEndpoint::listenUdp {}:{}: not an IPv4 address literal", ip, port);
                return std::unexpected(ERR::ADDR_INVALID);
            }
            addr.sin_port = ::htons(static_cast<uint16_t>(port));

            fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (fd < 0) [[unlikely]]
            {
                LOG_ERROR("SocketEndpoint::listenUdp {}:{}: socket() failed: {}", ip, port, errnoText(errno));
                return std::unexpected(ERR::SOCKET_FAILED);
            }

            constexpr int opt = 1;
            if (reuseAddr)
            {
                if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) [[unlikely]]
                {
                    LOG_ERROR("SocketEndpoint::listenUdp {}:{}: setsockopt(SO_REUSEADDR) failed: {}", ip, port,
                              errnoText(errno));
                    reset();
                    return std::unexpected(ERR::SETSOCKOPT_FAILED);
                }
            }
            if (reusePort)
            {
                if (::setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) [[unlikely]]
                {
                    LOG_ERROR("SocketEndpoint::listenUdp {}:{}: setsockopt(SO_REUSEPORT) failed: {}", ip, port,
                              errnoText(errno));
                    reset();
                    return std::unexpected(ERR::SETSOCKOPT_FAILED);
                }
            }

            if (::bind(fd, reinterpret_cast<const sockaddr *>(&addr), sizeof(sockaddr_in)) < 0) [[unlikely]]
            {
                LOG_ERROR("SocketEndpoint::listenUdp {}:{}: bind() failed: {}", ip, port, errnoText(errno));
                reset();
                return std::unexpected(ERR::BIND_FAILED);
            }

            if (port == 0)
            {
                socklen_t len = sizeof(addr);
                ::getsockname(fd, reinterpret_cast<sockaddr *>(&addr), &len);
            }

            return fd;
        }

        [[nodiscard]] inline Result<std::pair<int, sockaddr_in>> accept() noexcept
        {
            if (fd < 0) [[unlikely]]
            {
                return std::unexpected(ERR::ACCEPT_FAILED);
            }
            sockaddr_in clientAddr{};
            socklen_t len = sizeof(clientAddr);
            int clientFd = ::accept4(fd, reinterpret_cast<sockaddr *>(&clientAddr), &len, SOCK_NONBLOCK | SOCK_CLOEXEC);
            if (clientFd < 0) [[unlikely]]
            {
                return std::unexpected(ERR::ACCEPT_FAILED);
            }
            return std::make_pair(clientFd, clientAddr);
        }

        [[nodiscard]] inline Result<int> connectTcp(const char *ip, int port) noexcept
        {
            reset();
            if (ip == nullptr || port < 0 || port > 65535) [[unlikely]]
            {
                return std::unexpected(ERR::ADDR_INVALID);
            }

            addr.sin_family = AF_INET;
            if (::inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) [[unlikely]]
            {
                return std::unexpected(ERR::ADDR_INVALID);
            }
            addr.sin_port = ::htons(static_cast<uint16_t>(port));

            fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (fd < 0) [[unlikely]]
            {
                return std::unexpected(ERR::SOCKET_FAILED);
            }

            int rc = ::connect(fd, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr));
            if (rc < 0 && errno != EINPROGRESS) [[unlikely]]
            {
                reset();
                return std::unexpected(ERR::CONNECT_FAILED);
            }

            return fd;
        }
    };

    /**
     * @brief 协议监听端点封装（抽象单一端口监听器，支持 TCP 或 UDP 传输）
     */
    struct Listener
    {
        SocketEndpoint socket{};
        TransportType transport{TransportType::TCP};
        uint16_t configuredPort{0};
        int token{0};

        [[nodiscard]] constexpr bool isTcp() const noexcept { return transport == TransportType::TCP; }
        [[nodiscard]] constexpr bool isUdp() const noexcept { return transport == TransportType::UDP; }

        [[nodiscard]] constexpr bool valid() const noexcept { return socket.valid(); }
        [[nodiscard]] constexpr int fd() const noexcept { return socket.fd; }
        [[nodiscard]] constexpr const sockaddr_in &addr() const noexcept { return socket.addr; }

        inline void reset() noexcept { socket.reset(); }

        [[nodiscard]] inline Result<int> listen(const char *ip, int port = 0, int backlog = 128, bool reuseAddr = true,
                                                bool reusePort = true) noexcept
        {
            if (port == 0 && configuredPort != 0)
            {
                port = configuredPort;
            }
            if (isTcp())
            {
                return socket.listenTcp(ip, port, backlog, reuseAddr, reusePort);
            }
            else
            {
                return socket.listenUdp(ip, port, reuseAddr, reusePort);
            }
        }
    };

    /**
     * @brief 编译期监听器规格配置（用于去重与端口推导）
     */
    struct ListenerConfig
    {
        TransportType transport{TransportType::TCP};
        uint16_t defaultPort{0};
        size_t tag{0};

        constexpr bool operator==(const ListenerConfig &other) const noexcept
        {
            return transport == other.transport && defaultPort == other.defaultPort && tag == other.tag;
        }
    };

    /**
     * @brief 编译期空传输套接字端点（0 字节占位）
     */
    struct EmptySocket
    {
        static constexpr int fd = -1;
        static constexpr sockaddr_in addr{};

        [[nodiscard]] static constexpr bool valid() noexcept { return false; }
        [[nodiscard]] static constexpr int getFd() noexcept { return -1; }
        [[nodiscard]] static constexpr const sockaddr_in &getAddr() noexcept { return addr; }
        static constexpr void reset() noexcept {}

        [[nodiscard]] static constexpr Result<int> listenTcp(const char *, int, int = 128, bool = true,
                                                             bool = true) noexcept
        {
            return std::unexpected(ERR::SOCKET_FAILED);
        }
        [[nodiscard]] static constexpr Result<int> listenUdp(const char *, int, bool = true, bool = true) noexcept
        {
            return std::unexpected(ERR::SOCKET_FAILED);
        }
        [[nodiscard]] static constexpr Result<std::pair<int, sockaddr_in>> accept() noexcept
        {
            return std::unexpected(ERR::SOCKET_FAILED);
        }
        [[nodiscard]] static constexpr Result<int> connectTcp(const char *, int) noexcept
        {
            return std::unexpected(ERR::SOCKET_FAILED);
        }
    };

    /**
     * @brief 编译期协议套接字组合（按需零开销分配）
     */
    template <bool EnableTcp, bool EnableUdp>
    struct TransportSockets
    {
        using TcpEndpoint = std::conditional_t<EnableTcp, SocketEndpoint, EmptySocket>;
        using UdpEndpoint = std::conditional_t<EnableUdp, SocketEndpoint, EmptySocket>;

        [[no_unique_address]] TcpEndpoint tcp{};
        [[no_unique_address]] UdpEndpoint udp{};

        inline void reset() noexcept
        {
            if constexpr (EnableTcp)
            {
                tcp.reset();
            }
            if constexpr (EnableUdp)
            {
                udp.reset();
            }
        }
    };

    namespace net
    {
        [[nodiscard]] inline Result<int> listenTcp(const char *ip, int port, sockaddr_in &outAddr, int backlog = 128,
                                                   bool reuseAddr = true, bool reusePort = true) noexcept
        {
            SocketEndpoint ep;
            auto res = ep.listenTcp(ip, port, backlog, reuseAddr, reusePort);
            if (!res)
                return res;
            outAddr = ep.addr;
            return res;
        }

        [[nodiscard]] inline Result<int> listenUdp(const char *ip, int port, sockaddr_in &outAddr,
                                                   bool reuseAddr = true, bool reusePort = true) noexcept
        {
            SocketEndpoint ep;
            auto res = ep.listenUdp(ip, port, reuseAddr, reusePort);
            if (!res)
                return res;
            outAddr = ep.addr;
            return res;
        }

        [[nodiscard]] inline Result<std::pair<int, sockaddr_in>> accept(int listenFd) noexcept
        {
            SocketEndpoint ep;
            ep.fd = listenFd;
            return ep.accept();
        }

        [[nodiscard]] inline Result<int> connectTcp(const char *ip, int port, sockaddr_in &targetAddr) noexcept
        {
            SocketEndpoint ep;
            auto res = ep.connectTcp(ip, port);
            if (!res)
                return res;
            targetAddr = ep.addr;
            return res;
        }

        [[nodiscard]] inline Result<> checkConnectError(int socketFd) noexcept
        {
            if (socketFd < 0)
                return std::unexpected(ERR::SOCKET_FAILED);
            int err = 0;
            socklen_t len = sizeof(err);
            if (::getsockopt(socketFd, SOL_SOCKET, SO_ERROR, &err, &len) < 0)
                return std::unexpected(ERR::SOCKET_FAILED);
            if (err != 0)
                return std::unexpected(ERR::CONNECT_FAILED);
            return {};
        }
    } // namespace net

    /**
     * @brief 统一连接抽象基类
     *
     * 无论底层是原生 TCP，还是在 UDP 之上自己封装的可靠连接，皆统一继承自此类。
     */
    class ConnectionBase
    {
    protected:
        int fd_{-1};
        sockaddr_in peerAddr_{};
        TransportType transport_{TransportType::TCP};
        std::shared_ptr<const MynetConfig> config_{nullptr};

    public:
        ConnectionBase() = default;
        virtual ~ConnectionBase() = default;

        [[nodiscard]] inline int fd() const noexcept { return fd_; }
        inline void setFd(int fd) noexcept
        {
            fd_ = fd;
            if (fd_ >= 0)
            {
                config_ = getMynetConfigShared();
            }
        }
        [[nodiscard]] inline const sockaddr_in &peerAddr() const noexcept { return peerAddr_; }
        inline void setPeerAddr(const sockaddr_in &addr) noexcept { peerAddr_ = addr; }
        [[nodiscard]] inline TransportType transport() const noexcept { return transport_; }
        inline void setTransport(TransportType t) noexcept { transport_ = t; }

        [[nodiscard]] inline bool isTcp() const noexcept { return transport_ == TransportType::TCP; }
        [[nodiscard]] inline bool isUdp() const noexcept { return transport_ == TransportType::UDP; }

        [[nodiscard]] inline const MynetConfig &config() const noexcept
        {
            return config_ ? *config_ : *getMynetConfigShared();
        }

        [[nodiscard]] inline const std::shared_ptr<const MynetConfig> &configShared() const noexcept { return config_; }

        [[nodiscard]] inline uint32_t configGeneration() const noexcept
        {
            return MynetConfigHolder::getInstance().getGeneration();
        }

        virtual IO_STATUS handleRead() { return IO_STATUS::KEEP; }
        virtual IO_STATUS handleWrite() { return IO_STATUS::KEEP; }
        virtual void handle() {}
        virtual void close() {}
        virtual void reset() noexcept {}
    };

    /**
     * @brief 偏连接的流式协议处理器基类
     *
     * 继承自 ConnectionBase，提供流式会话所需的全部传输状态。
     */
    class HandlerConnection : public ConnectionBase
    {
    public:
        using SPLICE_CONTROL = mynet::SPLICE_CONTROL;

        /// 是否允许该处理器使用 Linux splice(2) 内核零拷贝（派生类按协议特性开启）
        static constexpr bool kEnableSplice = true;

        using RequestCallback = std::function<void(uint8_t cmd, const handler::ProxyAddress &target)>;

        inline void enableSpliceForward(int targetFd) noexcept { setSpliceTarget(targetFd); }
        inline void enableSpliceForward(SPLICE_CONTROL ctrl) noexcept { setSpliceTarget(ctrl); }
        inline void disableSpliceForward() noexcept { disableSplice(); }
        [[nodiscard]] inline bool isSpliceForwardActive() const noexcept { return isSpliceActive(); }

        // ---- 代理与状态机公共接口 (Proxy & State Machine Hooks) ----
        virtual void handle() {}

        void setOnRequest(RequestCallback cb) noexcept { requestCallback_ = std::move(cb); }
        void setTarget(const handler::ProxyAddress &target) noexcept
        {
            targetAddress_ = target;
            target_ = target;
        }
        void setCommand(uint8_t cmd) noexcept { command_ = cmd; }
        void setStage(handler::InboundStage st) noexcept { inboundStage_ = st; }
        void setStage(handler::OutboundStage st) noexcept { outboundStage_ = st; }

        [[nodiscard]] inline handler::InboundStage inboundStage() const noexcept { return inboundStage_; }
        [[nodiscard]] inline handler::OutboundStage outboundStage() const noexcept { return outboundStage_; }
        [[nodiscard]] inline handler::InboundStage stage() const noexcept { return inboundStage_; }
        [[nodiscard]] virtual bool isEstablished() const noexcept
        {
            return inboundStage_ == handler::InboundStage::STREAMING ||
                   outboundStage_ == handler::OutboundStage::STREAMING;
        }
        [[nodiscard]] inline uint8_t command() const noexcept { return command_; }
        [[nodiscard]] inline const std::optional<handler::ProxyAddress> &targetAddress() const noexcept
        {
            return targetAddress_;
        }
        [[nodiscard]] inline const handler::ProxyAddress &target() const noexcept
        {
            if (targetAddress_.has_value())
            {
                return *targetAddress_;
            }
            return target_;
        }

        /**
         * @brief 默认构造函数（使用全局 ConnectionConfig 设定的默认响应队列容量与参数）
         */
        HandlerConnection() noexcept
            : HandlerConnection(getConnectionConfig())
        {
        }

        /**
         * @brief 显式指定响应队列槽位容量构造
         *
         * @param responseCapacity 响应队列槽位容量（开箱即可用，支持后续按需 reserveResponses 调整）
         */
        explicit HandlerConnection(size_t responseCapacity) noexcept
        {
            [[maybe_unused]] auto _ =
                responseQueue_.init(responseCapacity); // 槽位分配失败降级为容量 0 拒收，不折损零异常构造
        }

        /**
         * @brief 显式传入完整连接配置构造
         */
        explicit HandlerConnection(const ConnectionConfig &config) noexcept
            : maxRequestBytes_(config.maxRequestBytes)
        {
            requestBuffer_.setHighWaterMark(config.readHighWaterMark);
            [[maybe_unused]] auto _ = responseQueue_.init(config.responseCapacity);
        }

        /**
         * @brief 显式传入目标地址构造（出站代理协议使用）
         */
        explicit HandlerConnection(const handler::ProxyAddress &target) noexcept
            : HandlerConnection()
        {
            targetAddress_ = target;
            target_ = target;
        }

        virtual ~HandlerConnection() noexcept = default;

        HandlerConnection(const HandlerConnection &) =
            delete; // a connection handler holds parser state bound to one connection
        HandlerConnection &operator=(const HandlerConnection &) =
            delete; // a connection handler holds parser state bound to one connection
        HandlerConnection(HandlerConnection &&) =
            delete; // a connection handler holds parser state bound to one connection
        HandlerConnection &
        operator=(HandlerConnection &&) = delete; // a connection handler holds parser state bound to one connection

        /**
         * @brief 重置处理器状态（派生类重置专属解析器后应调用本实现）
         */
        virtual void reset() noexcept
        {
            requestBuffer_.reset();
            requestBuffer_.setHighWaterMark(getConnectionConfig().readHighWaterMark);
            responseQueue_.reset();
            spare_.clear();
            closeAfterResponse_ = false;
            spliceControl_ = SPLICE_CONTROL::DISABLED;
            spliceTargetFd_ = -1;
            maxRequestBytes_ = getConnectionConfig().maxRequestBytes;
            fd_ = -1;
            inboundStage_ = handler::InboundStage::HANDSHAKE;
            outboundStage_ = handler::OutboundStage::INITIAL;
            targetAddress_.reset();
            target_ = {};
            command_ = 0;
            requestCallback_ = nullptr;
        }

        // ---- 读取侧控制 (Read Side) ----

        /**
         * @brief 追加一段对端请求字节到解析缓冲（零异常，失败显式错误码）
         *
         * RequestBuffer::append() 为 nothrow 接口：堆扩容失败以 ERR::BUF_ALLOC_FAILED
         * 交付，缓冲区保持原样，调用方据此可安全丢弃本次读到的字节（对端重传
         * 或连接关闭兜底）。
         *
         * @param buf 对端字节首地址（允许为 nullptr，此时为无操作）
         * @param rn 本次读取的字节数（须非负）
         * @return 成功 {}；解析缓冲扩容失败 std::unexpected(ERR::BUF_ALLOC_FAILED)
         */
        [[nodiscard]] inline Result<> appendRequest(const char *buf, ssize_t rn) noexcept
        {
            if (buf != nullptr && rn > 0) [[likely]]
            {
                return requestBuffer_.append(buf, static_cast<size_t>(rn));
            }
            return {};
        }

        /**
         * @brief 追加一段视图请求字节到解析缓冲（视图适配重载）
         */
        [[nodiscard]] inline Result<> appendRequest(std::string_view sv) noexcept
        {
            return appendRequest(sv.data(), static_cast<ssize_t>(sv.size()));
        }

        /**
         * @brief 确保请求解析缓冲区至少拥有 minBytes 的可直写连续空间（零拷贝直接读取）
         *
         * @param minBytes 期望的最小写窗口字节数（默认由全局 ConnectionConfig 提供）
         * @return 成功返回可直写的内存首地址指针；扩容失败返回错误码
         */
        [[nodiscard]] inline std::expected<char *, ERR>
        prepareRequestWritable(size_t minBytes = getConnectionConfig().readChunkSize) noexcept
        {
            if (auto res = requestBuffer_.ensureWritable(minBytes); !res) [[unlikely]]
            {
                return std::unexpected(res.error());
            }
            return requestBuffer_.writableBegin();
        }

        /**
         * @brief 当前请求缓冲区可直接写入的连续窗口首地址
         */
        [[nodiscard]] inline char *requestWritableBegin() noexcept { return requestBuffer_.writableBegin(); }

        /**
         * @brief 当前请求缓冲区可直接写入的连续窗口大小
         */
        [[nodiscard]] inline size_t requestWritableBytes() const noexcept { return requestBuffer_.writableBytes(); }

        /**
         * @brief 提交直写到请求解析缓冲区的实际字节数
         *
         * @param n 实际写入字节数（不得超过 requestWritableBytes()）
         */
        inline void commitRequest(size_t n) noexcept { requestBuffer_.commitWritten(n); }

        [[nodiscard]] inline bool requestOverLimit() const noexcept
        {
            return requestBuffer_.readableBytes() > maxRequestBytes_;
        }

        [[nodiscard]] inline size_t requestBytes() const noexcept { return requestBuffer_.readableBytes(); }

        [[nodiscard]] inline const char *requestBegin() const noexcept { return requestBuffer_.readableBegin(); }

        inline void requestConsume(size_t n) noexcept { requestBuffer_.retrieve(n); }

        inline void requestClear() noexcept { requestBuffer_.reset(); }

        /**
         * @brief 剩余信用窗口（为 0 时事件循环将暂停接收读取，实施背压保护）
         */
        [[nodiscard]] inline size_t readCredit() const noexcept
        {
            const size_t used = requestBuffer_.readableBytes();
            return used >= maxRequestBytes_ ? 0 : maxRequestBytes_ - used;
        }

        inline void setMaxRequestBytes(size_t n) noexcept { maxRequestBytes_ = n; }
        [[nodiscard]] inline size_t maxRequestBytes() const noexcept { return maxRequestBytes_; }

        // ---- 发送响应侧控制 (Write Side) ----

        [[nodiscard]] inline bool hasResponse() const noexcept { return !responseQueue_.empty(); }

        /**
         * @brief 处理器是否因出站背压而暂缓了解码、且凭当前状态仍能继续推进
         *
         * 连接层在响应队列被搬运之后据此重新驱动 handle()。默认 false：只有
         * 会主动分轮解码的处理器（如 HandlerHttp2）才需要覆写。
         */
        [[nodiscard]] inline bool needsHandle() const noexcept { return false; }

        [[nodiscard]] inline size_t responseCount() const noexcept { return responseQueue_.size(); }

        /**
         * @brief 响应队列的槽位容量（用于在压满前施加背压，避免 mux 帧被丢弃）
         */
        [[nodiscard]] inline size_t responseCapacity() const noexcept { return responseQueue_.capacity(); }

        [[nodiscard]] inline std::string takeResponse()
        {
            if (responseQueue_.empty()) [[unlikely]]
            {
                return std::string();
            }
            std::string out = std::move(responseQueue_.front());
            if (spare_.capacity() > 0)
            {
                responseQueue_.front() = std::move(spare_);
            }
            responseQueue_.pop();
            return out;
        }

        /**
         * @brief 回收已发送完毕的空闲响应缓冲区（零堆重分配复用）
         */
        inline void recycleSpare(std::string &&s) noexcept
        {
            if (s.capacity() > spare_.capacity())
            {
                s.clear();
                spare_ = std::move(s);
            }
        }

        /**
         * @brief 推入一条完整响应（移动语义）
         */
        [[nodiscard]] inline Result<> pushResponse(std::string &&s) noexcept
        {
            return responseQueue_.push(std::move(s));
        }

        /**
         * @brief 推入一条完整响应（左值引用，转为视图原地复用槽位容量）
         */
        [[nodiscard]] inline Result<> pushResponse(const std::string &s) noexcept
        {
            return pushResponse(std::string_view(s));
        }

        /**
         * @brief 推入一段视图响应（零拷贝适配 string_view 与连续字节）
         */
        [[nodiscard]] inline Result<> pushResponse(std::string_view sv) noexcept
        {
            if (sv.data() == nullptr || sv.empty())
            {
                return {};
            }
            return responseQueue_.emplace(sv);
        }

        /**
         * @brief 推入以空终止的字符串字面量（重载消歧义，内部转为 string_view）
         */
        [[nodiscard]] inline Result<> pushResponse(const char *s) noexcept
        {
            if (s == nullptr) [[unlikely]]
            {
                return {};
            }
            return pushResponse(std::string_view(s));
        }

        /**
         * @brief 预分配响应队列槽位（连接建立时调用一次）
         *
         * @param capacity 槽位数量（允许流水线化的最大响应条数）
         * @return 成功 {}；槽位分配失败 std::unexpected(ERR::POOL_ALLOC_FAILED)
         */
        [[nodiscard]] inline Result<> reserveResponses(size_t capacity) noexcept
        {
            return responseQueue_.init(capacity);
        }

        // ---- 生命周期管理 (Lifecycle) ----

        [[nodiscard]] inline bool closeAfterResponse() const noexcept { return closeAfterResponse_; }

        inline void setCloseAfterResponse(bool v) noexcept { closeAfterResponse_ = v; }

        // ---- 零拷贝管道控制 (Zero-Copy Splice Routing) ----

        /**
         * @brief 设置零拷贝数据转发的目标描述符
         *
         * 解耦核心：不再写死当前套接字。
         * - targetFd >= 0: 转发至目标描述符，自动将状态切换为 ACTIVE；
         * - targetFd < 0: 关闭零拷贝，回到 DISABLED。
         */
        inline void setSpliceTarget(int targetFd) noexcept
        {
            spliceTargetFd_ = targetFd;
            spliceControl_ = (targetFd >= 0) ? SPLICE_CONTROL::ACTIVE : SPLICE_CONTROL::DISABLED;
        }

        /**
         * @brief 设置零拷贝管道控制状态
         */
        inline void setSpliceControl(SPLICE_CONTROL ctrl) noexcept
        {
            spliceControl_ = ctrl;
            if (ctrl == SPLICE_CONTROL::DISABLED || ctrl == SPLICE_CONTROL::CLOSED)
            {
                spliceTargetFd_ = -1;
            }
        }

        /**
         * @brief 设置零拷贝目标控制状态（重定向至 setSpliceControl）
         */
        inline void setSpliceTarget(SPLICE_CONTROL ctrl) noexcept { setSpliceControl(ctrl); }

        [[nodiscard]] inline SPLICE_CONTROL spliceControl() const noexcept { return spliceControl_; }
        [[nodiscard]] inline int spliceTarget() const noexcept { return spliceTargetFd_; }
        [[nodiscard]] inline bool isSpliceActive() const noexcept
        {
            return spliceControl_ == SPLICE_CONTROL::ACTIVE && spliceTargetFd_ >= 0;
        }

        /// 挂起 / 暂停零拷贝直通
        inline void pauseSplice() noexcept
        {
            if (spliceControl_ == SPLICE_CONTROL::ACTIVE)
            {
                spliceControl_ = SPLICE_CONTROL::PAUSED;
            }
        }

        /// 恢复零拷贝直通
        inline void resumeSplice() noexcept
        {
            if (spliceControl_ == SPLICE_CONTROL::PAUSED)
            {
                spliceControl_ = (spliceTargetFd_ >= 0) ? SPLICE_CONTROL::ACTIVE : SPLICE_CONTROL::DISABLED;
            }
        }

        /// 排空零拷贝管道残留数据
        inline void drainSplice() noexcept
        {
            if (spliceControl_ == SPLICE_CONTROL::ACTIVE)
            {
                spliceControl_ = SPLICE_CONTROL::DRAINING;
            }
        }

        /// 禁用零拷贝
        inline void disableSplice() noexcept
        {
            spliceControl_ = SPLICE_CONTROL::DISABLED;
            spliceTargetFd_ = -1;
        }

        [[nodiscard]] inline bool spliceEnabled() const noexcept { return isSpliceActive(); }

        /**
         * @brief 连接就绪与描述符分配钩子
         *
         * 在连接成功建立并绑定底层 fd 后由 Connection 层回调。
         *
         * @param fd 连接关联的底层套接字文件描述符
         */
        virtual void onConnect(int fd) noexcept { fd_ = fd; }

        [[nodiscard]] inline int fd() const noexcept { return fd_; }

        /**
         * @brief 协议升级钩子（如 HTTP/1.1 Upgrade，连接语义由此移交上层）
         */
        virtual void onUpgrade() noexcept {}

        /**
         * @brief 一条协议消息处理完成（流式消息）
         */
        virtual void onMessageComplete() noexcept {}

        /**
         * @brief 协议解析失败
         *
         * @param reason 人类可读的失败原因，允许为空指针
         */
        virtual void onParseError([[maybe_unused]] const char *reason) noexcept
        {
            inboundStage_ = handler::InboundStage::ERROR;
            outboundStage_ = handler::OutboundStage::ERROR;
        }

    protected:
        RequestBuffer requestBuffer_;
        ResponseQueue responseQueue_;
        std::string spare_{};
        size_t maxRequestBytes_ = getConnectionConfig().maxRequestBytes;
        bool closeAfterResponse_ = false;
        SPLICE_CONTROL spliceControl_ = SPLICE_CONTROL::DISABLED;
        int spliceTargetFd_ = -1;
        int fd_ = -1;
        handler::InboundStage inboundStage_{handler::InboundStage::HANDSHAKE};
        handler::OutboundStage outboundStage_{handler::OutboundStage::INITIAL};
        std::optional<handler::ProxyAddress> targetAddress_{std::nullopt};
        handler::ProxyAddress target_{};
        uint8_t command_{0};
        RequestCallback requestCallback_{nullptr};
    };

    /**
     * @brief 偏连接的流式处理器派生约束
     *
     * 要求派生自 HandlerConnection，而非仅仅方法上凑齐同名成员。
     * 这条约束才是连接层真正依赖的不变量：请求缓冲区、响应队列、读信用与
     * 关闭语义必须来自同一个已在构造时定容的基类子对象。
     */
    template <typename H>
    concept DerivedFromHandlerConnection = std::derived_from<H, HandlerConnection>;

    /**
     * @brief 流式会话处理器的必需方法集合
     *
     * 名字直指含义：这是 Connection<H> 及流式处理架构下对派生处理器的全量契约清单，
     * 逐项校验所有成员函数的签名与 noexcept 规范，防止派生类用 = delete 或不兼容签名破坏契约。
     */
    template <typename H>
    concept MandatoryMethodConnection =
        DerivedFromHandlerConnection<H> && Resettable<H> &&
        requires(H &h, const char *buf, ssize_t rn, size_t n, std::string_view sv, const std::string &str,
                 std::string &&s, bool b, int fd, SPLICE_CONTROL ctrl) {
            // ---- 读取侧控制 (Read Side) ----
            { h.appendRequest(buf, rn) } noexcept -> std::same_as<Result<>>;
            { h.appendRequest(sv) } noexcept -> std::same_as<Result<>>;
            { h.prepareRequestWritable(n) } noexcept -> std::same_as<std::expected<char *, ERR>>;
            { h.requestWritableBegin() } noexcept -> std::same_as<char *>;
            { h.requestWritableBytes() } noexcept -> std::same_as<size_t>;
            { h.commitRequest(n) } noexcept;
            { h.requestOverLimit() } noexcept -> std::same_as<bool>;
            { h.requestBytes() } noexcept -> std::same_as<size_t>;
            { h.requestBegin() } noexcept -> std::same_as<const char *>;
            { h.requestConsume(n) } noexcept;
            { h.requestClear() } noexcept;
            { h.readCredit() } noexcept -> std::same_as<size_t>;
            { h.setMaxRequestBytes(n) } noexcept;

            // ---- 发送响应侧控制 (Write Side) ----
            { h.hasResponse() } noexcept -> std::same_as<bool>;
            { h.responseCount() } noexcept -> std::same_as<size_t>;
            { h.takeResponse() } -> std::same_as<std::string>;
            { h.recycleSpare(std::move(s)) } noexcept;
            { h.pushResponse(std::move(s)) } noexcept -> std::same_as<Result<>>;
            { h.pushResponse(str) } noexcept -> std::same_as<Result<>>;
            { h.pushResponse(sv) } noexcept -> std::same_as<Result<>>;
            { h.pushResponse(buf) } noexcept -> std::same_as<Result<>>;
            { h.reserveResponses(n) } noexcept -> std::same_as<Result<>>;

            // ---- 生命周期管理 (Lifecycle) ----
            { h.closeAfterResponse() } noexcept -> std::same_as<bool>;
            { h.setCloseAfterResponse(b) } noexcept;

            // ---- 零拷贝管道控制 (Zero-Copy Splice Routing) ----
            { h.setSpliceTarget(fd) } noexcept;
            { h.setSpliceTarget(ctrl) } noexcept;
            { h.setSpliceControl(ctrl) } noexcept;
            { h.spliceControl() } noexcept -> std::same_as<SPLICE_CONTROL>;
            { h.spliceTarget() } noexcept -> std::same_as<int>;
            { h.isSpliceActive() } noexcept -> std::same_as<bool>;
            { h.pauseSplice() } noexcept;
            { h.resumeSplice() } noexcept;
            { h.drainSplice() } noexcept;
            { h.disableSplice() } noexcept;
            { h.spliceEnabled() } noexcept -> std::same_as<bool>;

            // ---- 协议钩子与连接状态 (Hooks & Connection State) ----
            { h.onConnect(fd) } noexcept;
            { h.onUpgrade() } noexcept;
            { h.onMessageComplete() } noexcept;
            { h.onParseError(buf) } noexcept;
            { h.fd() } noexcept -> std::same_as<int>;
            { h.handle() };
        };

    /**
     * @brief 握手演进状态别名
     */
    enum class HANDSHAKE_STATUS : uint8_t
    {
        DONE = 0,
        IN_PROGRESS = 1,
        FAILED = 2
    };

    namespace detail
    {
        template <typename T1, typename T2>
        struct ConnectionTypes
        {
            using Protocol = T1;
            using Handler = T2;
        };

        template <typename T1>
        struct ConnectionTypes<T1, void>
        {
            static constexpr bool isHandler = std::derived_from<T1, HandlerConnection>;
            using Protocol = std::conditional_t<isHandler, EmptyProtocol, T1>;
            using Handler = std::conditional_t<isHandler, T1, HandlerConnection>;
        };

        template <>
        struct ConnectionTypes<EmptyProtocol, void>
        {
            using Protocol = EmptyProtocol;
            using Handler = HandlerConnection;
        };
    } // namespace detail

    /**
     * @brief 活跃网络连接核心数据与传输聚合体
     *
     * 架构核心支柱：
     * 1. 纯净流式抽象：本类专职负责底层流式连接（TCP/流套接字）的数据传输、零拷贝 splice、读写缓冲背压与事件调度；
     * 2. 彻底剥离握手：入站 TLS 握手等专职逻辑彻底下沉至 AcceptorBase 体系，Connection 不包含 OpenSSL 握手函数；
     * 3. 编译期协议上下文占位：[[no_unique_address]] ProtocolContext protocol_{}，空协议类型占 0 字节；
     * 4. 业务解耦：handler_ 作为成员变量承载具体协议业务，未设置时为空指针（nullptr）；
     * 5. 无害抽象层：当 handler_ 为空时，Connection 表现为一个通用的无害纯流式连接，不强求业务处理器。
     */
    template <typename ProtoOrHandler = EmptyProtocol, typename MaybeHandler = void>
    class Connection : public ConnectionBase
    {
    public:
        using Types = detail::ConnectionTypes<ProtoOrHandler, MaybeHandler>;
        using ProtocolContext = typename Types::Protocol;
        using Handler = typename Types::Handler;
        using Protocol = ProtocolContext;

        enum class CONN_STATE : uint8_t
        {
            OPEN = 0,
            CLOSING = 1,
            CLOSED = 2
        };

        Connection() noexcept = default;
        ~Connection() noexcept override { reset(); }

        Connection(const Connection &) = delete;
        Connection &operator=(const Connection &) = delete;
        Connection(Connection &&) noexcept = default;
        Connection &operator=(Connection &&) noexcept = default;

        inline void setFd(int fd) noexcept
        {
            ConnectionBase::setFd(fd);
            if (fd_ >= 0)
            {
                applyQuickAck();
                handler().onConnect(fd_);
            }
        }

        // ---- 协议上下文与业务处理器挂钩 (Protocol & Handler Slots) ----

        [[nodiscard]] inline ProtocolContext &protocol() noexcept { return protocol_; }
        [[nodiscard]] inline const ProtocolContext &protocol() const noexcept { return protocol_; }

        inline void setHandler(Handler *h) noexcept { handler_ = h; }
        [[nodiscard]] inline bool hasHandler() const noexcept { return handler_ != nullptr; }

        [[nodiscard]] inline Handler &handler() noexcept
        {
            if (handler_ == nullptr)
            {
                if (!defaultHandler_.has_value())
                {
                    defaultHandler_.emplace();
                }
                handler_ = &(*defaultHandler_);
            }
            return *handler_;
        }

        [[nodiscard]] inline const Handler &handler() const noexcept
        {
            if (handler_ == nullptr)
            {
                auto *nonConst = const_cast<Connection *>(this);
                if (!nonConst->defaultHandler_.has_value())
                {
                    nonConst->defaultHandler_.emplace();
                }
                nonConst->handler_ = &(*nonConst->defaultHandler_);
            }
            return *handler_;
        }

        // ---- 连接基础属性与状态查询 ----

        [[nodiscard]] inline CONN_STATE state() const noexcept { return state_; }
        [[nodiscard]] inline uint32_t events() const noexcept { return events_; }
        inline void setEvents(uint32_t events) noexcept { events_ = events; }

        [[nodiscard]] inline bool wantRead() const noexcept { return !readPaused_ && state_ == CONN_STATE::OPEN; }
        [[nodiscard]] inline bool wantWrite() const noexcept { return wantWrite_ || hasPendingWrite(); }
        inline void setWantWrite(bool v) noexcept { wantWrite_ = v; }

        [[nodiscard]] inline bool hasPendingWrite() const noexcept
        {
            if (pendingBytes_ > 0 || pipePending_ > 0)
            {
                return true;
            }
            if (handler_ != nullptr && handler_->hasResponse())
            {
                return true;
            }
            return false;
        }

        [[nodiscard]] inline size_t pendingBytes() const noexcept { return pendingBytes_ + pipePending_; }
        [[nodiscard]] inline size_t pendingSize() const noexcept { return pendingBytes_ + pipePending_; }
        [[nodiscard]] inline size_t pipePending() const noexcept { return pipePending_; }

        [[nodiscard]] inline size_t writeHighWaterMark() const noexcept { return writeHighWaterMark_; }
        inline void setWriteHighWaterMark(size_t n) noexcept { writeHighWaterMark_ = n; }

        [[nodiscard]] inline bool closeAfterWrite() const noexcept { return closeAfterWrite_; }
        inline void setCloseAfterWrite(bool v) noexcept { closeAfterWrite_ = v; }

        [[nodiscard]] inline uint64_t timerId() const noexcept { return timerId_; }
        inline void setTimerId(uint64_t id) noexcept { timerId_ = id; }

        [[nodiscard]] inline std::chrono::steady_clock::time_point lastActive() const noexcept { return lastActive_; }
        inline void touch() noexcept { lastActive_ = std::chrono::steady_clock::now(); }

        // TLS 兼容存根（TLS 由 Acceptor 处理，Connection 层为纯流式传输，故恒返回空/假）
        [[nodiscard]] constexpr void *ssl() const noexcept { return nullptr; }
        [[nodiscard]] constexpr bool ktlsRxActive() const noexcept { return false; }
        [[nodiscard]] constexpr bool ktlsTxActive() const noexcept { return false; }

        // ---- 零拷贝管道控制 (Zero-Copy Splice Routing) ----

        [[nodiscard]] inline bool isSpliceEnabled() const noexcept
        {
            if (handler_ != nullptr)
            {
                return Handler::kEnableSplice && handler_->isSpliceActive();
            }
            return false;
        }

        [[nodiscard]] inline bool ensurePipe() noexcept
        {
            if (pipeFd_[0] >= 0) [[likely]]
            {
                return true;
            }
            if (::pipe2(pipeFd_, O_NONBLOCK | O_CLOEXEC) < 0) [[unlikely]]
            {
                LOG_WARN("Connection::ensurePipe: fd {}: pipe2 failed: {}", fd_, errnoText(errno));
                pipeFd_[0] = -1;
                pipeFd_[1] = -1;
                return false;
            }
            return true;
        }

        [[nodiscard]] inline std::expected<size_t, IO_END>
        spliceTo(int targetFd, size_t maxBytes = getConnectionConfig().spliceChunkSize) noexcept
        {
            if (targetFd < 0 || fd_ < 0) [[unlikely]]
            {
                return std::unexpected(IO_END::FATAL);
            }
            if (!ensurePipe()) [[unlikely]]
            {
                return std::unexpected(IO_END::FATAL);
            }

            while (pipePending_ > 0)
            {
                const ssize_t sOut =
                    ::splice(pipeFd_[0], nullptr, targetFd, nullptr, pipePending_, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
                if (sOut > 0) [[likely]]
                {
                    pipePending_ -= static_cast<size_t>(sOut);
                    continue;
                }
                if (sOut < 0)
                {
                    if (errno == EINTR)
                        continue;
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                        return std::unexpected(IO_END::WOULDBLOCK);
                    return std::unexpected(IO_END::FATAL);
                }
                break;
            }
            if (pipePending_ > 0)
            {
                return std::unexpected(IO_END::WOULDBLOCK);
            }

            const ssize_t sIn =
                ::splice(fd_, nullptr, pipeFd_[1], nullptr, maxBytes, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
            if (sIn <= 0)
            {
                if (sIn == 0)
                    return std::unexpected(IO_END::EOF_REACHED);
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    return std::unexpected(IO_END::WOULDBLOCK);
                if (errno == EINTR)
                    return 0;
                return std::unexpected(IO_END::FATAL);
            }

            pipePending_ += static_cast<size_t>(sIn);
            size_t totalWritten = 0;

            while (pipePending_ > 0)
            {
                const ssize_t sOut =
                    ::splice(pipeFd_[0], nullptr, targetFd, nullptr, pipePending_, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
                if (sOut > 0) [[likely]]
                {
                    pipePending_ -= static_cast<size_t>(sOut);
                    totalWritten += static_cast<size_t>(sOut);
                    continue;
                }
                if (sOut < 0 && errno == EINTR)
                    continue;
                break;
            }

            return totalWritten;
        }

        [[nodiscard]] inline std::expected<size_t, IO_END>
        spliceFrom(int sourceFd, size_t maxBytes = getConnectionConfig().spliceChunkSize) noexcept
        {
            if (sourceFd < 0 || fd_ < 0) [[unlikely]]
            {
                return std::unexpected(IO_END::FATAL);
            }
            if (!ensurePipe()) [[unlikely]]
            {
                return std::unexpected(IO_END::FATAL);
            }

            while (pipePending_ > 0)
            {
                const ssize_t sOut =
                    ::splice(pipeFd_[0], nullptr, fd_, nullptr, pipePending_, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
                if (sOut > 0) [[likely]]
                {
                    pipePending_ -= static_cast<size_t>(sOut);
                    continue;
                }
                if (sOut < 0)
                {
                    if (errno == EINTR)
                        continue;
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                        return std::unexpected(IO_END::WOULDBLOCK);
                    return std::unexpected(IO_END::FATAL);
                }
                break;
            }
            if (pipePending_ > 0)
            {
                return std::unexpected(IO_END::WOULDBLOCK);
            }

            const ssize_t sIn =
                ::splice(sourceFd, nullptr, pipeFd_[1], nullptr, maxBytes, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
            if (sIn <= 0)
            {
                if (sIn == 0)
                    return std::unexpected(IO_END::EOF_REACHED);
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    return std::unexpected(IO_END::WOULDBLOCK);
                if (errno == EINTR)
                    return 0;
                return std::unexpected(IO_END::FATAL);
            }

            pipePending_ += static_cast<size_t>(sIn);
            size_t totalWritten = 0;

            while (pipePending_ > 0)
            {
                const ssize_t sOut =
                    ::splice(pipeFd_[0], nullptr, fd_, nullptr, pipePending_, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
                if (sOut > 0) [[likely]]
                {
                    pipePending_ -= static_cast<size_t>(sOut);
                    totalWritten += static_cast<size_t>(sOut);
                    continue;
                }
                if (sOut < 0 && errno == EINTR)
                    continue;
                break;
            }

            return totalWritten;
        }

        inline IO_STATUS handleSplice() noexcept
        {
            if (handler_ == nullptr)
            {
                return IO_STATUS::KEEP;
            }

            const int targetFd = handler_->spliceTarget();
            const SPLICE_CONTROL ctrl = handler_->spliceControl();

            if (targetFd < 0 || ctrl == SPLICE_CONTROL::PAUSED || ctrl == SPLICE_CONTROL::CLOSED)
            {
                return IO_STATUS::KEEP;
            }

            const size_t spliceChunk = getConnectionConfig().spliceChunkSize;

            while (pipePending_ > 0)
            {
                const ssize_t sOut =
                    ::splice(pipeFd_[0], nullptr, targetFd, nullptr, pipePending_, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
                if (sOut > 0) [[likely]]
                {
                    pipePending_ -= static_cast<size_t>(sOut);
                    continue;
                }
                if (sOut < 0)
                {
                    if (errno == EINTR)
                        continue;
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                    {
                        wantWrite_ = true;
                        readPaused_ = true;
                        return IO_STATUS::KEEP;
                    }
                    peerGone_ = true;
                    return IO_STATUS::CLOSE;
                }
                break;
            }

            if (pipePending_ > 0)
            {
                wantWrite_ = true;
                readPaused_ = true;
                return IO_STATUS::KEEP;
            }

            if (ctrl == SPLICE_CONTROL::DRAINING)
            {
                handler_->setSpliceControl(SPLICE_CONTROL::CLOSED);
                return IO_STATUS::KEEP;
            }

            while (!readPaused_)
            {
                const ssize_t sIn =
                    ::splice(fd_, nullptr, pipeFd_[1], nullptr, spliceChunk, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
                if (sIn > 0) [[likely]]
                {
                    touch();
                    pipePending_ += static_cast<size_t>(sIn);

                    while (pipePending_ > 0)
                    {
                        const ssize_t sOut = ::splice(pipeFd_[0], nullptr, targetFd, nullptr, pipePending_,
                                                      SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
                        if (sOut > 0) [[likely]]
                        {
                            pipePending_ -= static_cast<size_t>(sOut);
                            continue;
                        }
                        if (sOut < 0)
                        {
                            if (errno == EAGAIN || errno == EWOULDBLOCK)
                            {
                                wantWrite_ = true;
                                readPaused_ = true;
                                return IO_STATUS::KEEP;
                            }
                            if (errno == EINTR)
                                continue;
                            peerGone_ = true;
                            return IO_STATUS::CLOSE;
                        }
                        break;
                    }
                    continue;
                }

                if (sIn == 0)
                {
                    peerGone_ = true;
                    return IO_STATUS::CLOSE;
                }

                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    break;
                }
                if (errno == EINTR)
                {
                    continue;
                }
                peerGone_ = true;
                return IO_STATUS::CLOSE;
            }

            return IO_STATUS::KEEP;
        }

        // ---- 写入与响应缓冲泵送 (Write Path & Response Queue) ----

        inline void pump() noexcept
        {
            if (handler_ == nullptr)
            {
                return;
            }
            const size_t hardCap = writeHighWaterMark_ * getConnectionConfig().writeHardCapFactor;
            while (handler_->hasResponse())
            {
                if (pendingBytes_ >= hardCap) [[unlikely]]
                {
                    LOG_WARN("Connection: fd {}: write backlog {} exceeds hard cap, closing after flush", fd_,
                             pendingBytes_);
                    closeAfterWrite_ = true;
                    break;
                }
                std::string resp = handler_->takeResponse();
                if (!resp.empty())
                {
                    pendingBytes_ += resp.size();
                    writeQueue_.push_back(std::move(resp));
                }
                if (pendingBytes_ > writeHighWaterMark_)
                {
                    readPaused_ = true;
                }
            }
            if (handler_->closeAfterResponse())
            {
                closeAfterWrite_ = true;
            }
        }

        inline bool commitSent(size_t n) noexcept
        {
            size_t toConsume = n;
            while (toConsume > 0 && !writeQueue_.empty())
            {
                auto &front = writeQueue_.front();
                const size_t rem = front.size() - writeOffset_;
                if (toConsume >= rem)
                {
                    toConsume -= rem;
                    pendingBytes_ -= rem;
                    writeOffset_ = 0;
                    if (handler_ != nullptr)
                    {
                        if constexpr (requires { handler_->recycleSpare(std::move(front)); })
                        {
                            handler_->recycleSpare(std::move(front));
                        }
                    }
                    writeQueue_.pop_front();
                }
                else
                {
                    writeOffset_ += toConsume;
                    pendingBytes_ -= toConsume;
                    toConsume = 0;
                }
            }
            if (readPaused_ && pendingBytes_ <= writeHighWaterMark_)
            {
                if (handler_ == nullptr || handler_->readCredit() > 0)
                {
                    readPaused_ = false;
                }
            }
            return true;
        }

        // ---- 事件循环虚接口驱动 (Event Loop Drives) ----

        void handle() override
        {
            if (handler_ != nullptr)
            {
                handler_->handle();
            }
        }

        inline IO_STATUS handleWrite() override
        {
            if (fd_ < 0)
            {
                return IO_STATUS::CLOSE;
            }

            pump();

            if (pipePending_ > 0 && handler_ != nullptr)
            {
                const int targetFd = handler_->spliceTarget();
                if (targetFd >= 0)
                {
                    const ssize_t sOut = ::splice(pipeFd_[0], nullptr, targetFd, nullptr, pipePending_,
                                                  SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
                    if (sOut > 0)
                    {
                        pipePending_ -= static_cast<size_t>(sOut);
                        if (pipePending_ == 0)
                        {
                            readPaused_ = false;
                            wantWrite_ = false;
                        }
                    }
                }
            }

            while (!writeQueue_.empty())
            {
                auto &front = writeQueue_.front();
                const char *buf = front.data() + writeOffset_;
                const size_t len = front.size() - writeOffset_;

                const ssize_t sn = ::send(fd_, buf, len, MSG_NOSIGNAL);
                if (sn > 0)
                {
                    touch();
                    commitSent(static_cast<size_t>(sn));
                    continue;
                }
                if (sn < 0)
                {
                    if (errno == EINTR)
                        continue;
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                    {
                        wantWrite_ = true;
                        return IO_STATUS::KEEP;
                    }
                    peerGone_ = true;
                    return IO_STATUS::CLOSE;
                }
                break;
            }

            if (writeQueue_.empty())
            {
                wantWrite_ = false;
                if (closeAfterWrite_ || peerGone_)
                {
                    return IO_STATUS::CLOSE;
                }
            }
            return IO_STATUS::KEEP;
        }

        inline IO_STATUS handleRead() override
        {
            if (fd_ < 0)
            {
                return IO_STATUS::CLOSE;
            }

            if (isSpliceEnabled())
            {
                if (ensurePipe())
                {
                    applyQuickAck();
                    return handleSplice();
                }
            }

            // 无 handler 时：无害流式抽象层，执行纯流式非阻塞读取到局部临时缓冲
            if (handler_ == nullptr)
            {
                char buf[4096];
                const ssize_t rn = ::recv(fd_, buf, sizeof(buf), 0);
                if (rn > 0)
                {
                    touch();
                    return IO_STATUS::KEEP;
                }
                if (rn == 0)
                {
                    peerGone_ = true;
                    return IO_STATUS::CLOSE;
                }
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    return IO_STATUS::KEEP;
                }
                if (errno == EINTR)
                {
                    return IO_STATUS::KEEP;
                }
                peerGone_ = true;
                return IO_STATUS::CLOSE;
            }

            // 挂载具体业务 handler 时：流式数据直入 handler 请求缓冲并驱动业务处理
            while (!readPaused_)
            {
                const size_t credit = handler_->readCredit();
                if (credit == 0) [[unlikely]]
                {
                    readPaused_ = true;
                    break;
                }

                const size_t want = std::min(getConnectionConfig().readChunkSize, credit);
                auto prepRes = handler_->prepareRequestWritable(want);
                if (!prepRes) [[unlikely]]
                {
                    LOG_ERROR("Connection: prepareRequestWritable failed, fd {} closing", fd_);
                    peerGone_ = true;
                    return IO_STATUS::CLOSE;
                }

                char *target = *prepRes;
                const size_t maxLen = std::min(handler_->requestWritableBytes(), credit);

                const ssize_t rn = ::recv(fd_, target, maxLen, 0);
                if (rn > 0)
                {
                    applyQuickAck();
                    handler_->commitRequest(static_cast<size_t>(rn));
                    touch();
                    if (handler_->requestOverLimit()) [[unlikely]]
                    {
                        handler_->onParseError("request exceeds the read limit");
                        pump();
                        closeAfterWrite_ = true;
                        readPaused_ = true;
                        return IO_STATUS::KEEP;
                    }
                    handler_->handle();
                    pump();
                    if (closeAfterWrite_)
                    {
                        break;
                    }
                    continue;
                }

                if (rn == 0)
                {
                    peerGone_ = true;
                    closeAfterWrite_ = true;
                    if (pendingBytes_ > 0)
                    {
                        return IO_STATUS::KEEP;
                    }
                    return IO_STATUS::CLOSE;
                }

                if (errno == EINTR)
                {
                    continue;
                }
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    break;
                }
                peerGone_ = true;
                return IO_STATUS::CLOSE;
            }

            pump();
            if (handler_->closeAfterResponse())
            {
                closeAfterWrite_ = true;
            }
            if (pendingBytes_ > writeHighWaterMark_)
            {
                readPaused_ = true;
            }
            if (peerGone_ && pendingBytes_ == 0)
            {
                return IO_STATUS::CLOSE;
            }
            return IO_STATUS::KEEP;
        }

        inline void close() override
        {
            state_ = CONN_STATE::CLOSED;
            if (fd_ != -1)
            {
                ::close(fd_);
                fd_ = -1;
            }
        }

        inline void reset() noexcept override
        {
            if (fd_ != -1)
            {
                ::close(fd_);
                fd_ = -1;
            }
            if (pipeFd_[0] != -1)
            {
                ::close(pipeFd_[0]);
                pipeFd_[0] = -1;
            }
            if (pipeFd_[1] != -1)
            {
                ::close(pipeFd_[1]);
                pipeFd_[1] = -1;
            }
            pipePending_ = 0;
            peerAddr_ = {};
            writeQueue_.clear();
            writeOffset_ = 0;
            pendingBytes_ = 0;
            state_ = CONN_STATE::OPEN;
            readPaused_ = false;
            wantWrite_ = false;
            closeAfterWrite_ = false;
            peerGone_ = false;
            timerId_ = 0;
            lastActive_ = std::chrono::steady_clock::now();
            config_.reset();
            writeHighWaterMark_ = getConnectionConfig().writeHighWaterMark;
            if (defaultHandler_.has_value())
            {
                defaultHandler_->reset();
            }
            handler_ = nullptr;
            defaultHandler_.reset();
        }

    private:
        inline void applyQuickAck() noexcept
        {
            if (isTcp() && config().server.tcpQuickAck && fd_ >= 0)
            {
                int val = 1;
                ::setsockopt(fd_, IPPROTO_TCP, TCP_QUICKACK, &val, sizeof(val));
            }
        }

        [[no_unique_address]] ProtocolContext protocol_{};
        Handler *handler_{nullptr};
        std::optional<Handler> defaultHandler_{};

        CONN_STATE state_{CONN_STATE::OPEN};
        uint32_t events_{0};
        bool wantWrite_{false};
        bool readPaused_{false};
        bool closeAfterWrite_{false};
        bool peerGone_{false};
        uint64_t timerId_{0};
        std::chrono::steady_clock::time_point lastActive_{std::chrono::steady_clock::now()};

        int pipeFd_[2]{-1, -1};
        size_t pipePending_{0};

        std::deque<std::string> writeQueue_{};
        size_t writeQueueSize_{0};
        size_t writeOffset_{0};
        size_t pendingBytes_{0};
        size_t writeHighWaterMark_{getConnectionConfig().writeHighWaterMark};
        size_t writeLowWaterMark_{16 * 1024 * 1024};
    };

    /**
     * @brief 非流式处理器使用的占位会话对象
     *
     * 纯数据报处理器不需要 Connection 承载会话，但引擎的成员声明（连接池、
     * 会话索引等）必须在类作用域里写一个具体类型。本类型只提供 ObjectPool
     * 所需的 Resettable 契约，不携带任何流式状态。
     */
    struct NoConnection
    {
        void reset() noexcept {}
    };

    /**
     * @brief 会话对象槽位的编译期选择器
     *
     * 满足 MandatoryMethodConnection 的处理器映射到 Connection<H>；否则映射到 NoConnection。
     *
     * 为什么不用 std::conditional_t：`Connection<H>` 是受约束模板，一旦在类作用域
     * 里形成一个违约束的 template-id（即使是未选中的分支）就是硬错误。偏特化的
     * 匹配发生在约束求解阶段，不满足时直接退回主模板，因此不会触及 Connection。
     */
    template <typename H>
    struct ConnectionSlot
    {
        using Type = NoConnection;
    };

    template <MandatoryMethodConnection H>
    struct ConnectionSlot<H>
    {
        using Type = Connection<H>;
    };

    class HandlerDatagram;

    template <>
    struct Protocol<HandlerDatagram>
    {
        sockaddr_in peer{};
        std::string bytes{};

        Protocol() noexcept = default;
        Protocol(const sockaddr_in &p, std::string b) noexcept
            : peer(p),
              bytes(std::move(b))
        {
        }
        Protocol(const sockaddr_in &p, const char *buf, size_t n)
            : peer(p),
              bytes((buf != nullptr && n > 0) ? std::string(buf, n) : std::string())
        {
        }

        void clear() noexcept
        {
            peer = {};
            bytes.clear();
        }
    };

    using DatagramQueue = ResponseQueueBase<Protocol<HandlerDatagram>>;

    [[nodiscard]] inline std::string datagramPeerText(const sockaddr_in &peer)
    {
        char host[INET_ADDRSTRLEN] = {};
        if (::inet_ntop(AF_INET, &peer.sin_addr, host, sizeof host) == nullptr) [[unlikely]]
        {
            return std::string("<unnamed>:") + std::to_string(::ntohs(peer.sin_port));
        }
        std::string out;
        out.reserve(22);
        out.append(host);
        out.push_back(':');
        out.append(std::to_string(::ntohs(peer.sin_port)));
        return out;
    }

    class HandlerDatagram : public ConnectionBase
    {
    public:
        using DatagramCallback = std::function<void(const sockaddr_in &peer, const handler::ProxyAddress &target,
                                                    const char *data, size_t n)>;

        HandlerDatagram() noexcept
            : HandlerDatagram(getDatagramConfig())
        {
            transport_ = TransportType::UDP;
        }

        explicit HandlerDatagram(const DatagramConfig &config) noexcept
            : maxDatagramBytes_(config.maxDatagramBytes),
              maxPendingOutgoing_(config.maxPendingOutgoing)
        {
            transport_ = TransportType::UDP;
            [[maybe_unused]] auto _ = outgoing_.init(maxPendingOutgoing_);
        }

        explicit HandlerDatagram(const sockaddr_in &peer) noexcept
            : HandlerDatagram()
        {
            transport_ = TransportType::UDP;
            remotePeer_ = peer;
        }

        virtual ~HandlerDatagram() noexcept = default;

        HandlerDatagram(const HandlerDatagram &) = delete;
        HandlerDatagram &operator=(const HandlerDatagram &) = delete;
        HandlerDatagram(HandlerDatagram &&) = delete;
        HandlerDatagram &operator=(HandlerDatagram &&) = delete;

        virtual void onDatagram([[maybe_unused]] const sockaddr_in &peer, [[maybe_unused]] const char *data,
                                [[maybe_unused]] size_t n) noexcept
        {
        }

        virtual void reset() noexcept override
        {
            const auto &cfg = getDatagramConfig();
            maxDatagramBytes_ = cfg.maxDatagramBytes;
            maxPendingOutgoing_ = cfg.maxPendingOutgoing;
            if (outgoing_.capacity() != maxPendingOutgoing_) [[unlikely]]
            {
                [[maybe_unused]] auto _ = outgoing_.init(maxPendingOutgoing_);
            }
            else
            {
                outgoing_.reset();
            }
            droppedOutgoing_ = 0;
            inboundStage_ = handler::InboundStage::STREAMING;
            outboundStage_ = handler::OutboundStage::STREAMING;
            remotePeer_ = {};
            datagramCallback_ = nullptr;
        }

        virtual void onMessageComplete() noexcept {}
        virtual void onParseError([[maybe_unused]] const char *reason) noexcept {}

        inline void sendTo(const sockaddr_in &target, const char *buf, size_t n)
        {
            contract_assert(buf != nullptr);
            if (!outgoing_.emplace(target, buf, n)) [[unlikely]]
            {
                ++droppedOutgoing_;
                LOG_WARN("HandlerDatagram: outgoing queue full ({} pending), dropping a {} byte packet for {}",
                         outgoing_.size(), n, datagramPeerText(target));
            }
        }

        inline void sendTo(const sockaddr_in &target, std::string bytes)
        {
            const size_t sz = bytes.size();
            if (!outgoing_.emplace(target, std::move(bytes))) [[unlikely]]
            {
                ++droppedOutgoing_;
                LOG_WARN("HandlerDatagram: outgoing queue full ({} pending), dropping a {} byte packet for {}",
                         outgoing_.size(), sz, datagramPeerText(target));
            }
        }

        inline void forwardTo(const sockaddr_in &upstream, const char *data, size_t n) { sendTo(upstream, data, n); }

        inline void broadcastTo(const std::vector<sockaddr_in> &targets, const char *buf, size_t n)
        {
            for (const auto &t : targets)
            {
                sendTo(t, buf, n);
            }
        }

        [[nodiscard]] inline bool hasOutgoing() const noexcept { return !outgoing_.empty(); }
        [[nodiscard]] inline size_t outgoingCount() const noexcept { return outgoing_.size(); }
        [[nodiscard]] inline const Protocol<HandlerDatagram> &peekOutgoing() const noexcept
        {
            return outgoing_.front();
        }

        [[nodiscard]] inline Protocol<HandlerDatagram> takeOutgoing()
        {
            if (outgoing_.empty()) [[unlikely]]
            {
                return {};
            }
            Protocol<HandlerDatagram> out = std::move(outgoing_.front());
            outgoing_.pop();
            return out;
        }

        inline void setMaxDatagramBytes(size_t n) noexcept { maxDatagramBytes_ = n; }
        inline void setMaxPendingOutgoing(size_t n) noexcept
        {
            contract_assert(n > 0);
            maxPendingOutgoing_ = n;
            [[maybe_unused]] auto _ = outgoing_.init(n);
        }
        [[nodiscard]] inline size_t maxPendingOutgoing() const noexcept { return maxPendingOutgoing_; }

        [[nodiscard]] inline DatagramQueue &outgoing() noexcept { return outgoing_; }
        [[nodiscard]] inline const DatagramQueue &outgoing() const noexcept { return outgoing_; }
        [[nodiscard]] inline size_t maxDatagramBytes() const noexcept { return maxDatagramBytes_; }
        [[nodiscard]] inline size_t droppedOutgoing() const noexcept { return droppedOutgoing_; }

        void setOnDatagram(DatagramCallback cb) noexcept { datagramCallback_ = std::move(cb); }
        void setTarget(const handler::ProxyAddress &target) noexcept { targetAddress_ = target; }
        void setStage(handler::InboundStage st) noexcept { inboundStage_ = st; }
        void setStage(handler::OutboundStage st) noexcept { outboundStage_ = st; }
        [[nodiscard]] inline handler::InboundStage inboundStage() const noexcept { return inboundStage_; }
        [[nodiscard]] inline handler::OutboundStage outboundStage() const noexcept { return outboundStage_; }
        [[nodiscard]] inline handler::InboundStage stage() const noexcept { return inboundStage_; }
        [[nodiscard]] virtual bool isEstablished() const noexcept
        {
            return inboundStage_ == handler::InboundStage::STREAMING ||
                   outboundStage_ == handler::OutboundStage::STREAMING;
        }

    protected:
        size_t maxDatagramBytes_{1 << 16};
        size_t maxPendingOutgoing_{1 << 10};
        DatagramQueue outgoing_{};
        size_t droppedOutgoing_{0};
        sockaddr_in remotePeer_{};
        std::optional<handler::ProxyAddress> targetAddress_{std::nullopt};
        handler::InboundStage inboundStage_{handler::InboundStage::STREAMING};
        handler::OutboundStage outboundStage_{handler::OutboundStage::STREAMING};
        DatagramCallback datagramCallback_{nullptr};
    };

    template <typename D>
    concept DerivedFromHandlerDatagram = std::is_base_of_v<HandlerDatagram, D>;

    template <typename D>
    concept MandatoryMethodDatagram = DerivedFromHandlerDatagram<D> && Resettable<D> &&
                                      requires(D &d, const sockaddr_in &peer, const char *buf, size_t n,
                                               std::string bytes, const std::vector<sockaddr_in> &targets) {
                                          { d.onDatagram(peer, buf, n) } noexcept;
                                          { d.onMessageComplete() } noexcept;
                                          { d.onParseError(buf) } noexcept;

                                          d.sendTo(peer, buf, n);
                                          d.sendTo(peer, std::move(bytes));
                                          d.forwardTo(peer, buf, n);
                                          d.broadcastTo(targets, buf, n);
                                          { d.hasOutgoing() } noexcept -> std::same_as<bool>;
                                          { d.outgoingCount() } noexcept -> std::same_as<size_t>;
                                          {
                                              d.peekOutgoing()
                                          } noexcept -> std::same_as<const Protocol<HandlerDatagram> &>;
                                          { d.takeOutgoing() } -> std::same_as<Protocol<HandlerDatagram>>;
                                          { d.droppedOutgoing() } noexcept -> std::same_as<size_t>;

                                          { d.setMaxDatagramBytes(n) } noexcept;
                                          { d.maxDatagramBytes() } noexcept -> std::same_as<size_t>;
                                          { d.setMaxPendingOutgoing(n) } noexcept;
                                          { d.maxPendingOutgoing() } noexcept -> std::same_as<size_t>;
                                      };

} // namespace mynet

namespace mynet::handler
{
    class HandlerInboundDatagramBase : public mynet::HandlerDatagram
    {
    protected:
        InboundStage stage_{InboundStage::STREAMING};

    public:
        HandlerInboundDatagramBase() noexcept = default;
        explicit HandlerInboundDatagramBase(const sockaddr_in &peer) noexcept
            : HandlerDatagram(peer)
        {
        }
        ~HandlerInboundDatagramBase() noexcept override = default;

        void setStage(InboundStage st) noexcept { stage_ = st; }
        [[nodiscard]] inline InboundStage inboundStage() const noexcept { return stage_; }
        [[nodiscard]] inline InboundStage stage() const noexcept { return stage_; }
        [[nodiscard]] bool isEstablished() const noexcept override { return stage_ == InboundStage::STREAMING; }

        void reset() noexcept override
        {
            HandlerDatagram::reset();
            stage_ = InboundStage::STREAMING;
        }

        void onParseError([[maybe_unused]] const char *reason) noexcept override { stage_ = InboundStage::ERROR; }
    };

    class HandlerOutboundDatagramBase : public mynet::HandlerDatagram
    {
    protected:
        OutboundStage stage_{OutboundStage::STREAMING};

    public:
        HandlerOutboundDatagramBase() noexcept = default;
        explicit HandlerOutboundDatagramBase(const sockaddr_in &peer) noexcept
            : HandlerDatagram(peer)
        {
        }
        ~HandlerOutboundDatagramBase() noexcept override = default;

        void setStage(OutboundStage st) noexcept { stage_ = st; }
        [[nodiscard]] inline OutboundStage outboundStage() const noexcept { return stage_; }
        [[nodiscard]] inline OutboundStage stage() const noexcept { return stage_; }
        [[nodiscard]] bool isEstablished() const noexcept override { return stage_ == OutboundStage::STREAMING; }

        void reset() noexcept override
        {
            HandlerDatagram::reset();
            stage_ = OutboundStage::STREAMING;
        }

        void onParseError([[maybe_unused]] const char *reason) noexcept override { stage_ = OutboundStage::ERROR; }
    };

    class HandlerInboundConnectionBase : public mynet::HandlerConnection
    {
    protected:
        InboundStage stage_{InboundStage::HANDSHAKE};

    public:
        using RequestCallback = HandlerConnection::RequestCallback;

        HandlerInboundConnectionBase() noexcept = default;
        ~HandlerInboundConnectionBase() noexcept override = default;

        void setStage(InboundStage st) noexcept { stage_ = st; }
        [[nodiscard]] inline InboundStage inboundStage() const noexcept { return stage_; }
        [[nodiscard]] inline InboundStage stage() const noexcept { return stage_; }
        [[nodiscard]] bool isEstablished() const noexcept override { return stage_ == InboundStage::STREAMING; }

        void reset() noexcept override
        {
            HandlerConnection::reset();
            stage_ = InboundStage::HANDSHAKE;
        }

        void onParseError([[maybe_unused]] const char *reason) noexcept override { stage_ = InboundStage::ERROR; }
    };

    class HandlerOutboundConnectionBase : public mynet::HandlerConnection
    {
    protected:
        OutboundStage stage_{OutboundStage::INITIAL};

    public:
        HandlerOutboundConnectionBase() noexcept = default;
        explicit HandlerOutboundConnectionBase(const handler::ProxyAddress &target) noexcept
            : HandlerConnection(target)
        {
        }
        ~HandlerOutboundConnectionBase() noexcept override = default;

        void setStage(OutboundStage st) noexcept { stage_ = st; }
        [[nodiscard]] inline OutboundStage outboundStage() const noexcept { return stage_; }
        [[nodiscard]] inline OutboundStage stage() const noexcept { return stage_; }
        [[nodiscard]] bool isEstablished() const noexcept override { return stage_ == OutboundStage::STREAMING; }

        void reset() noexcept override
        {
            HandlerConnection::reset();
            stage_ = OutboundStage::INITIAL;
        }

        void onParseError([[maybe_unused]] const char *reason) noexcept override { stage_ = OutboundStage::ERROR; }
    };
} // namespace mynet::handler
