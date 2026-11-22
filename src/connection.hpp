#pragma once

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "address.hpp"
#include "config/log.hpp"
#include "configHolder.hpp"
#include "constraints.hpp"
#include "error.hpp"
#include "listener.hpp"
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

    class HandlerBase;
    using Handler = HandlerBase;
    class HandlerConnection;
    class HandlerDatagram;

    namespace handler
    {
        using HandlerBase = mynet::HandlerBase;
    }

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

    class HandlerConnection;

    /**
     * @brief 统一连接抽象基类（流式传输基类）
     *
     * 无论底层是原生 TCP，还是在 UDP 之上自己封装的可靠连接，皆统一继承自此类。
     * 融合了连接的底层传输状态（fd、地址、配置）、请求缓冲区、响应队列、
     * 零拷贝 splice 管道，并提供流式读写与背压驱动的方法占位与实现。
     * 连接内部可挂载业务 Handler（handler_ 为空时作为纯净无害的流式连接）。
     */
    class ConnectionBase
    {
    public:
        using SPLICE_CONTROL = mynet::SPLICE_CONTROL;
        static constexpr bool kEnableSplice = true;

        enum class CONN_STATE : uint8_t
        {
            OPEN = 0,
            CLOSING = 1,
            CLOSED = 2
        };

    protected:
        int fd_{-1};
        sockaddr_in peerAddr_{};
        TransportType transport_{TransportType::TCP};
        std::shared_ptr<const MynetConfig> config_{nullptr};

        // 业务处理器挂载（纯业务 Handler 在连接之上、之内）
        HandlerConnection *handler_{nullptr};

        // 连接流式状态
        CONN_STATE state_{CONN_STATE::OPEN};
        uint32_t events_{0};
        bool wantWrite_{false};
        bool readPaused_{false};
        bool closeAfterWrite_{false};
        bool peerGone_{false};
        uint64_t timerId_{0};
        std::chrono::steady_clock::time_point lastActive_{std::chrono::steady_clock::now()};

        // 流式请求缓冲区
        RequestBuffer requestBuffer_{};
        size_t maxRequestBytes_{getConnectionConfig().maxRequestBytes};

        // 流式响应队列与写出缓冲
        ResponseQueue responseQueue_{};
        std::string spare_{};
        bool closeAfterResponse_{false};
        std::deque<std::string> writeQueue_{};
        size_t writeQueueSize_{0};
        size_t writeOffset_{0};
        size_t pendingBytes_{0};
        size_t writeHighWaterMark_{getConnectionConfig().writeHighWaterMark};
        size_t writeLowWaterMark_{16 * 1024 * 1024};

        // 零拷贝 splice 管道
        int pipeFd_[2]{-1, -1};
        size_t pipePending_{0};
        SPLICE_CONTROL spliceControl_{SPLICE_CONTROL::DISABLED};
        int spliceTargetFd_{-1};

    public:
        ConnectionBase() noexcept
            : ConnectionBase(getConnectionConfig())
        {
        }

        explicit ConnectionBase(size_t responseCapacity) noexcept
        {
            [[maybe_unused]] auto _ = responseQueue_.init(responseCapacity);
        }

        explicit ConnectionBase(const ConnectionConfig &config) noexcept
            : maxRequestBytes_(config.maxRequestBytes),
              writeHighWaterMark_(config.writeHighWaterMark)
        {
            requestBuffer_.setHighWaterMark(config.readHighWaterMark);
            [[maybe_unused]] auto _ = responseQueue_.init(config.responseCapacity);
        }

        virtual ~ConnectionBase() noexcept { ConnectionBase::reset(); }

        ConnectionBase(const ConnectionBase &) = delete;
        ConnectionBase &operator=(const ConnectionBase &) = delete;
        ConnectionBase(ConnectionBase &&) noexcept = default;
        ConnectionBase &operator=(ConnectionBase &&) noexcept = default;

        // ---- 基础属性 ----
        [[nodiscard]] inline int fd() const noexcept { return fd_; }
        virtual void setFd(int fd) noexcept;
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

        // ---- Handler 挂载 ----
        virtual void setHandler(HandlerConnection *h) noexcept;
        [[nodiscard]] inline bool hasHandler() const noexcept { return handler_ != nullptr; }
        [[nodiscard]] inline HandlerConnection *handler() noexcept { return handler_; }
        [[nodiscard]] inline const HandlerConnection *handler() const noexcept { return handler_; }

        // ---- 请求缓冲方法占位与实现 ----
        [[nodiscard]] inline Result<> appendRequest(const char *buf, ssize_t rn) noexcept
        {
            if (buf != nullptr && rn > 0) [[likely]]
            {
                return requestBuffer_.append(buf, static_cast<size_t>(rn));
            }
            return {};
        }
        [[nodiscard]] inline Result<> appendRequest(std::string_view sv) noexcept
        {
            return appendRequest(sv.data(), static_cast<ssize_t>(sv.size()));
        }
        [[nodiscard]] inline std::expected<char *, ERR>
        prepareRequestWritable(size_t minBytes = getConnectionConfig().readChunkSize) noexcept
        {
            if (auto res = requestBuffer_.ensureWritable(minBytes); !res) [[unlikely]]
            {
                return std::unexpected(res.error());
            }
            return requestBuffer_.writableBegin();
        }
        [[nodiscard]] inline char *requestWritableBegin() noexcept { return requestBuffer_.writableBegin(); }
        [[nodiscard]] inline size_t requestWritableBytes() const noexcept { return requestBuffer_.writableBytes(); }
        inline void commitRequest(size_t n) noexcept { requestBuffer_.commitWritten(n); }
        [[nodiscard]] inline bool requestOverLimit() const noexcept
        {
            return requestBuffer_.readableBytes() > maxRequestBytes_;
        }
        [[nodiscard]] inline size_t requestBytes() const noexcept { return requestBuffer_.readableBytes(); }
        [[nodiscard]] inline const char *requestBegin() const noexcept { return requestBuffer_.readableBegin(); }
        inline void requestConsume(size_t n) noexcept { requestBuffer_.retrieve(n); }
        inline void requestClear() noexcept { requestBuffer_.reset(); }
        [[nodiscard]] inline size_t readCredit() const noexcept
        {
            const size_t used = requestBuffer_.readableBytes();
            return used >= maxRequestBytes_ ? 0 : maxRequestBytes_ - used;
        }
        inline void setMaxRequestBytes(size_t n) noexcept { maxRequestBytes_ = n; }
        [[nodiscard]] inline size_t maxRequestBytes() const noexcept { return maxRequestBytes_; }

        // ---- 响应队列方法占位与实现 ----
        [[nodiscard]] inline bool hasResponse() const noexcept { return !responseQueue_.empty(); }
        [[nodiscard]] inline size_t responseCount() const noexcept { return responseQueue_.size(); }
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
        inline void recycleSpare(std::string &&s) noexcept
        {
            if (s.capacity() > spare_.capacity())
            {
                s.clear();
                spare_ = std::move(s);
            }
        }
        [[nodiscard]] inline Result<> pushResponse(std::string &&s) noexcept
        {
            return responseQueue_.push(std::move(s));
        }
        [[nodiscard]] inline Result<> pushResponse(const std::string &s) noexcept
        {
            return pushResponse(std::string_view(s));
        }
        [[nodiscard]] inline Result<> pushResponse(std::string_view sv) noexcept
        {
            if (sv.data() == nullptr || sv.empty())
            {
                return {};
            }
            return responseQueue_.emplace(sv);
        }
        [[nodiscard]] inline Result<> pushResponse(const char *s) noexcept
        {
            if (s == nullptr) [[unlikely]]
            {
                return {};
            }
            return pushResponse(std::string_view(s));
        }
        [[nodiscard]] inline Result<> reserveResponses(size_t capacity) noexcept
        {
            return responseQueue_.init(capacity);
        }
        [[nodiscard]] inline bool closeAfterResponse() const noexcept { return closeAfterResponse_; }
        inline void setCloseAfterResponse(bool v) noexcept { closeAfterResponse_ = v; }

        // ---- 零拷贝管道控制 (Zero-Copy Splice Routing) ----
        inline void setSpliceTarget(int targetFd) noexcept
        {
            spliceTargetFd_ = targetFd;
            spliceControl_ = (targetFd >= 0) ? SPLICE_CONTROL::ACTIVE : SPLICE_CONTROL::DISABLED;
        }
        inline void setSpliceControl(SPLICE_CONTROL ctrl) noexcept
        {
            spliceControl_ = ctrl;
            if (ctrl == SPLICE_CONTROL::DISABLED || ctrl == SPLICE_CONTROL::CLOSED)
            {
                spliceTargetFd_ = -1;
            }
        }
        inline void setSpliceTarget(SPLICE_CONTROL ctrl) noexcept { setSpliceControl(ctrl); }
        [[nodiscard]] inline SPLICE_CONTROL spliceControl() const noexcept { return spliceControl_; }
        [[nodiscard]] inline int spliceTarget() const noexcept { return spliceTargetFd_; }
        [[nodiscard]] inline bool isSpliceActive() const noexcept
        {
            return spliceControl_ == SPLICE_CONTROL::ACTIVE && spliceTargetFd_ >= 0;
        }
        inline void pauseSplice() noexcept
        {
            if (spliceControl_ == SPLICE_CONTROL::ACTIVE)
            {
                spliceControl_ = SPLICE_CONTROL::PAUSED;
            }
        }
        inline void resumeSplice() noexcept
        {
            if (spliceControl_ == SPLICE_CONTROL::PAUSED)
            {
                spliceControl_ = (spliceTargetFd_ >= 0) ? SPLICE_CONTROL::ACTIVE : SPLICE_CONTROL::DISABLED;
            }
        }
        inline void drainSplice() noexcept
        {
            if (spliceControl_ == SPLICE_CONTROL::ACTIVE)
            {
                spliceControl_ = SPLICE_CONTROL::DRAINING;
            }
        }
        inline void disableSplice() noexcept
        {
            spliceControl_ = SPLICE_CONTROL::DISABLED;
            spliceTargetFd_ = -1;
        }
        [[nodiscard]] inline bool spliceEnabled() const noexcept { return isSpliceActive(); }
        [[nodiscard]] inline bool isSpliceEnabled() const noexcept;

        // ---- 零拷贝传输实现 ----
        [[nodiscard]] inline bool ensurePipe() noexcept;
        [[nodiscard]] inline std::expected<size_t, IO_END>
        spliceTo(int targetFd, size_t maxBytes = getConnectionConfig().spliceChunkSize) noexcept;
        [[nodiscard]] inline std::expected<size_t, IO_END>
        spliceFrom(int sourceFd, size_t maxBytes = getConnectionConfig().spliceChunkSize) noexcept;
        inline IO_STATUS handleSplice() noexcept;

        // ---- 连接状态与事件状态查询 ----
        [[nodiscard]] inline CONN_STATE state() const noexcept { return state_; }
        [[nodiscard]] inline uint32_t events() const noexcept { return events_; }
        inline void setEvents(uint32_t events) noexcept { events_ = events; }
        [[nodiscard]] inline bool wantRead() const noexcept { return !readPaused_ && state_ == CONN_STATE::OPEN; }
        [[nodiscard]] inline bool wantWrite() const noexcept { return wantWrite_ || hasPendingWrite(); }
        inline void setWantWrite(bool v) noexcept { wantWrite_ = v; }
        [[nodiscard]] inline bool hasPendingWrite() const noexcept;
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

        [[nodiscard]] constexpr void *ssl() const noexcept { return nullptr; }
        [[nodiscard]] constexpr bool ktlsRxActive() const noexcept { return false; }
        [[nodiscard]] constexpr bool ktlsTxActive() const noexcept { return false; }

        inline void pump() noexcept;
        inline bool commitSent(size_t n) noexcept;

        virtual void handle();
        virtual IO_STATUS handleWrite();
        virtual IO_STATUS handleRead();
        virtual void close();
        virtual void reset() noexcept;

        inline void applyQuickAck() noexcept
        {
            if (isTcp() && config().server.tcpQuickAck && fd_ >= 0)
            {
                int val = 1;
                ::setsockopt(fd_, IPPROTO_TCP, TCP_QUICKACK, &val, sizeof(val));
            }
        }
    };

    /**
     * @brief 纯业务协议处理器基类 (HandlerBase)
     *
     * 架构核心支柱：
     * 1. 彻底与传输层无关：不包含任何底层 socket/fd/网络传输状态；
     * 2. 统一流式与数据报：无论是 TCP 流连接还是 UDP 数据报，业务状态机统一收敛为单一根基类；
     * 3. 在连接之上、之内：挂载于 ConnectionBase 或 DatagramSession，通过 connection_ 回溯宿主连接；
     * 4. 纯业务状态机：包含 stages、targetAddress、command、回调以及业务生命周期钩子。
     */
    class HandlerBase
    {
    public:
        using SPLICE_CONTROL = mynet::SPLICE_CONTROL;
        static constexpr bool kEnableSplice = true;
        using RequestCallback = std::function<void(uint8_t cmd, const handler::ProxyAddress &target)>;
        using DatagramCallback = std::function<void(const sockaddr_in &peer, const handler::ProxyAddress &target,
                                                    const char *data, size_t n)>;

    protected:
        ConnectionBase *connection_{nullptr};
        int fd_{-1};
        handler::InboundStage inboundStage_{handler::InboundStage::HANDSHAKE};
        handler::OutboundStage outboundStage_{handler::OutboundStage::INITIAL};
        std::optional<handler::ProxyAddress> targetAddress_{std::nullopt};
        handler::ProxyAddress target_{};
        uint8_t command_{0};
        RequestCallback requestCallback_{nullptr};
        DatagramCallback datagramCallback_{nullptr};
        sockaddr_in remotePeer_{};

    public:
        HandlerBase() noexcept = default;

        explicit HandlerBase(const handler::ProxyAddress &target) noexcept
        {
            targetAddress_ = target;
            target_ = target;
        }

        explicit HandlerBase(const sockaddr_in &peer) noexcept { remotePeer_ = peer; }

        virtual ~HandlerBase() noexcept = default;

        HandlerBase(const HandlerBase &) = delete;
        HandlerBase &operator=(const HandlerBase &) = delete;
        HandlerBase(HandlerBase &&) = delete;
        HandlerBase &operator=(HandlerBase &&) = delete;

        // ---- 连接关联与挂钩 (Connection Linkage) ----
        inline void setConnection(ConnectionBase *c) noexcept { connection_ = c; }
        [[nodiscard]] inline ConnectionBase *connection() const noexcept { return connection_; }

        // ---- 业务生命周期与钩子 ----
        virtual void handle() {}
        virtual void onMessageComplete() noexcept {}
        virtual void onParseError([[maybe_unused]] const char *reason) noexcept
        {
            inboundStage_ = handler::InboundStage::ERROR;
            outboundStage_ = handler::OutboundStage::ERROR;
        }
        virtual void onDatagram([[maybe_unused]] const sockaddr_in &peer, [[maybe_unused]] const char *data,
                                [[maybe_unused]] size_t n) noexcept
        {
        }

        virtual void reset() noexcept
        {
            fd_ = -1;
            inboundStage_ = handler::InboundStage::HANDSHAKE;
            outboundStage_ = handler::OutboundStage::INITIAL;
            targetAddress_.reset();
            target_ = {};
            command_ = 0;
            requestCallback_ = nullptr;
            datagramCallback_ = nullptr;
            remotePeer_ = {};
            connection_ = nullptr;
        }

        // ---- 代理业务状态机 ----
        void setOnRequest(RequestCallback cb) noexcept { requestCallback_ = std::move(cb); }
        void setOnDatagram(DatagramCallback cb) noexcept { datagramCallback_ = std::move(cb); }
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
        [[nodiscard]] inline int fd() const noexcept { return connection_ ? connection_->fd() : fd_; }
    };

    template <typename H>
    concept DerivedFromHandlerBase = std::derived_from<H, HandlerBase>;

    /**
     * @brief 纯业务流式协议处理器基类
     *
     * 继承自统一的 HandlerBase，提供流式会话所需的解析缓冲与零拷贝控制。
     */
    class HandlerConnection : public HandlerBase
    {
    public:
        using SPLICE_CONTROL = mynet::SPLICE_CONTROL;
        static constexpr bool kEnableSplice = true;
        using RequestCallback = HandlerBase::RequestCallback;

    protected:
        // 业务层缓冲与队列（承载业务帧与响应，并在独立实例化时作为完备回退）
        RequestBuffer requestBuffer_{};
        ResponseQueue responseQueue_{};
        std::string spare_{};
        size_t maxRequestBytes_{getConnectionConfig().maxRequestBytes};
        bool closeAfterResponse_{false};
        SPLICE_CONTROL spliceControl_{SPLICE_CONTROL::DISABLED};
        int spliceTargetFd_{-1};

    public:
        HandlerConnection() noexcept
            : HandlerConnection(getConnectionConfig())
        {
        }

        explicit HandlerConnection(size_t responseCapacity) noexcept
            : HandlerBase()
        {
            [[maybe_unused]] auto _ = responseQueue_.init(responseCapacity);
        }

        explicit HandlerConnection(const ConnectionConfig &config) noexcept
            : HandlerBase(),
              maxRequestBytes_(config.maxRequestBytes)
        {
            requestBuffer_.setHighWaterMark(config.readHighWaterMark);
            [[maybe_unused]] auto _ = responseQueue_.init(config.responseCapacity);
        }

        explicit HandlerConnection(const handler::ProxyAddress &target) noexcept
            : HandlerBase(target),
              maxRequestBytes_(getConnectionConfig().maxRequestBytes)
        {
            requestBuffer_.setHighWaterMark(getConnectionConfig().readHighWaterMark);
            [[maybe_unused]] auto _ = responseQueue_.init(getConnectionConfig().responseCapacity);
        }

        virtual ~HandlerConnection() noexcept override = default;

        HandlerConnection(const HandlerConnection &) = delete;
        HandlerConnection &operator=(const HandlerConnection &) = delete;
        HandlerConnection(HandlerConnection &&) = delete;
        HandlerConnection &operator=(HandlerConnection &&) = delete;

        // ---- 流式生命周期与连接钩子 ----
        virtual void handle() override {}
        virtual void onConnect(int fd) noexcept { fd_ = fd; }
        virtual void onUpgrade() noexcept {}
        [[nodiscard]] inline int fd() const noexcept { return HandlerBase::fd(); }

        virtual void reset() noexcept override
        {
            HandlerBase::reset();
            requestBuffer_.reset();
            requestBuffer_.setHighWaterMark(getConnectionConfig().readHighWaterMark);
            responseQueue_.reset();
            spare_.clear();
            closeAfterResponse_ = false;
            spliceControl_ = SPLICE_CONTROL::DISABLED;
            spliceTargetFd_ = -1;
            maxRequestBytes_ = getConnectionConfig().maxRequestBytes;
        }

        // ---- 业务缓冲区与响应队列操作 ----
        [[nodiscard]] inline Result<> appendRequest(const char *buf, ssize_t rn) noexcept
        {
            if (buf != nullptr && rn > 0) [[likely]]
            {
                return requestBuffer_.append(buf, static_cast<size_t>(rn));
            }
            return {};
        }
        [[nodiscard]] inline Result<> appendRequest(std::string_view sv) noexcept
        {
            return appendRequest(sv.data(), static_cast<ssize_t>(sv.size()));
        }
        [[nodiscard]] inline std::expected<char *, ERR>
        prepareRequestWritable(size_t minBytes = getConnectionConfig().readChunkSize) noexcept
        {
            if (auto res = requestBuffer_.ensureWritable(minBytes); !res) [[unlikely]]
            {
                return std::unexpected(res.error());
            }
            return requestBuffer_.writableBegin();
        }
        [[nodiscard]] inline char *requestWritableBegin() noexcept { return requestBuffer_.writableBegin(); }
        [[nodiscard]] inline size_t requestWritableBytes() const noexcept { return requestBuffer_.writableBytes(); }
        inline void commitRequest(size_t n) noexcept { requestBuffer_.commitWritten(n); }
        [[nodiscard]] inline bool requestOverLimit() const noexcept
        {
            return requestBuffer_.readableBytes() > maxRequestBytes_;
        }
        [[nodiscard]] inline size_t requestBytes() const noexcept { return requestBuffer_.readableBytes(); }
        [[nodiscard]] inline const char *requestBegin() const noexcept { return requestBuffer_.readableBegin(); }
        inline void requestConsume(size_t n) noexcept { requestBuffer_.retrieve(n); }
        inline void requestClear() noexcept { requestBuffer_.reset(); }
        [[nodiscard]] inline size_t readCredit() const noexcept
        {
            const size_t used = requestBuffer_.readableBytes();
            return used >= maxRequestBytes_ ? 0 : maxRequestBytes_ - used;
        }
        inline void setMaxRequestBytes(size_t n) noexcept { maxRequestBytes_ = n; }
        [[nodiscard]] inline size_t maxRequestBytes() const noexcept { return maxRequestBytes_; }

        [[nodiscard]] inline bool hasResponse() const noexcept { return !responseQueue_.empty(); }
        [[nodiscard]] inline bool needsHandle() const noexcept { return false; }
        [[nodiscard]] inline size_t responseCount() const noexcept { return responseQueue_.size(); }
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
        inline void recycleSpare(std::string &&s) noexcept
        {
            if (s.capacity() > spare_.capacity())
            {
                s.clear();
                spare_ = std::move(s);
            }
        }
        [[nodiscard]] inline Result<> pushResponse(std::string &&s) noexcept
        {
            return responseQueue_.push(std::move(s));
        }
        [[nodiscard]] inline Result<> pushResponse(const std::string &s) noexcept
        {
            return pushResponse(std::string_view(s));
        }
        [[nodiscard]] inline Result<> pushResponse(std::string_view sv) noexcept
        {
            if (sv.data() == nullptr || sv.empty())
            {
                return {};
            }
            return responseQueue_.emplace(sv);
        }
        [[nodiscard]] inline Result<> pushResponse(const char *s) noexcept
        {
            if (s == nullptr) [[unlikely]]
            {
                return {};
            }
            return pushResponse(std::string_view(s));
        }
        [[nodiscard]] inline Result<> reserveResponses(size_t capacity) noexcept
        {
            return responseQueue_.init(capacity);
        }
        [[nodiscard]] inline bool closeAfterResponse() const noexcept { return closeAfterResponse_; }
        inline void setCloseAfterResponse(bool v) noexcept { closeAfterResponse_ = v; }

        // ---- 零拷贝转发控制 ----
        inline void setSpliceTarget(int targetFd) noexcept
        {
            spliceTargetFd_ = targetFd;
            spliceControl_ = (targetFd >= 0) ? SPLICE_CONTROL::ACTIVE : SPLICE_CONTROL::DISABLED;
            if (connection_)
            {
                connection_->setSpliceTarget(targetFd);
            }
        }
        inline void setSpliceControl(SPLICE_CONTROL ctrl) noexcept
        {
            spliceControl_ = ctrl;
            if (ctrl == SPLICE_CONTROL::DISABLED || ctrl == SPLICE_CONTROL::CLOSED)
            {
                spliceTargetFd_ = -1;
            }
            if (connection_)
            {
                connection_->setSpliceControl(ctrl);
            }
        }
        inline void setSpliceTarget(SPLICE_CONTROL ctrl) noexcept { setSpliceControl(ctrl); }
        [[nodiscard]] inline SPLICE_CONTROL spliceControl() const noexcept { return spliceControl_; }
        [[nodiscard]] inline int spliceTarget() const noexcept { return spliceTargetFd_; }
        [[nodiscard]] inline bool isSpliceActive() const noexcept
        {
            return spliceControl_ == SPLICE_CONTROL::ACTIVE && spliceTargetFd_ >= 0;
        }
        inline void pauseSplice() noexcept
        {
            if (spliceControl_ == SPLICE_CONTROL::ACTIVE)
            {
                spliceControl_ = SPLICE_CONTROL::PAUSED;
            }
            if (connection_)
            {
                connection_->pauseSplice();
            }
        }
        inline void resumeSplice() noexcept
        {
            if (spliceControl_ == SPLICE_CONTROL::PAUSED)
            {
                spliceControl_ = (spliceTargetFd_ >= 0) ? SPLICE_CONTROL::ACTIVE : SPLICE_CONTROL::DISABLED;
            }
            if (connection_)
            {
                connection_->resumeSplice();
            }
        }
        inline void drainSplice() noexcept
        {
            if (spliceControl_ == SPLICE_CONTROL::ACTIVE)
            {
                spliceControl_ = SPLICE_CONTROL::DRAINING;
            }
            if (connection_)
            {
                connection_->drainSplice();
            }
        }
        inline void disableSplice() noexcept
        {
            spliceControl_ = SPLICE_CONTROL::DISABLED;
            spliceTargetFd_ = -1;
            if (connection_)
            {
                connection_->disableSplice();
            }
        }
        [[nodiscard]] inline bool spliceEnabled() const noexcept { return isSpliceActive(); }
        inline void enableSpliceForward(int targetFd) noexcept { setSpliceTarget(targetFd); }
        inline void enableSpliceForward(SPLICE_CONTROL ctrl) noexcept { setSpliceTarget(ctrl); }
        inline void disableSpliceForward() noexcept { disableSplice(); }
        [[nodiscard]] inline bool isSpliceForwardActive() const noexcept { return isSpliceActive(); }
    };

    // ---- ConnectionBase 对 HandlerConnection 的交互实现 ----

    inline void ConnectionBase::setFd(int fd) noexcept
    {
        fd_ = fd;
        if (fd_ >= 0)
        {
            config_ = getMynetConfigShared();
            applyQuickAck();
            if (handler_ != nullptr)
            {
                handler_->onConnect(fd_);
            }
        }
    }

    inline void ConnectionBase::setHandler(HandlerConnection *h) noexcept
    {
        handler_ = h;
        if (h != nullptr)
        {
            h->setConnection(this);
            if (fd_ >= 0)
            {
                h->onConnect(fd_);
            }
        }
    }

    inline bool ConnectionBase::isSpliceEnabled() const noexcept
    {
        if (handler_ != nullptr)
        {
            return handler_->isSpliceActive();
        }
        return isSpliceActive();
    }

    inline bool ConnectionBase::hasPendingWrite() const noexcept
    {
        if (pendingBytes_ > 0 || pipePending_ > 0)
        {
            return true;
        }
        if (hasResponse())
        {
            return true;
        }
        if (handler_ != nullptr && handler_->hasResponse())
        {
            return true;
        }
        return false;
    }

    inline bool ConnectionBase::ensurePipe() noexcept
    {
        if (pipeFd_[0] >= 0) [[likely]]
        {
            return true;
        }
        if (::pipe2(pipeFd_, O_NONBLOCK | O_CLOEXEC) < 0) [[unlikely]]
        {
            LOG_WARN("ConnectionBase::ensurePipe: fd {}: pipe2 failed: {}", fd_, errnoText(errno));
            pipeFd_[0] = -1;
            pipeFd_[1] = -1;
            return false;
        }
        return true;
    }

    inline std::expected<size_t, IO_END> ConnectionBase::spliceTo(int targetFd, size_t maxBytes) noexcept
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

        const ssize_t sIn = ::splice(fd_, nullptr, pipeFd_[1], nullptr, maxBytes, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
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

    inline std::expected<size_t, IO_END> ConnectionBase::spliceFrom(int sourceFd, size_t maxBytes) noexcept
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

    inline IO_STATUS ConnectionBase::handleSplice() noexcept
    {
        int targetFd = spliceTarget();
        SPLICE_CONTROL ctrl = spliceControl();
        if (handler_ != nullptr && handler_->spliceTarget() >= 0)
        {
            targetFd = handler_->spliceTarget();
            ctrl = handler_->spliceControl();
        }

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
            setSpliceControl(SPLICE_CONTROL::CLOSED);
            if (handler_ != nullptr)
            {
                handler_->setSpliceControl(SPLICE_CONTROL::CLOSED);
            }
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

    inline void ConnectionBase::pump() noexcept
    {
        const size_t hardCap = writeHighWaterMark_ * getConnectionConfig().writeHardCapFactor;
        if (handler_ != nullptr)
        {
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
        while (hasResponse())
        {
            if (pendingBytes_ >= hardCap) [[unlikely]]
            {
                LOG_WARN("Connection: fd {}: write backlog {} exceeds hard cap, closing after flush", fd_,
                         pendingBytes_);
                closeAfterWrite_ = true;
                break;
            }
            std::string resp = takeResponse();
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
        if (closeAfterResponse_)
        {
            closeAfterWrite_ = true;
        }
    }

    inline bool ConnectionBase::commitSent(size_t n) noexcept
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
                    handler_->recycleSpare(std::move(front));
                }
                else
                {
                    recycleSpare(std::move(front));
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

    inline void ConnectionBase::handle()
    {
        if (handler_ != nullptr)
        {
            handler_->handle();
        }
    }

    inline IO_STATUS ConnectionBase::handleWrite()
    {
        if (fd_ < 0)
        {
            return IO_STATUS::CLOSE;
        }

        pump();

        if (pipePending_ > 0)
        {
            int targetFd = spliceTarget();
            if (handler_ != nullptr && handler_->spliceTarget() >= 0)
            {
                targetFd = handler_->spliceTarget();
            }
            if (targetFd >= 0)
            {
                const ssize_t sOut =
                    ::splice(pipeFd_[0], nullptr, targetFd, nullptr, pipePending_, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
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

    inline IO_STATUS ConnectionBase::handleRead()
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
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
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
        if (handler_->closeAfterResponse() || closeAfterResponse_)
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

    inline void ConnectionBase::close()
    {
        state_ = CONN_STATE::CLOSED;
        if (fd_ != -1)
        {
            ::close(fd_);
            fd_ = -1;
        }
    }

    inline void ConnectionBase::reset() noexcept
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
        requestBuffer_.reset();
        requestBuffer_.setHighWaterMark(getConnectionConfig().readHighWaterMark);
        responseQueue_.reset();
        spare_.clear();
        writeQueue_.clear();
        writeOffset_ = 0;
        pendingBytes_ = 0;
        state_ = CONN_STATE::OPEN;
        readPaused_ = false;
        wantWrite_ = false;
        closeAfterWrite_ = false;
        closeAfterResponse_ = false;
        peerGone_ = false;
        timerId_ = 0;
        lastActive_ = std::chrono::steady_clock::now();
        config_.reset();
        writeHighWaterMark_ = getConnectionConfig().writeHighWaterMark;
        spliceControl_ = SPLICE_CONTROL::DISABLED;
        spliceTargetFd_ = -1;
        maxRequestBytes_ = getConnectionConfig().maxRequestBytes;
        handler_ = nullptr;
    }

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
     * 1. 纯净流式抽象：继承 ConnectionBase，复用统一连接底层传输缓冲、零拷贝 splice、读写缓冲背压与事件调度；
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

        Connection() noexcept = default;
        ~Connection() noexcept override { reset(); }

        Connection(const Connection &) = delete;
        Connection &operator=(const Connection &) = delete;
        Connection(Connection &&) noexcept = default;
        Connection &operator=(Connection &&) noexcept = default;

        inline void setFd(int fd) noexcept override
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

        using ConnectionBase::setHandler;
        inline void setHandler(Handler *h) noexcept
        {
            handler_ = h;
            ConnectionBase::setHandler(h);
        }
        [[nodiscard]] inline bool hasHandler() const noexcept { return handler_ != nullptr; }

        [[nodiscard]] inline Handler &handler() noexcept
        {
            if (handler_ == nullptr)
            {
                if (!defaultHandler_.has_value())
                {
                    defaultHandler_.emplace();
                }
                setHandler(&(*defaultHandler_));
            }
            return *static_cast<Handler *>(handler_);
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
                nonConst->setHandler(&(*nonConst->defaultHandler_));
            }
            return *static_cast<const Handler *>(handler_);
        }

        inline void reset() noexcept override
        {
            ConnectionBase::reset();
            if (defaultHandler_.has_value())
            {
                defaultHandler_->reset();
            }
            defaultHandler_.reset();
        }

    private:
        [[no_unique_address]] ProtocolContext protocol_{};
        std::optional<Handler> defaultHandler_{};
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

    /**
     * @brief 纯业务数据报协议处理器基类
     *
     * 继承自统一的 HandlerBase，提供数据报排队与发送控制。
     */
    class HandlerDatagram : public HandlerBase
    {
    public:
        using DatagramCallback = HandlerBase::DatagramCallback;

        HandlerDatagram() noexcept
            : HandlerDatagram(getDatagramConfig())
        {
        }

        explicit HandlerDatagram(const DatagramConfig &config) noexcept
            : HandlerBase(),
              maxDatagramBytes_(config.maxDatagramBytes),
              maxPendingOutgoing_(config.maxPendingOutgoing)
        {
            [[maybe_unused]] auto _ = outgoing_.init(maxPendingOutgoing_);
        }

        explicit HandlerDatagram(const sockaddr_in &peer) noexcept
            : HandlerBase(peer),
              maxDatagramBytes_(getDatagramConfig().maxDatagramBytes),
              maxPendingOutgoing_(getDatagramConfig().maxPendingOutgoing)
        {
            [[maybe_unused]] auto _ = outgoing_.init(maxPendingOutgoing_);
        }

        virtual ~HandlerDatagram() noexcept override = default;

        HandlerDatagram(const HandlerDatagram &) = delete;
        HandlerDatagram &operator=(const HandlerDatagram &) = delete;
        HandlerDatagram(HandlerDatagram &&) = delete;
        HandlerDatagram &operator=(HandlerDatagram &&) = delete;

        virtual void onDatagram([[maybe_unused]] const sockaddr_in &peer, [[maybe_unused]] const char *data,
                                [[maybe_unused]] size_t n) noexcept override
        {
        }

        virtual void reset() noexcept override
        {
            HandlerBase::reset();
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
        }

        virtual void onMessageComplete() noexcept override {}
        virtual void onParseError([[maybe_unused]] const char *reason) noexcept override {}

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

    protected:
        size_t maxDatagramBytes_{1 << 16};
        size_t maxPendingOutgoing_{1 << 10};
        DatagramQueue outgoing_{};
        size_t droppedOutgoing_{0};
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

    class HandlerInboundBase : public mynet::HandlerConnection
    {
    protected:
        InboundStage stage_{InboundStage::HANDSHAKE};

    public:
        using HandlerInboundConnectionBase = HandlerInboundBase;
        using HandlerInbound = HandlerInboundBase;
        using RequestCallback = HandlerBase::RequestCallback;
        using DatagramCallback = HandlerBase::DatagramCallback;

        HandlerInboundBase() noexcept = default;
        ~HandlerInboundBase() noexcept override = default;

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

    class HandlerOutboundBase : public mynet::HandlerConnection
    {
    protected:
        OutboundStage stage_{OutboundStage::INITIAL};

    public:
        using HandlerOutboundConnectionBase = HandlerOutboundBase;
        using HandlerOutbound = HandlerOutboundBase;

        HandlerOutboundBase() noexcept = default;
        explicit HandlerOutboundBase(const handler::ProxyAddress &target) noexcept
            : HandlerConnection(target)
        {
        }
        ~HandlerOutboundBase() noexcept override = default;

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

    using HandlerInboundConnectionBase = HandlerInboundBase;
    using HandlerOutboundConnectionBase = HandlerOutboundBase;
    using HandlerInbound = HandlerInboundBase;
    using HandlerOutbound = HandlerOutboundBase;
} // namespace mynet::handler

namespace mynet
{
    using HandlerInboundConnectionBase = handler::HandlerInboundBase;
    using HandlerOutboundConnectionBase = handler::HandlerOutboundBase;
    using HandlerInboundBase = handler::HandlerInboundBase;
    using HandlerOutboundBase = handler::HandlerOutboundBase;
    using HandlerInbound = handler::HandlerInboundBase;
    using HandlerOutbound = handler::HandlerOutboundBase;
} // namespace mynet
