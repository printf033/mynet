#pragma once

/**
 * @file forwarder.hpp
 * @brief 高性能双向流式与数据报中继转发引擎 (Forwarder)。
 *
 * 借鉴 sing-box 与 dae 的现代化内核架构，打通 Inbound（入站协议状态机）与
 * Outbound（出站协议状态机）之间的双向传输链路：
 * 1. 零拷贝转发：双端均为明文/内核解密 TCP 且启用 splice 时，自动建立 Linux splice(2)
 *    双向内核管道，实现零用户态内存拷贝的高速穿透；
 * 2. 缓冲泵送回落：双端包含 TLS 加密或协议变形时，自动回退到流控缓冲双向泵送；
 * 3. 握手预读残留数据自动排空：在连接升级为 STREAMING 阶段时，无缝冲刷握手期间预摄入的数据；
 * 4. 半关闭与全关闭生命周期级联：支持 FIN 报文双向传播与资源自愈清理；
 * 5. 全链路流量统计与会话生命周期管理：实时追踪上行/下行流量、包数与活跃时间戳；
 * 6. UDP/Datagram 代理会话管理与空闲会话超时排空。
 */

#include "address.hpp"
#include "config/log.hpp"
#include "configHolder.hpp"
#include "connection.hpp"
#include "datagram.hpp"
#include "dialer.hpp"
#include "ebpf.hpp"
#include "error.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string_view>
#if defined(__linux__)
#include <sys/epoll.h>
#endif
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

namespace mynet
{

    /**
     * @brief 转发工作模式
     */
    enum class ForwardMode : uint8_t
    {
        AUTO,             ///< 自动检测：依次尝试 KERNEL_SOCKMAP -> ZERO_COPY_SPLICE -> BUFFER_PUMP
        KERNEL_SOCKMAP,   ///< eBPF Sockmap 内核套接字直接流卸载（0 上下文切换，0 内存拷贝）
        ZERO_COPY_SPLICE, ///< 强制 Linux splice(2) 内核管道零拷贝转发
        BUFFER_PUMP       ///< 强制用户态缓冲泵送（支持 TLS、协议重写、帧拆拼等）
    };

    [[nodiscard]] inline constexpr const char *forwardModeName(ForwardMode mode) noexcept
    {
        switch (mode)
        {
        case ForwardMode::AUTO:
            return "AUTO";
        case ForwardMode::KERNEL_SOCKMAP:
            return "KERNEL_SOCKMAP";
        case ForwardMode::ZERO_COPY_SPLICE:
            return "ZERO_COPY_SPLICE";
        case ForwardMode::BUFFER_PUMP:
            return "BUFFER_PUMP";
        }
        return "UNKNOWN";
    }

    /**
     * @brief 转发会话生命周期状态
     */
    enum class ForwardSessionState : uint8_t
    {
        INIT,       ///< 会话初始化
        CONNECTING, ///< 正在握手或建连
        STREAMING,  ///< 全双工数据传输中
        DRAINING,   ///< 一端半关闭（EOF），正在排空对端残留数据
        CLOSED,     ///< 双向关闭，会话终止
        ERROR       ///< 传输异常（RST / 协议错误）
    };

    /**
     * @brief 转发流量与性能统计信息
     */
    struct ForwarderStats
    {
        uint64_t bytesUp{0};     ///< 上行传输字节数 (入站 -> 出站)
        uint64_t bytesDown{0};   ///< 下行传输字节数 (出站 -> 入站)
        uint64_t packetsUp{0};   ///< 上行报文/批次数
        uint64_t packetsDown{0}; ///< 下行报文/批次数
        std::chrono::steady_clock::time_point startTime{};
        std::chrono::steady_clock::time_point lastActive{};

        ForwarderStats() noexcept
        {
            auto now = std::chrono::steady_clock::now();
            startTime = now;
            lastActive = now;
        }

        [[nodiscard]] inline uint64_t totalBytes() const noexcept { return bytesUp + bytesDown; }
        [[nodiscard]] inline uint64_t totalPackets() const noexcept { return packetsUp + packetsDown; }
        [[nodiscard]] inline double
        idleSeconds(std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now()) const noexcept
        {
            return std::chrono::duration<double>(now - lastActive).count();
        }

        inline void touch() noexcept { lastActive = std::chrono::steady_clock::now(); }
    };

    /**
     * @brief 单次系统 splice 调用结果
     */
    struct SpliceResult
    {
        ssize_t bytesSpliced{0};
        bool eof{false};
        int err{0};
    };

    /**
     * @brief 单次双向泵送结果
     */
    struct PumpResult
    {
        size_t bytesUp{0};
        size_t bytesDown{0};
        [[nodiscard]] inline size_t total() const noexcept { return bytesUp + bytesDown; }
    };

    namespace detail
    {
        [[nodiscard]] inline SpliceResult splicePipes(int srcFd, int dstFd, int pipeWriteFd, int pipeReadFd,
                                                      size_t maxBytes, size_t *pipePending) noexcept
        {
            if (srcFd < 0 || dstFd < 0 || pipeWriteFd < 0 || pipeReadFd < 0)
            {
                return {.bytesSpliced = -1, .eof = false, .err = EINVAL};
            }

            size_t localPending = 0;
            size_t &pending = (pipePending != nullptr) ? *pipePending : localPending;
            size_t written = 0;

            auto drainPipeOut = [&]() noexcept -> std::optional<SpliceResult>
            {
                while (pending > 0)
                {
                    const ssize_t sOut =
                        ::splice(pipeReadFd, nullptr, dstFd, nullptr, pending, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
                    if (sOut > 0)
                    {
                        written += static_cast<size_t>(sOut);
                        pending -= static_cast<size_t>(sOut);
                        continue;
                    }
                    if (sOut < 0)
                    {
                        if (errno == EINTR)
                        {
                            continue;
                        }
                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                        {
                            return SpliceResult{
                                .bytesSpliced = static_cast<ssize_t>(written), .eof = false, .err = EAGAIN};
                        }
                        return SpliceResult{.bytesSpliced = static_cast<ssize_t>(written), .eof = false, .err = errno};
                    }
                    break;
                }
                return std::nullopt;
            };

            // 先排空上次因目的端 EAGAIN 遗留在管道内的字节，避免对端随后关闭时误判 EOF 丢数据
            if (auto stopRes = drainPipeOut(); stopRes.has_value())
            {
                return *stopRes;
            }

            // 1. 从源端摄入管道
            ssize_t sIn = -1;
            for (;;)
            {
                sIn = ::splice(srcFd, nullptr, pipeWriteFd, nullptr, maxBytes, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
                if (sIn < 0 && errno == EINTR)
                {
                    continue;
                }
                break;
            }
            if (sIn < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    return {.bytesSpliced = static_cast<ssize_t>(written), .eof = false, .err = EAGAIN};
                }
                return {.bytesSpliced = static_cast<ssize_t>(written), .eof = false, .err = errno};
            }
            if (sIn == 0)
            {
                return {.bytesSpliced = static_cast<ssize_t>(written), .eof = true, .err = 0};
            }

            pending += static_cast<size_t>(sIn);

            // 2. 从管道刷出至目的端
            if (auto stopRes = drainPipeOut(); stopRes.has_value())
            {
                return *stopRes;
            }

            return {.bytesSpliced = static_cast<ssize_t>(written), .eof = false, .err = 0};
        }

        [[nodiscard]] inline SpliceResult splicePipes(int srcFd, int dstFd, int pipeWriteFd, int pipeReadFd,
                                                      size_t maxBytes = 65536) noexcept
        {
            return splicePipes(srcFd, dstFd, pipeWriteFd, pipeReadFd, maxBytes, nullptr);
        }
    } // namespace detail

    /**
     * @brief 转发会话挂接外部事件循环 (EventLoop) 的可选轻量回调钩子
     */
    class ForwarderStreamSession;

    struct ForwarderLoopHooks
    {
        std::function<bool(int fd, uint32_t events, std::function<void(uint32_t)>)> addWatch{};
        std::function<bool(int fd, uint32_t events)> modWatch{};
        std::function<void(int fd)> delWatch{};
        std::function<void(std::function<void()>)> postTask{};

        // Proactor (io_uring) 原生异步接管钩子：存在时由引擎以 SQE/CQE 直接驱动 connect/recv/send/splice
        bool deferOutboundConnect{false};
        std::function<bool(const std::shared_ptr<ForwarderStreamSession> &session)> registerSession{};
        std::function<void(uint64_t sessionId)> notifySession{};
        std::function<bool(uint64_t sessionId, bool transferOutboundFdOwnership)> retireSession{};

        [[nodiscard]] inline bool active() const noexcept
        {
            return (static_cast<bool>(addWatch) && static_cast<bool>(delWatch)) || hasAsyncRelay();
        }
        [[nodiscard]] inline bool hasAsyncRelay() const noexcept
        {
            return static_cast<bool>(registerSession) && static_cast<bool>(retireSession);
        }
    };

    /**
     * @brief 传输层无关字节流通道抽象 (IStreamChannel)
     *
     * 将数据平面的读取/写入能力从内核 `int fd` 解耦，使得 Socket、TLS 内存流、WebSocket 流、
     * HTTP/2 逻辑流与 HTTP/3 QUIC 流都能通过同一套接口交由 Forwarder 桥接与中继。
     */
    class IStreamChannel
    {
    public:
        virtual ~IStreamChannel() noexcept = default;

        [[nodiscard]] virtual int fd() const noexcept { return -1; }
        [[nodiscard]] virtual bool isOpen() const noexcept = 0;
        [[nodiscard]] virtual bool isPassthrough() const noexcept { return false; }
        [[nodiscard]] virtual Result<size_t> readBytes(std::span<uint8_t> dst) noexcept = 0;
        [[nodiscard]] virtual Result<size_t> writeBytes(std::span<const uint8_t> src) noexcept = 0;
        virtual void closeChannel() noexcept = 0;
    };

    /**
     * @brief 基于 POSIX 非阻塞描述符的 IStreamChannel 实现
     */
    class SocketStreamChannel final : public IStreamChannel
    {
    private:
        int fd_{-1};
        bool ownsFd_{false};
        bool closed_{false};

    public:
        explicit SocketStreamChannel(int fd = -1, bool ownsFd = false) noexcept
            : fd_(fd),
              ownsFd_(ownsFd),
              closed_(fd < 0)
        {
        }

        ~SocketStreamChannel() noexcept override
        {
            if (ownsFd_ && fd_ >= 0)
            {
                ::close(fd_);
            }
            fd_ = -1;
        }

        [[nodiscard]] int fd() const noexcept override { return fd_; }
        [[nodiscard]] bool isOpen() const noexcept override { return !closed_ && fd_ >= 0; }
        [[nodiscard]] bool isPassthrough() const noexcept override { return isOpen(); }

        [[nodiscard]] Result<size_t> readBytes(std::span<uint8_t> dst) noexcept override
        {
            if (fd_ < 0 || closed_ || dst.empty())
            {
                return size_t{0};
            }
            const ssize_t n = ::read(fd_, dst.data(), dst.size());
            if (n > 0)
            {
                return static_cast<size_t>(n);
            }
            if (n == 0)
            {
                closed_ = true;
                return std::unexpected(ERR::CONNECT_FAILED);
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR || errno == ENOTCONN)
            {
                return size_t{0};
            }
            closed_ = true;
            return std::unexpected(ERR::CONNECT_FAILED);
        }

        [[nodiscard]] Result<size_t> writeBytes(std::span<const uint8_t> src) noexcept override
        {
            if (fd_ < 0 || closed_ || src.empty())
            {
                return size_t{0};
            }
            const ssize_t n = ::send(fd_, src.data(), src.size(), MSG_NOSIGNAL);
            if (n >= 0)
            {
                return static_cast<size_t>(n);
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR || errno == ENOTCONN)
            {
                return size_t{0};
            }
            closed_ = true;
            return std::unexpected(ERR::CONNECT_FAILED);
        }

        void closeChannel() noexcept override
        {
            closed_ = true;
            if (ownsFd_ && fd_ >= 0)
            {
                ::close(fd_);
                fd_ = -1;
            }
        }
    };

    /**
     * @brief 双向流式转发会话 (Stream Forwarding Session)
     *
     * 封装一对关联的入站处理器 (Inbound) 与出站处理器 (Outbound)，
     * 提供握手残留数据排空、内核 splice 激活、用户态数据泵送与半关闭协同管理。
     */
    class ForwarderStreamSession : public std::enable_shared_from_this<ForwarderStreamSession>
    {
    public:
        using StateChangeCallback = std::function<void(ForwarderStreamSession &, ForwardSessionState)>;
        using CloseCallback = std::function<void(ForwarderStreamSession &)>;

    private:
        uint64_t id_{0};
        ForwardSessionState state_{ForwardSessionState::INIT};
        ForwardMode configuredMode_{ForwardMode::AUTO};
        ForwardMode activeMode_{ForwardMode::BUFFER_PUMP};
        ForwarderConfig config_{};
        ForwarderStats stats_{};

        Handler *inbound_{nullptr};
        Handler *outbound_{nullptr};
        std::unique_ptr<Handler> ownedInbound_{nullptr};
        std::unique_ptr<Handler> ownedOutbound_{nullptr};
        std::shared_ptr<IStreamChannel> inboundChannel_{nullptr};
        std::shared_ptr<IStreamChannel> outboundChannel_{nullptr};
        bool inboundChannelDriven_{false};
        int sockmapFd_{-1};
        int pipeUp_[2]{-1, -1};
        int pipeDown_[2]{-1, -1};
        Address target_{};
        std::string outboundTag_{};

        struct PendingSlice
        {
            std::string data{};
            size_t offset{0};

            [[nodiscard]] inline bool empty() const noexcept { return offset >= data.size(); }
            [[nodiscard]] inline std::string_view remaining() const noexcept
            {
                return empty() ? std::string_view{} : std::string_view(data).substr(offset);
            }
            inline void assign(std::string s, size_t start = 0) noexcept
            {
                data = std::move(s);
                offset = start;
                if (offset >= data.size())
                {
                    clear();
                }
            }
            inline void advance(size_t n) noexcept
            {
                offset += n;
                if (offset >= data.size())
                {
                    clear();
                }
            }
            inline void clear() noexcept
            {
                data.clear();
                offset = 0;
            }
        };

        PendingSlice outboundPending_{};
        PendingSlice inboundPending_{};
        ForwarderLoopHooks loopHooks_{};
        bool outboundWatched_{false};
        bool ownsOutboundFd_{false};

        sockaddr_in outboundTargetAddr_{};
        bool outboundConnecting_{false};
        bool outboundConnectDeferred_{false};
        bool proactorManaged_{false};
        std::string proactorSendBuf_{};
        size_t proactorSendOffset_{0};

        bool inboundClosed_{false};
        bool outboundClosed_{false};
        bool sockmapPaused_{false};
        size_t pipeUpPending_{0};
        size_t pipeDownPending_{0};
        bool disableOffloadForSession_{false};
        bool disableSpliceForSession_{false};
        uint64_t inDetachHookToken_{0};
        uint64_t outDetachHookToken_{0};

        StateChangeCallback onStateChange_{nullptr};
        CloseCallback onClose_{nullptr};

    public:
        explicit ForwarderStreamSession(uint64_t sessionId, ForwarderConfig cfg = {}) noexcept
            : id_(sessionId),
              configuredMode_(cfg.enableSplice ? ForwardMode::AUTO : ForwardMode::BUFFER_PUMP),
              config_(cfg)
        {
        }

        ~ForwarderStreamSession() noexcept { close(true); }

        ForwarderStreamSession(const ForwarderStreamSession &) = delete;
        ForwarderStreamSession &operator=(const ForwarderStreamSession &) = delete;
        ForwarderStreamSession(ForwarderStreamSession &&) = delete;
        ForwarderStreamSession &operator=(ForwarderStreamSession &&) = delete;

        [[nodiscard]] inline uint64_t id() const noexcept { return id_; }
        [[nodiscard]] inline ForwardSessionState state() const noexcept { return state_; }
        [[nodiscard]] inline ForwardMode configuredMode() const noexcept { return configuredMode_; }
        [[nodiscard]] inline ForwardMode activeMode() const noexcept { return activeMode_; }
        [[nodiscard]] inline const ForwarderConfig &config() const noexcept { return config_; }
        [[nodiscard]] inline const ForwarderStats &stats() const noexcept { return stats_; }
        [[nodiscard]] inline ForwarderStats &stats() noexcept { return stats_; }

        [[nodiscard]] inline int inboundFd() const noexcept { return inboundChannel_ ? inboundChannel_->fd() : -1; }
        [[nodiscard]] inline int outboundFd() const noexcept { return outboundChannel_ ? outboundChannel_->fd() : -1; }
        [[nodiscard]] inline int sockmapFd() const noexcept { return sockmapFd_; }
        [[nodiscard]] inline int pipeUpRead() const noexcept { return pipeUp_[0]; }
        [[nodiscard]] inline int pipeUpWrite() const noexcept { return pipeUp_[1]; }
        [[nodiscard]] inline int pipeDownRead() const noexcept { return pipeDown_[0]; }
        [[nodiscard]] inline int pipeDownWrite() const noexcept { return pipeDown_[1]; }
        [[nodiscard]] inline bool ownsOutboundFd() const noexcept { return ownsOutboundFd_; }
        [[nodiscard]] inline bool proactorManaged() const noexcept { return proactorManaged_; }
        [[nodiscard]] inline bool isOutboundConnecting() const noexcept { return outboundConnecting_; }
        [[nodiscard]] inline bool isOutboundConnectDeferred() const noexcept { return outboundConnectDeferred_; }
        [[nodiscard]] inline const sockaddr_in &outboundTargetAddr() const noexcept { return outboundTargetAddr_; }
        [[nodiscard]] inline bool hasOutboundPendingToSend() const noexcept
        {
            return (proactorSendOffset_ < proactorSendBuf_.size()) || !outboundPending_.empty() ||
                   (outbound_ != nullptr && outbound_->hasResponse());
        }
        [[nodiscard]] inline size_t outboundReadCredit() const noexcept
        {
            return outbound_ != nullptr ? outbound_->readCredit() : config_.bufferChunkSize;
        }
        [[nodiscard]] inline Handler *inbound() noexcept { return inbound_; }
        [[nodiscard]] inline Handler *outbound() noexcept { return outbound_; }
        [[nodiscard]] inline const Address &target() const noexcept { return target_; }
        [[nodiscard]] inline const std::string &outboundTag() const noexcept { return outboundTag_; }

        inline void setTarget(const Address &target) noexcept { target_ = target; }
        inline void setOutboundTag(std::string tag) noexcept { outboundTag_ = std::move(tag); }
        inline void setInboundFd(int fd) noexcept
        {
            inboundChannel_ = (fd >= 0) ? std::make_shared<SocketStreamChannel>(fd, false) : nullptr;
            inboundChannelDriven_ = false;
        }
        inline void setOutboundFd(int fd) noexcept
        {
            outboundChannel_ = (fd >= 0) ? std::make_shared<SocketStreamChannel>(fd, false) : nullptr;
        }
        inline void setOutboundConnectState(bool connecting, bool deferred, const sockaddr_in &targetAddr) noexcept
        {
            outboundConnecting_ = connecting;
            outboundConnectDeferred_ = deferred;
            outboundTargetAddr_ = targetAddr;
        }
        inline void setInboundChannel(std::shared_ptr<IStreamChannel> ch) noexcept
        {
            inboundChannel_ = std::move(ch);
            inboundChannelDriven_ = (inboundChannel_ != nullptr);
        }
        inline void setOutboundChannel(std::shared_ptr<IStreamChannel> ch) noexcept { outboundChannel_ = std::move(ch); }
        inline void setLoopHooks(ForwarderLoopHooks hooks) noexcept { loopHooks_ = std::move(hooks); }
        inline void setOwnsOutboundFd(bool owns) noexcept { ownsOutboundFd_ = owns; }

        inline bool installOutboundWatch()
        {
            const int outFd = outboundFd();
            if (outboundWatched_ || proactorManaged_ || !loopHooks_.active() || outFd < 0 || outboundClosed_ ||
                state_ == ForwardSessionState::CLOSED)
            {
                return false;
            }
            if (loopHooks_.hasAsyncRelay() && outboundChannel_ != nullptr && outboundChannel_->isPassthrough())
            {
                proactorManaged_ = loopHooks_.registerSession(shared_from_this());
                return proactorManaged_;
            }
            if (!loopHooks_.addWatch || !loopHooks_.delWatch)
            {
                return false;
            }
#if defined(__linux__)
            std::weak_ptr<ForwarderStreamSession> weak = weak_from_this();
            uint32_t evMask = EPOLLIN | EPOLLOUT | EPOLLET;
#ifdef EPOLLRDHUP
            evMask |= EPOLLRDHUP;
#endif
            outboundWatched_ =
                loopHooks_.addWatch(outFd, evMask,
                                    [weak](uint32_t events)
                                    {
                                        auto self = weak.lock();
                                        if (self == nullptr || self->isClosed())
                                        {
                                            return;
                                        }
                                        const int fd = self->outboundFd();
                                        if (self->outboundConnecting_ && (events & EPOLLOUT) && fd >= 0)
                                        {
                                            int err = 0;
                                            socklen_t len = sizeof(err);
                                            if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0)
                                            {
                                                err = (errno != 0) ? errno : ECONNREFUSED;
                                            }
                                            self->outboundConnecting_ = false;
                                            if (err != 0)
                                            {
                                                self->markOutboundClosed();
                                                self->close();
                                                return;
                                            }
                                            if (self->outbound_ != nullptr)
                                            {
                                                self->outbound_->handle();
                                            }
                                        }
                                        if ((events & (EPOLLERR | EPOLLHUP)) && !(events & EPOLLIN))
                                        {
                                            self->markOutboundClosed();
                                        }
                                        else
                                        {
                                            (void)self->pump();
                                        }
                                        if (self->inboundClosed_ && self->outboundClosed_)
                                        {
                                            self->close();
                                        }
                                    });
#endif
            return outboundWatched_;
        }

        inline void setSockmapFd(int fd) noexcept { sockmapFd_ = fd; }
        inline void setOwnedInbound(std::unique_ptr<Handler> in) noexcept
        {
            ownedInbound_ = std::move(in);
            inbound_ = ownedInbound_.get();
        }
        inline void setOwnedOutbound(std::unique_ptr<Handler> out) noexcept
        {
            ownedOutbound_ = std::move(out);
            outbound_ = ownedOutbound_.get();
        }

        [[nodiscard]] inline bool isEstablished() const noexcept
        {
            return state_ == ForwardSessionState::STREAMING || state_ == ForwardSessionState::DRAINING;
        }

        [[nodiscard]] inline bool isClosed() const noexcept { return state_ == ForwardSessionState::CLOSED; }
        [[nodiscard]] inline bool isInboundClosed() const noexcept { return inboundClosed_; }
        [[nodiscard]] inline bool isOutboundClosed() const noexcept { return outboundClosed_; }

        inline void setOnStateChange(StateChangeCallback cb) noexcept { onStateChange_ = std::move(cb); }
        inline void setOnClose(CloseCallback cb) noexcept { onClose_ = std::move(cb); }

        inline void setState(ForwardSessionState newState) noexcept
        {
            if (state_ != newState)
            {
                state_ = newState;
                if (onStateChange_)
                {
                    onStateChange_(*this, newState);
                }
            }
        }

        /**
         * @brief 绑定入站与出站处理器，并建立双向流桥接
         *
         * @param in 入站处理器引用
         * @param out 出站处理器引用
         * @param inFd 入站套接字描述符（可选，默认从 in.fd() 获取）
         * @param outFd 出站套接字描述符（可选，默认从 out.fd() 获取）
         * @param userSslActive 是否存在用户态 SSL（若为 true 则禁止 splice 强制走用户态缓冲）
         * @return size_t 桥接初始化阶段预排空摄入的残余字节数
         */
        size_t attach(Handler &in, Handler &out, int inFd = -1, int outFd = -1, bool userSslActive = false)
        {
            return attachChannels(in, nullptr, out, nullptr, inFd, outFd, userSslActive);
        }

        size_t attachChannels(Handler &in, std::shared_ptr<IStreamChannel> inCh, Handler &out,
                              std::shared_ptr<IStreamChannel> outCh, int inFd = -1, int outFd = -1,
                              bool userSslActive = false)
        {
            inbound_ = &in;
            outbound_ = &out;
            inboundChannelDriven_ = (inCh != nullptr);
            if (inCh != nullptr)
            {
                inboundChannel_ = std::move(inCh);
            }
            else
            {
                const int resolvedInFd = (inFd >= 0) ? inFd : in.fd();
                inboundChannel_ =
                    (resolvedInFd >= 0) ? std::make_shared<SocketStreamChannel>(resolvedInFd, false) : nullptr;
            }
            if (outCh != nullptr)
            {
                outboundChannel_ = std::move(outCh);
            }
            else
            {
                const int resolvedOutFd = (outFd >= 0) ? outFd : out.fd();
                outboundChannel_ =
                    (resolvedOutFd >= 0) ? std::make_shared<SocketStreamChannel>(resolvedOutFd, false) : nullptr;
            }

            if (in.targetAddress().has_value())
            {
                target_ = *in.targetAddress();
            }
            else if (out.target().type == AddressType::IPV4 || out.target().type == AddressType::DOMAIN ||
                     out.target().type == AddressType::IPV6)
            {
                target_ = out.target();
            }

            // 绑定入站 Handler 外部数据面联动钩子及双向安全摘除钩子，防止借用型 Handler 早于 Forwarder
            // 析构导致悬空解引用
            {
                std::weak_ptr<ForwarderStreamSession> weak = weak_from_this();
                const bool hasShared = !weak.expired();
                in.setExternalDataPlane(
                    [this, weak, hasShared]()
                    {
                        auto guard = hasShared ? weak.lock() : nullptr;
                        if (hasShared && !guard)
                        {
                            return;
                        }
                        (void)pump();
                    },
                    [this, weak, hasShared](uint32_t events) -> int
                    {
                        auto guard = hasShared ? weak.lock() : nullptr;
                        if (hasShared && !guard)
                        {
                            return 1;
                        }
                        return onReactorInboundEvent(events);
                    },
                    [this, weak, hasShared]() -> bool
                    {
                        auto guard = hasShared ? weak.lock() : nullptr;
                        if (hasShared && !guard)
                        {
                            return false;
                        }
                        return activeMode_ == ForwardMode::KERNEL_SOCKMAP ||
                               activeMode_ == ForwardMode::ZERO_COPY_SPLICE;
                    });
                inDetachHookToken_ = in.addExternalDetachHook(
                    [this, weak, hasShared]()
                    {
                        auto guard = hasShared ? weak.lock() : nullptr;
                        if (hasShared && !guard)
                        {
                            return;
                        }
                        inDetachHookToken_ = 0;
                        inbound_ = nullptr;
                        markInboundClosed();
                        close(true);
                    });
                outDetachHookToken_ = out.addExternalDetachHook(
                    [this, weak, hasShared]()
                    {
                        auto guard = hasShared ? weak.lock() : nullptr;
                        if (hasShared && !guard)
                        {
                            return;
                        }
                        outDetachHookToken_ = 0;
                        outbound_ = nullptr;
                        markOutboundClosed();
                        close(true);
                    });
            }

            // 1. 握手残余数据预冲刷：排空握手期间在用户态缓冲区堆积的早期业务载荷
            size_t preFlushed = flushPrebuffered();

            // 2. 冲刷已生成的出站与入站协议头/握手报文 (如 SOCKS5 Greeting, Trojan Header, VLESS Header, HTTP CONNECT
            // 等)；若处于 Proactor 延迟异步建连阶段则等待 connect CQE 后再发
            if (!outboundConnectDeferred_)
            {
                flushOutboundResponses();
            }
            flushInboundResponses();

            // 3. 仅当出站协议已确立时，激活最优零拷贝转发通道
            if (outbound_ == nullptr || outbound_->isEstablished())
            {
                activateAdaptiveMode(userSslActive);
            }
            else
            {
                activateBufferPump();
            }

            setState(ForwardSessionState::STREAMING);
            return preFlushed;
        }

    private:
        inline void flushSideResponses(Handler *h, IStreamChannel *ch, PendingSlice &pending, bool isOutbound) noexcept
        {
            const bool &closedFlag = isOutbound ? outboundClosed_ : inboundClosed_;
            if (h == nullptr || closedFlag || ch == nullptr)
            {
                return;
            }
            if (isOutbound && (outboundConnectDeferred_ || proactorManaged_))
            {
                return;
            }

            // 当入站直接绑定在 Reactor/Proactor 管理的 Connection 上且非虚拟通道时，
            // Proactor 模式下只推进队列至 writeQueue_ 交由 io_uring SEND 发送；Reactor 下则直接 pump+handleWrite
            const int fd = ch->fd();
            if (!isOutbound && !inboundChannelDriven_ && h->connection() != nullptr && h->connection()->fd() == fd &&
                fd >= 0)
            {
                Connection *conn = h->connection();
                const size_t queued = h->responseBytes();
                conn->pump();
                if (proactorManaged_)
                {
                    if (queued > 0)
                    {
                        stats_.bytesDown += queued;
                        stats_.touch();
                    }
                    return;
                }
                if (conn->handleWrite() == IO_STATUS::CLOSE)
                {
                    markInboundClosed();
                }
                else if (queued > 0)
                {
                    stats_.bytesDown += queued;
                    stats_.touch();
                }
                return;
            }

            auto tryWrite = [&](std::string_view sv) noexcept -> ssize_t
            {
                auto r =
                    ch->writeBytes(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(sv.data()), sv.size()));
                if (!r)
                {
                    return -1;
                }
                return static_cast<ssize_t>(*r);
            };

            auto recordBytes = [&](size_t bytes) noexcept
            {
                if (isOutbound)
                {
                    stats_.bytesUp += bytes;
                }
                else
                {
                    stats_.bytesDown += bytes;
                }
                stats_.touch();
            };

            auto markClosed = [&]() noexcept
            {
                if (isOutbound)
                {
                    markOutboundClosed();
                }
                else
                {
                    markInboundClosed();
                }
            };

            if (!pending.empty())
            {
                const ssize_t n = tryWrite(pending.remaining());
                if (n > 0)
                {
                    recordBytes(static_cast<size_t>(n));
                    pending.advance(static_cast<size_t>(n));
                }
                else if (n < 0)
                {
                    markClosed();
                    return;
                }
                if (!pending.empty())
                {
                    return;
                }
            }

            while (h->hasResponse())
            {
                std::string resp = h->takeResponse();
                if (resp.empty())
                {
                    continue;
                }

                const ssize_t n = tryWrite(resp);
                if (n > 0)
                {
                    recordBytes(static_cast<size_t>(n));
                    if (static_cast<size_t>(n) < resp.size())
                    {
                        pending.assign(std::move(resp), static_cast<size_t>(n));
                        return;
                    }
                }
                else if (n == 0)
                {
                    pending.assign(std::move(resp), 0);
                    return;
                }
                else
                {
                    markClosed();
                    return;
                }
            }
        }

    public:
        inline void flushOutboundResponses() noexcept
        {
            flushSideResponses(outbound_, outboundChannel_.get(), outboundPending_, true);
        }

        inline void flushInboundResponses() noexcept
        {
            flushSideResponses(inbound_, inboundChannel_.get(), inboundPending_, false);
        }

        [[nodiscard]] inline bool hasOutboundSink() const noexcept { return outboundChannel_ != nullptr; }
        [[nodiscard]] inline bool hasInboundSink() const noexcept { return inboundChannel_ != nullptr; }

        /**
         * @brief 冲刷双端在建立转发前已摄入用户态缓冲区的早期数据
         *
         * @return size_t 冲刷迁移的总字节数
         */
        size_t flushPrebuffered() noexcept
        {
            size_t total = 0;
            // 上行预读数据冲刷：入站残余 -> 出站业务外发管线
            if (inbound_ != nullptr && outbound_ != nullptr && inbound_->requestBytes() > 0 && !outboundClosed_)
            {
                const size_t n = inbound_->requestBytes();
                std::string_view payload(inbound_->requestBegin(), n);
                if (auto res = outbound_->sendPayload(payload); res)
                {
                    inbound_->requestConsume(n);
                    if (!hasOutboundSink())
                    {
                        stats_.bytesUp += n;
                        ++stats_.packetsUp;
                        stats_.touch();
                    }
                    total += n;
                }
            }

            // 下行预读数据冲刷：出站残余 -> 入站业务外发管线
            if (outbound_ != nullptr && inbound_ != nullptr && outbound_->requestBytes() > 0 && !inboundClosed_)
            {
                const size_t n = outbound_->requestBytes();
                std::string_view payload(outbound_->requestBegin(), n);
                if (auto res = inbound_->sendPayload(payload); res)
                {
                    outbound_->requestConsume(n);
                    if (!hasInboundSink())
                    {
                        stats_.bytesDown += n;
                        ++stats_.packetsDown;
                        stats_.touch();
                    }
                    total += n;
                }
            }
            return total;
        }

        bool ensurePipes() noexcept
        {
            if (disableSpliceForSession_)
            {
                return false;
            }
            if (pipeUp_[0] < 0)
            {
                if (::pipe2(pipeUp_, O_NONBLOCK | O_CLOEXEC) < 0)
                {
                    pipeUp_[0] = pipeUp_[1] = -1;
                    disableSpliceForSession_ = true;
                    return false;
                }
            }
            if (pipeDown_[0] < 0)
            {
                if (::pipe2(pipeDown_, O_NONBLOCK | O_CLOEXEC) < 0)
                {
                    pipeDown_[0] = pipeDown_[1] = -1;
                    closePipes();
                    disableSpliceForSession_ = true;
                    return false;
                }
            }
            return true;
        }

        void closePipes() noexcept
        {
            if (pipeUp_[0] >= 0)
            {
                ::close(pipeUp_[0]);
                pipeUp_[0] = -1;
            }
            if (pipeUp_[1] >= 0)
            {
                ::close(pipeUp_[1]);
                pipeUp_[1] = -1;
            }
            if (pipeDown_[0] >= 0)
            {
                ::close(pipeDown_[0]);
                pipeDown_[0] = -1;
            }
            if (pipeDown_[1] >= 0)
            {
                ::close(pipeDown_[1]);
                pipeDown_[1] = -1;
            }
            pipeUpPending_ = 0;
            pipeDownPending_ = 0;
        }

        /**
         * @brief 激活 eBPF Sockmap 内核流卸载 (0 唤醒，0 内存拷贝)
         */
        bool activateSockmap() noexcept
        {
#if defined(__linux__) && defined(__NR_bpf)
            const int inFd = inboundFd();
            const int outFd = outboundFd();
            if (disableOffloadForSession_ || disableSpliceForSession_ || sockmapFd_ < 0 || inFd < 0 || outFd < 0)
            {
                return false;
            }
            // 预先准备双向管道，确保在 Sockmap 遇到局部阻塞或 SK_PASS 回退时具备零拷贝 splice 保底能力
            if (!ensurePipes())
            {
                return false;
            }
            if (!ebpf::EbpfEngine::attachPair(sockmapFd_, inFd, outFd))
            {
                return false;
            }
            activeMode_ = ForwardMode::KERNEL_SOCKMAP;
            return true;
#else
            return false;
#endif
        }

        /**
         * @brief 解除 eBPF Sockmap 绑定
         */
        void deactivateSockmap() noexcept
        {
            const int inFd = inboundFd();
            const int outFd = outboundFd();
            if (sockmapFd_ >= 0 && (inFd >= 0 || outFd >= 0))
            {
                ebpf::EbpfEngine::detachPair(sockmapFd_, inFd, outFd);
            }
        }

        [[nodiscard]] inline bool isSockmapPaused() const noexcept { return sockmapPaused_; }

        /**
         * @brief 运行期从 KERNEL_SOCKMAP 安全降级至 ZERO_COPY_SPLICE (如 SK_PASS 回流或发送积压背压)
         */
        void downgradeSockmapToSplice(bool dueToCongestion = false) noexcept
        {
            if (activeMode_ != ForwardMode::KERNEL_SOCKMAP && !dueToCongestion)
            {
                return;
            }
            deactivateSockmap();
            if (dueToCongestion)
            {
                sockmapPaused_ = true;
            }
            else
            {
                disableOffloadForSession_ = true;
                sockmapPaused_ = false;
            }

            if (!disableSpliceForSession_ && config_.enableSplice && configuredMode_ != ForwardMode::BUFFER_PUMP &&
                ensurePipes())
            {
                activateSplice();
            }
            else
            {
                downgradeSpliceToBufferPump();
            }
        }

        /**
         * @brief 运行期从 ZERO_COPY_SPLICE/SOCKMAP 无损降级至 BUFFER_PUMP（排空管道残余字节后切回用户态泵送）
         */
        void downgradeSpliceToBufferPump() noexcept
        {
            disableOffloadForSession_ = true;
            disableSpliceForSession_ = true;
            sockmapPaused_ = false;
            deactivateSockmap();

            activeMode_ = ForwardMode::BUFFER_PUMP;
            if (inbound_ != nullptr && inbound_->connection() != nullptr)
            {
                inbound_->connection()->resumeRead();
            }

            auto drainPipeToHandler = [&](int pipeRdFd, Handler *dstHandler, uint64_t &bytesStat, uint64_t &pktsStat,
                                          bool hasSink, bool closedFlag) noexcept
            {
                if (pipeRdFd < 0 || dstHandler == nullptr || closedFlag)
                {
                    return;
                }
                char buf[16384];
                for (;;)
                {
                    const ssize_t n = ::read(pipeRdFd, buf, sizeof(buf));
                    if (n > 0)
                    {
                        const size_t sz = static_cast<size_t>(n);
                        if (auto res = dstHandler->sendPayload(std::string_view(buf, sz)); res)
                        {
                            if (!hasSink)
                            {
                                bytesStat += sz;
                                ++pktsStat;
                                stats_.touch();
                            }
                        }
                        continue;
                    }
                    if (n < 0 && errno == EINTR)
                    {
                        continue;
                    }
                    break;
                }
            };

            drainPipeToHandler(pipeUp_[0], outbound_, stats_.bytesUp, stats_.packetsUp, hasOutboundSink(),
                               outboundClosed_);
            drainPipeToHandler(pipeDown_[0], inbound_, stats_.bytesDown, stats_.packetsDown, hasInboundSink(),
                               inboundClosed_);

            closePipes();
            flushOutboundResponses();
            flushInboundResponses();

            const int outFd = outboundFd();
            if (!proactorManaged_ && outFd >= 0 && !outboundClosed_ && loopHooks_.modWatch && outboundWatched_)
            {
                uint32_t evMask = EPOLLIN | EPOLLET;
#ifdef EPOLLRDHUP
                evMask |= EPOLLRDHUP;
#endif
                if (hasOutboundPendingToSend())
                {
                    evMask |= EPOLLOUT;
                }
                (void)loopHooks_.modWatch(outFd, evMask);
            }
            if (loopHooks_.notifySession)
            {
                loopHooks_.notifySession(id_);
            }
        }

        /**
         * @brief 处理 Reactor 模式下入站 fd 的 EPOLL 事件（SOCKMAP/SPLICE 全权接管，BUFFER_PUMP 返回 -1 交由
         * Connection）
         * @return -1: 交由 Connection::handleRead/Write 处理; 0: KEEP; 1: CLOSE
         */
        [[nodiscard]] int onReactorInboundEvent(uint32_t events) noexcept
        {
            if (proactorManaged_)
            {
                return -1;
            }
            if (state_ == ForwardSessionState::CLOSED || state_ == ForwardSessionState::ERROR)
            {
                return 1;
            }
            if (activeMode_ == ForwardMode::BUFFER_PUMP)
            {
                return -1;
            }

#if defined(__linux__)
            if (activeMode_ == ForwardMode::KERNEL_SOCKMAP)
            {
                if ((events & (EPOLLERR | EPOLLHUP)) && !(events & EPOLLIN))
                {
                    markInboundClosed();
                    return 1;
                }

                if (events & EPOLLIN)
                {
                    char peekByte = 0;
                    const int inFd = inboundFd();
                    const ssize_t pk = (inFd >= 0) ? ::recv(inFd, &peekByte, 1, MSG_PEEK | MSG_DONTWAIT) : -1;
                    if (pk == 0 || (pk < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR))
                    {
                        markInboundClosed();
                        return 1;
                    }
                    if (pk > 0)
                    {
                        // 内核 verdict 返回 SK_PASS 使数据落回用户态接收队列 -> 降级为 SPLICE 接管
                        downgradeSockmapToSplice(false);
                    }
                }
#ifdef EPOLLRDHUP
                if ((events & EPOLLRDHUP) && activeMode_ == ForwardMode::KERNEL_SOCKMAP)
                {
                    char peekByte = 0;
                    const int inFd = inboundFd();
                    if (inFd < 0 || ::recv(inFd, &peekByte, 1, MSG_PEEK | MSG_DONTWAIT) == 0)
                    {
                        markInboundClosed();
                        return 1;
                    }
                }
#endif
                if (activeMode_ == ForwardMode::KERNEL_SOCKMAP)
                {
                    checkAndApplySockmapBackpressure();
                    if (activeMode_ == ForwardMode::KERNEL_SOCKMAP)
                    {
                        if ((events & EPOLLOUT) && inbound_ != nullptr && inbound_->connection() != nullptr &&
                            inbound_->connection()->hasQueuedWrite())
                        {
                            if (inbound_->connection()->handleWrite() == IO_STATUS::CLOSE)
                            {
                                markInboundClosed();
                                return 1;
                            }
                        }
                        return (inboundClosed_ || state_ == ForwardSessionState::CLOSED) ? 1 : 0;
                    }
                }
            }

            if ((events & (EPOLLERR | EPOLLHUP)) && !(events & EPOLLIN))
            {
                markInboundClosed();
                return 1;
            }
            if ((events & EPOLLOUT) && inbound_ != nullptr && inbound_->connection() != nullptr &&
                (inbound_->hasResponse() || inbound_->connection()->hasQueuedWrite()))
            {
                if (inbound_->connection()->handleWrite() == IO_STATUS::CLOSE)
                {
                    markInboundClosed();
                    return 1;
                }
            }
            (void)pump();
            if (activeMode_ == ForwardMode::BUFFER_PUMP && !inboundClosed_ && state_ != ForwardSessionState::CLOSED)
            {
                // 刚降级为 BUFFER_PUMP：交还 Connection 在本轮事件中立刻完成读取/发送
                return -1;
            }
            if (inboundClosed_ || state_ == ForwardSessionState::CLOSED)
            {
                if (inboundClosed_ && outboundClosed_)
                {
                    close();
                }
                return 1;
            }
            return 0;
#else
            (void)events;
            return -1;
#endif
        }

        /**
         * @brief 查询套接字当前内核发送缓冲区未确认/排队积压字节数
         */
        [[nodiscard]] size_t getSocketPendingOutBytes(int fd) const noexcept
        {
#if defined(__linux__) && defined(SIOCOUTQ)
            if (fd < 0)
                return 0;
            int unsent = 0;
            if (::ioctl(fd, SIOCOUTQ, &unsent) == 0 && unsent > 0)
            {
                return static_cast<size_t>(unsent);
            }
#endif
            return 0;
        }

        /**
         * @brief 复用 Connection 配置的高水位线检查双端是否存在发送背压
         */
        [[nodiscard]] bool isBackpressured() const noexcept
        {
            const size_t highWater = getConnectionConfig().writeHighWaterMark;
            const int outFd = outboundFd();
            if (outFd >= 0 && getSocketPendingOutBytes(outFd) > highWater)
            {
                return true;
            }
            const int inFd = inboundFd();
            if (inFd >= 0 && getSocketPendingOutBytes(inFd) > highWater)
            {
                return true;
            }
            return false;
        }

        /**
         * @brief eBPF Sockmap 模式与 Connection 统一背压自愈联动
         */
        void checkAndApplySockmapBackpressure() noexcept
        {
            const bool congested = isBackpressured();
            if (activeMode_ == ForwardMode::KERNEL_SOCKMAP && congested)
            {
                // 检测到下游套接字发送缓冲区堆积超过既定高水位线，
                // 主动暂停 Sockmap 内核流卸载，回退至 splice 管道与 Connection 用户态背压控流
                downgradeSockmapToSplice(true);
            }
            else if (sockmapPaused_ && !disableOffloadForSession_ && !disableSpliceForSession_ && !congested)
            {
                // 发送队列积压排空落回高水位线以内，恢复 Sockmap 内核极速直连
                if (activateSockmap())
                {
                    sockmapPaused_ = false;
                }
            }
        }

        /**
         * @brief 统一阶梯自适应激活最优转发通道：Sockmap -> Splice -> Buffer Pump
         */
        void activateAdaptiveMode(bool userSslActive = false) noexcept
        {
            const bool readyForBypass =
                !outboundConnecting_ && !outboundConnectDeferred_ &&
                (inbound_ == nullptr || inbound_->requestBytes() == 0) &&
                (outbound_ == nullptr || (outbound_->isEstablished() && outbound_->requestBytes() == 0)) &&
                !hasOutboundPendingToSend() && inboundPending_.empty();

            if (!readyForBypass)
            {
                activateBufferPump();
                return;
            }

            const bool inCanSplice = (inbound_ == nullptr) || (inbound_->canSplice() && inbound_->isPassthrough());
            const bool outCanSplice = (outbound_ == nullptr) || (outbound_->canSplice() && outbound_->isPassthrough());
            const bool hasVirtualCh = (inboundChannel_ != nullptr && !inboundChannel_->isPassthrough()) ||
                                      (outboundChannel_ != nullptr && !outboundChannel_->isPassthrough());

            const bool canSplice = config_.enableSplice && !disableSpliceForSession_ &&
                                   (configuredMode_ != ForwardMode::BUFFER_PUMP) && !userSslActive && !hasVirtualCh &&
                                   inCanSplice && outCanSplice && (inboundFd() >= 0) && (outboundFd() >= 0);

            const bool canOffload =
                !disableOffloadForSession_ &&
                (configuredMode_ == ForwardMode::AUTO || configuredMode_ == ForwardMode::KERNEL_SOCKMAP) &&
                (sockmapFd_ >= 0) && canSplice;

            if (canOffload && activateSockmap())
            {
                // Sockmap 挂载成功
            }
            else if (canSplice && ensurePipes())
            {
                activateSplice();
            }
            else
            {
                activateBufferPump();
            }
        }

        /**
         * @brief 激活 Linux splice(2) 内核零拷贝双向直通
         */
        void activateSplice() noexcept
        {
            if (disableSpliceForSession_ || !ensurePipes())
            {
                activateBufferPump();
                return;
            }
            activeMode_ = ForwardMode::ZERO_COPY_SPLICE;
        }

        /**
         * @brief 激活用户态缓冲流控泵送模式
         */
        void activateBufferPump() noexcept
        {
            activeMode_ = ForwardMode::BUFFER_PUMP;
            if (inbound_ != nullptr && inbound_->connection() != nullptr)
            {
                inbound_->connection()->resumeRead();
            }
        }

        /**
         * @brief 内存侧双向数据与协议状态桥接（Reactor::pump 与 Proactor CQE 完成回调共用）
         */
        inline PumpResult pumpMemoryBridging() noexcept
        {
            PumpResult result{};

            // 1. 上行泵送：Inbound RequestBuffer -> Outbound sendPayload()
            if (inbound_ != nullptr && outbound_ != nullptr && !outboundClosed_)
            {
                const size_t avail = inbound_->requestBytes();
                if (avail > 0)
                {
                    const size_t toPump = std::min(avail, config_.bufferChunkSize);
                    std::string_view chunk(inbound_->requestBegin(), toPump);
                    if (auto res = outbound_->sendPayload(chunk); res)
                    {
                        inbound_->requestConsume(toPump);
                        if (!hasOutboundSink())
                        {
                            stats_.bytesUp += toPump;
                            ++stats_.packetsUp;
                            stats_.touch();
                        }
                        result.bytesUp += toPump;
                    }
                }
            }

            // 2. 下行泵送：Outbound RequestBuffer -> Inbound sendPayload()
            if (outbound_ != nullptr && inbound_ != nullptr && !inboundClosed_)
            {
                const size_t avail = outbound_->requestBytes();
                if (avail > 0)
                {
                    const size_t toPump = std::min(avail, config_.bufferChunkSize);
                    std::string_view chunk(outbound_->requestBegin(), toPump);
                    if (auto res = inbound_->sendPayload(chunk); res)
                    {
                        outbound_->requestConsume(toPump);
                        if (!hasInboundSink())
                        {
                            stats_.bytesDown += toPump;
                            ++stats_.packetsDown;
                            stats_.touch();
                        }
                        result.bytesDown += toPump;
                    }
                }
            }

            if (outbound_ != nullptr && outbound_->isEstablished() && activeMode_ == ForwardMode::BUFFER_PUMP &&
                config_.enableSplice && !disableSpliceForSession_ && configuredMode_ != ForwardMode::BUFFER_PUMP &&
                !hasOutboundPendingToSend())
            {
                activateAdaptiveMode(false);
            }

            return result;
        }

        // ---- Proactor (io_uring) 异步完成回调接口 ----
        inline void onProactorConnectComplete(int err) noexcept
        {
            outboundConnecting_ = false;
            outboundConnectDeferred_ = false;
            if (err != 0)
            {
                markOutboundClosed();
                return;
            }
            if (outbound_ != nullptr)
            {
                outbound_->handle();
            }
            (void)pumpMemoryBridging();
            if (inbound_ != nullptr && inbound_->connection() != nullptr)
            {
                inbound_->connection()->pump();
            }
            if (outbound_ != nullptr && outbound_->isEstablished() && activeMode_ == ForwardMode::BUFFER_PUMP &&
                config_.enableSplice && !disableSpliceForSession_ && configuredMode_ != ForwardMode::BUFFER_PUMP &&
                !hasOutboundPendingToSend() && inbound_ != nullptr && outbound_->isPassthrough() &&
                inbound_->isPassthrough() && inbound_->requestBytes() == 0 && outbound_->requestBytes() == 0)
            {
                activateAdaptiveMode(false);
            }
            checkCloseCascade();
        }

        inline void onProactorOutboundRecv(const char *data, ssize_t res) noexcept
        {
            if (res > 0)
            {
                if (outbound_ != nullptr && data != nullptr)
                {
                    [[maybe_unused]] auto _ = outbound_->appendRequest(data, res);
                    [[maybe_unused]] auto _w = outbound_->processWireToApp();
                    outbound_->drive();
                }
                (void)pumpMemoryBridging();
                if (inbound_ != nullptr && inbound_->connection() != nullptr)
                {
                    inbound_->connection()->pump();
                }
                checkCloseCascade();
            }
            else if (res == 0)
            {
                markOutboundClosed();
            }
            else if (res != -EAGAIN && res != -EINTR)
            {
                markOutboundClosed();
            }
        }

        [[nodiscard]] inline std::string_view beginProactorOutboundSend(size_t maxChunk) noexcept
        {
            if (proactorSendOffset_ < proactorSendBuf_.size())
            {
                return std::string_view(proactorSendBuf_).substr(proactorSendOffset_);
            }
            proactorSendBuf_.clear();
            proactorSendOffset_ = 0;

            if (!outboundPending_.empty())
            {
                if (outboundPending_.offset == 0 && outboundPending_.data.size() <= maxChunk)
                {
                    proactorSendBuf_.swap(outboundPending_.data);
                    outboundPending_.clear();
                }
                else
                {
                    const auto rem = outboundPending_.remaining();
                    const size_t take = std::min(rem.size(), maxChunk);
                    proactorSendBuf_.assign(rem.data(), take);
                    outboundPending_.advance(take);
                }
                return proactorSendBuf_;
            }

            while (outbound_ != nullptr && outbound_->hasResponse())
            {
                proactorSendBuf_ = outbound_->takeResponse();
                if (!proactorSendBuf_.empty())
                {
                    return proactorSendBuf_;
                }
            }
            return {};
        }

        inline bool finishProactorOutboundSend(ssize_t res) noexcept
        {
            if (res > 0)
            {
                const size_t sent = static_cast<size_t>(res);
                stats_.bytesUp += sent;
                ++stats_.packetsUp;
                stats_.touch();
                proactorSendOffset_ += sent;
                if (proactorSendOffset_ >= proactorSendBuf_.size())
                {
                    proactorSendBuf_.clear();
                    proactorSendOffset_ = 0;
                }
            }
            else if (res < 0 && res != -EAGAIN && res != -EINTR)
            {
                proactorSendBuf_.clear();
                proactorSendOffset_ = 0;
                markOutboundClosed();
                return false;
            }
            if (outbound_ != nullptr && outbound_->isEstablished() && activeMode_ == ForwardMode::BUFFER_PUMP &&
                config_.enableSplice && !disableSpliceForSession_ && configuredMode_ != ForwardMode::BUFFER_PUMP &&
                !hasOutboundPendingToSend() && inbound_ != nullptr && outbound_->isPassthrough() &&
                inbound_->isPassthrough() && inbound_->requestBytes() == 0 && outbound_->requestBytes() == 0)
            {
                activateAdaptiveMode(false);
            }
            checkCloseCascade();
            return hasOutboundPendingToSend();
        }

        inline void onProactorSpliceResult(bool isDown, ssize_t res) noexcept
        {
            if (res > 0)
            {
                const size_t bytes = static_cast<size_t>(res);
                if (isDown)
                {
                    stats_.bytesDown += bytes;
                }
                else
                {
                    stats_.bytesUp += bytes;
                }
                stats_.touch();
            }
            else if (res < 0 && isSpliceUnsupportedErrno(static_cast<int>(-res)))
            {
                downgradeSpliceToBufferPump();
                return;
            }
            else if (res == 0 || (res < 0 && res != -EAGAIN && res != -EINTR))
            {
                if (isDown)
                {
                    markOutboundClosed();
                }
                else
                {
                    markInboundClosed();
                }
            }
            checkCloseCascade();
        }

        /**
         * @brief 执行一轮用户态双向数据泵送与半关闭状态收敛
         *
         * @return PumpResult 本轮双向泵送成功传输的数据字节统计 (bytesUp 与 bytesDown)
         */
        PumpResult pump() noexcept
        {
            if (state_ == ForwardSessionState::CLOSED || state_ == ForwardSessionState::ERROR)
            {
                return {};
            }

            if (proactorManaged_)
            {
                if (activeMode_ == ForwardMode::BUFFER_PUMP && inbound_ != nullptr && inbound_->usesWireBuffer())
                {
                    inbound_->drive();
                }
                if (outbound_ != nullptr && !outbound_->isEstablished())
                {
                    [[maybe_unused]] auto _ = outbound_->processWireToApp();
                    outbound_->drive();
                }
                PumpResult result = pumpMemoryBridging();
                flushInboundResponses();
                checkCloseCascade();
                if (loopHooks_.notifySession)
                {
                    loopHooks_.notifySession(id_);
                }
                return result;
            }

            PumpResult result{};

            auto readSideAndDrive = [&](Handler *h, IStreamChannel *ch, bool &closedFlag, bool isOutbound) noexcept
            {
                if (h == nullptr || closedFlag)
                {
                    return;
                }
                auto markClosed = [&]() noexcept
                {
                    if (isOutbound)
                        markOutboundClosed();
                    else
                        markInboundClosed();
                };

                if (ch != nullptr && (isOutbound || inboundChannelDriven_))
                {
                    for (int iter = 0; iter < 64 && !closedFlag; ++iter)
                    {
                        const size_t credit = h->readCredit();
                        if (credit == 0)
                        {
                            break;
                        }
                        const size_t want = std::min(config_.bufferChunkSize, credit);
                        auto prep = h->prepareRequestWritable(want);
                        if (!prep)
                        {
                            markClosed();
                            break;
                        }
                        const size_t cap = std::min(h->requestWritableBytes(), want);
                        if (cap == 0)
                        {
                            break;
                        }

                        auto r = ch->readBytes(std::span<uint8_t>(reinterpret_cast<uint8_t *>(*prep), cap));
                        if (!r)
                        {
                            markClosed();
                            break;
                        }
                        if (*r == 0)
                        {
                            break;
                        }
                        h->commitRequest(*r);
                        [[maybe_unused]] auto _ = h->processWireToApp();
                    }
                }
                h->drive();
            };

            // 0. 推进未建连完成或处于用户态 BUFFER_PUMP 模式的通道读写与传输层状态机
            const bool outHandshaking = (outbound_ != nullptr && !outbound_->isEstablished());
            if (outHandshaking || activeMode_ == ForwardMode::BUFFER_PUMP)
            {
                if (outHandshaking)
                {
                    flushOutboundResponses();
                }
                if (activeMode_ == ForwardMode::BUFFER_PUMP && inboundChannelDriven_)
                {
                    readSideAndDrive(inbound_, inboundChannel_.get(), inboundClosed_, false);
                }
                else if (inbound_ != nullptr && inbound_->usesWireBuffer())
                {
                    inbound_->drive();
                }

                readSideAndDrive(outbound_, outboundChannel_.get(), outboundClosed_, true);
                if (outHandshaking)
                {
                    flushOutboundResponses();
                }
            }

            flushOutboundResponses();
            flushInboundResponses();

            PumpResult memRes = pumpMemoryBridging();
            result.bytesUp += memRes.bytesUp;
            result.bytesDown += memRes.bytesDown;

            flushOutboundResponses();
            flushInboundResponses();

            if (activeMode_ == ForwardMode::BUFFER_PUMP && outbound_ != nullptr && outbound_->isEstablished() &&
                config_.enableSplice && !disableSpliceForSession_ && configuredMode_ != ForwardMode::BUFFER_PUMP &&
                !hasOutboundPendingToSend() && (inbound_ == nullptr || inbound_->requestBytes() == 0) &&
                outbound_->requestBytes() == 0)
            {
                activateAdaptiveMode(false);
            }

            // 2.3 背压自愈与 SK_PASS 回流降级：若队列超限或 Sockmap 返回 SK_PASS 落回用户态，立刻切换至 SPLICE
            if (sockmapFd_ >= 0)
            {
                checkAndApplySockmapBackpressure();
            }

            if (activeMode_ == ForwardMode::KERNEL_SOCKMAP && inboundFd() >= 0 && outboundFd() >= 0 && !inboundClosed_ &&
                !outboundClosed_)
            {
                auto peekReadableOrEof = [&](int fd, bool isOutbound) noexcept -> bool
                {
                    char peekByte = 0;
                    const ssize_t pk = ::recv(fd, &peekByte, 1, MSG_PEEK | MSG_DONTWAIT);
                    if (pk > 0)
                    {
                        return true;
                    }
                    if (pk == 0 || (pk < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR))
                    {
                        if (isOutbound)
                            markOutboundClosed();
                        else
                            markInboundClosed();
                    }
                    return false;
                };
                if (peekReadableOrEof(inboundFd(), false) || peekReadableOrEof(outboundFd(), true))
                {
                    downgradeSockmapToSplice(false);
                }
            }

            // 2.5 若活跃于 splice 零拷贝管道模式，驱动双向管道传输（若底层不支持 splice 则无损降级为 BUFFER_PUMP）
            if (activeMode_ == ForwardMode::ZERO_COPY_SPLICE && inboundFd() >= 0 && outboundFd() >= 0 &&
                !outboundClosed_ && !inboundClosed_)
            {
                const uint64_t upBefore = stats_.bytesUp;
                const uint64_t downBefore = stats_.bytesDown;

                auto drainSpliceLoop = [&](bool isDown) noexcept
                {
                    for (int iter = 0; iter < 16; ++iter)
                    {
                        if (activeMode_ != ForwardMode::ZERO_COPY_SPLICE)
                        {
                            break;
                        }
                        auto tr = isDown ? transferOutboundToInbound() : transferInboundToOutbound();
                        if (tr == TransferResult::UNSUPPORTED)
                        {
                            downgradeSpliceToBufferPump();
                            break;
                        }
                        if (tr == TransferResult::ERROR || tr == TransferResult::CLOSED)
                        {
                            if (isDown)
                                markOutboundClosed();
                            else
                                markInboundClosed();
                            break;
                        }
                        if (tr != TransferResult::OK)
                        {
                            break;
                        }
                    }
                };
                drainSpliceLoop(true);
                drainSpliceLoop(false);

                result.bytesUp += static_cast<size_t>(stats_.bytesUp - upBefore);
                result.bytesDown += static_cast<size_t>(stats_.bytesDown - downBefore);

                // 若刚刚降级回 BUFFER_PUMP，立即补跑一轮内存读写以免本轮数据滞留
                if (activeMode_ == ForwardMode::BUFFER_PUMP && !inboundClosed_ && !outboundClosed_)
                {
                    if (inboundChannelDriven_)
                    {
                        readSideAndDrive(inbound_, inboundChannel_.get(), inboundClosed_, false);
                    }
                    readSideAndDrive(outbound_, outboundChannel_.get(), outboundClosed_, true);
                    PumpResult fallbackMem = pumpMemoryBridging();
                    result.bytesUp += fallbackMem.bytesUp;
                    result.bytesDown += fallbackMem.bytesDown;
                    flushOutboundResponses();
                    flushInboundResponses();
                }
            }

            // 3. 半关闭与全关闭状态检测与级联
            checkCloseCascade();

            return result;
        }

        /**
         * @brief 标记入站方向已关闭
         */
        inline void markInboundClosed() noexcept
        {
            inboundClosed_ = true;
            if (config_.propagateClose && outbound_ != nullptr)
            {
                outbound_->setCloseAfterResponse(true);
            }
            checkCloseCascade();
        }

        /**
         * @brief 标记出站方向已关闭
         */
        inline void markOutboundClosed() noexcept
        {
            LOG_WARN("markOutboundClosed: session {} outbound closed", id_);
            outboundClosed_ = true;
            if (config_.propagateClose && inbound_ != nullptr)
            {
                inbound_->setCloseAfterResponse(true);
            }
            checkCloseCascade();
        }

        /**
         * @brief 关闭本会话并释放关联转发引用
         */
        void close(bool force = false) noexcept
        {
            if (state_ == ForwardSessionState::CLOSED)
            {
                return;
            }

            inboundClosed_ = true;
            outboundClosed_ = true;

            const uint64_t inTok = inDetachHookToken_;
            const uint64_t outTok = outDetachHookToken_;
            inDetachHookToken_ = 0;
            outDetachHookToken_ = 0;

            if (inbound_ != nullptr)
            {
                inbound_->removeExternalDetachHook(inTok);
                inbound_->clearExternalDataPlane();
                if (force)
                {
                    inbound_->setCloseAfterResponse(true);
                }
            }
            if (outbound_ != nullptr)
            {
                outbound_->removeExternalDetachHook(outTok);
                if (force)
                {
                    outbound_->setCloseAfterResponse(true);
                }
            }

            closePipes();

            const int outFd = outboundFd();
            if (proactorManaged_ && loopHooks_.retireSession)
            {
                if (loopHooks_.retireSession(id_, ownsOutboundFd_))
                {
                    ownsOutboundFd_ = false;
                    outboundChannel_.reset();
                }
                proactorManaged_ = false;
            }
            else if (outboundWatched_ && loopHooks_.delWatch && outFd >= 0)
            {
                loopHooks_.delWatch(outFd);
                outboundWatched_ = false;
            }

            proactorSendBuf_.clear();
            proactorSendOffset_ = 0;

            if (activeMode_ == ForwardMode::KERNEL_SOCKMAP)
            {
                deactivateSockmap();
            }

            if (ownsOutboundFd_ && outboundFd() >= 0)
            {
                ::close(outboundFd());
                ownsOutboundFd_ = false;
                outboundChannel_.reset();
            }
            else if (outboundChannel_ != nullptr && !outboundChannel_->isPassthrough())
            {
                outboundChannel_->closeChannel();
            }

            outboundPending_.clear();
            inboundPending_.clear();

            inbound_ = nullptr;
            outbound_ = nullptr;
            setState(ForwardSessionState::CLOSED);

            if (onClose_)
            {
                onClose_(*this);
            }
        }

        enum class TransferResult : uint8_t
        {
            OK = 0,
            AGAIN = 1,
            CLOSED = 2,
            ERROR = 3,
            UNSUPPORTED = 4
        };

        TransferResult transferInboundToOutbound() noexcept
        {
            const int inFd = inboundFd();
            const int outFd = outboundFd();
            if (inboundClosed_ || inFd < 0 || outFd < 0)
            {
                return TransferResult::CLOSED;
            }

            if (pipeUp_[0] < 0 || pipeUp_[1] < 0)
            {
                return TransferResult::UNSUPPORTED;
            }

            auto res =
                detail::splicePipes(inFd, outFd, pipeUp_[1], pipeUp_[0], config_.spliceChunkSize, &pipeUpPending_);
            if (res.bytesSpliced > 0)
            {
                stats_.bytesUp += static_cast<size_t>(res.bytesSpliced);
                stats_.touch();
            }
            if (res.eof)
            {
                markInboundClosed();
                return TransferResult::CLOSED;
            }
            if (res.err == EAGAIN || res.err == EWOULDBLOCK)
            {
                return TransferResult::AGAIN;
            }
            if (res.err != 0)
            {
                if (isSpliceUnsupportedErrno(res.err))
                {
                    return TransferResult::UNSUPPORTED;
                }
                markInboundClosed();
                return TransferResult::ERROR;
            }
            return TransferResult::OK;
        }

        TransferResult transferOutboundToInbound() noexcept
        {
            const int inFd = inboundFd();
            const int outFd = outboundFd();
            if (outboundClosed_ || inFd < 0 || outFd < 0)
            {
                return TransferResult::CLOSED;
            }

            if (pipeDown_[0] < 0 || pipeDown_[1] < 0)
            {
                return TransferResult::UNSUPPORTED;
            }

            auto res =
                detail::splicePipes(outFd, inFd, pipeDown_[1], pipeDown_[0], config_.spliceChunkSize, &pipeDownPending_);
            if (res.bytesSpliced > 0)
            {
                stats_.bytesDown += static_cast<size_t>(res.bytesSpliced);
                stats_.touch();
            }
            if (res.eof)
            {
                markOutboundClosed();
                return TransferResult::CLOSED;
            }
            if (res.err == EAGAIN || res.err == EWOULDBLOCK)
            {
                return TransferResult::AGAIN;
            }
            if (res.err != 0)
            {
                if (isSpliceUnsupportedErrno(res.err))
                {
                    return TransferResult::UNSUPPORTED;
                }
                markOutboundClosed();
                return TransferResult::ERROR;
            }
            return TransferResult::OK;
        }

    private:
        inline void checkCloseCascade() noexcept
        {
            if (inbound_ != nullptr && inbound_->closeAfterResponse())
            {
                inboundClosed_ = true;
                if (config_.propagateClose && outbound_ != nullptr)
                {
                    outbound_->setCloseAfterResponse(true);
                }
            }

            if (outbound_ != nullptr && outbound_->closeAfterResponse())
            {
                outboundClosed_ = true;
                if (config_.propagateClose && inbound_ != nullptr)
                {
                    inbound_->setCloseAfterResponse(true);
                }
            }

            if (inboundClosed_ && outboundClosed_)
            {
                setState(ForwardSessionState::CLOSED);
            }
            else if (inboundClosed_ || outboundClosed_)
            {
                setState(ForwardSessionState::DRAINING);
            }
        }
    };

    struct DatagramSessionKey
    {
        sockaddr_in client{};
        sockaddr_in remote{};

        bool operator==(const DatagramSessionKey &other) const noexcept
        {
            return client.sin_addr.s_addr == other.client.sin_addr.s_addr && client.sin_port == other.client.sin_port &&
                   remote.sin_addr.s_addr == other.remote.sin_addr.s_addr && remote.sin_port == other.remote.sin_port;
        }
    };

    struct DatagramSessionKeyHash
    {
        size_t operator()(const DatagramSessionKey &k) const noexcept
        {
            const uint64_t c = (static_cast<uint64_t>(k.client.sin_addr.s_addr) << 16) | ntohs(k.client.sin_port);
            const uint64_t r = (static_cast<uint64_t>(k.remote.sin_addr.s_addr) << 16) | ntohs(k.remote.sin_port);
            return std::hash<uint64_t>{}(c ^ (r + 0x9e3779b97f4a7c15ULL + (c << 6) + (c >> 2)));
        }
    };

    /**
     * @brief 数据报/UDP 转发映射会话（直接复用 Datagram 端点管理出站 fd 与事件监听）
     */
    class ForwarderDatagramSession : public std::enable_shared_from_this<ForwarderDatagramSession>
    {
    private:
        uint64_t id_{0};
        sockaddr_in clientAddr_{};
        sockaddr_in remoteAddr_{};
        Datagram outbound_{};
        ForwarderStats stats_{};
        ForwarderLoopHooks loopHooks_{};
        bool outboundWatched_{false};
        std::function<void(const DatagramView &)> onReply_{nullptr};

    public:
        ForwarderDatagramSession(uint64_t id, const sockaddr_in &client, const sockaddr_in &remote,
                                 int outboundFd = -1) noexcept
            : id_(id),
              clientAddr_(client),
              remoteAddr_(remote),
              outbound_(outboundFd, outboundFd >= 0)
        {
        }

        ForwarderDatagramSession(uint64_t id, const sockaddr_in &client, const sockaddr_in &remote,
                                 Datagram outbound) noexcept
            : id_(id),
              clientAddr_(client),
              remoteAddr_(remote),
              outbound_(std::move(outbound))
        {
        }

        ~ForwarderDatagramSession() noexcept { close(); }

        ForwarderDatagramSession(const ForwarderDatagramSession &) = delete;
        ForwarderDatagramSession &operator=(const ForwarderDatagramSession &) = delete;
        ForwarderDatagramSession(ForwarderDatagramSession &&) = delete;
        ForwarderDatagramSession &operator=(ForwarderDatagramSession &&) = delete;

        [[nodiscard]] inline uint64_t id() const noexcept { return id_; }
        [[nodiscard]] inline const sockaddr_in &clientAddr() const noexcept { return clientAddr_; }
        [[nodiscard]] inline const sockaddr_in &remoteAddr() const noexcept { return remoteAddr_; }
        [[nodiscard]] inline Datagram &outbound() noexcept { return outbound_; }
        [[nodiscard]] inline const Datagram &outbound() const noexcept { return outbound_; }
        [[nodiscard]] inline int outboundFd() const noexcept { return outbound_.fd(); }
        [[nodiscard]] inline const ForwarderStats &stats() const noexcept { return stats_; }
        [[nodiscard]] inline ForwarderStats &stats() noexcept { return stats_; }

        inline void setOutboundFd(int fd, bool ownsFd = true) noexcept { outbound_.setFd(fd, ownsFd); }
        inline void setOutboundDatagram(Datagram dgram) noexcept { outbound_ = std::move(dgram); }
        inline void setLoopHooks(ForwarderLoopHooks hooks) noexcept { loopHooks_ = std::move(hooks); }

        inline bool installOutboundWatch(std::function<void(const DatagramView &)> onReply)
        {
            if (outboundWatched_ || !outbound_.valid() || !loopHooks_.addWatch || !loopHooks_.delWatch || !onReply)
            {
                return false;
            }
            onReply_ = std::move(onReply);
#if defined(__linux__)
            std::weak_ptr<ForwarderDatagramSession> weak = weak_from_this();
            const uint32_t mask = EPOLLIN | EPOLLET;
            outboundWatched_ = loopHooks_.addWatch(outbound_.fd(), mask,
                                                   [weak](uint32_t events)
                                                   {
                                                       auto self = weak.lock();
                                                       if (self == nullptr || !self->outbound_.valid())
                                                       {
                                                           return;
                                                       }
                                                       if ((events & (EPOLLERR | EPOLLHUP)) && !(events & EPOLLIN))
                                                       {
                                                           self->close();
                                                           return;
                                                       }
                                                       if (events & EPOLLIN)
                                                       {
                                                           (void)self->outbound_.drain(
                                                               [&](const DatagramView &view)
                                                               {
                                                                   if (self->onReply_)
                                                                   {
                                                                       self->onReply_(view);
                                                                   }
                                                               });
                                                       }
                                                   });
#endif
            return outboundWatched_;
        }

        inline void close() noexcept
        {
            if (outboundWatched_ && loopHooks_.delWatch && outbound_.valid())
            {
                loopHooks_.delWatch(outbound_.fd());
                outboundWatched_ = false;
            }
            onReply_ = nullptr;
            outbound_.close();
        }

        inline void touch() noexcept { stats_.touch(); }

        inline void recordUp(size_t bytes) noexcept
        {
            stats_.bytesUp += bytes;
            ++stats_.packetsUp;
            stats_.touch();
        }

        inline void recordDown(size_t bytes) noexcept
        {
            stats_.bytesDown += bytes;
            ++stats_.packetsDown;
            stats_.touch();
        }

        [[nodiscard]] inline bool isExpired(std::chrono::steady_clock::time_point now,
                                            std::chrono::seconds timeout) const noexcept
        {
            return (now - stats_.lastActive) >= timeout;
        }
    };

    /**
     * @brief 统一中继转发引擎 (Forwarder Engine & Coordinator)
     *
     * 贯通全库 Inbound 与 Outbound 的核心数据平面调度器，管理流式会话与数据报会话池。
     */
    class Forwarder
    {
    private:
        std::atomic<uint64_t> nextSessionId_{1};
        ForwarderConfig defaultConfig_{};

        mutable std::mutex streamMutex_{};
        std::unordered_map<uint64_t, std::shared_ptr<ForwarderStreamSession>> streamSessions_{};

        mutable std::mutex datagramMutex_{};
        std::unordered_map<DatagramSessionKey, std::shared_ptr<ForwarderDatagramSession>, DatagramSessionKeyHash>
            datagramSessions_{};

        std::atomic<uint64_t> totalBytesUp_{0};
        std::atomic<uint64_t> totalBytesDown_{0};
        std::atomic<uint64_t> totalPacketsUp_{0};
        std::atomic<uint64_t> totalPacketsDown_{0};
        int sockmapFd_{-1};
        ForwarderLoopHooks loopHooks_{};

        inline void recordAndStoreSession(const std::shared_ptr<ForwarderStreamSession> &session)
        {
            if (session->stats().bytesUp > 0)
            {
                totalBytesUp_.fetch_add(session->stats().bytesUp, std::memory_order_relaxed);
                totalPacketsUp_.fetch_add(session->stats().packetsUp, std::memory_order_relaxed);
            }
            if (session->stats().bytesDown > 0)
            {
                totalBytesDown_.fetch_add(session->stats().bytesDown, std::memory_order_relaxed);
                totalPacketsDown_.fetch_add(session->stats().packetsDown, std::memory_order_relaxed);
            }

            if (loopHooks_.active())
            {
                session->setLoopHooks(loopHooks_);
                (void)session->installOutboundWatch();
            }

            {
                std::lock_guard<std::mutex> lock(streamMutex_);
                streamSessions_.emplace(session->id(), session);
            }
        }

    public:
        Forwarder() = default;
        explicit Forwarder(ForwarderConfig config) noexcept
            : defaultConfig_(config)
        {
        }

        ~Forwarder() noexcept { closeAll(); }

        Forwarder(const Forwarder &) = delete;
        Forwarder &operator=(const Forwarder &) = delete;
        Forwarder(Forwarder &&) = delete;
        Forwarder &operator=(Forwarder &&) = delete;

        [[nodiscard]] inline const ForwarderConfig &config() const noexcept { return defaultConfig_; }
        inline void setConfig(const ForwarderConfig &cfg) noexcept { defaultConfig_ = cfg; }
        [[nodiscard]] inline int sockmapFd() const noexcept { return sockmapFd_; }
        inline void setSockmapFd(int fd) noexcept { sockmapFd_ = fd; }
        [[nodiscard]] inline const ForwarderLoopHooks &loopHooks() const noexcept { return loopHooks_; }
        inline void setLoopHooks(ForwarderLoopHooks hooks) noexcept { loopHooks_ = std::move(hooks); }
        inline void clearLoopHooks() noexcept { loopHooks_ = {}; }

        inline bool activateLoopWatch(const std::shared_ptr<ForwarderStreamSession> &session)
        {
            if (session == nullptr || !loopHooks_.active())
            {
                return false;
            }
            session->setLoopHooks(loopHooks_);
            return session->installOutboundWatch();
        }

        /**
         * @brief 桥接入站流式处理器与出站流式处理器
         *
         * @param inbound 入站协议处理器（如 HandlerInboundSocks5, HandlerInboundTrojan, HandlerInboundDirect）
         * @param outbound 出站协议处理器（如 HandlerOutboundDirect, HandlerOutboundTrojan, HandlerOutboundSocks5）
         * @param cfg 显式转发配置覆盖（可选）
         * @return std::shared_ptr<ForwarderStreamSession> 转发会话句柄
         */
        std::shared_ptr<ForwarderStreamSession> bridge(Handler &inbound, Handler &outbound,
                                                       std::optional<ForwarderConfig> cfg = std::nullopt)
        {
            const ForwarderConfig actualConfig = cfg.value_or(defaultConfig_);
            const uint64_t sid = nextSessionId_.fetch_add(1, std::memory_order_relaxed);
            auto session = std::make_shared<ForwarderStreamSession>(sid, actualConfig);
            session->setSockmapFd(sockmapFd_);

            [[maybe_unused]] auto preFlushed = session->attach(inbound, outbound, inbound.fd(), outbound.fd(), false);
            recordAndStoreSession(session);
            return session;
        }

        std::shared_ptr<ForwarderStreamSession>
        bridgeDispatched(Handler &inbound, std::unique_ptr<Handler> outbound, int inFd, int outFd, bool ownsOutboundFd,
                         bool connecting, bool connectDeferred, const sockaddr_in &peerAddr, const Address &target,
                         std::string outboundTag, std::optional<ForwarderConfig> cfg = std::nullopt)
        {
            const ForwarderConfig actualConfig = cfg.value_or(defaultConfig_);
            const uint64_t sid = nextSessionId_.fetch_add(1, std::memory_order_relaxed);
            auto session = std::make_shared<ForwarderStreamSession>(sid, actualConfig);
            session->setSockmapFd(sockmapFd_);
            session->setOwnsOutboundFd(ownsOutboundFd);
            session->setOutboundConnectState(connecting, connectDeferred, peerAddr);
            session->setTarget(target);
            session->setOutboundTag(std::move(outboundTag));
            session->setOwnedOutbound(std::move(outbound));

            Handler *outPtr = session->outbound();
            const int resolvedInFd = (inFd >= 0) ? inFd : inbound.fd();
            [[maybe_unused]] auto preFlushed = session->attach(inbound, *outPtr, resolvedInFd, outFd, false);
            recordAndStoreSession(session);
            return session;
        }

        /**
         * @brief 桥接基于 IStreamChannel 的通用异步流通道（支持 QUIC 流 / 内存管道 / 用户态多路复用子流等非 fd 流）
         */
        std::shared_ptr<ForwarderStreamSession> bridgeChannels(Handler &inbound, std::shared_ptr<IStreamChannel> inCh,
                                                               Handler &outbound, std::shared_ptr<IStreamChannel> outCh,
                                                               std::optional<ForwarderConfig> cfg = std::nullopt)
        {
            const ForwarderConfig actualConfig = cfg.value_or(defaultConfig_);
            const uint64_t sid = nextSessionId_.fetch_add(1, std::memory_order_relaxed);
            auto session = std::make_shared<ForwarderStreamSession>(sid, actualConfig);
            session->setSockmapFd(sockmapFd_);

            [[maybe_unused]] auto preFlushed =
                session->attachChannels(inbound, std::move(inCh), outbound, std::move(outCh), -1, -1, false);
            recordAndStoreSession(session);
            return session;
        }

        /**
         * @brief 桥接两个底层流式连接对象 (ConnectionBase &inboundConn 与 ConnectionBase &outboundConn)
         *
         * 自动检查双端是否启用 SSL，自动提取套接字描述符并装配零拷贝 splice 或用户态泵送。
         */
        std::shared_ptr<ForwarderStreamSession> bridge(Connection &inboundConn, Connection &outboundConn,
                                                       std::optional<ForwarderConfig> cfg = std::nullopt)
        {
            const ForwarderConfig actualConfig = cfg.value_or(defaultConfig_);
            const uint64_t sid = nextSessionId_.fetch_add(1, std::memory_order_relaxed);
            auto session = std::make_shared<ForwarderStreamSession>(sid, actualConfig);
            session->setSockmapFd(sockmapFd_);

            const bool inUserSsl =
                (inboundConn.ssl() != nullptr) && !(inboundConn.ktlsRxActive() && inboundConn.ktlsTxActive());
            const bool outUserSsl =
                (outboundConn.ssl() != nullptr) && !(outboundConn.ktlsRxActive() && outboundConn.ktlsTxActive());
            const bool userSsl = inUserSsl || outUserSsl;
            auto *inHandler = inboundConn.handler();
            auto *outHandler = outboundConn.handler();
            contract_assert(inHandler != nullptr && outHandler != nullptr);

            [[maybe_unused]] auto preFlushed =
                session->attach(*inHandler, *outHandler, inboundConn.fd(), outboundConn.fd(), userSsl);
            recordAndStoreSession(session);

            // 若预摄入数据冲刷到了出站连接响应队列，驱动一次连接层 pump
            if (outHandler->hasResponse())
            {
                outboundConn.pump();
                outboundConn.setWantWrite(outboundConn.hasPendingWrite());
            }
            if (inHandler->hasResponse())
            {
                inboundConn.pump();
                inboundConn.setWantWrite(inboundConn.hasPendingWrite());
            }

            return session;
        }

        /**
         * @brief 直接桥接两个裸套接字文件描述符（纯管道零拷贝或透传转发）
         */
        std::shared_ptr<ForwarderStreamSession> bridgeSockets(int inFd, int outFd,
                                                              std::optional<ForwarderConfig> cfg = std::nullopt)
        {
            contract_assert(inFd >= 0 && outFd >= 0);
            const ForwarderConfig actualConfig = cfg.value_or(defaultConfig_);
            const uint64_t sid = nextSessionId_.fetch_add(1, std::memory_order_relaxed);
            auto session = std::make_shared<ForwarderStreamSession>(sid, actualConfig);
            session->setSockmapFd(sockmapFd_);

            session->setInboundFd(inFd);
            session->setOutboundFd(outFd);
            session->activateAdaptiveMode();
            session->setState(ForwardSessionState::STREAMING);

            recordAndStoreSession(session);
            return session;
        }

        /**
         * @brief 驱动单个流式会话的一轮数据泵送
         */
        inline size_t pumpSession(ForwarderStreamSession &session) noexcept
        {
            PumpResult res = session.pump();
            if (res.bytesUp > 0)
            {
                totalBytesUp_.fetch_add(res.bytesUp, std::memory_order_relaxed);
                totalPacketsUp_.fetch_add(1, std::memory_order_relaxed);
            }
            if (res.bytesDown > 0)
            {
                totalBytesDown_.fetch_add(res.bytesDown, std::memory_order_relaxed);
                totalPacketsDown_.fetch_add(1, std::memory_order_relaxed);
            }
            return res.total();
        }

        /**
         * @brief 轮询并驱动所有活跃流式会话的数据泵送，并自动回收已关闭的会话
         *
         * @return size_t 本轮所有会话累计传输的字节总量
         */
        size_t pumpAll()
        {
            std::vector<std::shared_ptr<ForwarderStreamSession>> sessions;
            {
                std::lock_guard<std::mutex> lock(streamMutex_);
                sessions.reserve(streamSessions_.size());
                for (const auto &pair : streamSessions_)
                {
                    sessions.push_back(pair.second);
                }
            }

            size_t totalPumped = 0;
            std::vector<uint64_t> toRemove;

            for (auto &session : sessions)
            {
                if (session != nullptr)
                {
                    PumpResult res = session->pump();
                    if (res.bytesUp > 0)
                    {
                        totalBytesUp_.fetch_add(res.bytesUp, std::memory_order_relaxed);
                        totalPacketsUp_.fetch_add(1, std::memory_order_relaxed);
                    }
                    if (res.bytesDown > 0)
                    {
                        totalBytesDown_.fetch_add(res.bytesDown, std::memory_order_relaxed);
                        totalPacketsDown_.fetch_add(1, std::memory_order_relaxed);
                    }
                    totalPumped += res.total();
                    if (session->isClosed())
                    {
                        toRemove.push_back(session->id());
                    }
                }
            }

            if (!toRemove.empty())
            {
                std::lock_guard<std::mutex> lock(streamMutex_);
                for (uint64_t id : toRemove)
                {
                    streamSessions_.erase(id);
                }
            }

            return totalPumped;
        }

        /**
         * @brief 根据会话 ID 查找活跃流式转发会话
         */
        [[nodiscard]] std::shared_ptr<ForwarderStreamSession> findStreamSession(uint64_t id) const
        {
            std::lock_guard<std::mutex> lock(streamMutex_);
            auto it = streamSessions_.find(id);
            return (it != streamSessions_.end()) ? it->second : nullptr;
        }

        /**
         * @brief 关闭并移除指定的流式转发会话
         */
        void closeStreamSession(uint64_t id, bool force = false)
        {
            std::shared_ptr<ForwarderStreamSession> session;
            {
                std::lock_guard<std::mutex> lock(streamMutex_);
                auto it = streamSessions_.find(id);
                if (it != streamSessions_.end())
                {
                    session = std::move(it->second);
                    streamSessions_.erase(it);
                }
            }
            if (session != nullptr)
            {
                session->close(force);
            }
        }

        /**
         * @brief 排空超过空闲时限的僵尸会话
         *
         * @param timeout 空闲超时阈值（默认取 defaultOptions_.idleTimeout）
         * @return size_t 被清理的僵尸会话数量
         */
        size_t sweepIdleStreamSessions(std::optional<std::chrono::seconds> timeout = std::nullopt)
        {
            const auto maxIdle = timeout.value_or(std::chrono::seconds(defaultConfig_.sessionIdleTimeoutSecs));
            const auto now = std::chrono::steady_clock::now();
            std::vector<std::shared_ptr<ForwarderStreamSession>> toClose;

            {
                std::lock_guard<std::mutex> lock(streamMutex_);
                for (auto it = streamSessions_.begin(); it != streamSessions_.end();)
                {
                    auto &session = it->second;
                    if (session->isClosed() || (now - session->stats().lastActive) >= maxIdle)
                    {
                        toClose.push_back(session);
                        it = streamSessions_.erase(it);
                    }
                    else
                    {
                        ++it;
                    }
                }
            }

            for (auto &session : toClose)
            {
                session->close(true);
            }
            return toClose.size();
        }

        // =====================================================================
        // 数据报 (Datagram / UDP) 转发管理接口
        // =====================================================================

        /**
         * @brief 按五元组复用或新建 UDP 数据报转发会话（复用 DatagramSessionKey 与 Datagram 端点）
         */
        std::shared_ptr<ForwarderDatagramSession>
        getOrCreateDatagramSession(const sockaddr_in &client, const sockaddr_in &remote, int outboundFd = -1)
        {
            const DatagramSessionKey key{.client = client, .remote = remote};
            int duplicateFdToClose = -1;
            std::shared_ptr<ForwarderDatagramSession> result;

            {
                std::lock_guard<std::mutex> lock(datagramMutex_);
                auto it = datagramSessions_.find(key);
                if (it != datagramSessions_.end() && it->second != nullptr)
                {
                    result = it->second;
                    result->touch();
                    if (outboundFd >= 0)
                    {
                        if (result->outboundFd() < 0)
                        {
                            result->setOutboundFd(outboundFd, true);
                        }
                        else if (outboundFd != result->outboundFd())
                        {
                            duplicateFdToClose = outboundFd;
                        }
                    }
                }
                else
                {
                    const uint64_t sid = nextSessionId_.fetch_add(1, std::memory_order_relaxed);
                    result = std::make_shared<ForwarderDatagramSession>(sid, client, remote, outboundFd);
                    datagramSessions_.emplace(key, result);
                }
            }
            if (duplicateFdToClose >= 0)
            {
                ::close(duplicateFdToClose);
            }
            return result;
        }

        [[nodiscard]] std::shared_ptr<ForwarderDatagramSession> findDatagramSession(const sockaddr_in &client,
                                                                                    const sockaddr_in &remote) const
        {
            const DatagramSessionKey key{.client = client, .remote = remote};
            std::lock_guard<std::mutex> lock(datagramMutex_);
            auto it = datagramSessions_.find(key);
            if (it != datagramSessions_.end() && it->second != nullptr)
            {
                it->second->touch();
                return it->second;
            }
            return nullptr;
        }

        inline bool activateDatagramWatch(const std::shared_ptr<ForwarderDatagramSession> &session, Handler &inbound)
        {
            if (session == nullptr || !loopHooks_.active() || !session->outbound().valid())
            {
                return false;
            }
            session->setLoopHooks(loopHooks_);
            std::weak_ptr<ForwarderDatagramSession> weakSess = session;
            return session->installOutboundWatch(
                [this, weakSess, &inbound](const DatagramView &view)
                {
                    auto sess = weakSess.lock();
                    if (sess == nullptr)
                    {
                        return;
                    }
                    const std::string_view payload(reinterpret_cast<const char *>(view.payload.data()),
                                                   view.payload.size());
                    [[maybe_unused]] auto _ = forwardDatagramToClient(inbound, sess->clientAddr(), payload, sess.get());
                    if (inbound.fd() >= 0 && inbound.hasOutgoing())
                    {
                        Datagram inDgram(inbound.fd(), /*ownsFd=*/false);
                        auto batch = inbound.takeAllOutgoing();
                        inDgram.sendPackets(batch, sess->clientAddr());
                    }
                });
        }

        /**
         * @brief 通过 Datagram::sendTo 向远端上游转发来自客户端的 UDP 载荷
         */
        [[nodiscard]] Result<size_t> forwardDatagramToRemote(int outboundFd, const sockaddr_in &remote,
                                                             std::string_view payload,
                                                             ForwarderDatagramSession *session = nullptr) noexcept
        {
            if (outboundFd < 0 || payload.empty())
            {
                return std::unexpected(ERR::SOCKET_FAILED);
            }

            Datagram endpoint(outboundFd, /*ownsFd=*/false);
            auto sentRes = endpoint.sendTo(remote, payload);
            if (!sentRes)
            {
                LOG_WARN("forwardDatagramToRemote: sendTo() failed: {}", toString(sentRes.error()));
                return std::unexpected(sentRes.error());
            }

            const size_t n = *sentRes;
            if (n > 0)
            {
                if (session != nullptr)
                {
                    session->recordUp(n);
                }
                totalBytesUp_.fetch_add(n, std::memory_order_relaxed);
                totalPacketsUp_.fetch_add(1, std::memory_order_relaxed);
            }
            return n;
        }

        [[nodiscard]] Result<size_t> forwardDatagramToRemote(ForwarderDatagramSession &session,
                                                             std::string_view payload) noexcept
        {
            return forwardDatagramToRemote(session.outboundFd(), session.remoteAddr(), payload, &session);
        }

        /**
         * @brief 将上游响应的数据报封装并回传给客户端
         */
        [[nodiscard]] Result<size_t> forwardDatagramToClient(Handler &inbound, const sockaddr_in &client,
                                                             std::string_view payload,
                                                             ForwarderDatagramSession *session = nullptr) noexcept
        {
            if (payload.empty())
            {
                return 0;
            }

            inbound.sendTo(client, payload.data(), payload.size());
            const size_t n = payload.size();
            if (session != nullptr)
            {
                session->recordDown(n);
            }
            totalBytesDown_.fetch_add(n, std::memory_order_relaxed);
            totalPacketsDown_.fetch_add(1, std::memory_order_relaxed);
            return n;
        }

        /**
         * @brief 排空超时的 UDP 会话（同步清理会话表与 NAT 映射表并关断 watch）
         */
        size_t sweepIdleDatagramSessions(std::optional<std::chrono::seconds> timeout = std::nullopt)
        {
            const auto maxIdle = timeout.value_or(std::chrono::seconds(defaultConfig_.udpSessionTimeoutSecs));
            const auto now = std::chrono::steady_clock::now();
            std::vector<std::shared_ptr<ForwarderDatagramSession>> toRemove;

            {
                std::lock_guard<std::mutex> lock(datagramMutex_);
                for (auto it = datagramSessions_.begin(); it != datagramSessions_.end();)
                {
                    if (it->second->isExpired(now, maxIdle))
                    {
                        toRemove.push_back(it->second);
                        it = datagramSessions_.erase(it);
                    }
                    else
                    {
                        ++it;
                    }
                }
            }

            for (auto &sess : toRemove)
            {
                if (sess != nullptr)
                {
                    sess->close();
                }
            }
            return toRemove.size();
        }

        // =====================================================================
        // 全局聚合监控指标
        // =====================================================================

        [[nodiscard]] inline std::vector<std::shared_ptr<ForwarderStreamSession>> streamSessions() const
        {
            std::lock_guard<std::mutex> lock(streamMutex_);
            std::vector<std::shared_ptr<ForwarderStreamSession>> list;
            list.reserve(streamSessions_.size());
            for (const auto &pair : streamSessions_)
            {
                list.push_back(pair.second);
            }
            return list;
        }

        [[nodiscard]] inline size_t activeStreamSessions() const noexcept
        {
            std::lock_guard<std::mutex> lock(streamMutex_);
            return streamSessions_.size();
        }

        [[nodiscard]] inline size_t activeDatagramSessions() const noexcept
        {
            std::lock_guard<std::mutex> lock(datagramMutex_);
            return datagramSessions_.size();
        }

        [[nodiscard]] inline uint64_t totalBytesUp() const noexcept
        {
            return totalBytesUp_.load(std::memory_order_relaxed);
        }

        [[nodiscard]] inline uint64_t totalBytesDown() const noexcept
        {
            return totalBytesDown_.load(std::memory_order_relaxed);
        }

        [[nodiscard]] inline uint64_t totalPacketsUp() const noexcept
        {
            return totalPacketsUp_.load(std::memory_order_relaxed);
        }

        [[nodiscard]] inline uint64_t totalPacketsDown() const noexcept
        {
            return totalPacketsDown_.load(std::memory_order_relaxed);
        }

        /**
         * @brief 关闭所有活跃会话并重置 Forwarder
         */
        void closeAll() noexcept
        {
            std::unordered_map<uint64_t, std::shared_ptr<ForwarderStreamSession>> streams;
            std::unordered_map<DatagramSessionKey, std::shared_ptr<ForwarderDatagramSession>, DatagramSessionKeyHash>
                dgrams;

            {
                std::lock_guard<std::mutex> lock(streamMutex_);
                streams = std::move(streamSessions_);
            }
            {
                std::lock_guard<std::mutex> lock(datagramMutex_);
                dgrams = std::move(datagramSessions_);
            }

            for (auto &pair : streams)
            {
                if (pair.second != nullptr)
                {
                    pair.second->close(true);
                }
            }
            for (auto &pair : dgrams)
            {
                if (pair.second != nullptr)
                {
                    pair.second->close();
                }
            }
            dgrams.clear();
        }
    };

} // namespace mynet
