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

    /**
     * @brief 分散-聚集向量写入与协议头前缀冲刷器 (借鉴 dae writev scatter-gather header prefixing)
     *
     * 在转发代理协议报文（如 Shadowsocks 盐/Nonce、Socks5 目标头、Trojan 校验散列等）时：
     * 将协议头（前缀）与后续应用层载荷合并为一个系统调用 ::writev(2) 发送，
     * 避免因两次 ::write(2) 造成的额外系统调用开销与小包拆分（Nagle 延迟）。
     */
    class ScatterGatherFlusher
    {
    public:
        /**
         * @brief 将多个非连续内存切片一次性原子写入套接字
         */
        static ssize_t writevBuffers(int fd, std::span<const iovec> iovs) noexcept
        {
            if (fd < 0 || iovs.empty())
                return 0;
            return ::writev(fd, iovs.data(), static_cast<int>(iovs.size()));
        }

        /**
         * @brief 将前缀协议头与数据载荷以 writev 聚集发送
         */
        static ssize_t writePrefixed(int fd, std::span<const uint8_t> header, std::span<const uint8_t> payload) noexcept
        {
            if (fd < 0)
                return -1;
            iovec iov[2];
            iov[0].iov_base = const_cast<uint8_t *>(header.data());
            iov[0].iov_len = header.size();
            iov[1].iov_base = const_cast<uint8_t *>(payload.data());
            iov[1].iov_len = payload.size();
            return ::writev(fd, iov, 2);
        }

        /**
         * @brief 配合 FIONREAD 动态从客户端套接字抓取伴随载荷，并与协议头一起原子发送 (机制 71: tryRelayGatherWrite)
         *
         * 检查源套接字缓冲区是否有伴随到达的应用层载荷：
         * 若有，单次读取并与协议前缀以 writev 聚集原子发送，消灭两次系统调用与 Nagle 延时。
         */
        static ssize_t writePrefixedWithGather(int dstFd, std::span<const uint8_t> header, int srcFd,
                                               std::span<uint8_t> scratchBuf) noexcept
        {
            if (dstFd < 0)
                return -1;
            int pending = 0;
            size_t payloadLen = 0;
            if (srcFd >= 0 && ::ioctl(srcFd, FIONREAD, &pending) == 0 && pending > 0 && !scratchBuf.empty())
            {
                size_t toRead = std::min(static_cast<size_t>(pending), scratchBuf.size());
                ssize_t n = ::read(srcFd, scratchBuf.data(), toRead);
                if (n > 0)
                {
                    payloadLen = static_cast<size_t>(n);
                }
            }
            if (payloadLen > 0)
            {
                return writePrefixed(dstFd, header, std::span<const uint8_t>(scratchBuf.data(), payloadLen));
            }
            return writePrefixed(dstFd, header, {});
        }
    };

    namespace detail
    {
        [[nodiscard]] inline SpliceResult splicePipes(int srcFd, int dstFd, int pipeWriteFd, int pipeReadFd,
                                                      size_t maxBytes = 65536) noexcept
        {
            if (srcFd < 0 || dstFd < 0 || pipeWriteFd < 0 || pipeReadFd < 0)
            {
                return {.bytesSpliced = -1, .eof = false, .err = EINVAL};
            }

            // 1. 从源端摄入管道
            const ssize_t sIn =
                ::splice(srcFd, nullptr, pipeWriteFd, nullptr, maxBytes, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
            if (sIn < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    return {.bytesSpliced = 0, .eof = false, .err = EAGAIN};
                }
                return {.bytesSpliced = -1, .eof = false, .err = errno};
            }
            if (sIn == 0)
            {
                return {.bytesSpliced = 0, .eof = true, .err = 0};
            }

            // 2. 从管道刷出至目的端
            size_t pending = static_cast<size_t>(sIn);
            size_t written = 0;
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
                        return {.bytesSpliced = static_cast<ssize_t>(written), .eof = false, .err = EAGAIN};
                    }
                    return {.bytesSpliced = static_cast<ssize_t>(written), .eof = false, .err = errno};
                }
                break;
            }

            return {.bytesSpliced = static_cast<ssize_t>(written), .eof = false, .err = 0};
        }
    } // namespace detail

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

        handler::HandlerInboundConnectionBase *inbound_{nullptr};
        handler::HandlerOutboundConnectionBase *outbound_{nullptr};
        std::unique_ptr<handler::HandlerInboundConnectionBase> ownedInbound_{nullptr};
        std::unique_ptr<handler::HandlerOutboundConnectionBase> ownedOutbound_{nullptr};
        int inboundFd_{-1};
        int outboundFd_{-1};
        int sockmapFd_{-1};
        int pipeUp_[2]{-1, -1};
        int pipeDown_[2]{-1, -1};
        handler::ProxyAddress target_{};

        bool inboundClosed_{false};
        bool outboundClosed_{false};
        bool sockmapPaused_{false};

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

        [[nodiscard]] inline int inboundFd() const noexcept { return inboundFd_; }
        [[nodiscard]] inline int outboundFd() const noexcept { return outboundFd_; }
        [[nodiscard]] inline int sockmapFd() const noexcept { return sockmapFd_; }
        [[nodiscard]] inline handler::HandlerInboundConnectionBase *inbound() noexcept { return inbound_; }
        [[nodiscard]] inline handler::HandlerOutboundConnectionBase *outbound() noexcept { return outbound_; }
        [[nodiscard]] inline const handler::ProxyAddress &target() const noexcept { return target_; }

        inline void setTarget(const handler::ProxyAddress &target) noexcept { target_ = target; }
        inline void setInboundFd(int fd) noexcept { inboundFd_ = fd; }
        inline void setOutboundFd(int fd) noexcept { outboundFd_ = fd; }
        inline void setSockmapFd(int fd) noexcept { sockmapFd_ = fd; }
        inline void setOwnedInbound(std::unique_ptr<handler::HandlerInboundConnectionBase> in) noexcept
        {
            ownedInbound_ = std::move(in);
            inbound_ = ownedInbound_.get();
        }
        inline void setOwnedOutbound(std::unique_ptr<handler::HandlerOutboundConnectionBase> out) noexcept
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
        size_t attach(handler::HandlerInboundConnectionBase &in, handler::HandlerOutboundConnectionBase &out,
                      int inFd = -1, int outFd = -1, bool userSslActive = false)
        {
            inbound_ = &in;
            outbound_ = &out;
            inboundFd_ = (inFd >= 0) ? inFd : in.fd();
            outboundFd_ = (outFd >= 0) ? outFd : out.fd();

            if (in.targetAddress().has_value())
            {
                target_ = *in.targetAddress();
            }
            else if (out.target().type == handler::AddressType::IPV4 ||
                     out.target().type == handler::AddressType::DOMAIN ||
                     out.target().type == handler::AddressType::IPV6)
            {
                target_ = out.target();
            }

            // 1. 握手残余数据预冲刷：排空握手期间在用户态缓冲区堆积的早期业务载荷
            size_t preFlushed = flushPrebuffered();

            // 2. 冲刷已生成的出站与入站协议头/握手报文 (如 SOCKS5 Greeting, Trojan Header, VLESS Header, HTTP CONNECT
            // 等)
            flushOutboundResponses();
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

        inline void flushOutboundResponses() noexcept
        {
            if (outbound_ != nullptr && outboundFd_ >= 0)
            {
                while (outbound_->hasResponse())
                {
                    std::string resp = outbound_->takeResponse();
                    if (!resp.empty())
                    {
                        ssize_t n = ::send(outboundFd_, resp.data(), resp.size(), MSG_NOSIGNAL);
                        if (n > 0)
                        {
                            stats_.bytesUp += static_cast<size_t>(n);
                            stats_.touch();
                        }
                    }
                }
            }
        }

        inline void flushInboundResponses() noexcept
        {
            if (inbound_ != nullptr && inboundFd_ >= 0)
            {
                while (inbound_->hasResponse())
                {
                    std::string resp = inbound_->takeResponse();
                    if (!resp.empty())
                    {
                        ssize_t n = ::send(inboundFd_, resp.data(), resp.size(), MSG_NOSIGNAL);
                        if (n > 0)
                        {
                            stats_.bytesDown += static_cast<size_t>(n);
                            stats_.touch();
                        }
                    }
                }
            }
        }

        /**
         * @brief 冲刷双端在建立转发前已摄入用户态缓冲区的早期数据
         *
         * @return size_t 冲刷迁移的总字节数
         */
        size_t flushPrebuffered() noexcept
        {
            size_t total = 0;
            // 上行预读数据冲刷：入站残余 -> 出站待发队列
            if (inbound_ != nullptr && outbound_ != nullptr && inbound_->requestBytes() > 0 && !outboundClosed_)
            {
                const size_t n = inbound_->requestBytes();
                std::string_view payload(inbound_->requestBegin(), n);
                if (auto res = outbound_->pushResponse(payload); res)
                {
                    inbound_->requestConsume(n);
                    stats_.bytesUp += n;
                    ++stats_.packetsUp;
                    stats_.touch();
                    total += n;
                }
            }

            // 下行预读数据冲刷：出站残余 -> 入站待发队列
            if (outbound_ != nullptr && inbound_ != nullptr && outbound_->requestBytes() > 0 && !inboundClosed_)
            {
                const size_t n = outbound_->requestBytes();
                std::string_view payload(outbound_->requestBegin(), n);
                if (auto res = inbound_->pushResponse(payload); res)
                {
                    outbound_->requestConsume(n);
                    stats_.bytesDown += n;
                    ++stats_.packetsDown;
                    stats_.touch();
                    total += n;
                }
            }
            return total;
        }

        void ensurePipes() noexcept
        {
            if (pipeUp_[0] < 0)
            {
                if (::pipe2(pipeUp_, O_NONBLOCK | O_CLOEXEC) < 0)
                {
                    pipeUp_[0] = pipeUp_[1] = -1;
                }
            }
            if (pipeDown_[0] < 0)
            {
                if (::pipe2(pipeDown_, O_NONBLOCK | O_CLOEXEC) < 0)
                {
                    pipeDown_[0] = pipeDown_[1] = -1;
                }
            }
        }

        /**
         * @brief 激活 eBPF Sockmap 内核流卸载 (0 唤醒，0 内存拷贝)
         */
        bool activateSockmap() noexcept
        {
#if defined(__linux__) && defined(__NR_bpf)
            if (sockmapFd_ < 0 || inboundFd_ < 0 || outboundFd_ < 0)
            {
                return false;
            }
            // 预先准备双向管道，确保在 Sockmap 遇到局部阻塞或用户态需要排空时具备零拷贝 splice 保底能力
            ensurePipes();
            if (!ebpf::EbpfEngine::attachPair(sockmapFd_, inboundFd_, outboundFd_))
            {
                return false;
            }
            activeMode_ = ForwardMode::KERNEL_SOCKMAP;
            if (inbound_ != nullptr)
            {
                inbound_->setSpliceTarget(outboundFd_);
            }
            if (outbound_ != nullptr)
            {
                outbound_->setSpliceTarget(inboundFd_);
            }
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
            if (sockmapFd_ >= 0 && inboundFd_ >= 0)
            {
                ebpf::EbpfEngine::detachPair(sockmapFd_, inboundFd_);
            }
        }

        [[nodiscard]] inline bool isSockmapPaused() const noexcept { return sockmapPaused_; }

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
            if (outboundFd_ >= 0 && getSocketPendingOutBytes(outboundFd_) > highWater)
            {
                return true;
            }
            if (inboundFd_ >= 0 && getSocketPendingOutBytes(inboundFd_) > highWater)
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
                deactivateSockmap();
                activeMode_ = ForwardMode::ZERO_COPY_SPLICE;
                sockmapPaused_ = true;
            }
            else if (sockmapPaused_ && !congested)
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
            const bool inCanSplice = (inbound_ == nullptr) || inbound_->kEnableSplice;
            const bool outCanSplice = (outbound_ == nullptr) || outbound_->kEnableSplice;

            const bool canSplice = config_.enableSplice && (configuredMode_ != ForwardMode::BUFFER_PUMP) &&
                                   !userSslActive && inCanSplice && outCanSplice && (inboundFd_ >= 0) &&
                                   (outboundFd_ >= 0);

            const bool canOffload =
                (configuredMode_ == ForwardMode::AUTO || configuredMode_ == ForwardMode::KERNEL_SOCKMAP) &&
                (sockmapFd_ >= 0) && canSplice;

            if (canOffload && activateSockmap())
            {
                // Sockmap 挂载成功
            }
            else if (canSplice)
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
            activeMode_ = ForwardMode::ZERO_COPY_SPLICE;
            if (inbound_ != nullptr && outboundFd_ >= 0)
            {
                inbound_->setSpliceTarget(outboundFd_);
            }
            if (outbound_ != nullptr && inboundFd_ >= 0)
            {
                outbound_->setSpliceTarget(inboundFd_);
            }
            ensurePipes();
        }

        /**
         * @brief 激活用户态缓冲流控泵送模式
         */
        void activateBufferPump() noexcept
        {
            activeMode_ = ForwardMode::BUFFER_PUMP;
            if (inbound_ != nullptr)
            {
                inbound_->disableSplice();
            }
            if (outbound_ != nullptr)
            {
                outbound_->disableSplice();
            }
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

            PumpResult result{};

            // 0. 若出站协议握手尚未建立完成 (如 SOCKS5 等待协商与回执、VLESS 等待响应等)：
            if (outbound_ != nullptr && !outbound_->isEstablished() && !outboundClosed_ && outboundFd_ >= 0)
            {
                flushOutboundResponses();

                char hbuf[4096];
                ssize_t hn = ::read(outboundFd_, hbuf, sizeof(hbuf));
                if (hn > 0)
                {
                    [[maybe_unused]] auto _ = outbound_->appendRequest(hbuf, hn);
                    outbound_->handle();
                    flushOutboundResponses();

                    if (outbound_->isEstablished())
                    {
                        activateAdaptiveMode(false);
                    }
                }
                else if (hn == 0)
                {
                    markOutboundClosed();
                }
                else if (errno != EAGAIN && errno != EWOULDBLOCK)
                {
                    markOutboundClosed();
                }
            }

            flushOutboundResponses();
            flushInboundResponses();

            // 1. 上行泵送：Inbound RequestBuffer -> Outbound ResponseQueue
            if (inbound_ != nullptr && outbound_ != nullptr && !outboundClosed_)
            {
                const size_t avail = inbound_->requestBytes();
                if (avail > 0)
                {
                    const size_t toPump = std::min(avail, config_.bufferChunkSize);
                    std::string_view chunk(inbound_->requestBegin(), toPump);
                    if (auto res = outbound_->pushResponse(chunk); res)
                    {
                        inbound_->requestConsume(toPump);
                        stats_.bytesUp += toPump;
                        ++stats_.packetsUp;
                        stats_.touch();
                        result.bytesUp += toPump;
                    }
                }
            }

            // 2. 下行泵送：Outbound RequestBuffer -> Inbound ResponseQueue
            if (outbound_ != nullptr && inbound_ != nullptr && !inboundClosed_)
            {
                const size_t avail = outbound_->requestBytes();
                if (avail > 0)
                {
                    const size_t toPump = std::min(avail, config_.bufferChunkSize);
                    std::string_view chunk(outbound_->requestBegin(), toPump);
                    if (auto res = inbound_->pushResponse(chunk); res)
                    {
                        outbound_->requestConsume(toPump);
                        stats_.bytesDown += toPump;
                        ++stats_.packetsDown;
                        stats_.touch();
                        result.bytesDown += toPump;
                    }
                }
            }

            // 2.3 背压自愈与流控复用：当套接字队列积压超过 writeHighWaterMark 时自动触发背压保护
            if (sockmapFd_ >= 0)
            {
                checkAndApplySockmapBackpressure();
            }

            // 2.5 若活跃于套接字直通/零拷贝通道，驱动双向管道传输
            if (inboundFd_ >= 0 && outboundFd_ >= 0 && !outboundClosed_ && !inboundClosed_)
            {
                const uint64_t upBefore = stats_.bytesUp;
                const uint64_t downBefore = stats_.bytesDown;

                auto trDown = transferOutboundToInbound();
                if (trDown == TransferResult::ERROR || trDown == TransferResult::CLOSED)
                {
                    markOutboundClosed();
                }
                auto trUp = transferInboundToOutbound();
                if (trUp == TransferResult::ERROR || trUp == TransferResult::CLOSED)
                {
                    markInboundClosed();
                }

                result.bytesUp += static_cast<size_t>(stats_.bytesUp - upBefore);
                result.bytesDown += static_cast<size_t>(stats_.bytesDown - downBefore);
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

            if (inbound_ != nullptr)
            {
                inbound_->disableSplice();
                if (force)
                {
                    inbound_->setCloseAfterResponse(true);
                }
            }
            if (outbound_ != nullptr)
            {
                outbound_->disableSplice();
                if (force)
                {
                    outbound_->setCloseAfterResponse(true);
                }
            }

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

            if (activeMode_ == ForwardMode::KERNEL_SOCKMAP)
            {
                deactivateSockmap();
            }

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
            ERROR = 3
        };

        TransferResult transferInboundToOutbound() noexcept
        {
            if (inboundClosed_ || inboundFd_ < 0 || outboundFd_ < 0)
            {
                return TransferResult::CLOSED;
            }

            if ((activeMode_ == ForwardMode::ZERO_COPY_SPLICE || activeMode_ == ForwardMode::KERNEL_SOCKMAP) &&
                pipeUp_[0] >= 0 && pipeUp_[1] >= 0)
            {
                auto res =
                    detail::splicePipes(inboundFd_, outboundFd_, pipeUp_[1], pipeUp_[0], config_.spliceChunkSize);
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
                    markInboundClosed();
                    return TransferResult::ERROR;
                }
                return TransferResult::OK;
            }

            char buf[16384];
            ssize_t n = ::read(inboundFd_, buf, sizeof(buf));
            if (n > 0)
            {
                ssize_t w = ::write(outboundFd_, buf, static_cast<size_t>(n));
                if (w > 0)
                {
                    stats_.bytesUp += static_cast<size_t>(w);
                    stats_.touch();
                    return TransferResult::OK;
                }
            }
            else if (n == 0)
            {
                markInboundClosed();
                return TransferResult::CLOSED;
            }
            else if (errno != EAGAIN && errno != EWOULDBLOCK)
            {
                markInboundClosed();
                return TransferResult::ERROR;
            }
            return TransferResult::AGAIN;
        }

        TransferResult transferOutboundToInbound() noexcept
        {
            if (outboundClosed_ || inboundFd_ < 0 || outboundFd_ < 0)
            {
                return TransferResult::CLOSED;
            }

            if ((activeMode_ == ForwardMode::ZERO_COPY_SPLICE || activeMode_ == ForwardMode::KERNEL_SOCKMAP) &&
                pipeDown_[0] >= 0 && pipeDown_[1] >= 0)
            {
                auto res =
                    detail::splicePipes(outboundFd_, inboundFd_, pipeDown_[1], pipeDown_[0], config_.spliceChunkSize);
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
                    markOutboundClosed();
                    return TransferResult::ERROR;
                }
                return TransferResult::OK;
            }

            char buf[16384];
            ssize_t n = ::read(outboundFd_, buf, sizeof(buf));
            if (n > 0)
            {
                ssize_t w = ::write(inboundFd_, buf, static_cast<size_t>(n));
                if (w > 0)
                {
                    stats_.bytesDown += static_cast<size_t>(w);
                    stats_.touch();
                    return TransferResult::OK;
                }
            }
            else if (n == 0)
            {
                markOutboundClosed();
                return TransferResult::CLOSED;
            }
            else if (errno != EAGAIN && errno != EWOULDBLOCK)
            {
                markOutboundClosed();
                return TransferResult::ERROR;
            }
            return TransferResult::AGAIN;
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

    /**
     * @brief 数据报/UDP 转发映射会话 (Datagram Forwarding Session)
     */
    class ForwarderDatagramSession
    {
    private:
        uint64_t id_{0};
        sockaddr_in clientAddr_{};
        sockaddr_in remoteAddr_{};
        int outboundFd_{-1};
        ForwarderStats stats_{};

    public:
        ForwarderDatagramSession(uint64_t id, const sockaddr_in &client, const sockaddr_in &remote,
                                 int outboundFd = -1) noexcept
            : id_(id),
              clientAddr_(client),
              remoteAddr_(remote),
              outboundFd_(outboundFd)
        {
        }

        ~ForwarderDatagramSession() noexcept
        {
            if (outboundFd_ >= 0)
            {
                ::close(outboundFd_);
                outboundFd_ = -1;
            }
        }

        ForwarderDatagramSession(const ForwarderDatagramSession &) = delete;
        ForwarderDatagramSession &operator=(const ForwarderDatagramSession &) = delete;
        ForwarderDatagramSession(ForwarderDatagramSession &&) = delete;
        ForwarderDatagramSession &operator=(ForwarderDatagramSession &&) = delete;

        [[nodiscard]] inline uint64_t id() const noexcept { return id_; }
        [[nodiscard]] inline const sockaddr_in &clientAddr() const noexcept { return clientAddr_; }
        [[nodiscard]] inline const sockaddr_in &remoteAddr() const noexcept { return remoteAddr_; }
        [[nodiscard]] inline int outboundFd() const noexcept { return outboundFd_; }
        [[nodiscard]] inline const ForwarderStats &stats() const noexcept { return stats_; }
        [[nodiscard]] inline ForwarderStats &stats() noexcept { return stats_; }

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
        std::unordered_map<uint64_t, std::shared_ptr<ForwarderDatagramSession>> datagramSessions_{};

        std::atomic<uint64_t> totalBytesUp_{0};
        std::atomic<uint64_t> totalBytesDown_{0};
        std::atomic<uint64_t> totalPacketsUp_{0};
        std::atomic<uint64_t> totalPacketsDown_{0};
        int sockmapFd_{-1};

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

        /**
         * @brief 桥接入站流式处理器与出站流式处理器
         *
         * @param inbound 入站协议处理器（如 HandlerInboundSocks5, HandlerInboundTrojan, HandlerInboundDirect）
         * @param outbound 出站协议处理器（如 HandlerOutboundDirect, HandlerOutboundTrojan, HandlerOutboundSocks5）
         * @param cfg 显式转发配置覆盖（可选）
         * @return std::shared_ptr<ForwarderStreamSession> 转发会话句柄
         */
        std::shared_ptr<ForwarderStreamSession> bridge(handler::HandlerInboundConnectionBase &inbound,
                                                       handler::HandlerOutboundConnectionBase &outbound,
                                                       std::optional<ForwarderConfig> cfg = std::nullopt)
        {
            const ForwarderConfig actualConfig = cfg.value_or(defaultConfig_);
            const uint64_t sid = nextSessionId_.fetch_add(1, std::memory_order_relaxed);
            auto session = std::make_shared<ForwarderStreamSession>(sid, actualConfig);
            session->setSockmapFd(sockmapFd_);

            [[maybe_unused]] auto preFlushed = session->attach(inbound, outbound, inbound.fd(), outbound.fd(), false);
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

            {
                std::lock_guard<std::mutex> lock(streamMutex_);
                streamSessions_.emplace(sid, session);
            }
            return session;
        }

        /**
         * @brief 桥接两个底层流式连接对象 (ConnectionBase &inboundConn 与 ConnectionBase &outboundConn)
         *
         * 自动检查双端是否启用 SSL，自动提取套接字描述符并装配零拷贝 splice 或用户态泵送。
         */
        std::shared_ptr<ForwarderStreamSession> bridge(ConnectionBase &inboundConn, ConnectionBase &outboundConn,
                                                       std::optional<ForwarderConfig> cfg = std::nullopt)
        {
            const ForwarderConfig actualConfig = cfg.value_or(defaultConfig_);
            const uint64_t sid = nextSessionId_.fetch_add(1, std::memory_order_relaxed);
            auto session = std::make_shared<ForwarderStreamSession>(sid, actualConfig);
            session->setSockmapFd(sockmapFd_);

            const bool userSsl = (inboundConn.ssl() != nullptr || outboundConn.ssl() != nullptr);
            auto *inHandler = static_cast<handler::HandlerInboundConnectionBase *>(inboundConn.handler());
            auto *outHandler = static_cast<handler::HandlerOutboundConnectionBase *>(outboundConn.handler());
            contract_assert(inHandler != nullptr && outHandler != nullptr);

            [[maybe_unused]] auto preFlushed =
                session->attach(*inHandler, *outHandler, inboundConn.fd(), outboundConn.fd(), userSsl);
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

            {
                std::lock_guard<std::mutex> lock(streamMutex_);
                streamSessions_.emplace(sid, session);
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

            {
                std::lock_guard<std::mutex> lock(streamMutex_);
                streamSessions_.emplace(sid, session);
            }
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
         * @brief 获取或创建关联的 UDP 数据报转发会话
         */
        std::shared_ptr<ForwarderDatagramSession>
        getOrCreateDatagramSession(const sockaddr_in &client, const sockaddr_in &remote, int outboundFd = -1)
        {
            const uint64_t sid = nextSessionId_.fetch_add(1, std::memory_order_relaxed);
            auto session = std::make_shared<ForwarderDatagramSession>(sid, client, remote, outboundFd);

            std::lock_guard<std::mutex> lock(datagramMutex_);
            datagramSessions_.emplace(sid, session);
            return session;
        }

        /**
         * @brief 向远端上游服务器转发来自客户端的 UDP 载荷
         */
        [[nodiscard]] Result<size_t> forwardDatagramToRemote(int outboundFd, const sockaddr_in &remote,
                                                             std::string_view payload,
                                                             ForwarderDatagramSession *session = nullptr) noexcept
        {
            if (outboundFd < 0 || payload.empty())
            {
                return std::unexpected(ERR::SOCKET_FAILED);
            }

            const ssize_t sent = ::sendto(outboundFd, payload.data(), payload.size(), MSG_NOSIGNAL,
                                          reinterpret_cast<const sockaddr *>(&remote), sizeof(remote));
            if (sent < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    return 0;
                }
                LOG_WARN("forwardDatagramToRemote: sendto() failed: {}", errnoText(errno));
                return std::unexpected(ERR::SOCKET_FAILED);
            }

            const size_t n = static_cast<size_t>(sent);
            if (session != nullptr)
            {
                session->recordUp(n);
            }
            totalBytesUp_.fetch_add(n, std::memory_order_relaxed);
            totalPacketsUp_.fetch_add(1, std::memory_order_relaxed);
            return n;
        }

        /**
         * @brief 将上游响应的数据报封装并回传给客户端
         */
        [[nodiscard]] Result<size_t> forwardDatagramToClient(handler::HandlerInboundDatagramBase &inbound,
                                                             const sockaddr_in &client, std::string_view payload,
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
         * @brief 排空超时的 UDP 会话
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

            return toRemove.size();
        }

        // =====================================================================
        // 静态独立零拷贝直通工具 (Standalone Splice Utilities)
        // =====================================================================

        /**
         * @brief 使用显式管道在两个描述符之间执行一次非阻塞内核零拷贝拼接 (splice)
         *
         * 拓扑：srcFd -> pipeWriteFd | pipeReadFd -> dstFd
         *
         * @param srcFd 源套接字描述符
         * @param dstFd 目的套接字描述符
         * @param pipeWriteFd 管道写入端描述符 (pipeFd[1])
         * @param pipeReadFd 管道读取端描述符 (pipeFd[0])
         * @param maxBytes 单次拼接最大字节数
         * @return SpliceResult 拼接状态与字节数
         */
        [[nodiscard]] static SpliceResult splicePipes(int srcFd, int dstFd, int pipeWriteFd, int pipeReadFd,
                                                      size_t maxBytes = 65536) noexcept
        {
            return detail::splicePipes(srcFd, dstFd, pipeWriteFd, pipeReadFd, maxBytes);
        }

        /**
         * @brief 在两个套接字描述符间单次自建临时管道执行零拷贝转发 (一次性便利函数)
         */
        [[nodiscard]] static SpliceResult spliceDirect(int srcFd, int dstFd, size_t maxBytes = 65536) noexcept
        {
            int pipeFds[2] = {-1, -1};
            if (::pipe2(pipeFds, O_NONBLOCK | O_CLOEXEC) < 0)
            {
                return {.bytesSpliced = -1, .eof = false, .err = errno};
            }

            SpliceResult res = splicePipes(srcFd, dstFd, pipeFds[1], pipeFds[0], maxBytes);
            ::close(pipeFds[0]);
            ::close(pipeFds[1]);
            return res;
        }

        // =====================================================================
        // 全局聚合监控指标
        // =====================================================================

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
            std::unordered_map<uint64_t, std::shared_ptr<ForwarderDatagramSession>> dgrams;

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
            dgrams.clear();
        }
    };

} // namespace mynet
