#pragma once

#include "configHolder.hpp"
#include "constraints.hpp"
#include "error.hpp"
#include "handler/http/v3/frame.hpp"
#include "handler/http/v3/qpack.hpp"
#include "handler/http/v3/varint.hpp"
#include "config/log.hpp"
#include "requestBuffer.hpp"
#include "responseQueue.hpp"
#include "config/tls.hpp"
#include <arpa/inet.h>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unordered_map>
#include <utility>
#include <vector>

namespace mynet
{

    class HandlerDatagram;

    /**
     * @brief 数据报协议外发参数包特化
     *
     * 包含目标对端网络地址 sockaddr_in peer 与待发送载荷 std::string bytes。
     */
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

    /**
     * @brief 数据报外发响应队列特化类型（基于通用 ResponseQueueBase）
     */
    using DatagramQueue = ResponseQueueBase<Protocol<HandlerDatagram>>;

    /**
     * @brief 格式化 IPv4 对端套接字地址文本 ("192.0.2.7:5353")
     *
     * @param peer 对端 sockaddr_in 地址结构
     * @return std::string 人类可读地址字符串
     */
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
     * @brief UDP 数据报无连接协议处理器基类
     *
     * 本类是报文传输层次的根：不继承任何处理器基类，独立提供无连接套接字上
     * 对端报文交织问题所需的外发队列管理与溢出丢包计数防护，以及与传输无关的
     * 生命周期钩子（reset / onMessageComplete / onParseError）。派生类实现
     * onDatagram() 后再叠加自身协议语义。
     *
     * 被 Reactor/Proactor 以 UDP 方式驱动时，派生类只需继承本类：数据报路径不经过
     * Connection，引擎不会为纯报文处理器实例化任何流式设施。需要同时承载流式会话的
     * 协议（如 HTTP/3 over QUIC）则另行多重继承 HandlerConnection；两者是并列的
     * 独立基类，不存在虚继承。
     */
    class HandlerDatagram
    {
    public:
        HandlerDatagram() noexcept
            : HandlerDatagram(getDatagramConfig())
        {
        }

        explicit HandlerDatagram(const DatagramConfig &config) noexcept
            : maxDatagramBytes_(config.maxDatagramBytes),
              maxPendingOutgoing_(config.maxPendingOutgoing)
        {
            [[maybe_unused]] auto _ = outgoing_.init(maxPendingOutgoing_);
        }

        virtual ~HandlerDatagram() noexcept = default;

        HandlerDatagram(const HandlerDatagram &) = delete; // a datagram handler owns the outgoing queue for one socket
        HandlerDatagram &
        operator=(const HandlerDatagram &) = delete; // a datagram handler owns the outgoing queue for one socket
        HandlerDatagram(HandlerDatagram &&) = delete; // a datagram handler owns the outgoing queue for one socket
        HandlerDatagram &
        operator=(HandlerDatagram &&) = delete; // a datagram handler owns the outgoing queue for one socket

        /**
         * @brief 单个完整数据报到达业务入口钩子（派生类实现具体的协议解析、转发或回显）
         *
         * 基类提供空操作，不再强行写死默认回显；回显等具体业务逻辑完全由派生类决定。
         *
         * @param peer 发送方网络地址
         * @param data 报文载荷首地址
         * @param n 报文有效字节长度
         */
        virtual void onDatagram([[maybe_unused]] const sockaddr_in &peer, [[maybe_unused]] const char *data,
                                [[maybe_unused]] size_t n) noexcept
        {
        }

        /**
         * @brief 重置处理器状态与队列计数
         */
        virtual void reset() noexcept
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
        }

        /**
         * @brief 一条协议消息处理完成（单个数据报）
         */
        virtual void onMessageComplete() noexcept {}

        /**
         * @brief 协议解析失败
         *
         * @param reason 人类可读的失败原因，允许为空指针
         */
        virtual void onParseError([[maybe_unused]] const char *reason) noexcept {}

        // ---- 报文发送与转发队列管理 (Send / Forward / Broadcast) ----

        /**
         * @brief 向指定目标地址发送数据报（涵盖回复、反向代理转发或主动发起）
         *
         * @param target 目标对端网络地址
         * @param buf 报文载荷首地址（非空）
         * @param n 报文有效字节长度
         */
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

        /**
         * @brief 向指定目标地址发送数据报（移动语义载荷）
         */
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

        /**
         * @brief 将当前收到的报文零修改转发至上游目标地址（UDP 代理 / 网关转发语义）
         *
         * @param upstream 上游服务器对端地址
         * @param data 报文载荷首地址
         * @param n 报文有效字节长度
         */
        inline void forwardTo(const sockaddr_in &upstream, const char *data, size_t n) { sendTo(upstream, data, n); }

        /**
         * @brief 将同一份报文广播/多播至多个目标地址
         *
         * @param targets 目标对端地址列表
         * @param data 报文载荷首地址
         * @param n 报文有效字节长度
         */
        inline void broadcastTo(const std::vector<sockaddr_in> &targets, const char *data, size_t n)
        {
            if (data == nullptr || n == 0)
                return;
            for (const auto &target : targets)
            {
                sendTo(target, data, n);
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

        [[nodiscard]] inline size_t droppedOutgoing() const noexcept { return droppedOutgoing_; }

        inline void setMaxDatagramBytes(size_t n) noexcept { maxDatagramBytes_ = n; }
        [[nodiscard]] inline size_t maxDatagramBytes() const noexcept { return maxDatagramBytes_; }

        inline void setMaxPendingOutgoing(size_t n) noexcept
        {
            contract_assert(n > 0);
            maxPendingOutgoing_ = n;
            [[maybe_unused]] auto _ = outgoing_.init(n);
        }
        [[nodiscard]] inline size_t maxPendingOutgoing() const noexcept { return maxPendingOutgoing_; }

    protected:
        size_t maxDatagramBytes_ = getDatagramConfig().maxDatagramBytes;
        size_t maxPendingOutgoing_ = getDatagramConfig().maxPendingOutgoing;
        size_t droppedOutgoing_ = 0;
        DatagramQueue outgoing_{};
    };

    /**
     * @brief 偏报文的数据报处理器派生约束
     */
    template <typename D>
    concept DerivedFromHandlerDatagram = std::derived_from<D, HandlerDatagram>;

    /**
     * @brief 数据报处理器的必需方法集合
     *
     * 与 MandatoryMethodConnection 对称：这是 Datagram<H> 及数据报处理架构下
     * 对派生处理器的全量契约清单，逐项校验所有成员函数的签名与 noexcept 规范，
     * 防止派生类用 = delete 或不兼容签名破坏报文处理契约。
     */
    template <typename D>
    concept MandatoryMethodDatagram = DerivedFromHandlerDatagram<D> && Resettable<D> &&
                                      requires(D &d, const sockaddr_in &peer, const char *buf, size_t n,
                                               std::string bytes, const std::vector<sockaddr_in> &targets) {
                                          // ---- 报文接收入口与生命周期钩子 ----
                                          { d.onDatagram(peer, buf, n) } noexcept;
                                          { d.onMessageComplete() } noexcept;
                                          { d.onParseError(buf) } noexcept;

                                          // ---- 报文发送与转发队列控制 ----
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

                                          // ---- 容量与限制控制 ----
                                          { d.setMaxDatagramBytes(n) } noexcept;
                                          { d.maxDatagramBytes() } noexcept -> std::same_as<size_t>;
                                          { d.setMaxPendingOutgoing(n) } noexcept;
                                          { d.maxPendingOutgoing() } noexcept -> std::same_as<size_t>;
                                      };

    /**
     * @brief 数据报传输层会话（Connection<H> 在 UDP 路径上的对等物）
     *
     * 分层与流式一侧保持对称：
     * - HandlerDatagram 是协议侧根类，持有外发队列与报文上界，只关心「发什么」；
     * - 本类是该处理器在一条 UDP 套接字上的传输侧载体，持有接收窗口与收发计数，
     *   并承担超界截断、发送失败统计这些与协议语义无关的工作；
     * - 引擎因此退化为事件分发：可读就 recvfrom 进 recvBuffer()，交给 receiveFrom()
     *   派发，再用 flushTo() 把外发报文排空。
     *
     * 与 Connection<H> 的差异源于传输语义本身：UDP 无连接，所以本类不持有 fd
     * （fd 归 AcceptorBase，生命周期比会话更长），也不持有对端地址（每条报文自带），
     * 因此没有握手、状态机、写队列与读信用背压——那些是流式传输才需要的。
     * 省下来的开销全部投给了报文路径最关心的两件事：定容接收窗口（一次分配、
     * 永不重分配）与可统计的截断/丢发。
     *
     * 一个实例只绑定一个处理器；bind() 之后 bound() 为真。引擎以
     * DatagramSlot<H> 在编译期决定用本类还是 NoDatagram。
     */
    template <MandatoryMethodDatagram HandlerType>
    class Datagram
    {
    public:
        using Handler = HandlerType;

#ifdef MYNET_HAVE_QUIC
        struct QuicStreamState
        {
            SSL *stream = nullptr;
            RequestBuffer inBuf{};
            std::vector<http::v3::Header> headers{};
            std::string body{};
            bool responseSent = false;
        };

        struct QuicConnState
        {
            SSL *conn = nullptr;
            SSL *ctrlStream = nullptr;
            std::vector<SSL *> uniStreams{};
            std::unordered_map<uint64_t, QuicStreamState> bidiStreams{};
        };
#endif

        Datagram() noexcept = default;
        ~Datagram() noexcept { reset(); }

        Datagram(const Datagram &) = delete; // a datagram binding owns a handler reference and the receive window of one socket
        Datagram &operator=(const Datagram &) = delete; // a datagram binding owns a handler reference and the receive window of one socket
        Datagram(Datagram &&) = delete; // a datagram binding owns a handler reference and the receive window of one socket
        Datagram &operator=(Datagram &&) = delete; // a datagram binding owns a handler reference and the receive window of one socket

        /**
         * @brief 计算接收窗口容量（纯函数，便于单独验证边界）
         *
         * 规则：取 max(报文上界 + 1, preferredCapacity)，下限 1；上界为 SIZE_MAX
         * 时饱和而不是回绕——回绕会把窗口塌缩到 1 字节，等于把每条报文都判成截断。
         *
         * @param maxDatagramBytes 处理器声明的单报文上界
         * @param preferredCapacity 期望的最小窗口字节数
         * @return 接收窗口应分配的字节数
         */
        [[nodiscard]] static constexpr size_t windowCapacityFor(size_t maxDatagramBytes,
                                                                size_t preferredCapacity = 0) noexcept
        {
            size_t cap =
                (maxDatagramBytes == std::numeric_limits<size_t>::max()) ? maxDatagramBytes : maxDatagramBytes + 1;
            if (preferredCapacity > cap)
            {
                cap = preferredCapacity;
            }
            return cap == 0 ? 1 : cap;
        }

        /**
         * @brief 绑定处理器并一次性定容接收窗口
         *
         * 窗口取 max(处理器报文上界 + 1, preferredCapacity)：多出的那一个字节是
         * 「对端报文超出上界」的可观测信号——recvfrom 写满窗口时必然多读 1 字节，
         * 无需额外系统调用或 MSG_TRUNC 辅助判断。preferredCapacity 供引擎追加
         * 物理链路层约束（如 Proactor 的内核 Buffer Ring 尺寸）。
         *
         * @param handler 处理器引用，生命周期必须覆盖绑定期间
         * @param preferredCapacity 期望的最小窗口字节数（0 表示只按上界定容）
         */
        void bind(Handler &handler, size_t preferredCapacity = 0) noexcept
        {
            reset();
            handler_ = &handler;
            recvWindow_.resize(windowCapacityFor(handler_->maxDatagramBytes(), preferredCapacity));
        }

        /**
         * @brief 解除绑定、释放接收窗口与 TLS/QUIC 状态并清零收发计数
         */
        void reset() noexcept
        {
            handler_ = nullptr;
            recvWindow_.clear();
            hasPendingPacket_ = false;
            pendingPacket_ = {};
            receivedDatagrams_ = 0;
            receivedBytes_ = 0;
            truncatedDatagrams_ = 0;
            sentDatagrams_ = 0;
            sendFailures_ = 0;
#if defined(__linux__)
            batchRecvBuf_.reset();
#endif
#ifdef MYNET_HAVE_QUIC
            if (quicListener_ != nullptr)
            {
                for (auto &qc : quicConns_)
                {
                    for (auto &[id, st] : qc->bidiStreams)
                    {
                        if (st.stream != nullptr)
                        {
                            SSL_free(st.stream);
                        }
                    }
                    for (SSL *uni : qc->uniStreams)
                    {
                        if (uni != nullptr)
                        {
                            SSL_free(uni);
                        }
                    }
                    if (qc->ctrlStream != nullptr)
                    {
                        SSL_free(qc->ctrlStream);
                    }
                    if (qc->conn != nullptr)
                    {
                        SSL_free(qc->conn);
                    }
                }
                quicConns_.clear();
                SSL_free(quicListener_);
                quicListener_ = nullptr;
            }
#endif
        }

        [[nodiscard]] inline bool bound() const noexcept { return handler_ != nullptr; }

        [[nodiscard]] inline bool isQuic() const noexcept
        {
#ifdef MYNET_HAVE_QUIC
            return quicListener_ != nullptr;
#else
            return false;
#endif
        }

        /**
         * @brief 启动 QUIC TLS 监听器（对齐 Connection::startTLS）
         */
        [[nodiscard]] inline Result<> startTLS(SSL_CTX *ctx, int fd) noexcept
        {
#ifdef MYNET_HAVE_QUIC
            if (ctx == nullptr || fd < 0) [[unlikely]]
            {
                return std::unexpected(ERR::SSL_CTX_FAILED);
            }
            quicListener_ = SSL_new_listener(ctx, 0);
            if (quicListener_ == nullptr) [[unlikely]]
            {
                LOG_ERROR("Datagram::startTLS: SSL_new_listener failed: {}", sslText());
                return std::unexpected(ERR::SSL_CTX_FAILED);
            }

            SSL_set_blocking_mode(quicListener_, 0);
            SSL_set_default_stream_mode(quicListener_, SSL_DEFAULT_STREAM_MODE_NONE);
            SSL_set_incoming_stream_policy(quicListener_, SSL_INCOMING_STREAM_POLICY_ACCEPT, 0);

            if (!SSL_set_fd(quicListener_, fd)) [[unlikely]]
            {
                LOG_ERROR("Datagram::startTLS: SSL_set_fd failed on fd {}: {}", fd, sslText());
                SSL_free(quicListener_);
                quicListener_ = nullptr;
                return std::unexpected(ERR::SSL_SET_FD_FAILED);
            }

            if (!SSL_listen(quicListener_)) [[unlikely]]
            {
                LOG_ERROR("Datagram::startTLS: SSL_listen failed: {}", sslText());
                SSL_free(quicListener_);
                quicListener_ = nullptr;
                return std::unexpected(ERR::LISTEN_FAILED);
            }
            return {};
#else
            (void)ctx;
            (void)fd;
            return std::unexpected(ERR::SSL_CTX_FAILED);
#endif
        }

        /**
         * @brief 定时推进 QUIC 状态机（驱动重传、ACK 定时器等）
         */
        inline void tick([[maybe_unused]] int fd) noexcept
        {
#ifdef MYNET_HAVE_QUIC
            if (quicListener_ != nullptr)
            {
                handleQuic(fd);
            }
#endif
        }

        [[nodiscard]] inline Handler *handler() noexcept { return handler_; }
        [[nodiscard]] inline const Handler *handler() const noexcept { return handler_; }

        /**
         * @brief 当前绑定的处理器的单报文接收上界
         */
        [[nodiscard]] inline size_t maxDatagramBytes() const noexcept
        {
            return handler_ != nullptr ? handler_->maxDatagramBytes() : 0;
        }

        /**
         * @brief 接收窗口首地址（供 recvfrom / io_uring recvmsg 直接写入）
         */
        [[nodiscard]] inline char *recvBuffer() noexcept { return recvWindow_.data(); }

        /**
         * @brief 接收窗口容量（即 recvfrom 的缓冲区长度参数）
         */
        [[nodiscard]] inline size_t recvCapacity() const noexcept { return recvWindow_.size(); }

        /**
         * @brief 把一条收到的报文交给处理器
         *
         * 截断判定与日志在这里统一处理，两个引擎不再各写一遍：读出字节数超过
         * 处理器声明的上界即视为截断，按上界交付并计入 truncatedDatagrams()。
         *
         * 计数语义：receivedBytes() 累计的是**本次读出**的字节数，上界是接收窗口
         * 而非链路上的报文长度。两个引擎的窗口不同（Reactor 恰为上界+1，Proactor
         * 至少为内核缓冲尺寸），因此同一条超界报文在两者下会记录不同的字节数；
         * 交付给处理器的载荷长度则一致，都是 min(n, 上界)。
         *
         * @param peer 发送方地址
         * @param data 报文首地址（通常就是 recvBuffer()）
         * @param n 读出的字节数（可能因窗口写满而大于上界）
         */
        inline void receiveFrom(const sockaddr_in &peer, const char *data, size_t n) noexcept
        {
            if (handler_ == nullptr) [[unlikely]]
            {
                return;
            }
            ++receivedDatagrams_;
            receivedBytes_ += n;
            const size_t cap = handler_->maxDatagramBytes();
            if (n > cap) [[unlikely]]
            {
                ++truncatedDatagrams_;
                LOG_WARN("Datagram: {} bytes from {} exceeds the {} byte limit, truncated", n, datagramPeerText(peer),
                         cap);
                n = cap;
            }
            handler_->onDatagram(peer, data, n);
        }

        inline void setBatchIo(bool enable) noexcept { batchIoEnabled_ = enable; }
        [[nodiscard]] inline bool isBatchIoEnabled() const noexcept { return batchIoEnabled_; }

        /**
         * @brief 排空处理器积压的待发报文队列（包含 EAGAIN/EWOULDBLOCK 时未发出的暂存报文）
         *
         * @param fd 已绑定的 UDP 套接字描述符
         * @return 本次成功发出的报文条数（累计值见 sentDatagrams()）
         *
         * 刻意不加 [[nodiscard]]：这是以副作用为主的操作，返回值只是附带观测，
         * 而引擎的流式路径也会实例化到这个调用点（经空壳 NoDatagram）。
         */
        inline size_t flushTo(int fd) noexcept
        {
            if (handler_ == nullptr) [[unlikely]]
            {
                return 0;
            }
            size_t sent = 0;

            // 优先重试此前遭遇 EAGAIN/EWOULDBLOCK 暂存的报文
            if (hasPendingPacket_)
            {
                for (;;)
                {
                    ssize_t n = ::sendto(fd, pendingPacket_.bytes.data(), pendingPacket_.bytes.size(), 0,
                                         reinterpret_cast<const sockaddr *>(&pendingPacket_.peer),
                                         static_cast<socklen_t>(sizeof(sockaddr_in)));
                    if (n < 0) [[unlikely]]
                    {
                        if (errno == EINTR)
                        {
                            continue;
                        }
                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                        {
                            // 内核发送缓冲区依然已满，保留暂存报文，等待下一次写就绪事件
                            return sent;
                        }
                        ++sendFailures_;
                        LOG_WARN("Datagram: retry pending sendto to {} failed: {}",
                                 datagramPeerText(pendingPacket_.peer), errnoText(errno));
                        hasPendingPacket_ = false;
                        pendingPacket_ = {};
                        break;
                    }
                    ++sentDatagrams_;
                    ++sent;
                    hasPendingPacket_ = false;
                    pendingPacket_ = {};
                    break;
                }
            }

#if defined(__linux__)
            // 模块二：UDP 批量发送优化 (sendmmsg)
            while (batchIoEnabled_ && handler_->outgoingCount() > 1)
            {
                std::array<Protocol<HandlerDatagram>, kDatagramBatchSize> batchPackets;
                mmsghdr sendMsgs[kDatagramBatchSize]{};
                iovec sendIovs[kDatagramBatchSize]{};
                size_t count = 0;

                while (count < kDatagramBatchSize && handler_->hasOutgoing())
                {
                    batchPackets[count] = handler_->takeOutgoing();
                    sendIovs[count].iov_base = const_cast<char *>(batchPackets[count].bytes.data());
                    sendIovs[count].iov_len = batchPackets[count].bytes.size();
                    sendMsgs[count].msg_hdr.msg_name = &batchPackets[count].peer;
                    sendMsgs[count].msg_hdr.msg_namelen = sizeof(sockaddr_in);
                    sendMsgs[count].msg_hdr.msg_iov = &sendIovs[count];
                    sendMsgs[count].msg_hdr.msg_iovlen = 1;
                    sendMsgs[count].msg_hdr.msg_control = nullptr;
                    sendMsgs[count].msg_hdr.msg_controllen = 0;
                    sendMsgs[count].msg_hdr.msg_flags = 0;
                    ++count;
                }

                if (count == 0)
                {
                    break;
                }

                int ret = ::sendmmsg(fd, sendMsgs, count, MSG_DONTWAIT);
                if (ret > 0)
                {
                    sentDatagrams_ += static_cast<size_t>(ret);
                    sent += static_cast<size_t>(ret);
                    if (static_cast<size_t>(ret) < count)
                    {
                        pendingPacket_ = std::move(batchPackets[static_cast<size_t>(ret)]);
                        hasPendingPacket_ = true;
                        for (size_t i = static_cast<size_t>(ret) + 1; i < count; ++i)
                        {
                            handler_->sendTo(batchPackets[i].peer, std::move(batchPackets[i].bytes));
                        }
                        return sent;
                    }
                }
                else
                {
                    if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                    {
                        pendingPacket_ = std::move(batchPackets[0]);
                        hasPendingPacket_ = true;
                        for (size_t i = 1; i < count; ++i)
                        {
                            handler_->sendTo(batchPackets[i].peer, std::move(batchPackets[i].bytes));
                        }
                        return sent;
                    }
                    if (ret < 0 && errno == EINTR)
                    {
                        for (size_t i = 0; i < count; ++i)
                        {
                            handler_->sendTo(batchPackets[i].peer, std::move(batchPackets[i].bytes));
                        }
                        continue;
                    }
                    ++sendFailures_;
                    LOG_WARN("Datagram: sendmmsg failed: {}", errnoText(errno));
                    break;
                }
            }
#endif

            while (handler_->hasOutgoing())
            {
                Protocol<HandlerDatagram> packet = handler_->takeOutgoing();
                for (;;)
                {
                    ssize_t n = ::sendto(fd, packet.bytes.data(), packet.bytes.size(), 0,
                                         reinterpret_cast<const sockaddr *>(&packet.peer),
                                         static_cast<socklen_t>(sizeof(sockaddr_in)));
                    if (n < 0) [[unlikely]]
                    {
                        if (errno == EINTR)
                        {
                            continue;
                        }
                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                        {
                            // 内核发送缓冲区满：暂存该报文，防止静默丢包，等待下次写事件触发 flushTo
                            pendingPacket_ = std::move(packet);
                            hasPendingPacket_ = true;
                            return sent;
                        }
                        ++sendFailures_;
                        LOG_WARN("Datagram: sendto to {} failed: {}", datagramPeerText(packet.peer), errnoText(errno));
                        break;
                    }
                    ++sentDatagrams_;
                    ++sent;
                    break;
                }
            }
            return sent;
        }

        /**
         * @brief 绕过队列直接向目标地址发送单条报文（同步非阻塞）
         *
         * @param fd UDP 套接字描述符
         * @param peer 目标地址
         * @param data 报文载荷首地址
         * @param n 报文有效字节数
         * @return ssize_t 实际写入字节数，或负数表示系统调用失败
         */
        inline ssize_t sendDirect(int fd, const sockaddr_in &peer, const char *data, size_t n) noexcept
        {
            if (data == nullptr && n > 0)
                return -1;
            for (;;)
            {
                ssize_t ret = ::sendto(fd, data, n, 0, reinterpret_cast<const sockaddr *>(&peer),
                                       static_cast<socklen_t>(sizeof(sockaddr_in)));
                if (ret < 0)
                {
                    if (errno == EINTR)
                        continue;
                    ++sendFailures_;
                    return -1;
                }
                ++sentDatagrams_;
                return ret;
            }
        }

        [[nodiscard]] inline bool hasPending() const noexcept
        {
            return hasPendingPacket_ || (handler_ != nullptr && handler_->hasOutgoing());
        }

        /**
         * @brief 数据报读事件驱动核心：从套接字循环读空所有可用报文并交付处理器
         *
         * @param fd UDP 套接字描述符
         * @return IO 处理决策（保持存活 KEEP）
         */
        [[nodiscard]] inline IO_STATUS handleRead(int fd) noexcept
        {
            if (handler_ == nullptr || fd < 0) [[unlikely]]
            {
                return IO_STATUS::KEEP;
            }
#ifdef MYNET_HAVE_QUIC
            if (quicListener_ != nullptr)
            {
                handleQuic(fd);
                return IO_STATUS::KEEP;
            }
#endif

#if defined(__linux__)
            // 模块二：UDP 批量接收优化 (recvmmsg)
            if (batchIoEnabled_)
            {
                if (!batchRecvBuf_) [[unlikely]]
                {
                    batchRecvBuf_ = std::make_unique<BatchRecvBuffer>();
                }
                const size_t maxPerPacket = std::min(recvCapacity(), size_t(65536));
                for (;;)
                {
                    for (size_t i = 0; i < kDatagramBatchSize; ++i)
                    {
                        batchRecvBuf_->iovs[i].iov_base = batchRecvBuf_->buffers[i];
                        batchRecvBuf_->iovs[i].iov_len = maxPerPacket;
                        batchRecvBuf_->msgs[i].msg_hdr.msg_name = &batchRecvBuf_->addrs[i];
                        batchRecvBuf_->msgs[i].msg_hdr.msg_namelen = sizeof(sockaddr_in);
                        batchRecvBuf_->msgs[i].msg_hdr.msg_iov = &batchRecvBuf_->iovs[i];
                        batchRecvBuf_->msgs[i].msg_hdr.msg_iovlen = 1;
                        batchRecvBuf_->msgs[i].msg_hdr.msg_control = nullptr;
                        batchRecvBuf_->msgs[i].msg_hdr.msg_controllen = 0;
                        batchRecvBuf_->msgs[i].msg_hdr.msg_flags = 0;
                        batchRecvBuf_->msgs[i].msg_len = 0;
                    }

                    int ret = ::recvmmsg(fd, batchRecvBuf_->msgs, kDatagramBatchSize, MSG_DONTWAIT, nullptr);
                    if (ret < 0)
                    {
                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                        {
                            break;
                        }
                        if (errno == EINTR)
                        {
                            continue;
                        }
                        LOG_WARN("Datagram::handleRead: recvmmsg on fd {} failed: {}", fd, errnoText(errno));
                        break;
                    }
                    if (ret == 0)
                    {
                        break;
                    }

                    for (int i = 0; i < ret; ++i)
                    {
                        receiveFrom(batchRecvBuf_->addrs[i], batchRecvBuf_->buffers[i],
                                    static_cast<size_t>(batchRecvBuf_->msgs[i].msg_len));
                    }
                }
                [[maybe_unused]] auto _ = handleWrite(fd);
                return IO_STATUS::KEEP;
            }
#endif

            char *window = recvBuffer();
            const size_t windowBytes = recvCapacity();
            for (;;)
            {
                sockaddr_in peer{};
                socklen_t peerLen = static_cast<socklen_t>(sizeof(sockaddr_in));
                ssize_t n = ::recvfrom(fd, window, windowBytes, 0, reinterpret_cast<sockaddr *>(&peer), &peerLen);
                if (n < 0)
                {
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                    {
                        break;
                    }
                    if (errno == EINTR)
                    {
                        continue;
                    }
                    LOG_WARN("Datagram::handleRead: recvfrom on fd {} failed: {}", fd, errnoText(errno));
                    break;
                }
                receiveFrom(peer, window, static_cast<size_t>(n));
            }
            [[maybe_unused]] auto _ = handleWrite(fd);
            return IO_STATUS::KEEP;
        }

        /**
         * @brief 数据报写事件驱动核心：排空外发回复队列
         *
         * @param fd UDP 套接字描述符
         * @return IO 处理决策（保持存活 KEEP）
         */
        [[nodiscard]] inline IO_STATUS handleWrite(int fd) noexcept
        {
            if (handler_ == nullptr || fd < 0) [[unlikely]]
            {
                return IO_STATUS::KEEP;
            }
#ifdef MYNET_HAVE_QUIC
            if (quicListener_ != nullptr)
            {
                handleQuic(fd);
                return IO_STATUS::KEEP;
            }
#endif
            flushTo(fd);
            return IO_STATUS::KEEP;
        }

#ifdef MYNET_HAVE_QUIC
        inline void handleQuic([[maybe_unused]] int fd) noexcept
        {
            if (quicListener_ == nullptr) [[unlikely]]
            {
                return;
            }

            SSL_handle_events(quicListener_);
            for (auto &qc : quicConns_)
            {
                SSL_handle_events(qc->conn);
            }

            // 接受新建立的 QUIC 连接
            while (SSL *conn = SSL_accept_connection(quicListener_, SSL_ACCEPT_CONNECTION_NO_BLOCK))
            {
                LOG_DEBUG("Datagram: accepted new QUIC connection");
                SSL_set_blocking_mode(conn, 0);
                SSL_set_default_stream_mode(conn, SSL_DEFAULT_STREAM_MODE_NONE);
                SSL_set_incoming_stream_policy(conn, SSL_INCOMING_STREAM_POLICY_ACCEPT, 0);

                auto qc = std::make_unique<QuicConnState>();
                qc->conn = conn;

                // RFC 9114 Section 6.2.1: 打开单向控制流并发送 SETTINGS 首帧
                SSL *ctrl = SSL_new_stream(conn, SSL_STREAM_FLAG_UNI);
                if (ctrl != nullptr)
                {
                    std::string ctrlPayload;
                    http::v3::appendVarint(ctrlPayload, 0x00); // Control stream
                    http::v3::Settings s;
                    std::string setPayload;
                    s.encode(setPayload);
                    http::v3::appendFrame(ctrlPayload, std::to_underlying(http::v3::FRAME_TYPE::SETTINGS), setPayload);
                    size_t written = 0;
                    SSL_write_ex(ctrl, ctrlPayload.data(), ctrlPayload.size(), &written);
                    qc->ctrlStream = ctrl;
                    SSL_handle_events(conn);
                }

                quicConns_.push_back(std::move(qc));
            }

            // 轮询活跃连接中的新流与数据
            for (auto it = quicConns_.begin(); it != quicConns_.end();)
            {
                auto &qc = *it;

                while (SSL *stream = SSL_accept_stream(qc->conn, SSL_ACCEPT_STREAM_NO_BLOCK))
                {
                    const int streamType = SSL_get_stream_type(stream);
                    const uint64_t streamId = SSL_get_stream_id(stream);
                    LOG_DEBUG("Datagram: accepted QUIC stream {} (type={})", streamId, streamType);
                    if (streamType == SSL_STREAM_TYPE_BIDI)
                    {
                        SSL_set_blocking_mode(stream, 0);
                        qc->bidiStreams.emplace(streamId, QuicStreamState{.stream = stream});
                        if constexpr (requires { handler_->onStreamOpen(streamId); })
                        {
                            handler_->onStreamOpen(streamId);
                        }
                    }
                    else
                    {
                        qc->uniStreams.push_back(stream);
                    }
                }

                // 排空客户端单向流（维持连接健康）
                for (SSL *uni : qc->uniStreams)
                {
                    uint8_t discard[512];
                    size_t dlen = 0;
                    while (SSL_read_ex(uni, discard, sizeof(discard), &dlen) > 0)
                    {
                    }
                }

                // 处理双向请求流
                for (auto sIt = qc->bidiStreams.begin(); sIt != qc->bidiStreams.end();)
                {
                    auto &[streamId, st] = *sIt;
                    uint8_t buf[4096];
                    size_t nread = 0;
                    while (SSL_read_ex(st.stream, buf, sizeof(buf), &nread) > 0)
                    {
                        [[maybe_unused]] auto _ = st.inBuf.append(reinterpret_cast<const char *>(buf), nread);
                    }

                    // 零拷贝解码 HTTP/3 帧
                    http::v3::FrameDecoder decoder;
                    while (true)
                    {
                        auto fRes = decoder.nextView(st.inBuf);
                        if (!fRes || !fRes->has_value())
                        {
                            break;
                        }
                        auto &frame = **fRes;
                        if (frame.type == std::to_underlying(http::v3::FRAME_TYPE::HEADERS))
                        {
                            if constexpr (requires { handler_->onStreamHeaders(streamId, frame.payload); })
                            {
                                handler_->onStreamHeaders(streamId, frame.payload);
                            }
                            auto hRes = http::v3::decodeHeaders(frame.payload);
                            if (hRes)
                            {
                                st.headers = std::move(*hRes);
                                if constexpr (requires { handler_->onStreamHeadersDecoded(streamId, st.headers); })
                                {
                                    handler_->onStreamHeadersDecoded(streamId, st.headers);
                                }
                            }
                        }
                        else if (frame.type == std::to_underlying(http::v3::FRAME_TYPE::DATA))
                        {
                            if constexpr (requires { handler_->onStreamData(streamId, frame.payload); })
                            {
                                handler_->onStreamData(streamId, frame.payload);
                            }
                            st.body.append(frame.payload);
                        }
                    }

                    const int rstate = SSL_get_stream_read_state(st.stream);
                    if (!st.responseSent && (rstate == SSL_STREAM_STATE_FINISHED || !st.headers.empty()))
                    {
                        if constexpr (requires { handler_->onStreamEnd(streamId); })
                        {
                            handler_->onStreamEnd(streamId);
                        }
                        std::string responseBody;
                        if constexpr (requires { handler_->onRequest(streamId, st.headers, st.body, responseBody); })
                        {
                            handler_->onRequest(streamId, st.headers, st.body, responseBody);
                        }
                        else
                        {
                            responseBody = "HTTP/3 200 OK\n";
                        }

                        std::vector<http::v3::Header> respHeaders;
                        respHeaders.reserve(4);
                        respHeaders.push_back({":status", "200"});
                        respHeaders.push_back({"server", "mynet-http3"});
                        respHeaders.push_back({"content-type", "text/plain; charset=utf-8"});

                        std::string hdrPayload;
                        http::v3::encodeHeaders(hdrPayload, respHeaders);

                        std::string respFrames;
                        http::v3::appendFrame(respFrames, std::to_underlying(http::v3::FRAME_TYPE::HEADERS), hdrPayload);
                        if (!responseBody.empty())
                        {
                            http::v3::appendFrame(respFrames, std::to_underlying(http::v3::FRAME_TYPE::DATA), responseBody);
                        }

                        size_t written = 0;
                        SSL_write_ex(st.stream, respFrames.data(), respFrames.size(), &written);
                        SSL_stream_conclude(st.stream, 0);
                        SSL_handle_events(qc->conn);
                        st.responseSent = true;
                    }

                    const int wstate = SSL_get_stream_write_state(st.stream);
                    if (st.responseSent &&
                        (wstate == SSL_STREAM_STATE_FINISHED || rstate == SSL_STREAM_STATE_FINISHED))
                    {
                        if constexpr (requires { handler_->onStreamClose(streamId); })
                        {
                            handler_->onStreamClose(streamId);
                        }
                        SSL_free(st.stream);
                        sIt = qc->bidiStreams.erase(sIt);
                    }
                    else
                    {
                        ++sIt;
                    }
                }

                // 连接关闭回收
                if ((SSL_get_shutdown(qc->conn) & SSL_RECEIVED_SHUTDOWN) != 0)
                {
                    for (auto &[id, st] : qc->bidiStreams)
                    {
                        SSL_free(st.stream);
                    }
                    for (SSL *uni : qc->uniStreams)
                    {
                        SSL_free(uni);
                    }
                    if (qc->ctrlStream != nullptr)
                    {
                        SSL_free(qc->ctrlStream);
                    }
                    SSL_free(qc->conn);
                    it = quicConns_.erase(it);
                }
                else
                {
                    ++it;
                }
            }
        }
#endif

        /**
         * @brief 收发计数（只读）
         *
         * 定位是**单元测试与调试观测**，不是生产指标：引擎的 runUdp 在返回前
         * 会 reset() 清零，且引擎未暴露本会话对象，因此进程内无法在服务运行
         * 期间读到这些值。要变成真正的运维指标，需要引擎提供访问器并在 reset
         * 之前快照——那属于尚未实现的能力，不要据此假设它们可用。
         */

        [[nodiscard]] inline uint64_t receivedDatagrams() const noexcept { return receivedDatagrams_; }
        [[nodiscard]] inline uint64_t receivedBytes() const noexcept { return receivedBytes_; }
        [[nodiscard]] inline uint64_t truncatedDatagrams() const noexcept { return truncatedDatagrams_; }
        [[nodiscard]] inline uint64_t sentDatagrams() const noexcept { return sentDatagrams_; }
        [[nodiscard]] inline uint64_t sendFailures() const noexcept { return sendFailures_; }

    private:
        Handler *handler_ = nullptr;
        std::vector<char> recvWindow_{};
        Protocol<HandlerDatagram> pendingPacket_{};
        bool hasPendingPacket_ = false;
        bool batchIoEnabled_ = true;
        uint64_t receivedDatagrams_ = 0;
        uint64_t receivedBytes_ = 0;
        uint64_t truncatedDatagrams_ = 0;
        uint64_t sentDatagrams_ = 0;
        uint64_t sendFailures_ = 0;

#if defined(__linux__)
        static constexpr size_t kDatagramBatchSize = 32;

        struct BatchRecvBuffer
        {
            mmsghdr msgs[kDatagramBatchSize]{};
            iovec iovs[kDatagramBatchSize]{};
            sockaddr_in addrs[kDatagramBatchSize]{};
            alignas(64) char buffers[kDatagramBatchSize][65536]{};
        };

        std::unique_ptr<BatchRecvBuffer> batchRecvBuf_{};
#endif
#ifdef MYNET_HAVE_QUIC
        SSL *quicListener_ = nullptr;
        std::vector<std::unique_ptr<QuicConnState>> quicConns_{};
#endif
    };

    /**
     * @brief 非数据报处理器使用的占位会话对象
     *
     * 纯流式处理器不需要 UDP 会话，但引擎的成员声明（以及同时支持两种传输的
     * 处理器，如 HandlerHttp3）必须在类作用域里写一个具体类型。本类型提供与
     * Datagram 同形的空壳接口：bound() 恒为 false，收发接口为无操作，因此引擎
     * 里那些同时服务两条路径的函数即使对纯流式处理器实例化也能编译。
     */
    struct NoDatagram
    {
        void reset() noexcept {}
        [[nodiscard]] bool bound() const noexcept { return false; }
        [[nodiscard]] bool isQuic() const noexcept { return false; }
        [[nodiscard]] Result<> startTLS(SSL_CTX *, int) noexcept { return {}; }
        void tick(int) noexcept {}
        [[nodiscard]] size_t maxDatagramBytes() const noexcept { return 0; }
        [[nodiscard]] char *recvBuffer() noexcept { return nullptr; }
        [[nodiscard]] size_t recvCapacity() const noexcept { return 0; }
        void receiveFrom(const sockaddr_in &, const char *, size_t) noexcept {}
        size_t flushTo(int) noexcept { return 0; }
        [[nodiscard]] bool hasPending() const noexcept { return false; }
        ssize_t sendDirect(int, const sockaddr_in &, const char *, size_t) noexcept { return 0; }
        [[nodiscard]] IO_STATUS handleRead(int) noexcept { return IO_STATUS::KEEP; }
        [[nodiscard]] IO_STATUS handleWrite(int) noexcept { return IO_STATUS::KEEP; }
    };

    /**
     * @brief 数据报会话槽位的编译期选择器
     *
     * 与 ConnectionSlot 同构：满足 MandatoryMethodDatagram 的处理器映射到
     * Datagram<H>，否则映射到 NoDatagram。用偏特化而非 std::conditional_t，
     * 因为 Datagram<H> 是受约束模板，违约束的 template-id 出现在类作用域里
     * 就是硬错误，而偏特化在约束不满足时直接退回主模板。
     */
    template <typename H>
    struct DatagramSlot
    {
        using Type = NoDatagram;
    };

    template <MandatoryMethodDatagram H>
    struct DatagramSlot<H>
    {
        using Type = Datagram<H>;
    };

} // namespace mynet
