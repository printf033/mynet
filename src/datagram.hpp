#pragma once

#include "configHolder.hpp"
#include "constraints.hpp"
#include "error.hpp"
#include "log_config.hpp"
#include <arpa/inet.h>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <limits>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <utility>
#include <vector>

namespace mynet
{

    /**
     * @brief UDP 数据报报文上下文元信息封装（涵盖回复、转发、广播与主动发包）
     *
     * 关联目标对端地址元数据与待发送二进制报文载荷。
     */
    struct DatagramPacket
    {
        sockaddr_in peer{};
        std::string bytes{};
    };

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
        }

        virtual ~HandlerDatagram() noexcept = default;

        HandlerDatagram(const HandlerDatagram &) = delete ("a datagram handler owns the outgoing queue for one socket");
        HandlerDatagram &
        operator=(const HandlerDatagram &) = delete ("a datagram handler owns the outgoing queue for one socket");
        HandlerDatagram(HandlerDatagram &&) = delete ("a datagram handler owns the outgoing queue for one socket");
        HandlerDatagram &
        operator=(HandlerDatagram &&) = delete ("a datagram handler owns the outgoing queue for one socket");

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
            outgoing_.clear();
            droppedOutgoing_ = 0;
            maxDatagramBytes_ = getDatagramConfig().maxDatagramBytes;
            maxPendingOutgoing_ = getDatagramConfig().maxPendingOutgoing;
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
            if (outgoing_.size() >= maxPendingOutgoing_) [[unlikely]]
            {
                ++droppedOutgoing_;
                LOG_WARN("HandlerDatagram: outgoing queue full ({} pending), dropping a {} byte packet for {}",
                         outgoing_.size(), n, datagramPeerText(target));
                return;
            }
            outgoing_.push_back(DatagramPacket{target, (n > 0) ? std::string(buf, n) : std::string()});
        }

        /**
         * @brief 向指定目标地址发送数据报（移动语义载荷）
         */
        inline void sendTo(const sockaddr_in &target, std::string bytes)
        {
            if (outgoing_.size() >= maxPendingOutgoing_) [[unlikely]]
            {
                ++droppedOutgoing_;
                LOG_WARN("HandlerDatagram: outgoing queue full ({} pending), dropping a {} byte packet for {}",
                         outgoing_.size(), bytes.size(), datagramPeerText(target));
                return;
            }
            outgoing_.push_back(DatagramPacket{target, std::move(bytes)});
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
        [[nodiscard]] inline const DatagramPacket &peekOutgoing() const noexcept { return outgoing_.front(); }

        [[nodiscard]] inline DatagramPacket takeOutgoing()
        {
            if (outgoing_.empty()) [[unlikely]]
            {
                return {};
            }
            DatagramPacket out = std::move(outgoing_.front());
            outgoing_.pop_front();
            return out;
        }

        [[nodiscard]] inline size_t droppedOutgoing() const noexcept { return droppedOutgoing_; }

        inline void setMaxDatagramBytes(size_t n) noexcept { maxDatagramBytes_ = n; }
        [[nodiscard]] inline size_t maxDatagramBytes() const noexcept { return maxDatagramBytes_; }

        inline void setMaxPendingOutgoing(size_t n) noexcept
        {
            contract_assert(n > 0);
            maxPendingOutgoing_ = n;
        }
        [[nodiscard]] inline size_t maxPendingOutgoing() const noexcept { return maxPendingOutgoing_; }

    protected:
        size_t maxDatagramBytes_ = getDatagramConfig().maxDatagramBytes;
        size_t maxPendingOutgoing_ = getDatagramConfig().maxPendingOutgoing;
        size_t droppedOutgoing_ = 0;
        std::deque<DatagramPacket> outgoing_{};
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
                                          { d.peekOutgoing() } noexcept -> std::same_as<const DatagramPacket &>;
                                          { d.takeOutgoing() } -> std::same_as<DatagramPacket>;
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

        Datagram() noexcept = default;
        ~Datagram() noexcept = default;

        Datagram(const Datagram &) =
            delete ("a datagram binding owns a handler reference and the receive window of one socket");
        Datagram &operator=(const Datagram &) =
            delete ("a datagram binding owns a handler reference and the receive window of one socket");
        Datagram(Datagram &&) =
            delete ("a datagram binding owns a handler reference and the receive window of one socket");
        Datagram &operator=(Datagram &&) =
            delete ("a datagram binding owns a handler reference and the receive window of one socket");

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
         * @brief 解除绑定、释放接收窗口并清零收发计数
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
        }

        [[nodiscard]] inline bool bound() const noexcept { return handler_ != nullptr; }

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

            while (handler_->hasOutgoing())
            {
                DatagramPacket packet = handler_->takeOutgoing();
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
            flushTo(fd);
            return IO_STATUS::KEEP;
        }

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
        DatagramPacket pendingPacket_{};
        bool hasPendingPacket_ = false;
        uint64_t receivedDatagrams_ = 0;
        uint64_t receivedBytes_ = 0;
        uint64_t truncatedDatagrams_ = 0;
        uint64_t sentDatagrams_ = 0;
        uint64_t sendFailures_ = 0;
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
