#pragma once

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "buffer.hpp"
#include "constraints.hpp"
#include "configHolder.hpp"
#include "error.hpp"
#include "log_config.hpp"
#include "ringQueue.hpp"
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <expected>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <optional>
#include <string>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

namespace mynet
{

    /**
     * @brief 偏连接的流式协议处理器基类
     *
     * 本类是流式传输层次的根：不继承任何处理器基类，独立提供流式会话所需的全部
     * 传输状态：
     * - 请求解析缓冲区与零拷贝直写入口（prepareRequestWritable / commitRequest）；
     * - 响应队列（FIFO，可流水线化）与空闲缓冲复用（recycleSpare）；
     * - 读信用背压（readCredit / requestOverLimit）与单请求上限；
     * - 连接关闭语义（closeAfterResponse）与 splice 零拷贝环回开关；
     * - 与传输无关的生命周期钩子（reset / onMessageComplete / onParseError）。
     *
     * 协议处理器（HTTP/1.x、HTTP/2、Echo 等）继承本类并叠加自己的解析状态机；
     * 双传输处理器（如 HTTP/3）另行同时继承 HandlerDatagram。两者是并列的独立
     * 基类：成员访问是编译期确定的直接偏移，既不经过虚基类间接寻址，也不需要
     * 为共享子对象付出构造/销毁与去重记账。
     */
    class HandlerConnection
    {
    public:
        /// 是否允许该处理器使用 Linux splice(2) 内核零拷贝环回（派生类按协议特性开启）
        static constexpr bool kEnableSplice = false;

        /**
         * @brief 构造时一次性定容响应队列
         *
         * 默认 64 槽对齐流水线深度：开箱即可用，后续连接层可在建连时调用
         * reserveResponses() 按协议需求重新定容（init 幂等）。
         */
        explicit HandlerConnection(size_t responseCapacity = 64) noexcept
        {
            [[maybe_unused]] auto _ =
                responseQueue_.init(responseCapacity); // 槽位分配失败降级为容量 0 拒收，不折损零异常构造
        }

        virtual ~HandlerConnection() noexcept = default;

        HandlerConnection(const HandlerConnection &) =
            delete("a connection handler holds parser state bound to one connection");
        HandlerConnection &
        operator=(const HandlerConnection &) =
            delete("a connection handler holds parser state bound to one connection");
        HandlerConnection(HandlerConnection &&) =
            delete("a connection handler holds parser state bound to one connection");
        HandlerConnection &
        operator=(HandlerConnection &&) =
            delete("a connection handler holds parser state bound to one connection");

        /**
         * @brief 重置处理器状态（派生类重置专属解析器后应调用本实现）
         */
        virtual void reset() noexcept
        {
            requestBuffer_.reset();
            responseQueue_.clear();
            spare_.clear();
            closeAfterResponse_ = false;
            spliceEnabled_ = false;
        }

        // ---- 读取侧控制 (Read Side) ----

        /**
         * @brief 追加一段对端请求字节到解析缓冲（零异常，失败显式错误码）
         *
         * Buffer::append() 为 nothrow 接口：堆扩容失败以 ERR::BUF_ALLOC_FAILED
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
         * @brief 确保请求解析缓冲区至少拥有 minBytes 的可直写连续空间（零拷贝直接读取）
         *
         * @param minBytes 期望的最小写窗口字节数（默认 4096）
         * @return 成功返回可直写的内存首地址指针；扩容失败返回错误码
         */
        [[nodiscard]] inline std::expected<char *, ERR> prepareRequestWritable(size_t minBytes = 4 << 10) noexcept
        {
            if (auto res = requestBuffer_.ensureWritable(minBytes); !res) [[unlikely]]
            {
                return std::unexpected(res.error());
            }
            return requestBuffer_.writableBegin();
        }

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

        inline void requestClear() noexcept { requestBuffer_.retrieveAll(); }

        /**
         * @brief 剩余信用窗口（为 0 时事件循环将暂停接收读取，实施背压保护）
         */
        [[nodiscard]] inline size_t readCredit() const noexcept
        {
            const size_t used = requestBuffer_.readableBytes();
            return used >= maxRequestBytes_ ? 0 : maxRequestBytes_ - used;
        }

        inline void setMaxRequestBytes(size_t n) noexcept { maxRequestBytes_ = n; }

        // ---- 发送响应侧控制 (Write Side) ----

        [[nodiscard]] inline bool hasResponse() const noexcept { return !responseQueue_.empty(); }

        [[nodiscard]] inline size_t responseCount() const noexcept { return responseQueue_.size(); }

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

        [[nodiscard]] inline bool spliceEnabled() const noexcept { return spliceEnabled_; }

        inline void setSpliceEnabled(bool v) noexcept { spliceEnabled_ = v; }

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
        virtual void onParseError([[maybe_unused]] const char *reason) noexcept {}

        /**
         * @brief 默认执行逻辑：标准 Echo 协议回显
         */
        void process()
        {
            if (requestBuffer_.empty()) [[unlikely]]
            {
                return;
            }
            if (!pushResponse(requestBuffer_.readableView())) [[unlikely]]
            {
                LOG_WARN("HandlerConnection::process: response queue full, echoing dropped");
            }
            requestBuffer_.retrieveAll();
        }

    protected:
        Buffer requestBuffer_;
        RingQueue responseQueue_;
        std::string spare_{};
        size_t maxRequestBytes_ = 4 << 20;
        bool closeAfterResponse_ = false;
        bool spliceEnabled_ = false;
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
     * 名字直指含义：这是 Connection<H> 在热路径上真正会调用的方法清单，
     * 缺一不可。两层保证：
     * 1. 派生约束：必须继承 HandlerConnection，从而持有真实的请求/响应/背压状态；
     * 2. 方法约束：逐个校验签名与 noexcept，防止派生类用 = delete 或改签名
     *    让某个调用点失效。
     *
     * 仅靠方法约束会让一个手写同名成员但未继承 HandlerConnection 的类型通过，
     * 而 Connection<H> 仍能在其上编译——这类处理器没有共享的基类状态，
     * 语义上不可信，因此本概念显式要求派生关系。
     */
    template <typename H>
    concept MandatoryMethodConnection =
        DerivedFromHandlerConnection<H> && Resettable<H> &&
        requires(H &h, const char *buf, ssize_t rn, size_t n) {
            // 零异常纪律：摄入路径 noexcept，扩容失败经错误码交付
            { h.appendRequest(buf, rn) } noexcept -> std::same_as<Result<>>;
            { h.hasResponse() } noexcept -> std::same_as<bool>;
            { h.takeResponse() } -> std::same_as<std::string>;
            { h.requestOverLimit() } noexcept -> std::same_as<bool>;
            h.process();
            // 下面这些同样被连接层直接调用，无 requires 保护，必须由概念兜底：
            // 零拷贝直写窗口、读信用背压、请求上限与关闭/错误钩子
            { h.prepareRequestWritable(n) } noexcept;
            { h.requestWritableBytes() } noexcept -> std::same_as<size_t>;
            { h.commitRequest(n) } noexcept;
            { h.readCredit() } noexcept -> std::same_as<size_t>;
            { h.setMaxRequestBytes(n) } noexcept;
            { h.onParseError(buf) } noexcept;
            { h.closeAfterResponse() } noexcept -> std::same_as<bool>;
            // Connection::isSpliceEnabled() 在 kEnableSplice 为 true 时直接调用本方法，
            // 故它同样属于「热路径真正会调用的清单」。
            { h.spliceEnabled() } noexcept -> std::same_as<bool>;
        };

    /**
     * @brief I/O 处理后套接字保留决策
     */
    enum class IO_STATUS : uint8_t
    {
        KEEP = 0, ///< 保持存活：继续等待下一轮就绪通知或完成通知
        CLOSE = 1 ///< 关闭断开：立即进入下线回收流程
    };

    /**
     * @brief TLS 握手演进状态枚举
     */
    enum class HANDSHAKE_STATUS : uint8_t
    {
        DONE = 0,        ///< 握手圆满完成，加密通道正式开启
        IN_PROGRESS = 1, ///< 握手进行中，需等待更多握手记录交互
        FAILED = 2       ///< 握手失败（对端或本地拒绝）
    };

    /**
     * @brief 活跃网络连接核心数据与传输聚合体
     *
     * 架构核心支柱：
     * 1. 传输无关性：明文 TCP 与加密 TLS 共享完全一致的 recv/send 数据管道；
     * 2. 安全生命周期：协议处理器、接收缓冲与发送队列作为值语义聚合于本对象内，彻底防止部分发送的响应跨对象越界；
     * 3. 流水线队列：writeQueue_ 以独立 std::string 按值持有各条响应，HTTP/1.1 Pipelining
     * 在单次读取产生多个响应时零冲突；
     * 4. 完备的背压挂钩：结合 writeHighWaterMark_ 与 readPaused_ 防止内存无界暴涨。
     */
    template <typename HandlerType>
        requires MandatoryMethodConnection<HandlerType>
    class Connection
    {
    public:
        using Handler = HandlerType;

        enum class CONN_STATE : uint8_t
        {
            HANDSHAKE = 0,
            OPEN = 1,
            CLOSING = 2,
            CLOSED = 3
        };

        Connection() noexcept = default;
        ~Connection() noexcept { reset(); }

        Connection(const Connection &) =
            delete ("a connection owns a socket, its TLS state and its handler; there is nothing to share");
        Connection &operator=(const Connection &) =
            delete ("a connection owns a socket, its TLS state and its handler; there is nothing to share");
        Connection(Connection &&) noexcept =
            delete ("a connection owns a socket, its TLS state and its handler; it stays put in its session");
        Connection &operator=(Connection &&) noexcept =
            delete ("a connection owns a socket, its TLS state and its handler; it stays put in its session");

        inline void reset() noexcept
        {
            if (ssl_ != nullptr)
            {
                SSL_free(ssl_);
                ssl_ = nullptr;
            }
#ifdef MYNET_HAVE_KTLS
            ktlsRx_ = false;
#endif
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
            addr_ = {};
            handshakeDone_ = false;
            writeQueue_.clear();
            writeOffset_ = 0;
            pendingBytes_ = 0;
            state_ = CONN_STATE::OPEN;
            readPaused_ = false;
            wantWrite_ = false;
            closeAfterWrite_ = false;
            peerGone_ = false;
            shutdownSent_ = false;
            timerId_ = 0;
            lastActive_ = std::chrono::steady_clock::time_point{};
            events_ = 0;
            writeHighWaterMark_ = getNetConfig().server.writeHighWaterMark;
            handler_.reset();
            handler_.setMaxRequestBytes(getNetConfig().server.maxRequestBytes);
        }

        [[nodiscard]] inline int fd() const noexcept { return fd_; }
        inline void setFd(int fd) noexcept
        {
            fd_ = fd;
            if (fd_ >= 0)
            {
                if (getNetConfig().server.tcpNoDelay)
                {
                    constexpr int one = 1;
                    [[maybe_unused]] auto _ = ::setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
                }
                writeHighWaterMark_ = getNetConfig().server.writeHighWaterMark;
                handler_.setMaxRequestBytes(getNetConfig().server.maxRequestBytes);
            }
        }
        [[nodiscard]] inline const sockaddr_in &addr() const noexcept { return addr_; }
        [[nodiscard]] inline sockaddr_in &addr() noexcept { return addr_; }
        [[nodiscard]] inline HandlerType &handler() noexcept { return handler_; }
        [[nodiscard]] inline const HandlerType &handler() const noexcept { return handler_; }
        [[nodiscard]] inline SSL *ssl() const noexcept { return ssl_; }
        [[nodiscard]] inline CONN_STATE state() const noexcept { return state_; }
        [[nodiscard]] inline uint32_t events() const noexcept { return events_; }
        inline void setEvents(uint32_t events) noexcept { events_ = events; }

        [[nodiscard]] inline bool isSpliceEnabled() const noexcept
        {
            if (ssl_ != nullptr || !getNetConfig().server.enableSplice)
            {
                return false;
            }
            if constexpr (requires {
                              { HandlerType::kEnableSplice } -> std::convertible_to<bool>;
                          })
            {
                if constexpr (HandlerType::kEnableSplice)
                {
                    return handler_.spliceEnabled();
                }
            }
            return false;
        }

        [[nodiscard]] inline bool wantRead() const noexcept
        {
            return !readPaused_ && !peerGone_ && state_ != CONN_STATE::CLOSED;
        }

        [[nodiscard]] inline bool wantWrite() const noexcept
        {
            return pendingBytes_ > 0 || pipePending_ > 0 || wantWrite_ || closeAfterWrite_ ||
                   state_ == CONN_STATE::HANDSHAKE || handler_.hasResponse();
        }

        [[nodiscard]] inline bool writeBlocked() const noexcept
        {
            return pendingBytes_ > 0 || pipePending_ > 0 || wantWrite_ || closeAfterWrite_ || handler_.hasResponse();
        }

        [[nodiscard]] inline bool hasPendingWrite() const noexcept
        {
            return pendingBytes_ > 0 || pipePending_ > 0 || handler_.hasResponse();
        }

        [[nodiscard]] inline size_t pendingBytes() const noexcept { return pendingBytes_ + pipePending_; }
        [[nodiscard]] inline size_t pipePending() const noexcept { return pipePending_; }
        [[nodiscard]] inline size_t writeHighWaterMark() const noexcept { return writeHighWaterMark_; }
        inline void setWriteHighWaterMark(size_t n) noexcept { writeHighWaterMark_ = n; }
        [[nodiscard]] inline bool closeAfterWrite() const noexcept { return closeAfterWrite_; }
        inline void setCloseAfterWrite(bool v) noexcept { closeAfterWrite_ = v; }
        [[nodiscard]] inline uint64_t timerId() const noexcept { return timerId_; }
        inline void setTimerId(uint64_t id) noexcept { timerId_ = id; }
        [[nodiscard]] inline std::chrono::steady_clock::time_point lastActive() const noexcept { return lastActive_; }
        inline void touch() noexcept { lastActive_ = std::chrono::steady_clock::now(); }

        // ---- TLS 握手管理 ----

        [[nodiscard]] inline Result<> startTLS(SSL_CTX *ctx) noexcept
        {
            if (ctx == nullptr) [[unlikely]]
            {
                LOG_ERROR("Connection::startTLS: no SSL_CTX (fd {})", fd_);
                return std::unexpected(ERR::SSL_CTX_FAILED);
            }
            ssl_ = SSL_new(ctx);
            if (ssl_ == nullptr) [[unlikely]]
            {
                LOG_ERROR("Connection::startTLS: SSL_new() failed on fd {}: {}", fd_, sslText());
                return std::unexpected(ERR::SSL_NEW_FAILED);
            }
#ifdef MYNET_HAVE_KTLS
            ktlsRx_ = false;
            // 请求内核 TLS RX offload；仅当握手后 BIO_get_ktls_recv 确认生效时才走快路径
            SSL_set_options(ssl_, SSL_OP_ENABLE_KTLS);
#endif
            if (SSL_set_fd(ssl_, fd_) != 1) [[unlikely]]
            {
                LOG_ERROR("Connection::startTLS: SSL_set_fd({}) failed: {}", fd_, sslText());
                SSL_free(ssl_);
                ssl_ = nullptr;
                return std::unexpected(ERR::SSL_SET_FD_FAILED);
            }
            SSL_set_accept_state(ssl_);
            handshakeDone_ = false;
            state_ = CONN_STATE::HANDSHAKE;
            return {};
        }

        [[nodiscard]] inline HANDSHAKE_STATUS doHandshake() noexcept
        {
            if (ssl_ == nullptr || handshakeDone_) [[likely]]
            {
                return HANDSHAKE_STATUS::DONE;
            }
            const int r = SSL_accept(ssl_);
            if (r == 1)
            {
                handshakeDone_ = true;
#ifdef MYNET_HAVE_KTLS
                // 内核完成 RX offload 时读 BIO 已切换为 kTLS：后续 recv() 直接返回明文，
                // Proactor 可安全复用 multishot + buffer ring 快路径；未生效则保持慢路径
                ktlsRx_ = BIO_get_ktls_recv(SSL_get_rbio(ssl_)) > 0;
                if (ktlsRx_) [[unlikely]]
                {
                    LOG_INFO("Connection::doHandshake: fd {}: kTLS RX offload active", fd_);
                }
#endif
                return HANDSHAKE_STATUS::DONE;
            }
            switch (SSL_get_error(ssl_, r))
            {
            case SSL_ERROR_WANT_READ:
                wantWrite_ = false;
                return HANDSHAKE_STATUS::IN_PROGRESS;
            case SSL_ERROR_WANT_WRITE:
                wantWrite_ = true;
                return HANDSHAKE_STATUS::IN_PROGRESS;
            default:
                LOG_WARN("Connection::doHandshake: fd {}: {}", fd_, sslText());
                return HANDSHAKE_STATUS::FAILED;
            }
        }

        /// kTLS RX offload 是否已生效（握手后由内核确认）；仅诊断与 Proactor 路径选择使用。
        /// 构建探测未命中时恒返回 false，调用方无需条件编译，慢路径零回归。
        [[nodiscard]] inline bool ktlsRxActive() const noexcept
        {
#ifdef MYNET_HAVE_KTLS
            return ktlsRx_;
#else
            return false;
#endif
        }

        [[nodiscard]] inline const unsigned char *alpnSelected(unsigned int *len) const noexcept
        {
            const unsigned char *p = nullptr;
            if (ssl_ == nullptr) [[unlikely]]
            {
                *len = 0;
                return nullptr;
            }
            SSL_get0_alpn_selected(ssl_, &p, len);
            return p;
        }

        // ---- 读取主流程 (Read Path) ----

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

        [[nodiscard]] IO_STATUS handleSplice() noexcept
        {
            constexpr size_t kSpliceChunk = 64 << 10;

            // 1. 如果此前管道中尚有未排空的残留数据（对端 TCP 接收窗口满），先尝试刷出
            while (pipePending_ > 0)
            {
                const ssize_t sOut =
                    ::splice(pipeFd_[0], nullptr, fd_, nullptr, pipePending_, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
                if (sOut > 0) [[likely]]
                {
                    pipePending_ -= static_cast<size_t>(sOut);
                    touch();
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
                    {
                        continue;
                    }
                    if (errno == ECONNRESET || errno == EPIPE)
                    {
                        peerGone_ = true;
                        return IO_STATUS::CLOSE;
                    }
                    LOG_WARN("Connection::handleSplice: fd {}: splice pipe->socket failed: {}", fd_,
                             errnoText(errno));
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

            // 2. 管道已空，持续从对端 socket 读取数据移入管道，并直接环回写出（内核零拷贝）
            while (!readPaused_)
            {
                const ssize_t sIn =
                    ::splice(fd_, nullptr, pipeFd_[1], nullptr, kSpliceChunk, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
                if (sIn > 0) [[likely]]
                {
                    touch();
                    pipePending_ += static_cast<size_t>(sIn);

                    // 立即将摄入管道的数据原样零拷贝回显写入对端 socket
                    while (pipePending_ > 0)
                    {
                        const ssize_t sOut = ::splice(pipeFd_[0], nullptr, fd_, nullptr, pipePending_,
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
                            {
                                continue;
                            }
                            if (errno == ECONNRESET || errno == EPIPE)
                            {
                                peerGone_ = true;
                                return IO_STATUS::CLOSE;
                            }
                            LOG_WARN("Connection::handleSplice: fd {}: splice pipe->socket failed: {}", fd_,
                                     errnoText(errno));
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
                    continue;
                }
                if (sIn == 0)
                {
                    // 对端关闭写入端（EOF）
                    peerGone_ = true;
                    closeAfterWrite_ = true;
                    if (pipePending_ > 0)
                    {
                        wantWrite_ = true;
                        return IO_STATUS::KEEP;
                    }
                    return finishClose() ? IO_STATUS::CLOSE : IO_STATUS::KEEP;
                }
                // sIn < 0
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    break;
                }
                if (errno == EINTR)
                {
                    continue;
                }
                if (errno == ECONNRESET || errno == EPIPE)
                {
                    peerGone_ = true;
                    return IO_STATUS::CLOSE;
                }
                LOG_WARN("Connection::handleSplice: fd {}: splice socket->pipe failed: {}", fd_, errnoText(errno));
                peerGone_ = true;
                return IO_STATUS::CLOSE;
            }

            if (peerGone_ && pipePending_ == 0 && pendingBytes_ == 0)
            {
                return finishClose() ? IO_STATUS::CLOSE : IO_STATUS::KEEP;
            }
            return IO_STATUS::KEEP;
        }

        [[nodiscard]] IO_STATUS handleRead()
        {
            if (state_ == CONN_STATE::HANDSHAKE)
            {
                const HANDSHAKE_STATUS h = doHandshake();
                if (h == HANDSHAKE_STATUS::FAILED)
                {
                    return IO_STATUS::CLOSE;
                }
                if (h == HANDSHAKE_STATUS::IN_PROGRESS)
                {
                    return IO_STATUS::KEEP;
                }
                state_ = CONN_STATE::OPEN;
            }

            if (isSpliceEnabled())
            {
                if (ensurePipe())
                {
                    return handleSplice();
                }
            }

            while (!readPaused_)
            {
                const size_t credit = handler_.readCredit();
                if (credit == 0) [[unlikely]]
                {
                    readPaused_ = true;
                    break;
                }

                // 零拷贝直写：直接向 handler_ 的请求缓冲区发起底层接收，彻底消除栈临时缓冲与中间 memcpy
                const size_t want = std::min(size_t{4 << 10}, credit);
                auto prepRes = handler_.prepareRequestWritable(want);
                if (!prepRes) [[unlikely]]
                {
                    LOG_ERROR("Connection: prepareRequestWritable failed (allocation), fd {} closing", fd_);
                    peerGone_ = true;
                    return IO_STATUS::CLOSE;
                }

                char *target = *prepRes;
                const size_t maxLen = std::min(handler_.requestWritableBytes(), credit);

                std::expected<size_t, IO_END> rn = doRecv(target, maxLen);
                if (!rn)
                {
                    if (rn.error() == IO_END::INTERRUPTED)
                    {
                        continue;
                    }
                    if (rn.error() == IO_END::EOF_REACHED)
                    {
                        peerGone_ = true;
                        closeAfterWrite_ = true;
                        if (pendingBytes_ > 0)
                        {
                            return IO_STATUS::KEEP;
                        }
                        return finishClose() ? IO_STATUS::CLOSE : IO_STATUS::KEEP;
                    }
                    if (rn.error() == IO_END::FATAL)
                    {
                        peerGone_ = true;
                        return IO_STATUS::CLOSE;
                    }
                    break;
                }

                handler_.commitRequest(*rn);
                touch();
                if (handler_.requestOverLimit()) [[unlikely]]
                {
                    handler_.onParseError("request exceeds the read limit");
                    collectResponses();
                    closeAfterWrite_ = true;
                    readPaused_ = true;
                    return IO_STATUS::KEEP;
                }
                handler_.process();
                collectResponses();
                if (closeAfterWrite_)
                {
                    break;
                }
            }

            collectResponses();
            if (handler_.closeAfterResponse())
            {
                closeAfterWrite_ = true;
            }
            if (pendingBytes_ > writeHighWaterMark_)
            {
                readPaused_ = true;
            }
            if (peerGone_ && pendingBytes_ == 0)
            {
                return finishClose() ? IO_STATUS::CLOSE : IO_STATUS::KEEP;
            }
            return IO_STATUS::KEEP;
        }

        [[nodiscard]] inline bool finishClose() noexcept
        {
            if (ssl_ != nullptr && !shutdownSent_)
            {
                const int e = SSL_shutdown(ssl_);
                if (e < 0 && SSL_get_error(ssl_, e) == SSL_ERROR_WANT_WRITE)
                {
                    return false;
                }
                shutdownSent_ = true;
            }
            return true;
        }

        // ---- 发送主流程 (Write Path) ----

        [[nodiscard]] IO_STATUS handleWrite()
        {
            if (state_ == CONN_STATE::HANDSHAKE)
            {
                const HANDSHAKE_STATUS h = doHandshake();
                if (h == HANDSHAKE_STATUS::FAILED)
                {
                    return IO_STATUS::CLOSE;
                }
                if (h == HANDSHAKE_STATUS::IN_PROGRESS)
                {
                    return IO_STATUS::KEEP;
                }
                state_ = CONN_STATE::OPEN;
            }

            // 若存在内核 splice 管道残留数据，先冲刷管道
            if (pipePending_ > 0)
            {
                while (pipePending_ > 0)
                {
                    const ssize_t sOut =
                        ::splice(pipeFd_[0], nullptr, fd_, nullptr, pipePending_, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
                    if (sOut > 0) [[likely]]
                    {
                        pipePending_ -= static_cast<size_t>(sOut);
                        touch();
                        continue;
                    }
                    if (sOut < 0)
                    {
                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                        {
                            wantWrite_ = true;
                            return IO_STATUS::KEEP;
                        }
                        if (errno == EINTR)
                        {
                            continue;
                        }
                        if (errno == ECONNRESET || errno == EPIPE)
                        {
                            peerGone_ = true;
                            return IO_STATUS::CLOSE;
                        }
                        LOG_WARN("Connection::handleWrite: fd {}: splice pipe->socket failed: {}", fd_,
                                 errnoText(errno));
                        peerGone_ = true;
                        return IO_STATUS::CLOSE;
                    }
                    break;
                }
                if (pipePending_ == 0)
                {
                    wantWrite_ = false;
                    readPaused_ = false;
                }
            }

            collectResponses();
            const std::optional<IO_END> r = flush();
            if (r)
            {
                if (*r == IO_END::FATAL || *r == IO_END::EOF_REACHED)
                {
                    return IO_STATUS::CLOSE;
                }
                return IO_STATUS::KEEP;
            }
            if (closeAfterWrite_ && pipePending_ == 0 && writeQueue_.empty())
            {
                return finishClose() ? IO_STATUS::CLOSE : IO_STATUS::KEEP;
            }
            if (!peerGone_ && pipePending_ == 0 && handler_.readCredit() > 0 && pendingBytes_ <= writeHighWaterMark_)
            {
                readPaused_ = false;
            }
            return IO_STATUS::KEEP;
        }

        [[nodiscard]] inline std::optional<IO_END> flush() noexcept
        {
            while (true)
            {
                if (writeQueue_.empty())
                {
                    writeOffset_ = 0;
                    return std::nullopt;
                }

                // 明文多条响应积压路径：利用向量化 I/O (writev) 聚合至多 16 个分片单次系统调用冲刷
                if (ssl_ == nullptr && writeQueue_.size() > 1)
                {
                    constexpr size_t kMaxIov = 16;
                    iovec iov[kMaxIov];
                    size_t count = 0;
                    for (auto it = writeQueue_.begin(); it != writeQueue_.end() && count < kMaxIov; ++it)
                    {
                        const size_t offset = (count == 0) ? writeOffset_ : 0;
                        if (it->size() > offset)
                        {
                            iov[count].iov_base = const_cast<char *>(it->data() + offset);
                            iov[count].iov_len = it->size() - offset;
                            ++count;
                        }
                    }

                    if (count > 0)
                    {
                        msghdr msg{};
                        msg.msg_iov = iov;
                        msg.msg_iovlen = count;
                        const ssize_t sn = ::sendmsg(fd_, &msg, MSG_NOSIGNAL);
                        if (sn > 0) [[likely]]
                        {
                            size_t remaining = static_cast<size_t>(sn);
                            pendingBytes_ -= remaining;
                            while (remaining > 0 && !writeQueue_.empty())
                            {
                                const size_t avail = writeQueue_.front().size() - writeOffset_;
                                if (remaining >= avail)
                                {
                                    remaining -= avail;
                                    if constexpr (requires { handler_.recycleSpare(std::move(writeQueue_.front())); })
                                    {
                                        handler_.recycleSpare(std::move(writeQueue_.front()));
                                    }
                                    writeQueue_.pop_front();
                                    writeOffset_ = 0;
                                }
                                else
                                {
                                    writeOffset_ += remaining;
                                    remaining = 0;
                                }
                            }
                            continue;
                        }
                        if (sn < 0)
                        {
                            if (errno == EAGAIN || errno == EWOULDBLOCK)
                            {
                                return IO_END::WOULDBLOCK;
                            }
                            if (errno == EINTR)
                            {
                                continue;
                            }
                            if (errno == ECONNRESET || errno == EPIPE)
                            {
                                return IO_END::EOF_REACHED;
                            }
                            LOG_WARN("Connection::flush: fd {}: writev() failed: {}", fd_, errnoText(errno));
                            return IO_END::FATAL;
                        }
                    }
                }

                std::string &front = writeQueue_.front();
                if (writeOffset_ >= front.size())
                {
                    if constexpr (requires { handler_.recycleSpare(std::move(front)); })
                    {
                        handler_.recycleSpare(std::move(front));
                    }
                    writeQueue_.pop_front();
                    writeOffset_ = 0;
                    continue;
                }
                std::expected<size_t, IO_END> sn = doSend(front.data() + writeOffset_, front.size() - writeOffset_);
                if (sn)
                {
                    writeOffset_ += *sn;
                    pendingBytes_ -= *sn;
                    continue;
                }
                if (sn.error() == IO_END::INTERRUPTED)
                {
                    continue;
                }
                return sn.error();
            }
        }

        // ---- 双引擎通用钩子 (Hooks for Reactor & Proactor) ----

        inline void pump() noexcept
        {
            collectResponses();
            if (handler_.closeAfterResponse())
            {
                closeAfterWrite_ = true;
            }
        }

        inline void setWantWrite(bool v) noexcept { wantWrite_ = v; }

        inline void onPeerGone() noexcept
        {
            peerGone_ = true;
            closeAfterWrite_ = true;
        }

        inline void onFatal() noexcept
        {
            peerGone_ = true;
            state_ = CONN_STATE::CLOSED;
        }

        // ---- 针对 io_uring Proactor 异步写支持 ----

        [[nodiscard]] inline const char *pendingData() const noexcept
        {
            if (writeQueue_.empty()) [[unlikely]]
            {
                return nullptr;
            }
            return writeQueue_.front().data() + writeOffset_;
        }

        [[nodiscard]] inline size_t pendingSize() const noexcept
        {
            return writeQueue_.empty() ? 0 : writeQueue_.front().size() - writeOffset_;
        }

        [[nodiscard]] inline bool commitSent(size_t n) noexcept
        {
            while (n > 0 && !writeQueue_.empty())
            {
                std::string &front = writeQueue_.front();
                const size_t left = front.size() - writeOffset_;
                const size_t step = n < left ? n : left;
                writeOffset_ += step;
                pendingBytes_ -= step;
                n -= step;
                if (writeOffset_ >= front.size())
                {
                    if constexpr (requires { handler_.recycleSpare(std::move(front)); })
                    {
                        handler_.recycleSpare(std::move(front));
                    }
                    writeQueue_.pop_front();
                    writeOffset_ = 0;
                }
                else
                {
                    break;
                }
            }
            // Proactor 纯 io_uring 路径没有等价于 handleWrite 末尾的恢复点：
            // onSendDone 只调 commitSent。在此统一恢复读背压，与 handleWrite
            // 的恢复条件保持一致（流控 credit 存在且积压落回高水位以内）。
            if (readPaused_ && pendingBytes_ <= writeHighWaterMark_ && handler_.readCredit() > 0)
            {
                readPaused_ = false;
            }
            return writeQueue_.empty();
        }

    private:
        int fd_ = -1;
        sockaddr_in addr_{};
        SSL *ssl_ = nullptr;
        bool handshakeDone_ = false;
#ifdef MYNET_HAVE_KTLS
        bool ktlsRx_ = false;
#endif
        HandlerType handler_{};

        std::deque<std::string> writeQueue_;
        size_t writeOffset_ = 0;
        size_t pendingBytes_ = 0;
        size_t writeHighWaterMark_ = getNetConfig().server.writeHighWaterMark;

        int pipeFd_[2] = {-1, -1};
        size_t pipePending_ = 0;

        CONN_STATE state_ = CONN_STATE::OPEN;
        bool readPaused_ = false;
        bool wantWrite_ = false;
        bool closeAfterWrite_ = false;
        bool peerGone_ = false;
        bool shutdownSent_ = false;

        uint64_t timerId_ = 0;
        std::chrono::steady_clock::time_point lastActive_{};
        uint32_t events_ = 0;

        inline static bool unexpectedEof() noexcept
        {
#ifdef SSL_R_UNEXPECTED_EOF_WHILE_READING
            const unsigned long e = ERR_peek_last_error();
            if (e != 0 && ERR_GET_LIB(e) == ERR_LIB_SSL && ERR_GET_REASON(e) == SSL_R_UNEXPECTED_EOF_WHILE_READING)
            {
                ::ERR_clear_error();
                return true;
            }
            return false;
#else
            return false;
#endif
        }

        [[nodiscard]] inline std::expected<size_t, IO_END> doRecv(char *buf, size_t cap) noexcept
        {
            if (ssl_ != nullptr)
            {
                const int rn = SSL_read(ssl_, buf, static_cast<int>(cap));
                if (rn > 0) [[likely]]
                {
                    return static_cast<size_t>(rn);
                }
                switch (SSL_get_error(ssl_, rn))
                {
                case SSL_ERROR_WANT_READ:
                    wantWrite_ = false;
                    return std::unexpected(IO_END::WOULDBLOCK);
                case SSL_ERROR_WANT_WRITE:
                    wantWrite_ = true;
                    return std::unexpected(IO_END::WOULDBLOCK);
                case SSL_ERROR_ZERO_RETURN:
                    return std::unexpected(IO_END::EOF_REACHED);
                case SSL_ERROR_SYSCALL:
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                    {
                        return std::unexpected(IO_END::WOULDBLOCK);
                    }
                    if (errno == EINTR)
                    {
                        return std::unexpected(IO_END::INTERRUPTED);
                    }
                    if (errno == 0 || errno == ECONNRESET || errno == EPIPE)
                    {
                        return std::unexpected(IO_END::EOF_REACHED);
                    }
                    LOG_WARN("Connection::doRecv: fd {}: SSL_read() failed: {}", fd_, errnoText(errno));
                    return std::unexpected(IO_END::FATAL);
                case SSL_ERROR_SSL:
                    if (unexpectedEof())
                    {
                        return std::unexpected(IO_END::EOF_REACHED);
                    }
                    LOG_WARN("Connection::doRecv: fd {}: SSL_read() failed: {}", fd_, sslText());
                    return std::unexpected(IO_END::FATAL);
                default:
                    LOG_WARN("Connection::doRecv: fd {}: SSL_read() failed: {}", fd_, sslText());
                    return std::unexpected(IO_END::FATAL);
                }
            }

            const ssize_t rn = ::recv(fd_, buf, cap, 0);
            if (rn > 0) [[likely]]
            {
                return static_cast<size_t>(rn);
            }
            if (rn == 0)
            {
                return std::unexpected(IO_END::EOF_REACHED);
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                return std::unexpected(IO_END::WOULDBLOCK);
            }
            if (errno == EINTR)
            {
                return std::unexpected(IO_END::INTERRUPTED);
            }
            if (errno == ECONNRESET || errno == EPIPE)
            {
                return std::unexpected(IO_END::EOF_REACHED);
            }
            LOG_WARN("Connection::doRecv: fd {}: recv() failed: {}", fd_, errnoText(errno));
            return std::unexpected(IO_END::FATAL);
        }

        [[nodiscard]] inline std::expected<size_t, IO_END> doSend(const char *buf, size_t n) noexcept
        {
            if (ssl_ != nullptr)
            {
                const int sn = SSL_write(ssl_, buf, static_cast<int>(n));
                if (sn > 0) [[likely]]
                {
                    return static_cast<size_t>(sn);
                }
                switch (SSL_get_error(ssl_, sn))
                {
                case SSL_ERROR_WANT_WRITE:
                    wantWrite_ = true;
                    return std::unexpected(IO_END::WOULDBLOCK);
                case SSL_ERROR_WANT_READ:
                    wantWrite_ = false;
                    return std::unexpected(IO_END::WOULDBLOCK);
                case SSL_ERROR_SYSCALL:
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                    {
                        wantWrite_ = true;
                        return std::unexpected(IO_END::WOULDBLOCK);
                    }
                    if (errno == EINTR)
                    {
                        return std::unexpected(IO_END::INTERRUPTED);
                    }
                    if (errno == 0 || errno == ECONNRESET || errno == EPIPE)
                    {
                        return std::unexpected(IO_END::EOF_REACHED);
                    }
                    LOG_WARN("Connection::doSend: fd {}: SSL_write() failed: {}", fd_, errnoText(errno));
                    return std::unexpected(IO_END::FATAL);
                default:
                    LOG_WARN("Connection::doSend: fd {}: SSL_write() failed: {}", fd_, sslText());
                    return std::unexpected(IO_END::FATAL);
                }
            }

            const ssize_t sn = ::send(fd_, buf, n, MSG_NOSIGNAL);
            if (sn > 0) [[likely]]
            {
                return static_cast<size_t>(sn);
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                wantWrite_ = true;
                return std::unexpected(IO_END::WOULDBLOCK);
            }
            if (errno == EINTR)
            {
                return std::unexpected(IO_END::INTERRUPTED);
            }
            if (errno == ECONNRESET || errno == EPIPE)
            {
                return std::unexpected(IO_END::EOF_REACHED);
            }
            LOG_WARN("Connection::doSend: fd {}: send() failed: {}", fd_, errnoText(errno));
            return std::unexpected(IO_END::FATAL);
        }

        inline void collectResponses()
        {
            while (handler_.hasResponse())
            {
                // 慢读放大硬顶：对端零窗口时 send 停滞，若继续收割响应，writeQueue_
                // 可积压至响应槽数(64) × 单请求上限(4MiB) = 256MiB/连接，多连接叠加导致 OOM。
                // 超过 2×高水位即停止搬运并标记发完即关，把单连接写队列压在 8MiB 以内。
                if (pendingBytes_ >= 2 * writeHighWaterMark_) [[unlikely]]
                {
                    LOG_WARN("Connection: fd {}: write backlog {} exceeds hard cap, closing after flush", fd_,
                             pendingBytes_);
                    closeAfterWrite_ = true;
                    break;
                }
                std::string response = handler_.takeResponse();
                if (response.empty()) [[unlikely]]
                {
                    continue;
                }
                pendingBytes_ += response.size();
                writeQueue_.push_back(std::move(response));
            }
            if (handler_.closeAfterResponse())
            {
                closeAfterWrite_ = true;
            }
            if (pendingBytes_ > writeHighWaterMark_)
            {
                readPaused_ = true;
            }
        }
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

} // namespace mynet
