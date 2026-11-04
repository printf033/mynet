#pragma once

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "configHolder.hpp"
#include "constraints.hpp"
#include "error.hpp"
#include "log_config.hpp"
#include "requestBuffer.hpp"
#include "responseQueue.hpp"
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
        using SPLICE_CONTROL = mynet::SPLICE_CONTROL;

        /// 是否允许该处理器使用 Linux splice(2) 内核零拷贝（派生类按协议特性开启）
        static constexpr bool kEnableSplice = false;

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

        virtual ~HandlerConnection() noexcept = default;

        HandlerConnection(const HandlerConnection &) =
            delete ("a connection handler holds parser state bound to one connection");
        HandlerConnection &operator=(const HandlerConnection &) =
            delete ("a connection handler holds parser state bound to one connection");
        HandlerConnection(HandlerConnection &&) =
            delete ("a connection handler holds parser state bound to one connection");
        HandlerConnection &
        operator=(HandlerConnection &&) = delete ("a connection handler holds parser state bound to one connection");

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
         * 连接层在响应队列被搬运之后据此重新驱动 process()。默认 false：只有
         * 会主动分轮解码的处理器（如 HandlerHttp2）才需要覆写。
         */
        [[nodiscard]] inline bool needsProcess() const noexcept { return false; }

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
        virtual void onParseError([[maybe_unused]] const char *reason) noexcept {}

        /**
         * @brief 默认执行逻辑：标准 Echo 协议回显
         */
        void echo()
        {
            if (requestBuffer_.empty()) [[unlikely]]
            {
                return;
            }
            if (!pushResponse(requestBuffer_.readableView())) [[unlikely]]
            {
                LOG_WARN("HandlerConnection::echo: response queue full, echoing dropped");
            }
            requestBuffer_.reset();
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
            h.echo();
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
            ktlsTx_ = false;
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
            writeHighWaterMark_ = getConnectionConfig().writeHighWaterMark;
            handler_.reset();
            handler_.setMaxRequestBytes(getConnectionConfig().maxRequestBytes);
        }

        [[nodiscard]] inline int fd() const noexcept { return fd_; }
        inline void setFd(int fd) noexcept
        {
            fd_ = fd;
            if (fd_ >= 0)
            {
                if (getServerConfig().tcpNoDelay)
                {
                    constexpr int one = 1;
                    [[maybe_unused]] auto _ = ::setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
                }
                applyQuickAck();
                writeHighWaterMark_ = getConnectionConfig().writeHighWaterMark;
                handler_.setMaxRequestBytes(getConnectionConfig().maxRequestBytes);
                handler_.onConnect(fd_);
            }
        }
        [[nodiscard]] inline const sockaddr_in &addr() const noexcept { return addr_; }
        [[nodiscard]] inline sockaddr_in &addr() noexcept { return addr_; }
        [[nodiscard]] inline Handler &handler() noexcept { return handler_; }
        [[nodiscard]] inline const Handler &handler() const noexcept { return handler_; }
        [[nodiscard]] inline SSL *ssl() const noexcept { return ssl_; }
        [[nodiscard]] inline CONN_STATE state() const noexcept { return state_; }
        [[nodiscard]] inline uint32_t events() const noexcept { return events_; }
        inline void setEvents(uint32_t events) noexcept { events_ = events; }

        /**
         * @brief 按配置重设 TCP_QUICKACK。
         *
         * Linux 语义：设置后只影响下一个待发 ACK，发出即失效，因此调用点必须
         * 分布在"每次可能产生 ACK 的收包之后"，而不是只在建连时设一次。
         * 关闭时（默认）本函数是空调用，热路径零系统调用。
         */
        inline void applyQuickAck() noexcept
        {
            if (fd_ >= 0 && getServerConfig().tcpQuickAck)
            {
                constexpr int one = 1;
                [[maybe_unused]] auto _ = ::setsockopt(fd_, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));
            }
        }

        [[nodiscard]] inline bool isSpliceEnabled() const noexcept
        {
            if (!getServerConfig().enableSplice)
            {
                return false;
            }
            if (ssl_ != nullptr)
            {
#ifdef MYNET_HAVE_KTLS
                // kTLS RX 激活时，内核已在接收队列中完成对称解密，splice(fd_, ...) 读出的即为明文
                if (!ktlsRx_)
                {
                    return false;
                }
#else
                return false;
#endif
            }
            if constexpr (requires {
                              { Handler::kEnableSplice } -> std::convertible_to<bool>;
                          })
            {
                if constexpr (Handler::kEnableSplice)
                {
                    return handler_.isSpliceActive() ||
                           (handler_.spliceControl() == SPLICE_CONTROL::DRAINING && pipePending_ > 0);
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
            ktlsTx_ = false;
            // 请求内核 TLS RX 与 TX offload；仅当握手后 BIO 确认生效时才走快路径
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
                // 内核完成 RX/TX offload 时底层 BIO 会切换为 kTLS：
                // RX 生效时后续 recv() 直接返回明文，Proactor 可安全复用 multishot + buffer ring 快路径；
                // TX 生效时发送可直接走 ::send 或 splice 零拷贝
                ktlsRx_ = BIO_get_ktls_recv(SSL_get_rbio(ssl_)) > 0;
                ktlsTx_ = BIO_get_ktls_send(SSL_get_wbio(ssl_)) > 0;
                if (ktlsRx_ || ktlsTx_) [[unlikely]]
                {
                    LOG_INFO("Connection::doHandshake: fd {}: kTLS offload active (RX={}, TX={})", fd_, ktlsRx_,
                             ktlsTx_);
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

        /// kTLS TX offload 是否已生效（握手后由内核确认）。
        [[nodiscard]] inline bool ktlsTxActive() const noexcept
        {
#ifdef MYNET_HAVE_KTLS
            return ktlsTx_;
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

        // ---- 零拷贝通用流管道 (Zero-Copy Splice APIs) ----

        /**
         * @brief 从当前网络连接套接字 (fd_) 向目标描述符零拷贝搬移数据（供反向代理至上游或文件上传落盘）
         *
         * @param targetFd 目标文件或套接字描述符
         * @param maxBytes 单次最大搬移字节数
         * @return 成功返回实际搬移字节数；出错返回 IO_END（WOULDBLOCK / EOF_REACHED / FATAL）
         */
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

            // 1. 若管道中已有残留数据，先尝试刷向目标描述符
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

            // 2. 从当前套接字摄入数据至管道写端
            const ssize_t sIn =
                ::splice(fd_, nullptr, pipeFd_[1], nullptr, maxBytes, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
            if (sIn <= 0)
            {
                if (sIn == 0)
                    return std::unexpected(IO_END::EOF_REACHED); // EOF
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    return std::unexpected(IO_END::WOULDBLOCK);
                if (errno == EINTR)
                    return 0;
                return std::unexpected(IO_END::FATAL);
            }

            pipePending_ += static_cast<size_t>(sIn);
            size_t totalWritten = 0;

            // 3. 将管道内数据泵至目标描述符
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

        /**
         * @brief 从源描述符向当前网络连接套接字 (fd_) 零拷贝搬移数据（供静态文件下载或上游响应回传）
         *
         * @param sourceFd 源文件或上游套接字描述符
         * @param maxBytes 单次最大搬移字节数
         * @return 成功返回实际搬移字节数；出错返回 IO_END（WOULDBLOCK / EOF_REACHED / FATAL）
         */
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

            // 1. 若管道中已有残留数据，先尝试刷向当前 socket
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

            // 2. 从源描述符摄入数据至管道写端
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

            // 3. 将管道内数据泵至当前连接套接字 fd_
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

        [[nodiscard]] IO_STATUS handleSplice() noexcept
        {
            const SPLICE_CONTROL ctrl = handler_.spliceControl();
            if (ctrl == SPLICE_CONTROL::PAUSED || ctrl == SPLICE_CONTROL::DISABLED || ctrl == SPLICE_CONTROL::CLOSED)
            {
                return IO_STATUS::KEEP;
            }

            const int targetFd = handler_.spliceTarget();
            if (targetFd < 0) [[unlikely]]
            {
                return IO_STATUS::KEEP;
            }
            const size_t spliceChunk = getConnectionConfig().spliceChunkSize;

            // 1. 如果此前管道中尚有未排空的残留数据（目标端 TCP 接收窗口满），先尝试刷出
            while (pipePending_ > 0)
            {
                const ssize_t sOut =
                    ::splice(pipeFd_[0], nullptr, targetFd, nullptr, pipePending_, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
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
                    LOG_WARN("Connection::handleSplice: fd {}: splice pipe->target ({}) failed: {}", fd_, targetFd,
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

            // 若当前处于排空状态，管道残留数据已刷空，则将通道置为 CLOSED 并退出
            if (ctrl == SPLICE_CONTROL::DRAINING)
            {
                handler_.setSpliceControl(SPLICE_CONTROL::CLOSED);
                return IO_STATUS::KEEP;
            }

            // 2. 管道已空，持续从对端 socket 读取数据移入管道，并直接向目标描述符转发写出（内核零拷贝）
            while (!readPaused_)
            {
                const ssize_t sIn =
                    ::splice(fd_, nullptr, pipeFd_[1], nullptr, spliceChunk, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
                if (sIn > 0) [[likely]]
                {
                    touch();
                    pipePending_ += static_cast<size_t>(sIn);

                    // 立即将摄入管道的数据原样零拷贝写入目标描述符
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
                            {
                                continue;
                            }
                            if (errno == ECONNRESET || errno == EPIPE)
                            {
                                peerGone_ = true;
                                return IO_STATUS::CLOSE;
                            }
                            LOG_WARN("Connection::handleSplice: fd {}: splice pipe->target ({}) failed: {}", fd_,
                                     targetFd, errnoText(errno));
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
                    // splice 路径不经过下面的 recv 循环，因此要在这里单独重置 quick ack，
                    // 否则开启 splice 时每个连接只会在建连那次拿到 quick ack。
                    applyQuickAck();
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
                const size_t want = std::min(getConnectionConfig().readChunkSize, credit);
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

                // TCP_QUICKACK 不是持久 socket 选项：内核发出下一个 ACK 后就会清除它。
                // 因此要它持续生效，必须每次收到数据后重设——这也是它默认关闭的原因
                // （每个 recv 多一次 setsockopt）。只在显式开启时才付出这个代价。
                applyQuickAck();
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
                if constexpr (requires { handler_.process(); })
                {
                    handler_.process();
                }
                else
                {
                    handler_.echo();
                }
                collectResponses();
                if (closeAfterWrite_)
                {
                    break;
                }
            }

            collectResponses();
            drainBackpressuredHandler();
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

            // 若存在内核 splice 管道残留数据，先冲刷管道至目标描述符
            if (pipePending_ > 0)
            {
                const int targetFd = handler_.spliceTarget();
                if (targetFd >= 0)
                {
                    while (pipePending_ > 0)
                    {
                        const ssize_t sOut = ::splice(pipeFd_[0], nullptr, targetFd, nullptr, pipePending_,
                                                      SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
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
                            LOG_WARN("Connection::handleWrite: fd {}: splice pipe->target ({}) failed: {}", fd_,
                                     targetFd, errnoText(errno));
                            peerGone_ = true;
                            return IO_STATUS::CLOSE;
                        }
                        break;
                    }
                    if (pipePending_ == 0)
                    {
                        wantWrite_ = false;
                        readPaused_ = false;
                        if (handler_.spliceControl() == SPLICE_CONTROL::DRAINING)
                        {
                            handler_.setSpliceControl(SPLICE_CONTROL::CLOSED);
                        }
                    }
                }
            }

            collectResponses();
            drainBackpressuredHandler();
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

                // 明文多条响应积压路径：利用向量化 I/O (writev) 聚合至多 maxWriteIov 个分片单次系统调用冲刷
                if (ssl_ == nullptr && writeQueue_.size() > 1)
                {
                    constexpr size_t kStackIovCapacity = 64;
                    const size_t maxIov = std::clamp(getConnectionConfig().maxWriteIov, size_t{1}, kStackIovCapacity);
                    iovec iov[kStackIovCapacity];
                    size_t count = 0;
                    for (auto it = writeQueue_.begin(); it != writeQueue_.end() && count < maxIov; ++it)
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

        /**
         * @brief 响应队列搬空后，继续驱动因出站背压提前返回的处理器
         *
         * HandlerHttp2 在响应队列压满时停下解码，把剩余帧留在请求缓冲里。连接层
         * 每轮只搬运一次响应队列，因此必须在这里补上"下一轮"，否则大响应会在
         * 队列第一次压满处永久停住（对端收不到数据也就不会再补窗口）。
         *
         * 以发送积压高水位为界：超过高水位就交给写路径，避免把内存一次性推满。
         */
        inline void drainBackpressuredHandler() noexcept
        {
            if constexpr (requires {
                              handler_.process();
                              handler_.needsProcess();
                          })
            {
                // 上界 + 进展检测：任何"声称需要推进却推不动"的退化路径（例如响应
                // 队列容量为 0、初始化失败）都只是把驱动推迟到下一个事件，绝不能在
                // 事件循环里空转。
                const size_t maxDrainRounds = getConnectionConfig().maxDrainRounds;
                for (size_t round = 0; round < maxDrainRounds; ++round)
                {
                    if (!handler_.needsProcess() || pendingBytes_ >= writeHighWaterMark_ || closeAfterWrite_ ||
                        peerGone_)
                    {
                        return;
                    }
                    const size_t bytesBefore = pendingBytes_;
                    const size_t bufferedBefore = handler_.requestBytes();
                    handler_.process();
                    collectResponses();
                    const bool progressed = pendingBytes_ > bytesBefore || handler_.requestBytes() < bufferedBefore;
                    if (!progressed)
                    {
                        return;
                    }
                }
            }
        }

        inline void pump() noexcept
        {
            collectResponses();
            drainBackpressuredHandler();
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
        bool ktlsTx_ = false;
#endif
        Handler handler_{};

        std::deque<std::string> writeQueue_;
        size_t writeOffset_ = 0;
        size_t pendingBytes_ = 0;
        size_t writeHighWaterMark_ = getConnectionConfig().writeHighWaterMark;

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
#ifdef MYNET_HAVE_KTLS
                // kTLS TX 生效时，内核直接在套接字发送层完成对称加密分帧，可走 ::send 极速路径
                if (ktlsTx_)
                {
                    const ssize_t sn = ::send(fd_, buf, n, MSG_NOSIGNAL);
                    if (sn > 0) [[likely]]
                    {
                        return static_cast<size_t>(sn);
                    }
                    if (sn < 0)
                    {
                        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                        {
                            return std::unexpected(IO_END::WOULDBLOCK);
                        }
                        if (errno == ECONNRESET || errno == EPIPE)
                        {
                            return std::unexpected(IO_END::EOF_REACHED);
                        }
                        LOG_WARN("Connection::doSend: fd {}: ktls send() failed: {}", fd_, errnoText(errno));
                        return std::unexpected(IO_END::FATAL);
                    }
                    return std::unexpected(IO_END::EOF_REACHED);
                }
#endif
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
                // 可积压导致 OOM。超过 writeHardCapFactor × 高水位即停止搬运并标记发完即关。
                const size_t hardCapFactor = getConnectionConfig().writeHardCapFactor;
                if (pendingBytes_ >= hardCapFactor * writeHighWaterMark_) [[unlikely]]
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
