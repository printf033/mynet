#pragma once

#include "concepts.hpp"
#include "error.hpp"
#include "handler.hpp"
#include "log.hpp"
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <expected>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <optional>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

namespace mynet
{

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
        requires ProtocolHandler<HandlerType>
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
            handler_.reset();
        }

        [[nodiscard]] inline int fd() const noexcept { return fd_; }
        inline void setFd(int fd) noexcept { fd_ = fd; }
        [[nodiscard]] inline const sockaddr_in &addr() const noexcept { return addr_; }
        [[nodiscard]] inline sockaddr_in &addr() noexcept { return addr_; }
        [[nodiscard]] inline HandlerType &handler() noexcept { return handler_; }
        [[nodiscard]] inline const HandlerType &handler() const noexcept { return handler_; }
        [[nodiscard]] inline SSL *ssl() const noexcept { return ssl_; }
        [[nodiscard]] inline CONN_STATE state() const noexcept { return state_; }
        [[nodiscard]] inline uint32_t events() const noexcept { return events_; }
        inline void setEvents(uint32_t events) noexcept { events_ = events; }

        [[nodiscard]] inline bool wantRead() const noexcept
        {
            return !readPaused_ && !peerGone_ && state_ != CONN_STATE::CLOSED;
        }

        [[nodiscard]] inline bool wantWrite() const noexcept
        {
            return pendingBytes_ > 0 || wantWrite_ || closeAfterWrite_ || state_ == CONN_STATE::HANDSHAKE ||
                   handler_.hasResponse();
        }

        [[nodiscard]] inline bool writeBlocked() const noexcept
        {
            return pendingBytes_ > 0 || wantWrite_ || closeAfterWrite_ || handler_.hasResponse();
        }

        [[nodiscard]] inline bool hasPendingWrite() const noexcept
        {
            return pendingBytes_ > 0 || handler_.hasResponse();
        }

        [[nodiscard]] inline size_t pendingBytes() const noexcept { return pendingBytes_; }
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
                LOG_ERROR("Connection::startTLS: SSL_new() failed on fd {}: {}", fd_, log::sslText());
                return std::unexpected(ERR::SSL_NEW_FAILED);
            }
#ifdef MYNET_HAVE_KTLS
            ktlsRx_ = false;
            // 请求内核 TLS RX offload；仅当握手后 BIO_get_ktls_recv 确认生效时才走快路径
            SSL_set_options(ssl_, SSL_OP_ENABLE_KTLS);
#endif
            if (SSL_set_fd(ssl_, fd_) != 1) [[unlikely]]
            {
                LOG_ERROR("Connection::startTLS: SSL_set_fd({}) failed: {}", fd_, log::sslText());
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
                LOG_WARN("Connection::doHandshake: fd {}: {}", fd_, log::sslText());
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

            char buf[4 << 10];
            while (!readPaused_)
            {
                std::expected<size_t, IO_END> rn = doRecv(buf, sizeof(buf));
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

                if (!handler_.appendRequest(buf, static_cast<ssize_t>(*rn))) [[unlikely]]
                {
                    // 解析缓冲扩容失败：请求流断裂，已收字节不可复用，连接降级关闭
                    LOG_ERROR("Connection: appendRequest failed (allocation), fd {} closing", fd_);
                    peerGone_ = true;
                    return IO_STATUS::CLOSE;
                }
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
            if (closeAfterWrite_)
            {
                return finishClose() ? IO_STATUS::CLOSE : IO_STATUS::KEEP;
            }
            if (!peerGone_ && handler_.readCredit() > 0 && pendingBytes_ <= writeHighWaterMark_)
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
                std::string &front = writeQueue_.front();
                if (writeOffset_ >= front.size())
                {
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
                    writeQueue_.pop_front();
                    writeOffset_ = 0;
                }
                else
                {
                    break;
                }
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
        size_t writeHighWaterMark_ = 4 << 20;

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
                    LOG_WARN("Connection::doRecv: fd {}: SSL_read() failed: {}", fd_, log::errnoText(errno));
                    return std::unexpected(IO_END::FATAL);
                case SSL_ERROR_SSL:
                    if (unexpectedEof())
                    {
                        return std::unexpected(IO_END::EOF_REACHED);
                    }
                    LOG_WARN("Connection::doRecv: fd {}: SSL_read() failed: {}", fd_, log::sslText());
                    return std::unexpected(IO_END::FATAL);
                default:
                    LOG_WARN("Connection::doRecv: fd {}: SSL_read() failed: {}", fd_, log::sslText());
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
            LOG_WARN("Connection::doRecv: fd {}: recv() failed: {}", fd_, log::errnoText(errno));
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
                    LOG_WARN("Connection::doSend: fd {}: SSL_write() failed: {}", fd_, log::errnoText(errno));
                    return std::unexpected(IO_END::FATAL);
                default:
                    LOG_WARN("Connection::doSend: fd {}: SSL_write() failed: {}", fd_, log::sslText());
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
            LOG_WARN("Connection::doSend: fd {}: send() failed: {}", fd_, log::errnoText(errno));
            return std::unexpected(IO_END::FATAL);
        }

        inline void collectResponses()
        {
            while (handler_.hasResponse())
            {
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

} // namespace mynet
