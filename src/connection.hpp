#pragma once
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "config/log.hpp"
#include "handler.hpp"
#include "listener.hpp"
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
#include <memory>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <new>
#include <optional>
#include <span>
#include <string>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

namespace mynet
{
    /**
     * @brief 统一连接抽象基类（流式传输基类）
     *
     * 无论底层是原生 TCP，还是在 UDP 之上自己封装的可靠连接，皆统一继承自此类。
     * 融合了连接的底层传输状态（fd、地址、配置）、请求缓冲区、响应队列、
     * 零拷贝 splice 管道，并提供流式读写与背压驱动的方法占位与实现。
     * 连接内部可挂载业务 Handler（handler_ 为空时作为纯净无害的流式连接）。
     */
    class Connection
    {
    public:
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

        // 业务处理器挂载（Connection 独占托管所有权）
        std::unique_ptr<Handler> handler_{nullptr};

        // 连接流式状态与背压控制（由 ConnectionBase 统一控制物理传输背压）
        CONN_STATE state_{CONN_STATE::OPEN};
        uint32_t events_{0};
        bool wantWrite_{false};
        bool readPaused_{false};
        bool closeAfterWrite_{false};
        bool peerGone_{false};
        uint64_t timerId_{0};
        std::chrono::steady_clock::time_point lastActive_{std::chrono::steady_clock::now()};

        // 写出缓冲与背压监控
        std::deque<std::string> writeQueue_{};
        size_t writeOffset_{0};
        size_t pendingBytes_{0};
        size_t writeHighWaterMark_{getConnectionConfig().writeHighWaterMark};

    public:
        Connection() noexcept
            : Connection(getConnectionConfig())
        {
        }

        explicit Connection([[maybe_unused]] size_t responseCapacity) noexcept {}

        explicit Connection(const ConnectionConfig &config) noexcept
            : writeHighWaterMark_(config.writeHighWaterMark)
        {
        }

        virtual ~Connection() noexcept { Connection::reset(); }

        Connection(const Connection &) = delete;
        Connection &operator=(const Connection &) = delete;
        Connection(Connection &&) noexcept = default;
        Connection &operator=(Connection &&) noexcept = default;

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
        virtual void setHandler(std::unique_ptr<Handler> h) noexcept;
        [[nodiscard]] inline bool hasHandler() const noexcept { return handler_ != nullptr; }
        [[nodiscard]] inline Handler *handler() noexcept { return handler_.get(); }
        [[nodiscard]] inline const Handler *handler() const noexcept { return handler_.get(); }

        // ---- 请求缓冲方法占位（委托至挂载的业务 Handler） ----
        [[nodiscard]] inline Result<> appendRequest(const char *buf, ssize_t rn) noexcept;
        [[nodiscard]] inline Result<> appendRequest(std::string_view sv) noexcept;
        [[nodiscard]] inline std::expected<char *, ERR>
        prepareRequestWritable(size_t minBytes = getConnectionConfig().readChunkSize) noexcept;
        [[nodiscard]] inline char *requestWritableBegin() noexcept;
        [[nodiscard]] inline size_t requestWritableBytes() const noexcept;
        inline void commitRequest(size_t n) noexcept;
        [[nodiscard]] inline bool requestOverLimit() const noexcept;
        [[nodiscard]] inline size_t requestBytes() const noexcept;
        [[nodiscard]] inline const char *requestBegin() const noexcept;
        inline void requestConsume(size_t n) noexcept;
        inline void requestClear() noexcept;
        [[nodiscard]] inline size_t readCredit() const noexcept;
        inline void setMaxRequestBytes(size_t n) noexcept;
        [[nodiscard]] inline size_t maxRequestBytes() const noexcept;

        // ---- 响应队列方法占位（委托至挂载的业务 Handler） ----
        [[nodiscard]] inline bool hasResponse() const noexcept;
        [[nodiscard]] inline size_t responseCount() const noexcept;
        [[nodiscard]] inline size_t responseCapacity() const noexcept;
        [[nodiscard]] inline std::string takeResponse();
        inline void recycleSpare(std::string &&s) noexcept;
        [[nodiscard]] inline Result<> pushResponse(std::string &&s) noexcept;
        [[nodiscard]] inline Result<> pushResponse(const std::string &s) noexcept;
        [[nodiscard]] inline Result<> pushResponse(std::string_view sv) noexcept;
        [[nodiscard]] inline Result<> pushResponse(const char *s) noexcept;
        [[nodiscard]] inline Result<> reserveResponses(size_t capacity) noexcept;
        [[nodiscard]] inline bool closeAfterResponse() const noexcept;
        inline void setCloseAfterResponse(bool v) noexcept;

        // ---- 连接状态与背压控制 ----
        [[nodiscard]] inline CONN_STATE state() const noexcept { return state_; }
        [[nodiscard]] inline uint32_t events() const noexcept { return events_; }
        inline void setEvents(uint32_t events) noexcept { events_ = events; }
        [[nodiscard]] inline bool wantRead() const noexcept { return !readPaused_ && state_ == CONN_STATE::OPEN; }
        [[nodiscard]] inline bool wantWrite() const noexcept { return wantWrite_ || hasPendingWrite(); }
        inline void setWantWrite(bool v) noexcept { wantWrite_ = v; }
        [[nodiscard]] inline bool isReadPaused() const noexcept { return readPaused_; }
        inline void pauseRead() noexcept { readPaused_ = true; }
        inline void resumeRead() noexcept { readPaused_ = false; }

        [[nodiscard]] inline bool hasPendingWrite() const noexcept;
        [[nodiscard]] inline size_t pendingBytes() const noexcept { return pendingBytes_; }
        [[nodiscard]] inline size_t writeHighWaterMark() const noexcept { return writeHighWaterMark_; }
        inline void setWriteHighWaterMark(size_t n) noexcept { writeHighWaterMark_ = n; }
        [[nodiscard]] inline bool closeAfterWrite() const noexcept { return closeAfterWrite_; }
        inline void setCloseAfterWrite(bool v) noexcept { closeAfterWrite_ = v; }
        [[nodiscard]] inline uint64_t timerId() const noexcept { return timerId_; }
        inline void setTimerId(uint64_t id) noexcept { timerId_ = id; }
        [[nodiscard]] inline std::chrono::steady_clock::time_point lastActive() const noexcept { return lastActive_; }
        inline void touch() noexcept { lastActive_ = std::chrono::steady_clock::now(); }

        [[nodiscard]] inline void *ssl() const noexcept;
        [[nodiscard]] inline bool ktlsRxActive() const noexcept;
        [[nodiscard]] inline bool ktlsTxActive() const noexcept;

        inline void pump() noexcept;
        inline bool commitSent(size_t n) noexcept;
        [[nodiscard]] inline bool hasQueuedWrite() const noexcept { return !writeQueue_.empty(); }
        [[nodiscard]] inline std::string_view frontWriteSpan() const noexcept
        {
            if (writeQueue_.empty() || writeOffset_ >= writeQueue_.front().size())
            {
                return {};
            }
            return std::string_view(writeQueue_.front()).substr(writeOffset_);
        }

        virtual void handle();
        [[nodiscard]] inline std::optional<IO_STATUS> tryHandleExternalIo(uint32_t events);
        [[nodiscard]] inline bool hasExternalDataPlane() const noexcept;
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

    inline int Handler::fd() const noexcept
    {
        return connection_ ? connection_->fd() : fd_;
    }

    // ---- ConnectionBase 对 HandlerConnection 的交互实现 ----

    inline Result<> Connection::appendRequest(const char *buf, ssize_t rn) noexcept
    {
        return handler_ != nullptr ? handler_->appendRequest(buf, rn) : Result<>{};
    }
    inline Result<> Connection::appendRequest(std::string_view sv) noexcept
    {
        return handler_ != nullptr ? handler_->appendRequest(sv) : Result<>{};
    }
    inline std::expected<char *, ERR> Connection::prepareRequestWritable(size_t minBytes) noexcept
    {
        return handler_ != nullptr ? handler_->prepareRequestWritable(minBytes)
                                   : std::unexpected(ERR::POOL_ALLOC_FAILED);
    }
    inline char *Connection::requestWritableBegin() noexcept
    {
        return handler_ != nullptr ? handler_->requestWritableBegin() : nullptr;
    }
    inline size_t Connection::requestWritableBytes() const noexcept
    {
        return handler_ != nullptr ? handler_->requestWritableBytes() : 0;
    }
    inline void Connection::commitRequest(size_t n) noexcept
    {
        if (handler_ != nullptr)
        {
            handler_->commitRequest(n);
        }
    }
    inline bool Connection::requestOverLimit() const noexcept
    {
        return handler_ != nullptr && handler_->requestOverLimit();
    }
    inline size_t Connection::requestBytes() const noexcept
    {
        return handler_ != nullptr ? handler_->requestBytes() : 0;
    }
    inline const char *Connection::requestBegin() const noexcept
    {
        return handler_ != nullptr ? handler_->requestBegin() : nullptr;
    }
    inline void Connection::requestConsume(size_t n) noexcept
    {
        if (handler_ != nullptr)
        {
            handler_->requestConsume(n);
        }
    }
    inline void Connection::requestClear() noexcept
    {
        if (handler_ != nullptr)
        {
            handler_->requestClear();
        }
    }
    inline size_t Connection::readCredit() const noexcept
    {
        return handler_ != nullptr ? handler_->readCredit() : 0;
    }
    inline void Connection::setMaxRequestBytes(size_t n) noexcept
    {
        if (handler_ != nullptr)
        {
            handler_->setMaxRequestBytes(n);
        }
    }
    inline size_t Connection::maxRequestBytes() const noexcept
    {
        return handler_ != nullptr ? handler_->maxRequestBytes() : getConnectionConfig().maxRequestBytes;
    }

    inline bool Connection::hasResponse() const noexcept
    {
        return handler_ != nullptr && handler_->hasResponse();
    }
    inline size_t Connection::responseCount() const noexcept
    {
        return handler_ != nullptr ? handler_->responseCount() : 0;
    }
    inline size_t Connection::responseCapacity() const noexcept
    {
        return handler_ != nullptr ? handler_->responseCapacity() : 0;
    }
    inline std::string Connection::takeResponse()
    {
        return handler_ != nullptr ? handler_->takeResponse() : std::string{};
    }
    inline void Connection::recycleSpare(std::string &&s) noexcept
    {
        if (handler_ != nullptr)
        {
            handler_->recycleSpare(std::move(s));
        }
    }
    inline Result<> Connection::pushResponse(std::string &&s) noexcept
    {
        return handler_ != nullptr ? handler_->pushResponse(std::move(s)) : Result<>{};
    }
    inline Result<> Connection::pushResponse(const std::string &s) noexcept
    {
        return handler_ != nullptr ? handler_->pushResponse(s) : Result<>{};
    }
    inline Result<> Connection::pushResponse(std::string_view sv) noexcept
    {
        return handler_ != nullptr ? handler_->pushResponse(sv) : Result<>{};
    }
    inline Result<> Connection::pushResponse(const char *s) noexcept
    {
        return handler_ != nullptr ? handler_->pushResponse(s) : Result<>{};
    }
    inline Result<> Connection::reserveResponses(size_t capacity) noexcept
    {
        return handler_ != nullptr ? handler_->reserveResponses(capacity) : Result<>{};
    }
    inline bool Connection::closeAfterResponse() const noexcept
    {
        return handler_ != nullptr && handler_->closeAfterResponse();
    }
    inline void Connection::setCloseAfterResponse(bool v) noexcept
    {
        if (handler_ != nullptr)
        {
            handler_->setCloseAfterResponse(v);
        }
    }

    inline void Connection::setFd(int fd) noexcept
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

    inline void Connection::setHandler(std::unique_ptr<Handler> h) noexcept
    {
        handler_ = std::move(h);
        if (handler_ != nullptr)
        {
            handler_->setConnection(this);
            if (fd_ >= 0)
            {
                handler_->onConnect(fd_);
            }
        }
    }

    inline void *Connection::ssl() const noexcept
    {
        return handler_ != nullptr ? std::as_const(*handler_).transportPipeline().nativeSslHandle() : nullptr;
    }

    inline bool Connection::ktlsRxActive() const noexcept
    {
        return handler_ != nullptr && std::as_const(*handler_).transportPipeline().ktlsRxActive();
    }

    inline bool Connection::ktlsTxActive() const noexcept
    {
        return handler_ != nullptr && std::as_const(*handler_).transportPipeline().ktlsTxActive();
    }

    inline bool Connection::hasPendingWrite() const noexcept
    {
        if (pendingBytes_ > 0)
        {
            return true;
        }
        if (handler_ != nullptr && handler_->hasResponse())
        {
            return true;
        }
        return false;
    }

    [[nodiscard]] inline constexpr bool isSpliceUnsupportedErrno(int err) noexcept
    {
        return err == EINVAL || err == EOPNOTSUPP || err == ENOTSUP || err == ESPIPE || err == EXDEV || err == ENOSYS;
    }

    inline void Connection::pump() noexcept
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
    }

    inline bool Connection::commitSent(size_t n) noexcept
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

    inline bool Connection::hasExternalDataPlane() const noexcept
    {
        return handler_ != nullptr && handler_->hasExternalDataPlane();
    }

    inline std::optional<IO_STATUS> Connection::tryHandleExternalIo(uint32_t events)
    {
        if (fd_ < 0)
        {
            return IO_STATUS::CLOSE;
        }
        if (handler_ == nullptr)
        {
            return std::nullopt;
        }
        const int rc = handler_->handleExternalReactorIo(events);
        if (rc < 0)
        {
            return std::nullopt;
        }
        touch();
        return (rc > 0) ? IO_STATUS::CLOSE : IO_STATUS::KEEP;
    }

    inline void Connection::handle()
    {
        if (handler_ != nullptr)
        {
            handler_->drive();
        }
    }

    inline IO_STATUS Connection::handleWrite()
    {
        if (fd_ < 0)
        {
            return IO_STATUS::CLOSE;
        }

        pump();

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

    inline IO_STATUS Connection::handleRead()
    {
        if (fd_ < 0)
        {
            return IO_STATUS::CLOSE;
        }

        if (handler_ != nullptr && handler_->shouldSuppressConnRecv())
        {
            return IO_STATUS::KEEP;
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
                handler_->drive();
                handler_->notifyExternalData();
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

    inline void Connection::close()
    {
        state_ = CONN_STATE::CLOSED;
        if (handler_ != nullptr)
        {
            handler_->notifyExternalClosed();
        }
        if (fd_ != -1)
        {
            ::close(fd_);
            fd_ = -1;
        }
    }

    inline void Connection::reset() noexcept
    {
        if (fd_ != -1)
        {
            ::close(fd_);
            fd_ = -1;
        }
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
        handler_.reset();
    }

} // namespace mynet
