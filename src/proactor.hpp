#pragma once

/**
 * @file proactor.hpp
 * @brief 高性能 Linux io_uring 前摄器（Proactor）服务器实现。
 */

#include "configHolder.hpp"
#include "connection.hpp"
#include "datagram.hpp"
#include "error.hpp"
#include "event.hpp"
#include "log_config.hpp"
#include "objectPool.hpp"
#include "tls.hpp"
#include <bit>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <liburing.h>
#include <optional>
#include <poll.h>
#include <stop_token>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace mynet
{

    /**
     * @class Proactor
     * @brief 基于 io_uring 完成事件驱动的高性能异步服务器引擎。
     *
     * 深度集成内核管理的 Buffer Ring 与 multishot 操作，实现零系统调用开销的极致异步 I/O。
     *
     * @tparam Event 满足 DerivedFromEventBase 与 Resettable 约束的套接字事件包装类型。
     */
    template <typename Event>
        requires DerivedFromEventBase<Event> && Resettable<Event> &&
                 (MandatoryMethodConnection<typename Event::Handler> ||
                  MandatoryMethodDatagram<typename Event::Handler>)
    class Proactor
    {
    public:
        using Handler = typename Event::Handler;
        using Conn = typename ConnectionSlot<Handler>::Type;

        ///
        /// 该处理器是否由 Connection 承载会话（即满足流式契约）。
        ///
        /// 为 false 时（纯数据报处理器）Conn 退化为 NoConnection，会话对象不再
        /// 携带流式状态；流式专用成员函数另以 kStreaming 约束自身，因此
        /// runUdp 不会被实例化到任何 Connection 代码。
        ///
        static constexpr bool kStreaming = MandatoryMethodConnection<Handler>;

        Proactor() noexcept = default;

        ~Proactor() noexcept { reset(); }

        Proactor(const Proactor &) = delete("a proactor owns the io_uring ring and the buffers handed to the kernel");
        Proactor &
        operator=(const Proactor &) = delete("a proactor owns the io_uring ring and the buffers handed to the kernel");
        Proactor(Proactor &&) noexcept =
            delete ("a proactor owns the io_uring ring and the buffers handed to the kernel");
        Proactor &operator=(Proactor &&) noexcept =
            delete ("a proactor owns the io_uring ring and the buffers handed to the kernel");

        /**
         * @brief 以全局配置（server + proactor 段）运行 TCP 服务器，直至被请求停止。
         * @param ip 监听 IPv4 地址字面量。
         * @param port 监听端口。
         * @return 正常停止返回 {}，启动或运行时失败返回错误码。
         */
        /**
         * @brief 完全以全局配置运行 TCP 服务器（监听地址取自 server.host/port）。
         */
        [[nodiscard]] Result<> runTcp()
            requires SocketEvent<Event> && kStreaming
        {
            const NetConfig cfg = getNetConfig();
            return runTcp(cfg.server.host.c_str(), static_cast<int>(cfg.server.port), cfg.server, cfg.proactor);
        }

        [[nodiscard]] Result<> runTcp(const char *ip, int port)
            requires SocketEvent<Event> && kStreaming
        {
            const NetConfig cfg = getNetConfig();
            return runTcp(ip, port, cfg.server, cfg.proactor);
        }

        /**
         * @brief 以显式配置运行 TCP 服务器，直至被请求停止。
         *
         * 监听参数取自 server 段，环/缓冲/池参数取自 proactor 段；两者都由
         * config.lua 解析并钳位，引擎侧不再保留任何默认实参。
         *
         * @param ip 监听 IPv4 地址字面量。
         * @param port 监听端口。
         * @param server 服务端传输配置（backlog / idleTimeoutSecs 等）。
         * @param proactor io_uring 队列、缓冲环与会话池配置。
         * @return 正常停止返回 {}，启动或运行时失败返回错误码。
         */
        [[nodiscard]] Result<> runTcp(const char *ip, int port, const ServerConfig &server,
                                      const ProactorConfig &proactor)
            requires SocketEvent<Event> && kStreaming
        {
            contract_assert(validServerConfig(server));
            contract_assert(validProactorConfig(proactor));
            if (auto err = acceptor_.listenTcp(ip, port, server.backlog); !err) [[unlikely]]
            {
                reset();
                return err;
            }
            Result<> rc = serve(server, proactor, true);
            reset();
            return rc;
        }

        /**
         * @brief 以全局配置运行 TLS/SSL 服务器，TLS 协商参数取自 security 段。
         * @param ip 监听 IPv4 地址字面量。
         * @param port 监听端口。
         * @param crt PEM 格式证书文件路径。
         * @param key PEM 格式私钥文件路径。
         * @return 正常停止返回 {}，启动或运行时失败返回错误码。
         */
        /**
         * @brief 完全以全局配置运行 TLS 服务器：监听地址与证书路径都取自配置段。
         *
         * 证书与私钥取自 security.certFile / security.keyFile；任一为空表示"未配置"，
         * 直接失败而不是悄悄降级成明文——TLS 服务端不应在配置缺失时静默裸奔。
         */
        [[nodiscard]] Result<> runSsl()
            requires SslEvent<Event> && kStreaming
        {
            const NetConfig cfg = getNetConfig();
            if (cfg.security.certFile.empty() || cfg.security.keyFile.empty()) [[unlikely]]
            {
                LOG_ERROR("runSsl: security.certFile / security.keyFile are empty; "
                          "set them in config.lua or call the explicit-path overload");
                return std::unexpected(ERR::SSL_CERT_FAILED);
            }
            return runSsl(cfg.server.host.c_str(), static_cast<int>(cfg.server.port), cfg.security.certFile.c_str(),
                          cfg.security.keyFile.c_str(), cfg.server, cfg.proactor,
                          detail::tlsOptionsFrom(cfg.security));
        }

        /**
         * @brief 以全局配置的监听地址 + 显式证书路径运行 TLS 服务器。
         */
        [[nodiscard]] Result<> runSsl(const char *crt, const char *key)
            requires SslEvent<Event> && kStreaming
        {
            const NetConfig cfg = getNetConfig();
            return runSsl(cfg.server.host.c_str(), static_cast<int>(cfg.server.port), crt, key, cfg.server,
                          cfg.proactor, detail::tlsOptionsFrom(cfg.security));
        }

        [[nodiscard]] Result<> runSsl(const char *ip, int port, const char *crt, const char *key)
            requires SslEvent<Event> && kStreaming
        {
            const NetConfig cfg = getNetConfig();
            return runSsl(ip, port, crt, key, cfg.server, cfg.proactor, detail::tlsOptionsFrom(cfg.security));
        }

        /**
         * @brief 以显式 TLS 选项 + 全局 server/proactor 配置运行 TLS/SSL 服务器。
         * @param ip 监听 IPv4 地址字面量。
         * @param port 监听端口。
         * @param crt PEM 格式证书文件路径。
         * @param key PEM 格式私钥文件路径。
         * @param tlsOptions TLS 版本、密码套件与 ALPN 协商选项。
         * @return 正常停止返回 {}，启动或运行时失败返回错误码。
         */
        [[nodiscard]] Result<> runSsl(const char *ip, int port, const char *crt, const char *key,
                                      const TlsOptions &tlsOptions)
            requires SslEvent<Event> && kStreaming
        {
            const NetConfig cfg = getNetConfig();
            return runSsl(ip, port, crt, key, cfg.server, cfg.proactor, tlsOptions);
        }

        /**
         * @brief 以显式配置运行 TLS/SSL 服务器，直至被请求停止。
         * @param ip 监听 IPv4 地址字面量。
         * @param port 监听端口。
         * @param crt PEM 格式证书文件路径。
         * @param key PEM 格式私钥文件路径。
         * @param server 服务端传输配置。
         * @param proactor io_uring 队列、缓冲环与会话池配置。
         * @param tlsOptions TLS 协商选项。
         * @return 正常停止返回 {}，启动或运行时失败返回错误码。
         */
        [[nodiscard]] Result<> runSsl(const char *ip, int port, const char *crt, const char *key,
                                      const ServerConfig &server, const ProactorConfig &proactor,
                                      const TlsOptions &tlsOptions)
            requires SslEvent<Event> && kStreaming
        {
            contract_assert(validServerConfig(server));
            contract_assert(validProactorConfig(proactor));
            if (auto err = acceptor_.listenTcp(ip, port, server.backlog); !err) [[unlikely]]
            {
                reset();
                return err;
            }
            if ((protocol_.ctx = SSL_CTX_new(TLS_server_method())) == nullptr) [[unlikely]]
            {
                LOG_ERROR("Proactor::runSsl: SSL_CTX_new() failed: {}", sslText());
                reset();
                return std::unexpected(ERR::SSL_CTX_FAILED);
            }
            tlsOptions_ = tlsOptions;
            if (auto err = detail::configureTlsContext(protocol_.ctx, tlsOptions_, true); !err) [[unlikely]]
            {
                LOG_ERROR("Proactor::runSsl: invalid TLS options: {}", sslText());
                reset();
                return err;
            }
            if (SSL_CTX_use_certificate_file(protocol_.ctx, crt, SSL_FILETYPE_PEM) <= 0) [[unlikely]]
            {
                LOG_ERROR("Proactor::runSsl: certificate file \"{}\" could not be loaded: {}", crt, sslText());
                reset();
                return std::unexpected(ERR::SSL_CERT_FAILED);
            }
            if (SSL_CTX_use_PrivateKey_file(protocol_.ctx, key, SSL_FILETYPE_PEM) <= 0) [[unlikely]]
            {
                LOG_ERROR("Proactor::runSsl: private key file \"{}\" could not be loaded: {}", key, sslText());
                reset();
                return std::unexpected(ERR::SSL_KEY_FAILED);
            }
            if (SSL_CTX_check_private_key(protocol_.ctx) <= 0) [[unlikely]]
            {
                LOG_ERROR("Proactor::runSsl: private key \"{}\" does not match certificate \"{}\": {}", key, crt,
                          sslText());
                reset();
                return std::unexpected(ERR::SSL_KEY_MISMATCH);
            }
            Result<> rc = serve(server, proactor, true);
            reset();
            return rc;
        }

        /**
         * @brief 以全局配置（proactor 段）运行 UDP 数据报服务器，直至被请求停止。
         * @param ip 监听 IPv4 地址字面量。
         * @param port 监听端口。
         * @param handler 数据报处理器引用。
         * @return 正常停止返回 {}，启动或运行时失败返回错误码。
         */
        [[nodiscard]] Result<> runUdp(const char *ip, int port, Handler &handler)
            requires MandatoryMethodDatagram<Handler>
        {
            const ProactorConfig cfg = getProactorConfig();
            return runUdp(ip, port, handler, cfg);
        }

        /**
         * @brief 以显式配置运行 UDP 数据报服务器，直至被请求停止。
         *
         * UDP 路径不建立内核 Buffer Ring，proactor.bufEntries 被忽略；
         * proactor.udpBufSize 只作为**接收窗口下限**，真正的接收上界由处理器的
         * maxDatagramBytes() 决定，两者取较大者并额外留 1 字节用于超界判定，
         * 因此两个引擎交付给处理器的报文长度上界一致。
         *
         * @param ip 监听 IPv4 地址字面量。
         * @param port 监听端口。
         * @param handler 数据报处理器引用。
         * @param proactor io_uring 队列、会话池与 UDP 接收窗口配置。
         * @return 正常停止返回 {}，启动或运行时失败返回错误码。
         */
        [[nodiscard]] Result<> runUdp(const char *ip, int port, Handler &handler, const ProactorConfig &proactor)
            requires MandatoryMethodDatagram<Handler>
        {
            contract_assert(validProactorConfig(proactor));
            if (auto err = acceptor_.listenUdp(ip, port); !err) [[unlikely]]
            {
                reset();
                return err;
            }
            handler.reset();
            datagram_.bind(handler, proactor.udpBufSize);
            // UDP 只占用 1 个会话槽，server.maxConnections 对它没有意义，
            // 这里仍当前置条件校验（值本身必须合法），但不参与分配。
            const ServerConfig server = getServerConfig();
            Result<> rc = serve(server, proactor, false);
            reset();
            return rc;
        }

        /**
         * @brief 优雅停止 proactor 事件循环。
         */
        inline void stop() const noexcept { stopSource_.request_stop(); }

        /**
         * @brief io_uring 核心事件循环。
         */
        [[nodiscard]] inline Result<> serve(const ServerConfig &server, const ProactorConfig &proactor,
                                            bool withBufRing)
        {
            // 配置在 lua_config 解析阶段已完成钳位，这里不再重复兜底，
            // 避免引擎头文件与 config.lua 两处默认值分叉。
            contract_assert(validServerConfig(server));
            contract_assert(validProactorConfig(proactor));
            io_uring_params params = {};
            params.flags = IORING_SETUP_CQSIZE;
            params.cq_entries = static_cast<unsigned int>(proactor.cqEntries);
            int qi = io_uring_queue_init_params(static_cast<unsigned int>(proactor.sqEntries), &uring_, &params);
            if (qi < 0) [[unlikely]]
            {
                LOG_ERROR("Proactor::serve: io_uring_queue_init_params({} sq entries) failed: {}", proactor.sqEntries,
                          errnoText(-qi));
                reset();
                return std::unexpected(ERR::URING_QUEUE_FAILED);
            }
            uringInited_ = true;
            const size_t sessionSlots = datagram_.bound() ? 1 : server.maxConnections;
            if (auto poolRes = sessionPool_.init(sessionSlots); !poolRes) [[unlikely]]
            {
                LOG_ERROR("Proactor::serve: initialising session pool ({} slots) failed", sessionSlots);
                reset();
                return std::unexpected(ERR::POOL_ALLOC_FAILED);
            }
            // 数据报路径不投递任何 accept，旧实现以 maxAcceptEvents=0 调用时
            // 会退化成 1 槽。这里保留同样的 1 槽，而不是白占 maxAcceptEvents 份内存。
            const size_t acceptSlots = datagram_.bound() ? 1 : proactor.maxAcceptEvents;
            if (auto poolRes = acceptPool_.init(acceptSlots); !poolRes) [[unlikely]]
            {
                LOG_ERROR("Proactor::serve: initialising accept pool ({} slots) failed", acceptSlots);
                reset();
                return std::unexpected(ERR::POOL_ALLOC_FAILED);
            }
            sessions_.reserve(sessionSlots);
            maxAccepts_ = static_cast<int>(proactor.maxAcceptEvents);
            maxBufEntrs_ =
                withBufRing ? static_cast<int>(std::bit_ceil(static_cast<unsigned int>(proactor.bufEntries))) : 0;
            bufSize_ = static_cast<int>(proactor.bufSize);
            if (maxBufEntrs_ > 0)
            {
                int ma = posix_memalign(&bufBase_, proactor.bufRingAlignment,
                                        static_cast<size_t>(maxBufEntrs_) * static_cast<size_t>(bufSize_));
                if (ma != 0) [[unlikely]]
                {
                    LOG_ERROR("Proactor::serve: posix_memalign for {} buffers of {} bytes failed: {}", maxBufEntrs_,
                              bufSize_, errnoText(ma));
                    bufBase_ = nullptr;
                    reset();
                    return std::unexpected(ERR::URING_MEMALIGN_FAILED);
                }
                int ringErr = 0;
                bufRing_ = io_uring_setup_buf_ring(&uring_, static_cast<unsigned>(maxBufEntrs_), bgid_, 0, &ringErr);
                if (bufRing_ == nullptr) [[unlikely]]
                {
                    LOG_ERROR("Proactor::serve: io_uring_setup_buf_ring({} buffers, bgid {}) failed: {}", maxBufEntrs_,
                              bgid_, errnoText(ringErr));
                    reset();
                    return std::unexpected(ERR::URING_BUF_RING_FAILED);
                }
                for (int i = 0; i < maxBufEntrs_; ++i)
                {
                    io_uring_buf_ring_add(bufRing_,
                                          reinterpret_cast<char *>(bufBase_) +
                                              static_cast<size_t>(i) * static_cast<size_t>(bufSize_),
                                          static_cast<unsigned int>(bufSize_), i,
                                          io_uring_buf_ring_mask(static_cast<unsigned>(maxBufEntrs_)), i);
                }
                io_uring_buf_ring_advance(bufRing_, maxBufEntrs_);
            }
            idleTimeout_ = std::chrono::seconds(server.idleTimeoutSecs > 0 ? server.idleTimeoutSecs : 0);
            Result<> armed = {};
            if constexpr (kStreaming)
            {
                armed = datagram_.bound() ? postDatagramRecv() : postAccepts(maxAccepts_);
            }
            else
            {
                armed = postDatagramRecv();
            }
            if (!armed) [[unlikely]]
            {
                reset();
                return armed;
            }
            int si = io_uring_submit(&uring_);
            if (si < 0) [[unlikely]]
            {
                LOG_ERROR("Proactor::serve: submitting initial accepts failed: {}", errnoText(-si));
                reset();
                return std::unexpected(ERR::URING_SUBMIT_FAILED);
            }
            __kernel_timespec ts = {proactor.cqeWaitMs / 1000, (proactor.cqeWaitMs % 1000) * 1000000L};
            while (!stopSource_.stop_requested())
            {
                io_uring_cqe *cqe = nullptr;
                int e = io_uring_wait_cqe_timeout(&uring_, &cqe, &ts);
                if (e == -ETIME || e == -EINTR)
                {
                    if constexpr (kStreaming)
                    {
                        sweepIdle();
                        postCancels();
                    }
                    int subRet = io_uring_submit(&uring_);
                    if (subRet < 0) [[unlikely]]
                    {
                        LOG_ERROR("Proactor::serve: submitting cancel batch failed: {}", errnoText(-subRet));
                    }
                    continue;
                }
                if (e < 0) [[unlikely]]
                {
                    LOG_ERROR("Proactor::serve: io_uring_wait_cqe_timeout() failed: {}", errnoText(-e));
                    reset();
                    return std::unexpected(ERR::URING_WAIT_FAILED);
                }
                unsigned int head = 0;
                unsigned int count = 0;
                io_uring_for_each_cqe(&uring_, head, cqe)
                {
                    ++count;
                    handleCqe(cqe);
                }
                io_uring_cq_advance(&uring_, count);
                if constexpr (kStreaming)
                {
                    while (!datagram_.bound() && acceptOutstanding_ < maxAccepts_)
                    {
                        if (!postOneAccept())
                        {
                            break;
                        }
                    }
                }
                if constexpr (kStreaming)
                {
                    postCancels();
                }
                int subRet = io_uring_submit(&uring_);
                if (subRet < 0) [[unlikely]]
                {
                    LOG_ERROR("Proactor::serve: submitting completion batch failed: {}", errnoText(-subRet));
                    reset();
                    return std::unexpected(ERR::URING_SUBMIT_FAILED);
                }
                if constexpr (kStreaming)
                {
                    sweepIdle();
                }
            }
            reset();
            return {};
        }

        /**
         * @brief 重置 proactor 状态并回收全部关联资源。
         */
        inline void reset() noexcept
        {
            if (bufRing_ != nullptr && uringInited_)
            {
                io_uring_free_buf_ring(&uring_, bufRing_, static_cast<unsigned>(maxBufEntrs_), bgid_);
                bufRing_ = nullptr;
            }
            if (bufBase_ != nullptr)
            {
                ::free(bufBase_);
                bufBase_ = nullptr;
            }
            maxBufEntrs_ = 0;
            bufSize_ = 0;
            bgid_ = 1;
            acceptPool_.reset();
            sessionPool_.reset();
            sessions_.clear();
            acceptOutstanding_ = 0;
            maxAccepts_ = 0;
            idleTimeout_ = std::chrono::seconds(0);
            if (uringInited_)
            {
                io_uring_queue_exit(&uring_);
                uring_ = {};
                uringInited_ = false;
            }
            acceptor_.reset();
            datagram_.reset();
            cancelScratch_.clear();
            if constexpr (SslEvent<Event>)
            {
                if (protocol_.ctx != nullptr)
                {
                    SSL_CTX_free(protocol_.ctx);
                    protocol_.ctx = nullptr;
                }
            }
            tlsOptions_ = {};
        }

        [[nodiscard]] inline size_t sessions() const noexcept { return sessions_.size(); }

        [[nodiscard]] inline io_uring *ring() noexcept { return &uring_; }

    private:
        enum class OP_KIND : uint8_t
        {
            ACCEPT = 1,
            RECV = 2,
            SEND = 3,
            POLL = 4,
            DATAGRAM = 5
        };

        struct Session;

        struct OpBase
        {
            OP_KIND kind{};
            Session *session = nullptr;
        };

        struct Session
        {
            Conn conn{};
            OpBase recvOp{OP_KIND::RECV, this};
            OpBase sendOp{OP_KIND::SEND, this};
            OpBase pollOp{OP_KIND::POLL, this};
            size_t slot = 0;
            int inFlight = 0;
            bool dead = false;
            bool recycled = false;
            bool recvPosted = false;
            bool sendPosted = false;
            bool pollPosted = false;
            bool pollRetired = false;
            bool inCancelQueue = false;

            inline void reset() noexcept
            {
                conn.reset();
                slot = 0;
                inFlight = 0;
                dead = false;
                recycled = false;
                recvPosted = false;
                sendPosted = false;
                pollPosted = false;
                pollRetired = false;
                inCancelQueue = false;
            }
        };

        struct AcceptOp : public OpBase
        {
            AcceptOp() noexcept { this->kind = OP_KIND::ACCEPT; }

            sockaddr_in addr{};
            socklen_t addrLen = static_cast<socklen_t>(sizeof(sockaddr_in));

            inline void reset() noexcept
            {
                addr = {};
                addrLen = static_cast<socklen_t>(sizeof(sockaddr_in));
            }
        };

        struct DatagramOp : public OpBase
        {
            DatagramOp() noexcept { this->kind = OP_KIND::DATAGRAM; }

            sockaddr_in peer{};
            struct iovec iov{};
            struct msghdr msg{};
        };

        inline void handleCqe(io_uring_cqe *cqe)
        {
            auto *base = static_cast<OpBase *>(io_uring_cqe_get_data(cqe));
            if (base == nullptr) [[unlikely]]
            {
                return;
            }
            switch (base->kind)
            {
            case OP_KIND::ACCEPT:
                if constexpr (kStreaming)
                {
                    onAcceptDone(cqe, static_cast<AcceptOp *>(base));
                }
                break;
            case OP_KIND::RECV:
                if constexpr (kStreaming)
                {
                    onRecvDone(cqe, base->session);
                }
                break;
            case OP_KIND::SEND:
                if constexpr (kStreaming)
                {
                    onSendDone(cqe, base->session);
                }
                break;
            case OP_KIND::POLL:
                if constexpr (kStreaming)
                {
                    onPollDone(cqe, base->session);
                }
                break;
            case OP_KIND::DATAGRAM:
                onDatagramDone(cqe);
                break;
            }
        }

        inline void onDatagramDone(io_uring_cqe *cqe)
        {
            if (cqe->res < 0) [[unlikely]]
            {
                LOG_WARN("Proactor::onDatagramDone: recvmsg on fd {} failed: {}", acceptor_.fd, errnoText(-cqe->res));
            }
            else if (cqe->res > 0)
            {
                // 内核侧 MSG_TRUNC 只是冗余的双保险：Datagram::bind 保证窗口 ≥
                // 上界+1，所以任何超出上界的报文都一定会在 receiveFrom 的
                // n > cap 判定里被抓到。这里保留它，是因为它反映的是内核视角
                // （报文被 socket 缓冲区截断），与本库的上界判定不是同一件事。
                if ((datagramOp_.msg.msg_flags & MSG_TRUNC) != 0) [[unlikely]]
                {
                    LOG_WARN("Proactor::onDatagramDone: datagram from {} was truncated",
                             datagramPeerText(datagramOp_.peer));
                }
                datagram_.receiveFrom(datagramOp_.peer, datagram_.recvBuffer(), static_cast<size_t>(cqe->res));
                [[maybe_unused]] auto _ = datagram_.handleWrite(acceptor_.fd);
            }
            if (!stopSource_.stop_requested())
            {
                if (auto rc = postDatagramRecv(); !rc) [[unlikely]]
                {
                    LOG_ERROR("Proactor::onDatagramDone: re-arming datagram read failed: {}", toString(rc.error()));
                }
            }
        }

        [[nodiscard]] inline Result<> postDatagramRecv()
        {
            io_uring_sqe *sqe = getSqe();
            if (sqe == nullptr) [[unlikely]]
            {
                return std::unexpected(ERR::URING_SQE_FAILED);
            }
            datagramOp_.peer = {};
            datagramOp_.iov.iov_base = datagram_.recvBuffer();
            datagramOp_.iov.iov_len = datagram_.recvCapacity();
            datagramOp_.msg = {};
            datagramOp_.msg.msg_name = &datagramOp_.peer;
            datagramOp_.msg.msg_namelen = static_cast<socklen_t>(sizeof(sockaddr_in));
            datagramOp_.msg.msg_iov = &datagramOp_.iov;
            datagramOp_.msg.msg_iovlen = 1;
            io_uring_prep_recvmsg(sqe, acceptor_.fd, &datagramOp_.msg, 0);
            io_uring_sqe_set_data(sqe, &datagramOp_);
            return {};
        }

        [[nodiscard]] inline Result<> postAccepts(int count)
            requires kStreaming
        {
            for (int i = 0; i < count; ++i)
            {
                if (auto rc = postOneAccept(); !rc) [[unlikely]]
                {
                    return rc;
                }
            }
            return {};
        }

        inline io_uring_sqe *getSqe()
        {
            io_uring_sqe *sqe = io_uring_get_sqe(&uring_);
            if (sqe != nullptr)
            {
                return sqe;
            }
            int si = io_uring_submit(&uring_);
            if (si < 0) [[unlikely]]
            {
                LOG_ERROR("Proactor::getSqe: flushing full submission queue failed: {}", errnoText(-si));
                return nullptr;
            }
            return io_uring_get_sqe(&uring_);
        }

        [[nodiscard]] inline Result<> postOneAccept()
            requires kStreaming
        {
            AcceptOp *op = acceptPool_.acquire();
            if (op == nullptr) [[unlikely]]
            {
                LOG_WARN("Proactor::postOneAccept: all {} accept slots are in use", maxAccepts_);
                return std::unexpected(ERR::URING_ACCEPT_EXHAUSTED);
            }
            io_uring_sqe *sqe = getSqe();
            if (sqe == nullptr) [[unlikely]]
            {
                LOG_WARN("Proactor::postOneAccept: no submission queue entry available");
                acceptPool_.release(op);
                return std::unexpected(ERR::URING_SQE_FAILED);
            }
            op->addrLen = static_cast<socklen_t>(sizeof(sockaddr_in));
            io_uring_prep_accept(sqe, acceptor_.fd, reinterpret_cast<sockaddr *>(&op->addr), &op->addrLen,
                                 SOCK_NONBLOCK | SOCK_CLOEXEC);
            io_uring_sqe_set_data(sqe, op);
            ++acceptOutstanding_;
            return {};
        }

        inline void onAcceptDone(io_uring_cqe *cqe, AcceptOp *op)
            requires kStreaming
        {
            --acceptOutstanding_;
            if (cqe->res >= 0)
            {
                onNewConnection(cqe->res, op->addr);
            }
            else
            {
                LOG_DEBUG("Proactor::onAcceptDone: accept() failed: {}", errnoText(-cqe->res));
            }
            acceptPool_.release(op);
        }

        inline void onNewConnection(int fd, const sockaddr_in &addr)
        {
            Session *session = sessionPool_.acquire();
            if (session == nullptr) [[unlikely]]
            {
                LOG_WARN("Proactor::onNewConnection: session pool exhausted, closing fd {}", fd);
                ::close(fd);
                return;
            }
            session->dead = false;
            session->recycled = false;
            session->inFlight = 0;
            session->recvPosted = false;
            session->sendPosted = false;
            session->pollPosted = false;
            session->pollRetired = false;
            session->inCancelQueue = false;
            session->conn.setFd(fd);
            session->conn.addr() = addr;
            session->conn.touch();
            if constexpr (SslEvent<Event>)
            {
                if (protocol_.ctx == nullptr || !session->conn.startTLS(protocol_.ctx)) [[unlikely]]
                {
                    LOG_WARN("Proactor::onNewConnection: TLS setup for fd {} failed: {}", fd, sslText());
                    sessionPool_.release(session);
                    return;
                }
            }
            session->slot = sessions_.size();
            sessions_.push_back(session);
            if (postRecv(session) == IO_STATUS::CLOSE)
            {
                closeSession(session);
            }
        }

        [[nodiscard]] inline IO_STATUS postPoll(Session *session)
            requires kStreaming
        {
            Conn &conn = session->conn;
            unsigned int mask = 0;
            if (conn.wantRead())
            {
                mask |= POLLIN;
            }
            if (conn.writeBlocked())
            {
                mask |= POLLOUT;
            }
            if (mask == 0)
            {
                return IO_STATUS::CLOSE;
            }
            io_uring_sqe *sqe = getSqe();
            if (sqe == nullptr) [[unlikely]]
            {
                LOG_WARN("Proactor::postPoll: no submission queue entry for fd {}", conn.fd());
                return IO_STATUS::CLOSE;
            }
            io_uring_prep_poll_add(sqe, conn.fd(), mask);
            io_uring_sqe_set_data(sqe, &session->pollOp);
            session->pollPosted = true;
            ++session->inFlight;
            return IO_STATUS::KEEP;
        }

        [[nodiscard]] inline IO_STATUS postRecv(Session *session)
            requires kStreaming
        {
            // kTLS RX offload 生效的 TLS 会话：内核已解密，recv 直接吐明文，
            // 可复用 multishot + buffer ring 快路径；其余 TLS 会话仍走 poll→同步 SSL_read；
            // 启用 splice 零拷贝的会话走 poll→handleRead(handleSplice)
            if ((session->conn.ssl() != nullptr && !session->conn.ktlsRxActive()) || session->conn.isSpliceEnabled())
            {
                return postPoll(session);
            }
            io_uring_sqe *sqe = getSqe();
            if (sqe == nullptr) [[unlikely]]
            {
                LOG_WARN("Proactor::postRecv: no submission queue entry for fd {}", session->conn.fd());
                return IO_STATUS::CLOSE;
            }
            io_uring_prep_recv_multishot(sqe, session->conn.fd(), nullptr, 0, 0);
            sqe->buf_group = static_cast<uint16_t>(bgid_);
            sqe->flags |= IOSQE_BUFFER_SELECT;
            io_uring_sqe_set_data(sqe, &session->recvOp);
            session->recvPosted = true;
            ++session->inFlight;
            return IO_STATUS::KEEP;
        }

        inline void onRecvDone(io_uring_cqe *cqe, Session *session)
            requires kStreaming
        {
            if (session->conn.ssl() != nullptr && !session->conn.ktlsRxActive())
            {
                if (!(cqe->flags & IORING_CQE_F_MORE))
                {
                    session->recvPosted = false;
                    --session->inFlight;
                }
                settleSession(session);
                return;
            }
            if (!(cqe->flags & IORING_CQE_F_MORE))
            {
                session->recvPosted = false;
                --session->inFlight;
            }
            bool peerGone = false;
            bool fatal = false;
            if (cqe->res == 0)
            {
                peerGone = true;
            }
            else if (cqe->res < 0)
            {
                int err = -cqe->res;
                if (err == ECANCELED)
                {
                    peerGone = true;
                }
                else if (err == EAGAIN || err == EWOULDBLOCK || err == EINTR || err == ENOBUFS)
                {
                }
                else
                {
                    LOG_WARN("Proactor::onRecvDone: fd {}: recv() failed: {}", session->conn.fd(), errnoText(err));
                    fatal = true;
                }
            }
            else if (cqe->flags & IORING_CQE_F_BUFFER)
            {
                unsigned int bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
                if (static_cast<int>(bid) < maxBufEntrs_)
                {
                    if (!session->dead)
                    {
                        char *buf = reinterpret_cast<char *>(bufBase_) +
                                    static_cast<size_t>(bid) * static_cast<size_t>(bufSize_);
                        Handler &handler = session->conn.handler();
                        // Proactor 直接调用 handler.appendRequest，不经过
                        // Connection::handleRead，因此 quick ack 必须在这里重置；
                        // 否则 io_uring 路径上它只在建连时生效一次。
                        session->conn.applyQuickAck();
                        if (!handler.appendRequest(buf, static_cast<ssize_t>(cqe->res))) [[unlikely]]
                        {
                            // 解析缓冲扩容失败：请求流断裂，降级关闭会话；本次读缓冲已回收，避免泄漏 fd 与会话槽
                            LOG_ERROR("Proactor: appendRequest failed (allocation), fd {} closing", session->conn.fd());
                            recycleBuffer(bid);
                            closeSession(session);
                            settleSession(session);
                            return;
                        }
                        if (handler.requestOverLimit()) [[unlikely]]
                        {
                            handler.onParseError("request exceeds the read limit");
                            session->conn.setCloseAfterWrite(true);
                        }
                        else
                        {
                            if constexpr (requires { handler.process(); })
                            {
                                handler.process();
                            }
                            else
                            {
                                handler.echo();
                            }
                        }
                        session->conn.touch();
                        recycleBuffer(bid);
                        session->conn.pump();
                        sendPending(session);
                    }
                    else
                    {
                        recycleBuffer(bid);
                    }
                }
            }
            if (fatal) [[unlikely]]
            {
                session->conn.onFatal();
                closeSession(session);
                settleSession(session);
                return;
            }
            if (peerGone)
            {
                session->conn.onPeerGone();
                if (session->conn.pendingSize() == 0)
                {
                    closeSession(session);
                    settleSession(session);
                    return;
                }
                if (!session->sendPosted)
                {
                    sendPending(session);
                }
            }
            else if (!session->dead && !session->recvPosted)
            {
                if (postRecv(session) == IO_STATUS::CLOSE)
                {
                    closeSession(session);
                }
            }
            settleSession(session);
        }

        inline void onPollDone(io_uring_cqe *cqe, Session *session)
            requires kStreaming
        {
            if (!session->pollPosted && !session->pollRetired) [[unlikely]]
            {
                return;
            }
            session->pollPosted = false;
            bool retired = session->pollRetired;
            session->pollRetired = false;
            --session->inFlight;
            if (retired)
            {
                settleSession(session);
                return;
            }
            Conn &conn = session->conn;
            if (cqe->res < 0) [[unlikely]]
            {
                int err = -cqe->res;
                if (err != EAGAIN && err != EWOULDBLOCK && err != EINTR)
                {
                    LOG_WARN("Proactor::onPollDone: fd {}: poll() failed: {}", conn.fd(), errnoText(err));
                    conn.onFatal();
                    closeSession(session);
                }
                else if (postPoll(session) == IO_STATUS::CLOSE)
                {
                    closeSession(session);
                }
                settleSession(session);
                return;
            }
            if ((cqe->res & (POLLERR | POLLHUP)) && !(cqe->res & POLLIN)) [[unlikely]]
            {
                closeSession(session);
                settleSession(session);
                return;
            }
            if (cqe->res & POLLIN)
            {
                if (conn.handleRead() == IO_STATUS::CLOSE) [[unlikely]]
                {
                    closeSession(session);
                    settleSession(session);
                    return;
                }
            }
            if (cqe->res & POLLOUT)
            {
                if (conn.handleWrite() == IO_STATUS::CLOSE) [[unlikely]]
                {
                    closeSession(session);
                    settleSession(session);
                    return;
                }
            }
            conn.pump();
            if (postPoll(session) == IO_STATUS::CLOSE)
            {
                closeSession(session);
            }
            settleSession(session);
        }

        inline void sendPending(Session *session)
        {
            if (session->sendPosted || session->dead)
            {
                return;
            }
            Conn &conn = session->conn;
            // kTLS RX 会话的接收已走 buffer ring 快路径，但发送仍需同步 SSL_write（TX 未 offload）
            if (conn.ssl() != nullptr)
            {
                return;
            }
            size_t n = conn.pendingSize();
            if (n == 0)
            {
                if (conn.closeAfterWrite())
                {
                    closeSession(session);
                }
                return;
            }
            io_uring_sqe *sqe = getSqe();
            if (sqe == nullptr) [[unlikely]]
            {
                LOG_WARN("Proactor::sendPending: no submission queue entry for fd {}", conn.fd());
                closeSession(session);
                return;
            }
            io_uring_prep_send(sqe, conn.fd(), conn.pendingData(), n, MSG_NOSIGNAL);
            io_uring_sqe_set_data(sqe, &session->sendOp);
            session->sendPosted = true;
            ++session->inFlight;
        }

        inline void onSendDone(io_uring_cqe *cqe, Session *session)
            requires kStreaming
        {
            --session->inFlight;
            session->sendPosted = false;
            if (cqe->res < 0) [[unlikely]]
            {
                int err = -cqe->res;
                if (err == ECANCELED)
                {
                    settleSession(session);
                    return;
                }
                if (err != EAGAIN && err != EWOULDBLOCK && err != EINTR)
                {
                    LOG_WARN("Proactor::onSendDone: fd {}: send() failed: {}", session->conn.fd(), errnoText(err));
                    session->conn.onFatal();
                    closeSession(session);
                    settleSession(session);
                    return;
                }
            }
            else if (cqe->res > 0)
            {
                [[maybe_unused]] auto _ = session->conn.commitSent(static_cast<size_t>(cqe->res));
                session->conn.touch();
            }
            else [[unlikely]]
            {
                LOG_WARN("Proactor::onSendDone: fd {}: send() completed without moving bytes", session->conn.fd());
                session->conn.onFatal();
                closeSession(session);
                settleSession(session);
                return;
            }
            if (session->dead)
            {
                settleSession(session);
                return;
            }
            if (session->conn.closeAfterWrite() && session->conn.pendingSize() == 0)
            {
                closeSession(session);
                settleSession(session);
                return;
            }
            sendPending(session);
            settleSession(session);
        }

        inline void closeSession(Session *session)
            requires kStreaming
        {
            if (session->dead)
            {
                return;
            }
            session->dead = true;
            if (session->pollPosted)
            {
                session->pollRetired = true;
            }
            if (session->inFlight > 0)
            {
                if (!session->inCancelQueue)
                {
                    cancelScratch_.push_back(session);
                    session->inCancelQueue = true;
                }
            }
            else
            {
                recycleSession(session);
            }
        }

        inline void postCancels()
            requires kStreaming
        {
            size_t done = 0;
            for (Session *session : cancelScratch_)
            {
                bool sqeAvailable = true;
                if (session->inFlight > 0)
                {
                    if (session->pollPosted || session->pollRetired)
                    {
                        io_uring_sqe *sqe = io_uring_get_sqe(&uring_);
                        if (sqe == nullptr)
                        {
                            sqeAvailable = false;
                        }
                        else
                        {
                            io_uring_prep_poll_remove(sqe, reinterpret_cast<uint64_t>(&session->pollOp));
                            io_uring_sqe_set_data(sqe, nullptr);
                        }
                    }
                    if (sqeAvailable && session->recvPosted)
                    {
                        io_uring_sqe *sqe = io_uring_get_sqe(&uring_);
                        if (sqe == nullptr)
                        {
                            sqeAvailable = false;
                        }
                        else
                        {
                            io_uring_prep_cancel64(sqe, reinterpret_cast<uint64_t>(&session->recvOp), 0);
                            io_uring_sqe_set_data(sqe, nullptr);
                        }
                    }
                    if (sqeAvailable && session->sendPosted)
                    {
                        io_uring_sqe *sqe = io_uring_get_sqe(&uring_);
                        if (sqe == nullptr)
                        {
                            sqeAvailable = false;
                        }
                        else
                        {
                            io_uring_prep_cancel64(sqe, reinterpret_cast<uint64_t>(&session->sendOp), 0);
                            io_uring_sqe_set_data(sqe, nullptr);
                        }
                    }
                }
                if (!sqeAvailable)
                {
                    break;
                }
                session->inCancelQueue = false;
                ++done;
            }
            if (done > 0)
            {
                std::vector<Session *> processed(cancelScratch_.begin(),
                                                 cancelScratch_.begin() + static_cast<long>(done));
                cancelScratch_.erase(cancelScratch_.begin(), cancelScratch_.begin() + static_cast<long>(done));
                for (Session *s : processed)
                {
                    settleSession(s);
                }
            }
        }

        inline void settleSession(Session *session)
            requires kStreaming
        {
            if (session->dead && session->inFlight == 0 && !session->inCancelQueue)
            {
                recycleSession(session);
            }
        }

        inline void recycleSession(Session *session)
        {
            if (session->recycled)
            {
                return;
            }
            session->recycled = true;
            size_t slot = session->slot;
            if (slot < sessions_.size() && sessions_[slot] == session)
            {
                sessions_[slot] = sessions_.back();
                sessions_[slot]->slot = slot;
                sessions_.pop_back();
            }
            sessionPool_.release(session);
        }

        inline void recycleBuffer(unsigned int bid)
        {
            if (bufRing_ == nullptr)
            {
                return;
            }
            io_uring_buf_ring_add(
                bufRing_, reinterpret_cast<char *>(bufBase_) + static_cast<size_t>(bid) * static_cast<size_t>(bufSize_),
                static_cast<unsigned int>(bufSize_), static_cast<int>(bid),
                io_uring_buf_ring_mask(static_cast<unsigned>(maxBufEntrs_)), 0);
            io_uring_buf_ring_advance(bufRing_, 1);
        }

        inline void sweepIdle()
            requires kStreaming
        {
            if (idleTimeout_.count() <= 0)
            {
                return;
            }
            auto now = std::chrono::steady_clock::now();
            sweepScratch_.clear();
            for (Session *session : sessions_)
            {
                if (now - session->conn.lastActive() >= idleTimeout_)
                {
                    sweepScratch_.push_back(session);
                }
            }
            for (Session *session : sweepScratch_)
            {
                closeSession(session);
            }
        }

        io_uring uring_{};
        bool uringInited_ = false;
        int bgid_ = 1;
        io_uring_buf_ring *bufRing_ = nullptr;
        int maxBufEntrs_ = 0;
        int bufSize_ = 0;
        void *bufBase_ = nullptr;
        Event acceptor_;
        Protocol<Event> protocol_{};
        ObjectPool<Session> sessionPool_{};
        ObjectPool<AcceptOp> acceptPool_{};
        std::vector<Session *> sessions_{};
        std::vector<Session *> sweepScratch_{};
        std::vector<Session *> cancelScratch_{};
        int acceptOutstanding_ = 0;
        int maxAccepts_ = 0;
        typename DatagramSlot<Handler>::Type datagram_{};
        TlsOptions tlsOptions_{};
        DatagramOp datagramOp_{};
        std::chrono::seconds idleTimeout_{0};
        std::stop_source stopSource_{};
    };

} // namespace mynet
