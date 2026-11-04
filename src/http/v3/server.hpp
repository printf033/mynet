#pragma once

/**
 * @file http/v3/server.hpp
 * @brief RFC 9114 HTTP/3 标准服务端引擎（基于 OpenSSL 3.6 QUIC 传输层）。
 *
 * 架构特性：
 * 1. 原生 QUIC 传输：集成 OpenSSL 3.6+ OSSL_QUIC_server_method，完整承载 TLS 1.3 握手、
 *    ALPN 协商（h3）、流多路复用与拥塞控制；
 * 2. 状态机驱动：建立单向控制流发送 HTTP/3 SETTINGS，管理双向流 HTTP/3 分帧与 QPACK 首部解压；
 * 3. 业务逻辑解耦：解复用 HTTP/3 请求后直接回调 HandlerHttp3::onRequest 钩子，支持任意自定义扩展；
 * 4. 标准客户端无缝互通：经由标准 curl --http3 验证（GET / POST 请求、响应首部与载荷回显）。
 */

#include "../../error.hpp"
#include "../../log_config.hpp"
#include "../../requestBuffer.hpp"
#include "../../tls.hpp"
#include "frame.hpp"
#include "handler.hpp"
#include "qpack.hpp"
#include <arpa/inet.h>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <memory>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/quic.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

namespace mynet
{
    namespace http::v3
    {
        /**
         * @class ServerHttp3
         * @brief RFC 9114 HTTP/3 服务端运行引擎
         */
        class ServerHttp3
        {
        public:
            ServerHttp3(std::string certPath = "", std::string keyPath = "") noexcept
                : certPath_(certPath.empty() ? (getSecurityConfig().certFile.empty() ? "certs/ser.crt"
                                                                                     : getSecurityConfig().certFile)
                                             : std::move(certPath)),
                  keyPath_(keyPath.empty()
                               ? (getSecurityConfig().keyFile.empty() ? "certs/ser.key" : getSecurityConfig().keyFile)
                               : std::move(keyPath))
            {
            }

            ~ServerHttp3() noexcept { stop(); }

            ServerHttp3(const ServerHttp3 &) = delete;
            ServerHttp3 &operator=(const ServerHttp3 &) = delete;
            ServerHttp3(ServerHttp3 &&) = delete;
            ServerHttp3 &operator=(ServerHttp3 &&) = delete;

            /**
             * @brief 配置 TLS 凭证文件路径
             */
            void setTlsCredentials(std::string certPath, std::string keyPath)
            {
                certPath_ = std::move(certPath);
                keyPath_ = std::move(keyPath);
            }

            /**
             * @brief 请求服务端事件循环安全退出
             */
            void stop() noexcept { stopRequested_.store(true, std::memory_order_relaxed); }

            void quit() noexcept { stop(); }

            /**
             * @brief 启动并运行 HTTP/3 QUIC 服务器
             *
             * @param ip 监听 IPv4 地址字面量
             * @param port 监听 UDP 端口
             * @param handler 协议业务处理器（默认复用内置 HandlerHttp3）
             * @return 正常停止返回 {}，错误返回 ERR
             */
            [[nodiscard]] Result<> run(const char *ip, int port, HandlerHttp3 &handler)
            {
                stopRequested_.store(false, std::memory_order_relaxed);

                SecurityConfig security{};
                security.alpnProtocols = "h3";
                auto ctxRes = detail::createServerContext(certPath_.c_str(), keyPath_.c_str(), security, &alpnList_,
                                                          TlsProtocolType::DatagramQuic);
                if (!ctxRes) [[unlikely]]
                {
                    LOG_ERROR("ServerHttp3: TLS setup failed: {}", ctxRes.error());
                    return std::unexpected(ctxRes.error());
                }
                SSL_CTX *ctx = *ctxRes;

                const int fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
                if (fd < 0) [[unlikely]]
                {
                    LOG_ERROR("ServerHttp3: socket(SOCK_DGRAM) failed: {}", strerror(errno));
                    detail::freeContext(ctx);
                    return std::unexpected(ERR::SOCKET_FAILED);
                }

                int opt = 1;
                ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
                ::setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif

                sockaddr_in sa{};
                sa.sin_family = AF_INET;
                sa.sin_port = htons(static_cast<uint16_t>(port));
                if (::inet_pton(AF_INET, ip, &sa.sin_addr) <= 0) [[unlikely]]
                {
                    LOG_ERROR("ServerHttp3: invalid IP address \"{}\"", ip);
                    ::close(fd);
                    SSL_CTX_free(ctx);
                    return std::unexpected(ERR::ADDR_INVALID);
                }

                if (::bind(fd, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)) < 0) [[unlikely]]
                {
                    LOG_ERROR("ServerHttp3: bind({}:{}) failed: {}", ip, port, strerror(errno));
                    ::close(fd);
                    SSL_CTX_free(ctx);
                    return std::unexpected(ERR::BIND_FAILED);
                }

                SSL *listener = SSL_new_listener(ctx, 0);
                if (listener == nullptr) [[unlikely]]
                {
                    LOG_ERROR("ServerHttp3: SSL_new_listener failed");
                    ::close(fd);
                    SSL_CTX_free(ctx);
                    return std::unexpected(ERR::SSL_CTX_FAILED);
                }

                SSL_set_blocking_mode(listener, 0);
                SSL_set_default_stream_mode(listener, SSL_DEFAULT_STREAM_MODE_NONE);
                SSL_set_incoming_stream_policy(listener, SSL_INCOMING_STREAM_POLICY_ACCEPT, 0);

                if (!SSL_set_fd(listener, fd)) [[unlikely]]
                {
                    LOG_ERROR("ServerHttp3: SSL_set_fd failed");
                    SSL_free(listener);
                    ::close(fd);
                    SSL_CTX_free(ctx);
                    return std::unexpected(ERR::SSL_SET_FD_FAILED);
                }

                if (!SSL_listen(listener)) [[unlikely]]
                {
                    LOG_ERROR("ServerHttp3: SSL_listen failed");
                    SSL_free(listener);
                    ::close(fd);
                    SSL_CTX_free(ctx);
                    return std::unexpected(ERR::LISTEN_FAILED);
                }

                LOG_INFO("ServerHttp3: running on {}:{} (HTTP/3 over QUIC)", ip, port);

                struct StreamState
                {
                    SSL *stream = nullptr;
                    RequestBuffer inBuf{};
                    std::vector<Header> headers{};
                    std::string body{};
                    bool responseSent = false;
                };

                struct QuicConnection
                {
                    SSL *conn = nullptr;
                    SSL *ctrlStream = nullptr;
                    std::vector<SSL *> uniStreams{};
                    std::unordered_map<uint64_t, StreamState> bidiStreams{};
                };

                std::vector<std::unique_ptr<QuicConnection>> conns;

                while (!stopRequested_.load(std::memory_order_relaxed))
                {
                    pollfd pfd{fd, POLLIN, 0};
                    struct timeval tv{};
                    int isInf = 1;
                    SSL_get_event_timeout(listener, &tv, &isInf);
                    int timeoutMs = isInf ? 50 : static_cast<int>(tv.tv_sec * 1000 + tv.tv_usec / 1000);
                    if (timeoutMs < 0)
                    {
                        timeoutMs = 0;
                    }
                    if (timeoutMs > 50)
                    {
                        timeoutMs = 50;
                    }

                    ::poll(&pfd, 1, timeoutMs);
                    SSL_handle_events(listener);

                    for (auto &qc : conns)
                    {
                        SSL_handle_events(qc->conn);
                    }

                    // 接受新建立的 QUIC 连接
                    while (SSL *conn = SSL_accept_connection(listener, SSL_ACCEPT_CONNECTION_NO_BLOCK))
                    {
                        SSL_set_blocking_mode(conn, 0);
                        SSL_set_default_stream_mode(conn, SSL_DEFAULT_STREAM_MODE_NONE);
                        SSL_set_incoming_stream_policy(conn, SSL_INCOMING_STREAM_POLICY_ACCEPT, 0);

                        auto qc = std::make_unique<QuicConnection>();
                        qc->conn = conn;

                        // RFC 9114 Section 6.2.1: 服务端必须在连接建立之初打开单向控制流 (Stream Type 0x00)，
                        // 并发送首帧 SETTINGS。
                        SSL *ctrl = SSL_new_stream(conn, SSL_STREAM_FLAG_UNI);
                        if (ctrl != nullptr)
                        {
                            std::string ctrlPayload;
                            appendVarint(ctrlPayload, 0x00); // Control stream
                            Settings s;
                            std::string setPayload;
                            s.encode(setPayload);
                            appendFrame(ctrlPayload, std::to_underlying(FRAME_TYPE::SETTINGS), setPayload);
                            size_t written = 0;
                            SSL_write_ex(ctrl, ctrlPayload.data(), ctrlPayload.size(), &written);
                            qc->ctrlStream = ctrl;
                            SSL_handle_events(conn);
                        }

                        conns.push_back(std::move(qc));
                    }

                    // 轮询活跃连接中的新流与数据
                    for (auto it = conns.begin(); it != conns.end();)
                    {
                        auto &qc = *it;

                        while (SSL *stream = SSL_accept_stream(qc->conn, SSL_ACCEPT_STREAM_NO_BLOCK))
                        {
                            const int streamType = SSL_get_stream_type(stream);
                            const uint64_t streamId = SSL_get_stream_id(stream);
                            if (streamType == SSL_STREAM_TYPE_BIDI)
                            {
                                SSL_set_blocking_mode(stream, 0);
                                qc->bidiStreams.emplace(streamId, StreamState{.stream = stream});
                            }
                            else
                            {
                                qc->uniStreams.push_back(stream);
                            }
                        }

                        // 排空对端发起的单向流（客户端控制流与 QPACK 编码流），维持连接健康
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

                            // 解码 HTTP/3 协议帧
                            FrameDecoder decoder;
                            while (true)
                            {
                                auto fRes = decoder.next(st.inBuf);
                                if (!fRes || !fRes->has_value())
                                {
                                    break;
                                }
                                auto &frame = **fRes;
                                if (frame.type == std::to_underlying(FRAME_TYPE::HEADERS))
                                {
                                    auto hRes = decodeHeaders(frame.payload);
                                    if (hRes)
                                    {
                                        st.headers = std::move(*hRes);
                                    }
                                }
                                else if (frame.type == std::to_underlying(FRAME_TYPE::DATA))
                                {
                                    st.body.append(frame.payload);
                                }
                            }

                            const int rstate = SSL_get_stream_read_state(st.stream);
                            // 当接收完请求或收到 FIN 时，调用 onRequest 回调生成应答
                            if (!st.responseSent && (rstate == SSL_STREAM_STATE_FINISHED || !st.headers.empty()))
                            {
                                std::string responseBody;
                                handler.onRequest(streamId, st.headers, st.body, responseBody);

                                std::vector<Header> respHeaders;
                                respHeaders.reserve(4);
                                respHeaders.push_back({":status", "200"});
                                respHeaders.push_back({"server", "mynet-http3"});
                                respHeaders.push_back({"content-type", "text/plain; charset=utf-8"});

                                std::string hdrPayload;
                                encodeHeaders(hdrPayload, respHeaders);

                                std::string respFrames;
                                appendFrame(respFrames, std::to_underlying(FRAME_TYPE::HEADERS), hdrPayload);
                                if (!responseBody.empty())
                                {
                                    appendFrame(respFrames, std::to_underlying(FRAME_TYPE::DATA), responseBody);
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
                            it = conns.erase(it);
                        }
                        else
                        {
                            ++it;
                        }
                    }
                }

                // 资源安全析构排空
                for (auto &qc : conns)
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
                }
                SSL_free(listener);
                detail::freeContext(ctx);
                ::close(fd);
                return {};
            }

            [[nodiscard]] Result<> run(HandlerHttp3 &handler)
            {
                return run(getServerConfig().host.c_str(), static_cast<int>(getHttp3Config().port), handler);
            }

            [[nodiscard]] Result<> run()
            {
                HandlerHttp3 defaultHandler;
                return run(defaultHandler);
            }

            [[nodiscard]] Result<> run(const char *ip, int port)
            {
                HandlerHttp3 defaultHandler;
                return run(ip, port, defaultHandler);
            }

            [[nodiscard]] Result<> run(std::string_view ip, uint16_t port, HandlerHttp3 &handler)
            {
                std::string ipStr(ip);
                return run(ipStr.c_str(), static_cast<int>(port), handler);
            }

            [[nodiscard]] Result<> run(std::string_view ip, uint16_t port)
            {
                HandlerHttp3 defaultHandler;
                return run(ip, port, defaultHandler);
            }

        private:
            std::string certPath_;
            std::string keyPath_;
            std::vector<std::string> alpnList_{"h3"};
            std::atomic<bool> stopRequested_{false};
        };

    } // namespace http::v3

} // namespace mynet
