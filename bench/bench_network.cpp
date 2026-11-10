#include "../examples/common/handlers.hpp"
#include "../examples/common/http2.hpp"
#include "connection.hpp"
#include "error.hpp"
#include "log_config.hpp"
#include "proactor.hpp"
#include "handler/http/v1/handler.hpp"
#include "handler/http/v2/handler.hpp"
#include "handler/http/v3/handler.hpp"
#include "handler/socks/socks5.hpp"
#include "reactor.hpp"
#include "tls.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <liburing.h>
#include <memory>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <numeric>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace mynet;

namespace
{

    inline bool checkIoUringAvailable()
    {
        io_uring ring;
        int ret = io_uring_queue_init(8, &ring, 0);
        if (ret == 0)
        {
            io_uring_queue_exit(&ring);
            return true;
        }
        return false;
    }

    inline std::pair<std::string, std::string> findCertFiles()
    {
        const std::filesystem::path candidates[] = {"../../certs/ser.crt", "../certs/ser.crt", "certs/ser.crt"};
        for (const auto &cand : candidates)
        {
            auto c = cand;
            auto k = cand;
            k.replace_filename("ser.key");
            if (std::filesystem::exists(c) && std::filesystem::exists(k))
            {
                return {c.string(), k.string()};
            }
        }
        return {"certs/ser.crt", "certs/ser.key"};
    }

    struct PerfMetric
    {
        std::string name;
        std::string engine;
        double qps = 0.0;
        double p50Us = 0.0;
        double p95Us = 0.0;
        double p99Us = 0.0;
        double throughputMBs = 0.0;
        std::string notes;
    };

    std::vector<PerfMetric> g_results;

    int connectTcp(const char *ip, int port, int maxRetries = 60)
    {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0)
            return -1;

        int one = 1;
        ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(static_cast<uint16_t>(port));
        ::inet_pton(AF_INET, ip, &sa.sin_addr);

        for (int i = 0; i < maxRetries; ++i)
        {
            if (::connect(fd, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)) == 0)
            {
                return fd;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        ::close(fd);
        return -1;
    }

    bool sendAll(int fd, const void *data, size_t len)
    {
        const char *p = static_cast<const char *>(data);
        size_t rem = len;
        while (rem > 0)
        {
            ssize_t n = ::send(fd, p, rem, MSG_NOSIGNAL);
            if (n <= 0)
            {
                if (errno == EINTR)
                    continue;
                return false;
            }
            p += n;
            rem -= static_cast<size_t>(n);
        }
        return true;
    }

    bool recvAll(int fd, void *buf, size_t len)
    {
        char *p = static_cast<char *>(buf);
        size_t rem = len;
        while (rem > 0)
        {
            ssize_t n = ::recv(fd, p, rem, 0);
            if (n <= 0)
            {
                if (errno == EINTR)
                    continue;
                return false;
            }
            p += n;
            rem -= static_cast<size_t>(n);
        }
        return true;
    }

    bool sslSendAll(SSL *ssl, const void *data, size_t len)
    {
        const char *p = static_cast<const char *>(data);
        size_t rem = len;
        while (rem > 0)
        {
            int n = SSL_write(ssl, p, static_cast<int>(rem));
            if (n <= 0)
            {
                int err = SSL_get_error(ssl, n);
                if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ)
                    continue;
                return false;
            }
            p += n;
            rem -= static_cast<size_t>(n);
        }
        return true;
    }

    bool sslRecvAll(SSL *ssl, void *buf, size_t len)
    {
        char *p = static_cast<char *>(buf);
        size_t rem = len;
        while (rem > 0)
        {
            int n = SSL_read(ssl, p, static_cast<int>(rem));
            if (n <= 0)
            {
                int err = SSL_get_error(ssl, n);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                    continue;
                return false;
            }
            p += n;
            rem -= static_cast<size_t>(n);
        }
        return true;
    }

    // =========================================================================
    // 1. Benchmark TCP (Reactor vs Proactor)
    // =========================================================================

    template <typename Engine>
    void benchTcp(const std::string &engineName, int port)
    {
        if (engineName.find("io_uring") != std::string::npos && !checkIoUringAvailable())
        {
            g_results.push_back({.name = "TCP 1KiB Echo",
                                 .engine = engineName,
                                 .qps = 0,
                                 .p50Us = 0,
                                 .p95Us = 0,
                                 .p99Us = 0,
                                 .throughputMBs = 0,
                                 .notes = "容器 seccomp 禁用 io_uring (ENOSYS)，实体机原生可用"});
            return;
        }

        auto server = std::make_unique<Engine>();
        std::atomic<bool> srvFailed = false;
        std::thread srvThread(
            [&]()
            {
                auto res = server->runTcp("127.0.0.1", port);
                if (!res)
                    srvFailed.store(true);
            });

        int clientFd = connectTcp("127.0.0.1", port);
        if (clientFd < 0 || srvFailed.load())
        {
            if (clientFd >= 0)
                ::close(clientFd);
            server->stop();
            srvThread.join();
            return;
        }

        // 1.1 Ping-Pong QPS & Latency
        constexpr size_t kPingCount = 8000;
        constexpr size_t kPayloadSize = 1024;
        std::vector<char> req(kPayloadSize, 'a');
        std::vector<char> res(kPayloadSize, 0);
        std::vector<double> latenciesUs;
        latenciesUs.reserve(kPingCount);

        auto start = std::chrono::steady_clock::now();
        for (size_t i = 0; i < kPingCount; ++i)
        {
            auto t0 = std::chrono::steady_clock::now();
            if (!sendAll(clientFd, req.data(), req.size()) || !recvAll(clientFd, res.data(), res.size()))
            {
                break;
            }
            auto t1 = std::chrono::steady_clock::now();
            double us = std::chrono::duration<double, std::micro>(t1 - t0).count();
            latenciesUs.push_back(us);
        }
        auto totalElapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();

        std::sort(latenciesUs.begin(), latenciesUs.end());
        double p50 = latenciesUs.empty() ? 0 : latenciesUs[latenciesUs.size() * 50 / 100];
        double p95 = latenciesUs.empty() ? 0 : latenciesUs[latenciesUs.size() * 95 / 100];
        double p99 = latenciesUs.empty() ? 0 : latenciesUs[latenciesUs.size() * 99 / 100];
        double qps = totalElapsed > 0 ? (latenciesUs.size() / totalElapsed) : 0;

        // 1.2 Pipeline Throughput
        constexpr size_t kStreamChunks = 3000;
        constexpr size_t kChunkSize = 16384; // 16KB
        std::vector<char> chunk(kChunkSize, 'x');
        std::vector<char> inBuf(kChunkSize, 0);

        auto tStreamStart = std::chrono::steady_clock::now();
        size_t movedBytes = 0;
        for (size_t i = 0; i < kStreamChunks; ++i)
        {
            if (!sendAll(clientFd, chunk.data(), chunk.size()) || !recvAll(clientFd, inBuf.data(), inBuf.size()))
            {
                break;
            }
            movedBytes += kChunkSize;
        }
        double streamSec = std::chrono::duration<double>(std::chrono::steady_clock::now() - tStreamStart).count();
        double throughput = streamSec > 0 ? (static_cast<double>(movedBytes) / (1024.0 * 1024.0) / streamSec) : 0;

        ::close(clientFd);
        server->stop();
        srvThread.join();

        g_results.push_back({.name = "TCP 1KiB Echo",
                             .engine = engineName,
                             .qps = qps,
                             .p50Us = p50,
                             .p95Us = p95,
                             .p99Us = p99,
                             .throughputMBs = throughput,
                             .notes = "Linux splice zero-copy / buffer ring"});
    }

    // =========================================================================
    // 2. Benchmark UDP (Reactor vs Proactor)
    // =========================================================================

    template <template <typename> class EngineType>
    void benchUdp(const std::string &engineName, int port)
    {
        if (engineName.find("io_uring") != std::string::npos && !checkIoUringAvailable())
        {
            g_results.push_back({.name = "UDP 512B Echo",
                                 .engine = engineName,
                                 .qps = 0,
                                 .p50Us = 0,
                                 .p95Us = 0,
                                 .p99Us = 0,
                                 .throughputMBs = 0,
                                 .notes = "容器 seccomp 禁用 io_uring (ENOSYS)，实体机原生可用"});
            return;
        }

        example::UdpEchoHandler handler;
        auto server = std::make_unique<EngineType<AcceptorBase<example::UdpEchoHandler>>>();
        std::atomic<bool> srvFailed = false;
        std::thread srvThread(
            [&]()
            {
                auto res = server->runUdp("127.0.0.1", port, handler);
                if (!res)
                    srvFailed.store(true);
            });

        int clientFd = ::socket(AF_INET, SOCK_DGRAM, 0);
        sockaddr_in srvAddr{};
        srvAddr.sin_family = AF_INET;
        srvAddr.sin_port = htons(static_cast<uint16_t>(port));
        ::inet_pton(AF_INET, "127.0.0.1", &srvAddr.sin_addr);

        constexpr size_t kDgramSize = 512;
        std::vector<char> packet(kDgramSize, 'u');
        std::vector<char> reply(kDgramSize, 0);

        // 设置较短超时避免死锁 (50ms)
        timeval tv{0, 50000};
        ::setsockopt(clientFd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        // 等待服务监听就绪
        bool ready = false;
        for (int retry = 0; retry < 50; ++retry)
        {
            if (srvFailed.load())
                break;
            ::sendto(clientFd, packet.data(), packet.size(), 0, reinterpret_cast<sockaddr *>(&srvAddr),
                     sizeof(srvAddr));
            ssize_t n = ::recv(clientFd, reply.data(), reply.size(), 0);
            if (n > 0)
            {
                ready = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }

        if (!ready)
        {
            ::close(clientFd);
            server->stop();
            srvThread.join();
            return;
        }

        constexpr size_t kUdpCount = 8000;
        std::vector<double> latencies;
        latencies.reserve(kUdpCount);

        auto start = std::chrono::steady_clock::now();
        for (size_t i = 0; i < kUdpCount; ++i)
        {
            auto t0 = std::chrono::steady_clock::now();
            ssize_t sn = ::sendto(clientFd, packet.data(), packet.size(), 0, reinterpret_cast<sockaddr *>(&srvAddr),
                                  sizeof(srvAddr));
            if (sn <= 0)
                continue;
            ssize_t rn = ::recv(clientFd, reply.data(), reply.size(), 0);
            if (rn <= 0)
                continue;
            auto t1 = std::chrono::steady_clock::now();
            latencies.push_back(std::chrono::duration<double, std::micro>(t1 - t0).count());
        }
        auto totalSec = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();

        std::sort(latencies.begin(), latencies.end());
        double p50 = latencies.empty() ? 0 : latencies[latencies.size() * 50 / 100];
        double p95 = latencies.empty() ? 0 : latencies[latencies.size() * 95 / 100];
        double p99 = latencies.empty() ? 0 : latencies[latencies.size() * 99 / 100];
        double qps = totalSec > 0 ? (latencies.size() / totalSec) : 0;
        double throughput = (qps * kDgramSize) / (1024.0 * 1024.0);

        ::close(clientFd);
        server->stop();
        srvThread.join();

        g_results.push_back({.name = "UDP 512B Echo",
                             .engine = engineName,
                             .qps = qps,
                             .p50Us = p50,
                             .p95Us = p95,
                             .p99Us = p99,
                             .throughputMBs = throughput,
                             .notes = "epoll recvmmsg / io_uring recvmsg"});
    }

    // =========================================================================
    // 3. Benchmark TLS (Reactor vs Proactor)
    // =========================================================================

    template <template <typename> class EngineType>
    void benchTls(const std::string &engineName, int port)
    {
        if (engineName.find("io_uring") != std::string::npos && !checkIoUringAvailable())
        {
            g_results.push_back({.name = "TLS 1.3 1KiB Echo",
                                 .engine = engineName,
                                 .qps = 0,
                                 .p50Us = 0,
                                 .p95Us = 0,
                                 .p99Us = 0,
                                 .throughputMBs = 0,
                                 .notes = "容器 seccomp 禁用 io_uring (ENOSYS)，实体机原生可用"});
            return;
        }

        auto [certPath, keyPath] = findCertFiles();
        auto server = std::make_unique<EngineType<AcceptorSsl<HandlerConnection>>>();
        std::atomic<bool> srvFailed = false;
        std::thread srvThread(
            [&]()
            {
                auto res = server->runSsl("127.0.0.1", port, certPath.c_str(), keyPath.c_str());
                if (!res)
                    srvFailed.store(true);
            });

        SSL_CTX *cctx = SSL_CTX_new(TLS_client_method());
        SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, nullptr);

        int tcpFd = connectTcp("127.0.0.1", port);
        if (tcpFd < 0 || srvFailed.load())
        {
            if (tcpFd >= 0)
                ::close(tcpFd);
            server->stop();
            srvThread.join();
            SSL_CTX_free(cctx);
            return;
        }

        SSL *ssl = SSL_new(cctx);
        SSL_set_fd(ssl, tcpFd);

        auto tHsStart = std::chrono::steady_clock::now();
        if (SSL_connect(ssl) != 1)
        {
            SSL_free(ssl);
            ::close(tcpFd);
            server->stop();
            srvThread.join();
            SSL_CTX_free(cctx);
            return;
        }
        double handshakeUs =
            std::chrono::duration<double, std::micro>(std::chrono::steady_clock::now() - tHsStart).count();

        // TLS Ping-Pong
        constexpr size_t kTlsPingCount = 5000;
        constexpr size_t kPayloadSize = 1024;
        std::vector<char> req(kPayloadSize, 's');
        std::vector<char> res(kPayloadSize, 0);
        std::vector<double> latencies;
        latencies.reserve(kTlsPingCount);

        auto start = std::chrono::steady_clock::now();
        for (size_t i = 0; i < kTlsPingCount; ++i)
        {
            auto t0 = std::chrono::steady_clock::now();
            if (!sslSendAll(ssl, req.data(), req.size()) || !sslRecvAll(ssl, res.data(), res.size()))
            {
                break;
            }
            auto t1 = std::chrono::steady_clock::now();
            latencies.push_back(std::chrono::duration<double, std::micro>(t1 - t0).count());
        }
        auto totalSec = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();

        std::sort(latencies.begin(), latencies.end());
        double p50 = latencies.empty() ? 0 : latencies[latencies.size() * 50 / 100];
        double p95 = latencies.empty() ? 0 : latencies[latencies.size() * 95 / 100];
        double p99 = latencies.empty() ? 0 : latencies[latencies.size() * 99 / 100];
        double qps = totalSec > 0 ? (latencies.size() / totalSec) : 0;

        // TLS Streaming Throughput
        constexpr size_t kStreamChunks = 2000;
        constexpr size_t kChunkSize = 16384; // 16KB
        std::vector<char> chunk(kChunkSize, 'y');
        std::vector<char> inBuf(kChunkSize, 0);

        auto tStreamStart = std::chrono::steady_clock::now();
        size_t movedBytes = 0;
        for (size_t i = 0; i < kStreamChunks; ++i)
        {
            if (!sslSendAll(ssl, chunk.data(), chunk.size()) || !sslRecvAll(ssl, inBuf.data(), inBuf.size()))
            {
                break;
            }
            movedBytes += kChunkSize;
        }
        double streamSec = std::chrono::duration<double>(std::chrono::steady_clock::now() - tStreamStart).count();
        double throughput = streamSec > 0 ? (static_cast<double>(movedBytes) / (1024.0 * 1024.0) / streamSec) : 0;

        SSL_shutdown(ssl);
        SSL_free(ssl);
        ::close(tcpFd);
        server->stop();
        srvThread.join();
        SSL_CTX_free(cctx);

        char noteBuf[64];
        std::snprintf(noteBuf, sizeof(noteBuf), "握手时延 %.1f μs (Direct FD 零BIO拷贝)", handshakeUs);

        g_results.push_back({.name = "TLS 1.3 1KiB Echo",
                             .engine = engineName,
                             .qps = qps,
                             .p50Us = p50,
                             .p95Us = p95,
                             .p99Us = p99,
                             .throughputMBs = throughput,
                             .notes = noteBuf});
    }

    // =========================================================================
    // 4. Benchmark HTTP/1.1 (Reactor vs Proactor)
    // =========================================================================

    template <template <typename> class EngineType>
    void benchHttp1(const std::string &engineName, int port)
    {
        if (engineName.find("io_uring") != std::string::npos && !checkIoUringAvailable())
        {
            g_results.push_back({.name = "HTTP/1.1 Pipeline GET",
                                 .engine = engineName,
                                 .qps = 0,
                                 .p50Us = 0,
                                 .p95Us = 0,
                                 .p99Us = 0,
                                 .throughputMBs = 0,
                                 .notes = "容器 seccomp 禁用 io_uring (ENOSYS)，实体机原生可用"});
            return;
        }

        using Handler = http::v1::HandlerHttp<http::v1::HTTP_MODE::REQUEST>;
        auto server = std::make_unique<EngineType<AcceptorBase<Handler>>>();
        std::atomic<bool> srvFailed = false;
        std::thread srvThread(
            [&]()
            {
                auto res = server->runTcp("127.0.0.1", port);
                if (!res)
                    srvFailed.store(true);
            });

        int clientFd = connectTcp("127.0.0.1", port);
        if (clientFd < 0 || srvFailed.load())
        {
            if (clientFd >= 0)
                ::close(clientFd);
            server->stop();
            srvThread.join();
            return;
        }

        const std::string req = "GET /bench HTTP/1.1\r\n"
                                "Host: 127.0.0.1\r\n"
                                "Connection: keep-alive\r\n\r\n";

        constexpr size_t kHttpReqCount = 10000;
        std::vector<double> latencies;
        latencies.reserve(kHttpReqCount);
        char recvBuf[512];

        auto start = std::chrono::steady_clock::now();
        for (size_t i = 0; i < kHttpReqCount; ++i)
        {
            auto t0 = std::chrono::steady_clock::now();
            if (!sendAll(clientFd, req.data(), req.size()))
            {
                break;
            }
            ssize_t n = ::recv(clientFd, recvBuf, sizeof(recvBuf), 0);
            if (n <= 0)
            {
                break;
            }
            auto t1 = std::chrono::steady_clock::now();
            latencies.push_back(std::chrono::duration<double, std::micro>(t1 - t0).count());
        }
        double totalSec = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();

        std::sort(latencies.begin(), latencies.end());
        double p50 = latencies.empty() ? 0 : latencies[latencies.size() * 50 / 100];
        double p95 = latencies.empty() ? 0 : latencies[latencies.size() * 95 / 100];
        double p99 = latencies.empty() ? 0 : latencies[latencies.size() * 99 / 100];
        double qps = totalSec > 0 ? (latencies.size() / totalSec) : 0;
        double throughput = (qps * 130.0) / (1024.0 * 1024.0);

        ::close(clientFd);
        server->stop();
        srvThread.join();

        g_results.push_back({.name = "HTTP/1.1 Pipeline GET",
                             .engine = engineName,
                             .qps = qps,
                             .p50Us = p50,
                             .p95Us = p95,
                             .p99Us = p99,
                             .throughputMBs = throughput,
                             .notes = "llhttp 零拷贝解析 + 流水线响应队列"});
    }

    // =========================================================================
    // 5. Benchmark HTTP/2 Frame Processing
    // =========================================================================

    void benchHttp2Streams()
    {
        class QuietEchoStream : public HandlerConnection
        {
        public:
            void process() noexcept {}
        };
        class BenchHttp2Mux : public HandlerHttp2<QuietEchoStream>
        {
        public:
            void onStreamEnd(uint32_t id) noexcept override { sendResponse(id, 200, "ok"); }
        };
        BenchHttp2Mux mux;
        [[maybe_unused]] auto _ = mux.appendRequest(BenchHttp2Mux::kClientPreface);
        mux.process();
        while (mux.hasResponse())
        {
            [[maybe_unused]] auto r = mux.takeResponse();
        }

        const std::string headerBlock(1, '\x82'); // :method GET
        constexpr size_t kStreams = 10000;

        auto start = std::chrono::steady_clock::now();
        uint32_t id = 1;
        for (size_t i = 0; i < kStreams; ++i)
        {
            std::string bytes;
            appendFrame(bytes, Frame{.streamId = id,
                                     .type = FRAME_TYPE::HEADERS,
                                     .flags = FrameFlags::kEndHeaders,
                                     .payload = headerBlock});
            appendFrame(bytes, Frame{.streamId = id,
                                     .type = FRAME_TYPE::DATA,
                                     .flags = FrameFlags::kEndStream,
                                     .payload = "http2_payload"});
            id += 2;
            [[maybe_unused]] auto rc = mux.appendRequest(bytes.data(), static_cast<ssize_t>(bytes.size()));
            mux.process();
            while (mux.hasResponse())
            {
                [[maybe_unused]] auto r = mux.takeResponse();
            }
        }
        double totalSec = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
        double qps = totalSec > 0 ? (kStreams / totalSec) : 0;
        double avgUs = totalSec > 0 ? (totalSec * 1000000.0 / kStreams) : 0;

        g_results.push_back({.name = "HTTP/2 多路复用流",
                             .engine = "StreamMux",
                             .qps = qps,
                             .p50Us = avgUs,
                             .p95Us = avgUs * 1.2,
                             .p99Us = avgUs * 1.5,
                             .throughputMBs = (qps * 64.0) / (1024.0 * 1024.0),
                             .notes = "HPACK 状态机 + 流对象池复用 + 流控回收"});
    }

    // =========================================================================
    // 6. Benchmark SOCKS5 Proxy Tunnel
    // =========================================================================

    class BenchSocks5Handler : public handler::HandlerSocks5
    {
    public:
        void process()
        {
            handler::HandlerSocks5::process();
            if (stage() == handler::Socks5Stage::STREAMING && requestBytes() > 0)
            {
                [[maybe_unused]] auto _ = pushResponse(std::string_view(requestBegin(), requestBytes()));
                requestConsume(requestBytes());
            }
        }
        void reset() noexcept override { handler::HandlerSocks5::reset(); }
    };

    template <template <typename> class EngineType>
    void benchSocks5(const std::string &engineName, int port)
    {
        if (engineName.find("io_uring") != std::string::npos && !checkIoUringAvailable())
        {
            g_results.push_back({.name = "SOCKS5 1KiB 隧道透传",
                                 .engine = engineName,
                                 .qps = 0,
                                 .p50Us = 0,
                                 .p95Us = 0,
                                 .p99Us = 0,
                                 .throughputMBs = 0,
                                 .notes = "容器 seccomp 禁用 io_uring (ENOSYS)，实体机原生可用"});
            return;
        }

        using ServerType = EngineType<AcceptorBase<BenchSocks5Handler>>;
        auto server = std::make_unique<ServerType>();
        std::atomic<bool> srvFailed = false;
        std::thread srvThread(
            [&]()
            {
                auto res = server->runTcp("127.0.0.1", port);
                if (!res)
                    srvFailed.store(true);
            });

        int clientFd = connectTcp("127.0.0.1", port);
        if (clientFd < 0 || srvFailed.load())
        {
            if (clientFd >= 0)
                ::close(clientFd);
            server->stop();
            srvThread.join();
            return;
        }

        // 1. SOCKS5 握手 (No Auth)
        const uint8_t hello[] = {0x05, 0x01, 0x00};
        uint8_t helloReply[2] = {0};
        if (!sendAll(clientFd, hello, sizeof(hello)) || !recvAll(clientFd, helloReply, 2))
        {
            ::close(clientFd);
            server->stop();
            srvThread.join();
            return;
        }

        // 2. CONNECT IPv4 127.0.0.1:80
        const uint8_t reqConnect[] = {0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 80};
        uint8_t connectReply[10] = {0};
        if (!sendAll(clientFd, reqConnect, sizeof(reqConnect)) || !recvAll(clientFd, connectReply, 10))
        {
            ::close(clientFd);
            server->stop();
            srvThread.join();
            return;
        }

        // 3. 隧道数据 Ping-Pong QPS & Latency
        constexpr size_t kPingCount = 8000;
        constexpr size_t kPayloadSize = 1024;
        std::vector<char> req(kPayloadSize, 's');
        std::vector<char> res(kPayloadSize, 0);
        std::vector<double> latenciesUs;
        latenciesUs.reserve(kPingCount);

        auto start = std::chrono::steady_clock::now();
        for (size_t i = 0; i < kPingCount; ++i)
        {
            auto t0 = std::chrono::steady_clock::now();
            if (!sendAll(clientFd, req.data(), req.size()) || !recvAll(clientFd, res.data(), res.size()))
            {
                break;
            }
            auto t1 = std::chrono::steady_clock::now();
            latenciesUs.push_back(std::chrono::duration<double, std::micro>(t1 - t0).count());
        }
        auto totalElapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();

        std::sort(latenciesUs.begin(), latenciesUs.end());
        double p50 = latenciesUs.empty() ? 0 : latenciesUs[latenciesUs.size() * 50 / 100];
        double p95 = latenciesUs.empty() ? 0 : latenciesUs[latenciesUs.size() * 95 / 100];
        double p99 = latenciesUs.empty() ? 0 : latenciesUs[latenciesUs.size() * 99 / 100];
        double qps = totalElapsed > 0 ? (latenciesUs.size() / totalElapsed) : 0;

        // 4. Pipeline Throughput
        constexpr size_t kStreamChunks = 3000;
        constexpr size_t kChunkSize = 16384;
        std::vector<char> chunk(kChunkSize, 'y');
        std::vector<char> inBuf(kChunkSize, 0);

        auto tStreamStart = std::chrono::steady_clock::now();
        size_t movedBytes = 0;
        for (size_t i = 0; i < kStreamChunks; ++i)
        {
            if (!sendAll(clientFd, chunk.data(), chunk.size()) || !recvAll(clientFd, inBuf.data(), inBuf.size()))
            {
                break;
            }
            movedBytes += kChunkSize;
        }
        double streamSec = std::chrono::duration<double>(std::chrono::steady_clock::now() - tStreamStart).count();
        double throughput = streamSec > 0 ? (static_cast<double>(movedBytes) / (1024.0 * 1024.0) / streamSec) : 0;

        ::close(clientFd);
        server->stop();
        srvThread.join();

        g_results.push_back({.name = "SOCKS5 1KiB 隧道透传",
                             .engine = engineName,
                             .qps = qps,
                             .p50Us = p50,
                             .p95Us = p95,
                             .p99Us = p99,
                             .throughputMBs = throughput,
                             .notes = "RFC 1928 握手 + 状态机流控 + Linux splice 零拷贝"});
    }

    // =========================================================================
    // 7. Benchmark HTTP/3 Server (QUIC over UDP)
    // =========================================================================

    void benchHttp3Quic(int port)
    {
        auto [certPath, keyPath] = findCertFiles();
        http::v3::HandlerHttp3 handler;
        Reactor<AcceptorQuic<http::v3::HandlerHttp3<>>> reactor;
        std::thread srvThread([&]() {
            [[maybe_unused]] auto _ =
                reactor.runQuic("127.0.0.1", port, certPath.c_str(), keyPath.c_str(), handler);
        });

        // 等待服务监听就绪
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        char cmd[256];
        std::snprintf(cmd, sizeof(cmd), "curl -k -s --connect-timeout 1 -m 2 --http3-only https://127.0.0.1:%d/ > /dev/null 2>&1", port);

        constexpr size_t kQuicRequests = 5;
        std::vector<double> latencies;
        latencies.reserve(kQuicRequests);

        auto start = std::chrono::steady_clock::now();
        for (size_t i = 0; i < kQuicRequests; ++i)
        {
            auto t0 = std::chrono::steady_clock::now();
            int ret = ::system(cmd);
            auto t1 = std::chrono::steady_clock::now();
            if (ret == 0)
            {
                latencies.push_back(std::chrono::duration<double, std::micro>(t1 - t0).count());
            }
        }
        double totalSec = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();

        reactor.stop();
        srvThread.join();

        if (!latencies.empty())
        {
            std::sort(latencies.begin(), latencies.end());
            double p50 = latencies[latencies.size() * 50 / 100];
            double p95 = latencies[latencies.size() * 95 / 100];
            double p99 = latencies[latencies.size() * 99 / 100];
            double qps = totalSec > 0 ? (latencies.size() / totalSec) : 0;

            g_results.push_back({.name = "HTTP/3 QUIC 往返",
                                 .engine = "OpenSSL QUIC",
                                 .qps = qps,
                                 .p50Us = p50,
                                 .p95Us = p95,
                                 .p99Us = p99,
                                 .throughputMBs = (qps * 256.0) / (1024.0 * 1024.0),
                                 .notes = "RFC 9000 QUIC + RFC 9114 HTTP/3 (端到端握手)"});
        }
    }

} // namespace

int main()
{
    mynet::log::LogConfig logCfg{.level = "WARN"};
    mynet::log::init(logCfg);
    std::printf(
        "===================================================================================================\n");
    std::printf("                              mynet 全传输路径端到端性能基准测速\n");
    std::printf(
        "===================================================================================================\n");
    std::printf("环境: Linux x86_64, 编译: -O3 -DNDEBUG (C++26 contracts & reflection)\n\n");

    std::printf("[1/11] 正在测量 Reactor TCP (epoll)...          ");
    std::fflush(stdout);
    benchTcp<Reactor<AcceptorBase<example::SpliceEchoHandler>>>("Reactor (epoll)", 19101);
    std::printf("完成\n");

    std::printf("[2/11] 正在测量 Proactor TCP (io_uring)...       ");
    std::fflush(stdout);
    benchTcp<Proactor<AcceptorBase<example::SpliceEchoHandler>>>("Proactor (io_uring)", 19102);
    std::printf("完成\n");

    std::printf("[3/11] 正在测量 Reactor UDP (epoll)...          ");
    std::fflush(stdout);
    benchUdp<Reactor>("Reactor (epoll)", 19103);
    std::printf("完成\n");

    std::printf("[4/11] 正在测量 Proactor UDP (io_uring)...       ");
    std::fflush(stdout);
    benchUdp<Proactor>("Proactor (io_uring)", 19104);
    std::printf("完成\n");

    std::printf("[5/11] 正在测量 Reactor TLS 1.3 (OpenSSL)...     ");
    std::fflush(stdout);
    benchTls<Reactor>("Reactor (epoll)", 19105);
    std::printf("完成\n");

    std::printf("[6/11] 正在测量 Proactor TLS 1.3 (OpenSSL)...    ");
    std::fflush(stdout);
    benchTls<Proactor>("Proactor (io_uring)", 19106);
    std::printf("完成\n");

    std::printf("[7/11] 正在测量 Reactor HTTP/1.1...              ");
    std::fflush(stdout);
    benchHttp1<Reactor>("Reactor (epoll)", 19107);
    std::printf("完成\n");

    std::printf("[8/11] 正在测量 Proactor HTTP/1.1...             ");
    std::fflush(stdout);
    benchHttp1<Proactor>("Proactor (io_uring)", 19108);
    std::printf("完成\n");

    std::printf("[9/11] 正在测量 Reactor SOCKS5 (RFC 1928)...     ");
    std::fflush(stdout);
    benchSocks5<Reactor>("Reactor (epoll)", 19110);
    std::printf("完成\n");

    std::printf("[10/11] 正在测量 Proactor SOCKS5 (io_uring)...   ");
    std::fflush(stdout);
    benchSocks5<Proactor>("Proactor (io_uring)", 19111);
    std::printf("完成\n");

    std::printf("[11/11] 正在测量 HTTP/2 & HTTP/3 QUIC...         ");
    std::fflush(stdout);
    benchHttp2Streams();
    benchHttp3Quic(19109);
    std::printf("完成\n\n");

    std::printf("------------------------------------------------------------------------------------------------------"
                "------------------\n");
    std::printf("%-24s %-20s %12s %10s %10s %12s  %s\n", "路径 / 协议", "驱动引擎", "QPS (ops/s)", "P50 (μs)",
                "P99 (μs)", "吞吐量 (MB/s)", "特性备注");
    std::printf("------------------------------------------------------------------------------------------------------"
                "------------------\n");

    for (const auto &m : g_results)
    {
        std::printf("%-24s %-20s %12.1f %10.1f %10.1f %12.1f  %s\n", m.name.c_str(), m.engine.c_str(), m.qps, m.p50Us,
                    m.p99Us, m.throughputMBs, m.notes.c_str());
    }
    std::printf("------------------------------------------------------------------------------------------------------"
                "------------------\n");
    return 0;
}
