/**
 * @file test_singbox_interop.cpp
 * @brief mynet 与 sing-box 内核全协议全链路双向互通端到端测试
 *
 * 覆盖协议：
 * 1. SOCKS5 (Mynet Outbound -> Sing-box Inbound / Sing-box Outbound -> Mynet Inbound)
 * 2. HTTP Proxy (Mynet Outbound -> Sing-box Inbound / Sing-box Outbound -> Mynet Inbound)
 * 3. Trojan (Mynet Outbound -> Sing-box Inbound / Sing-box Outbound -> Mynet Inbound)
 * 4. VLESS (Mynet Outbound -> Sing-box Inbound / Sing-box Outbound -> Mynet Inbound)
 * 5. Shadowsocks (Mynet Outbound -> Sing-box Inbound / Sing-box Outbound -> Mynet Inbound)
 * 6. Mux (Sing-box SOCKS5/HTTP Outbound -> Mynet InboundMux)
 */

#include "../src/address.hpp"
#include "../src/forwarder.hpp"
#include "../src/http/http.hpp"
#include "../src/http/inbound.hpp"
#include "../src/http/outbound.hpp"
#include "../src/inboundManager.hpp"
#include "../src/shadowsocks/inbound.hpp"
#include "../src/shadowsocks/outbound.hpp"
#include "../src/shadowsocks/shadowsocks.hpp"
#include "../src/socks/inbound.hpp"
#include "../src/socks/outbound.hpp"
#include "../src/socks/socks5.hpp"
#include "../src/trojan/inbound.hpp"
#include "../src/trojan/outbound.hpp"
#include "../src/trojan/trojan.hpp"
#include "../src/vless/inbound.hpp"
#include "../src/vless/outbound.hpp"
#include "../src/vless/vless.hpp"
#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace mynet;
using namespace mynet::handler;

namespace
{

    std::string findSingBoxBinary()
    {
        const char *home = std::getenv("HOME");
        if (home != nullptr)
        {
            std::string userPath = std::string(home) + "/misc/sing-box";
            if (access(userPath.c_str(), X_OK) == 0)
            {
                return userPath;
            }
        }
        if (access("/usr/bin/sing-box", X_OK) == 0)
        {
            return "/usr/bin/sing-box";
        }
        if (access("/usr/local/bin/sing-box", X_OK) == 0)
        {
            return "/usr/local/bin/sing-box";
        }
        return "";
    }

    class EchoServer
    {
    private:
        int listenFd_{-1};
        uint16_t port_{0};
        std::atomic<bool> running_{false};
        std::thread worker_{};
        std::string prefix_{};

    public:
        explicit EchoServer(std::string prefix = "ECHO:")
            : prefix_(std::move(prefix))
        {
            listenFd_ = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (listenFd_ < 0)
                return;

            int opt = 1;
            ::setsockopt(listenFd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port = 0;

            if (::bind(listenFd_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0)
            {
                ::close(listenFd_);
                listenFd_ = -1;
                return;
            }

            socklen_t len = sizeof(addr);
            if (::getsockname(listenFd_, reinterpret_cast<sockaddr *>(&addr), &len) == 0)
            {
                port_ = ntohs(addr.sin_port);
            }

            if (::listen(listenFd_, 128) < 0)
            {
                ::close(listenFd_);
                listenFd_ = -1;
                return;
            }

            running_ = true;
            worker_ = std::thread([this]() { run(); });
        }

        ~EchoServer()
        {
            running_ = false;
            if (listenFd_ >= 0)
            {
                ::close(listenFd_);
                listenFd_ = -1;
            }
            if (worker_.joinable())
            {
                worker_.join();
            }
        }

        [[nodiscard]] bool isRunning() const noexcept { return running_ && (listenFd_ >= 0); }
        [[nodiscard]] uint16_t port() const noexcept { return port_; }

    private:
        void run()
        {
            while (running_)
            {
                pollfd pfd{listenFd_, POLLIN, 0};
                int rc = ::poll(&pfd, 1, 100);
                if (rc <= 0)
                    continue;

                sockaddr_in clientAddr{};
                socklen_t clen = sizeof(clientAddr);
                int clientFd = ::accept4(listenFd_, reinterpret_cast<sockaddr *>(&clientAddr), &clen,
                                         SOCK_NONBLOCK | SOCK_CLOEXEC);
                if (clientFd < 0)
                    continue;

                std::thread(
                    [clientFd, this]()
                    {
                        char buf[4096];
                        while (running_)
                        {
                            pollfd cpfd{clientFd, POLLIN, 0};
                            int prc = ::poll(&cpfd, 1, 500);
                            if (prc <= 0)
                            {
                                if (prc < 0 && errno != EINTR)
                                    break;
                                continue;
                            }
                            ssize_t n = ::read(clientFd, buf, sizeof(buf));
                            if (n <= 0)
                                break;

                            std::string reply = prefix_ + std::string(buf, n);
                            ssize_t sent = 0;
                            while (sent < static_cast<ssize_t>(reply.size()))
                            {
                                ssize_t s = ::send(clientFd, reply.data() + sent, reply.size() - sent, MSG_NOSIGNAL);
                                if (s <= 0)
                                    break;
                                sent += s;
                            }
                        }
                        ::close(clientFd);
                    })
                    .detach();
            }
        }
    };

    class SingBoxRunner
    {
    private:
        pid_t pid_{-1};
        std::string configPath_{};

    public:
        explicit SingBoxRunner(const std::string &jsonConfig)
        {
            std::string bin = findSingBoxBinary();
            if (bin.empty())
                return;

            char tmpTemplate[] = "/tmp/singbox_interop_XXXXXX.json";
            int fd = ::mkstemps(tmpTemplate, 5);
            if (fd < 0)
                return;

            [[maybe_unused]] auto _ = ::write(fd, jsonConfig.data(), jsonConfig.size());
            ::close(fd);
            configPath_ = tmpTemplate;

            pid_ = ::fork();
            if (pid_ == 0)
            {
                int devnull = ::open("/dev/null", O_RDWR);
                if (devnull >= 0)
                {
                    ::dup2(devnull, STDOUT_FILENO);
                    ::dup2(devnull, STDERR_FILENO);
                    ::close(devnull);
                }
                ::execl(bin.c_str(), bin.c_str(), "run", "-c", configPath_.c_str(), nullptr);
                ::_exit(127);
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(300));
        }

        ~SingBoxRunner() { stop(); }

        [[nodiscard]] bool isRunning() const noexcept
        {
            if (pid_ <= 0)
                return false;
            int status = 0;
            pid_t rc = ::waitpid(pid_, &status, WNOHANG);
            return (rc == 0);
        }

        void stop()
        {
            if (pid_ > 0)
            {
                ::kill(pid_, SIGTERM);
                int status = 0;
                for (int i = 0; i < 20; ++i)
                {
                    pid_t rc = ::waitpid(pid_, &status, WNOHANG);
                    if (rc > 0)
                    {
                        pid_ = -1;
                        break;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                }
                if (pid_ > 0)
                {
                    ::kill(pid_, SIGKILL);
                    ::waitpid(pid_, &status, 0);
                    pid_ = -1;
                }
            }
            if (!configPath_.empty())
            {
                ::unlink(configPath_.c_str());
                configPath_.clear();
            }
        }
    };

    int dialTcpClient(std::string_view host, uint16_t port, int timeoutMs = 2000)
    {
        int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd < 0)
            return -1;

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        ::inet_pton(AF_INET, std::string(host).c_str(), &addr.sin_addr);
        addr.sin_port = htons(port);

        int rc = ::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
        if (rc < 0 && errno != EINPROGRESS)
        {
            ::close(fd);
            return -1;
        }

        pollfd pfd{fd, POLLOUT, 0};
        if (::poll(&pfd, 1, timeoutMs) <= 0)
        {
            ::close(fd);
            return -1;
        }

        int err = 0;
        socklen_t elen = sizeof(err);
        if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) < 0 || err != 0)
        {
            ::close(fd);
            return -1;
        }
        return fd;
    }

    int readFull(int fd, void *buf, size_t n, int timeoutMs = 2000)
    {
        uint8_t *p = reinterpret_cast<uint8_t *>(buf);
        size_t total = 0;
        while (total < n)
        {
            pollfd pfd{fd, POLLIN, 0};
            int prc = ::poll(&pfd, 1, timeoutMs);
            if (prc <= 0)
                return -1;
            ssize_t rc = ::read(fd, p + total, n - total);
            if (rc <= 0)
                return -1;
            total += static_cast<size_t>(rc);
        }
        return static_cast<int>(total);
    }

    int readSome(int fd, void *buf, size_t maxLen, int timeoutMs = 2000)
    {
        pollfd pfd{fd, POLLIN, 0};
        int prc = ::poll(&pfd, 1, timeoutMs);
        if (prc <= 0)
            return -1;
        ssize_t rc = ::read(fd, buf, maxLen);
        return static_cast<int>(rc);
    }

    struct ThreadJoiner
    {
        std::thread &t;
        ~ThreadJoiner()
        {
            if (t.joinable())
                t.join();
        }
    };

} // namespace

// =============================================================================
// 1. SOCKS5 互通测试 (SOCKS5 Mutual Interoperability)
// =============================================================================

TEST(SingBoxInteropTest, MynetOutboundSocks5ToSingBoxInbound)
{
    ASSERT_FALSE(findSingBoxBinary().empty()) << "sing-box binary not found";

    EchoServer echo("ECHO_SOCKS5:");
    ASSERT_TRUE(echo.isRunning());

    // Sing-box 配置 SOCKS5 入站，端口 14001
    std::string sbConfig = R"({
      "log": {"level": "warn"},
      "route": {"auto_detect_interface": false},
      "inbounds": [{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 14001}],
      "outbounds": [{"type": "direct", "tag": "direct", "bind_interface": "lo"}]
    })";

    SingBoxRunner sb(sbConfig);
    ASSERT_TRUE(sb.isRunning());

    // Mynet OutboundSocks5 拨号至 Sing-box，目标为 EchoServer
    OutboundSocks5 outbound("sb-socks", "127.0.0.1", 14001);
    auto target = ProxyAddress::fromIPv4(htonl(INADDR_LOOPBACK), echo.port());

    auto dialRes = outbound.dialStream(target);
    ASSERT_TRUE(dialRes.has_value());
    int fd = dialRes->fd;
    ASSERT_GE(fd, 0);

    // 驱动握手
    auto &handler = *dialRes->handler;
    while (!handler.isEstablished())
    {
        while (handler.hasResponse())
        {
            std::string resp = handler.takeResponse();
            [[maybe_unused]] auto _ = ::send(fd, resp.data(), resp.size(), MSG_NOSIGNAL);
        }
        pollfd pfd{fd, POLLIN, 0};
        ASSERT_GT(::poll(&pfd, 1, 2000), 0);
        char buf[512];
        ssize_t n = ::read(fd, buf, sizeof(buf));
        ASSERT_GT(n, 0);
        [[maybe_unused]] auto _ = handler.appendRequest(buf, n);
        handler.handle();
    }
    EXPECT_TRUE(handler.isEstablished());

    // 发送业务数据
    std::string payload = "PING_SOCKS5";
    [[maybe_unused]] auto _ = ::send(fd, payload.data(), payload.size(), MSG_NOSIGNAL);

    pollfd pfd{fd, POLLIN, 0};
    ASSERT_GT(::poll(&pfd, 1, 2000), 0);
    char buf[512];
    ssize_t n = ::read(fd, buf, sizeof(buf));
    ASSERT_GT(n, 0);
    EXPECT_EQ(std::string(buf, n), "ECHO_SOCKS5:PING_SOCKS5");

    ::close(fd);
}

TEST(SingBoxInteropTest, SingBoxOutboundSocks5ToMynetInbound)
{
    ASSERT_FALSE(findSingBoxBinary().empty()) << "sing-box binary not found";

    EchoServer echo("ECHO_MYNET_SOCKS5:");
    ASSERT_TRUE(echo.isRunning());

    InboundSocks5 mynetIn("m-socks-in", "127.0.0.1", 0);
    ASSERT_TRUE(mynetIn.listen().has_value());
    uint16_t mynetPort = mynetIn.port();

    // Sing-box 配置 SOCKS5 出站指向 Mynet InboundSocks5
    std::string sbConfig = R"({
      "log": {"level": "warn"},
      "route": {"auto_detect_interface": false},
      "inbounds": [{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 14002}],
      "outbounds": [{"type": "socks", "tag": "socks-out", "server": "127.0.0.1", "server_port": )" +
                           std::to_string(mynetPort) + R"(}]
    })";

    SingBoxRunner sb(sbConfig);
    ASSERT_TRUE(sb.isRunning());

    std::thread mynetWorker(
        [&]()
        {
            auto acc = mynetIn.acceptOne();
            int retries = 0;
            while (!acc && retries < 20)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                acc = mynetIn.acceptOne();
                retries++;
            }
            if (!acc)
                return;
            int clientFd = acc->first;

            HandlerInboundSocks5 h;
            if (!inbound::driveHandshake(clientFd, h, 2000))
            {
                ::close(clientFd);
                return;
            }

            int echoFd = dialTcpClient("127.0.0.1", echo.port());
            if (echoFd >= 0)
            {
                if (h.requestBytes() > 0)
                {
                    [[maybe_unused]] auto _ = ::send(echoFd, h.requestBegin(), h.requestBytes(), MSG_NOSIGNAL);
                    h.requestConsume(h.requestBytes());
                }
                pollfd pfds[2] = {{clientFd, POLLIN, 0}, {echoFd, POLLIN, 0}};
                for (int i = 0; i < 50; ++i)
                {
                    int prc = ::poll(pfds, 2, 100);
                    if (prc <= 0)
                        continue;
                    if (pfds[0].revents & POLLIN)
                    {
                        char buf[1024];
                        ssize_t n = ::read(clientFd, buf, sizeof(buf));
                        if (n <= 0)
                            break;
                        [[maybe_unused]] auto _ = ::send(echoFd, buf, n, MSG_NOSIGNAL);
                    }
                    if (pfds[1].revents & POLLIN)
                    {
                        char buf[1024];
                        ssize_t n = ::read(echoFd, buf, sizeof(buf));
                        if (n <= 0)
                            break;
                        [[maybe_unused]] auto _ = ::send(clientFd, buf, n, MSG_NOSIGNAL);
                    }
                }
                ::close(echoFd);
            }
            ::close(clientFd);
        });

    int client = dialTcpClient("127.0.0.1", 14002);
    ASSERT_GE(client, 0);
    ThreadJoiner joiner(mynetWorker);

    // SOCKS5 握手
    char greeting[] = {0x05, 0x01, 0x00};
    [[maybe_unused]] auto _ = ::send(client, greeting, 3, MSG_NOSIGNAL);
    char gResp[2];
    ASSERT_EQ(readFull(client, gResp, 2), 2);
    ASSERT_EQ(gResp[1], 0x00);

    // CONNECT
    uint16_t eport = echo.port();
    std::vector<uint8_t> connReq = {
        0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, static_cast<uint8_t>(eport >> 8), static_cast<uint8_t>(eport & 0xFF)};
    [[maybe_unused]] auto _c = ::send(client, connReq.data(), connReq.size(), MSG_NOSIGNAL);
    char cResp[10];
    ASSERT_EQ(readFull(client, cResp, 10), 10);
    ASSERT_EQ(cResp[1], 0x00);

    // 发送业务数据
    std::string msg = "HELLO_FROM_SINGBOX_OUTBOUND";
    [[maybe_unused]] auto _m = ::send(client, msg.data(), msg.size(), MSG_NOSIGNAL);

    char echoBuf[512];
    int n = readSome(client, echoBuf, sizeof(echoBuf));
    ASSERT_GT(n, 0);
    EXPECT_EQ(std::string(echoBuf, n), "ECHO_MYNET_SOCKS5:HELLO_FROM_SINGBOX_OUTBOUND");

    ::close(client);
}

// =============================================================================
// 2. HTTP 代理互通测试 (HTTP Proxy Mutual Interoperability)
// =============================================================================

TEST(SingBoxInteropTest, MynetOutboundHttpToSingBoxInbound)
{
    ASSERT_FALSE(findSingBoxBinary().empty()) << "sing-box binary not found";

    EchoServer echo("ECHO_HTTP:");
    ASSERT_TRUE(echo.isRunning());

    // Sing-box 配置 HTTP 入站，端口 14003
    std::string sbConfig = R"({
      "log": {"level": "warn"},
      "route": {"auto_detect_interface": false},
      "inbounds": [{"type": "http", "tag": "http-in", "listen": "127.0.0.1", "listen_port": 14003}],
      "outbounds": [{"type": "direct", "tag": "direct", "bind_interface": "lo"}]
    })";

    SingBoxRunner sb(sbConfig);
    ASSERT_TRUE(sb.isRunning());

    OutboundHttp outbound("sb-http", "127.0.0.1", 14003);
    auto target = ProxyAddress::fromIPv4(htonl(INADDR_LOOPBACK), echo.port());

    auto dialRes = outbound.dialStream(target);
    ASSERT_TRUE(dialRes.has_value());
    int fd = dialRes->fd;
    ASSERT_GE(fd, 0);

    auto &handler = *dialRes->handler;
    while (!handler.isEstablished())
    {
        while (handler.hasResponse())
        {
            std::string resp = handler.takeResponse();
            [[maybe_unused]] auto _ = ::send(fd, resp.data(), resp.size(), MSG_NOSIGNAL);
        }
        pollfd pfd{fd, POLLIN, 0};
        ASSERT_GT(::poll(&pfd, 1, 2000), 0);
        char buf[512];
        ssize_t n = ::read(fd, buf, sizeof(buf));
        ASSERT_GT(n, 0);
        [[maybe_unused]] auto _ = handler.appendRequest(buf, n);
        handler.handle();
    }
    EXPECT_TRUE(handler.isEstablished());

    std::string payload = "DATA_HTTP_TUNNEL";
    [[maybe_unused]] auto _ = ::send(fd, payload.data(), payload.size(), MSG_NOSIGNAL);

    pollfd pfd{fd, POLLIN, 0};
    ASSERT_GT(::poll(&pfd, 1, 2000), 0);
    char buf[512];
    ssize_t n = ::read(fd, buf, sizeof(buf));
    ASSERT_GT(n, 0);
    EXPECT_EQ(std::string(buf, n), "ECHO_HTTP:DATA_HTTP_TUNNEL");

    ::close(fd);
}

TEST(SingBoxInteropTest, SingBoxOutboundHttpToMynetInbound)
{
    ASSERT_FALSE(findSingBoxBinary().empty()) << "sing-box binary not found";

    EchoServer echo("ECHO_MYNET_HTTP:");
    ASSERT_TRUE(echo.isRunning());

    InboundHttp mynetIn("m-http-in", "127.0.0.1", 0);
    ASSERT_TRUE(mynetIn.listen().has_value());
    uint16_t mynetPort = mynetIn.port();

    // Sing-box 配置 HTTP 出站指向 Mynet InboundHttp
    std::string sbConfig = R"({
      "log": {"level": "warn"},
      "route": {"auto_detect_interface": false},
      "inbounds": [{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 14010}],
      "outbounds": [{"type": "http", "tag": "http-out", "server": "127.0.0.1", "server_port": )" +
                           std::to_string(mynetPort) + R"(}]
    })";

    SingBoxRunner sb(sbConfig);
    ASSERT_TRUE(sb.isRunning());

    std::thread mynetWorker(
        [&]()
        {
            auto acc = mynetIn.acceptOne();
            int retries = 0;
            while (!acc && retries < 20)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                acc = mynetIn.acceptOne();
                retries++;
            }
            if (!acc)
                return;
            int clientFd = acc->first;

            HandlerInboundHttpProxy h;
            if (!inbound::driveHandshake(clientFd, h, 2000))
            {
                ::close(clientFd);
                return;
            }

            int echoFd = dialTcpClient("127.0.0.1", echo.port());
            if (echoFd >= 0)
            {
                if (h.requestBytes() > 0)
                {
                    [[maybe_unused]] auto _ = ::send(echoFd, h.requestBegin(), h.requestBytes(), MSG_NOSIGNAL);
                    h.requestConsume(h.requestBytes());
                }
                pollfd pfds[2] = {{clientFd, POLLIN, 0}, {echoFd, POLLIN, 0}};
                for (int i = 0; i < 50; ++i)
                {
                    int prc = ::poll(pfds, 2, 100);
                    if (prc <= 0)
                        continue;
                    if (pfds[0].revents & POLLIN)
                    {
                        char buf[1024];
                        ssize_t n = ::read(clientFd, buf, sizeof(buf));
                        if (n <= 0)
                            break;
                        [[maybe_unused]] auto _ = ::send(echoFd, buf, n, MSG_NOSIGNAL);
                    }
                    if (pfds[1].revents & POLLIN)
                    {
                        char buf[1024];
                        ssize_t n = ::read(echoFd, buf, sizeof(buf));
                        if (n <= 0)
                            break;
                        [[maybe_unused]] auto _ = ::send(clientFd, buf, n, MSG_NOSIGNAL);
                    }
                }
                ::close(echoFd);
            }
            ::close(clientFd);
        });

    int client = dialTcpClient("127.0.0.1", 14010);
    ASSERT_GE(client, 0);
    ThreadJoiner joiner(mynetWorker);

    // SOCKS5 握手
    char greeting[] = {0x05, 0x01, 0x00};
    [[maybe_unused]] auto _ = ::send(client, greeting, 3, MSG_NOSIGNAL);
    char gResp[2];
    ASSERT_EQ(readFull(client, gResp, 2), 2);
    ASSERT_EQ(gResp[1], 0x00);

    // CONNECT 到 EchoServer
    uint16_t eport = echo.port();
    std::vector<uint8_t> connReq = {
        0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, static_cast<uint8_t>(eport >> 8), static_cast<uint8_t>(eport & 0xFF)};
    [[maybe_unused]] auto _c = ::send(client, connReq.data(), connReq.size(), MSG_NOSIGNAL);
    char cResp[10];
    ASSERT_EQ(readFull(client, cResp, 10), 10);
    ASSERT_EQ(cResp[1], 0x00);

    // 传输业务数据
    std::string msg = "HELLO_HTTP_OUTBOUND";
    [[maybe_unused]] auto _m = ::send(client, msg.data(), msg.size(), MSG_NOSIGNAL);

    char echoBuf[512];
    int n = readSome(client, echoBuf, sizeof(echoBuf));
    ASSERT_GT(n, 0);
    EXPECT_EQ(std::string(echoBuf, n), "ECHO_MYNET_HTTP:HELLO_HTTP_OUTBOUND");

    ::close(client);
}

// =============================================================================
// 3. Trojan 互通测试 (Trojan Mutual Interoperability)
// =============================================================================

TEST(SingBoxInteropTest, MynetOutboundTrojanToSingBoxInbound)
{
    ASSERT_FALSE(findSingBoxBinary().empty()) << "sing-box binary not found";

    EchoServer echo("ECHO_TROJAN:");
    ASSERT_TRUE(echo.isRunning());

    // Sing-box 配置 Trojan 入站 (无 TLS)，端口 14004
    std::string sbConfig = R"({
      "log": {"level": "warn"},
      "route": {"auto_detect_interface": false},
      "inbounds": [{"type": "trojan", "tag": "trojan-in", "listen": "127.0.0.1", "listen_port": 14004, "users": [{"password": "secretpass"}]}],
      "outbounds": [{"type": "direct", "tag": "direct", "bind_interface": "lo"}]
    })";

    SingBoxRunner sb(sbConfig);
    ASSERT_TRUE(sb.isRunning());

    OutboundTrojan outbound("sb-trojan", "127.0.0.1", 14004, "secretpass");
    auto target = ProxyAddress::fromIPv4(htonl(INADDR_LOOPBACK), echo.port());

    auto dialRes = outbound.dialStream(target);
    ASSERT_TRUE(dialRes.has_value());
    int fd = dialRes->fd;
    ASSERT_GE(fd, 0);

    auto &handler = *dialRes->handler;
    while (handler.hasResponse())
    {
        std::string resp = handler.takeResponse();
        [[maybe_unused]] auto _ = ::send(fd, resp.data(), resp.size(), MSG_NOSIGNAL);
    }
    EXPECT_TRUE(handler.isEstablished());

    std::string payload = "PING_TROJAN";
    [[maybe_unused]] auto _ = ::send(fd, payload.data(), payload.size(), MSG_NOSIGNAL);

    pollfd pfd{fd, POLLIN, 0};
    ASSERT_GT(::poll(&pfd, 1, 2000), 0);
    char buf[512];
    ssize_t n = ::read(fd, buf, sizeof(buf));
    ASSERT_GT(n, 0);
    EXPECT_EQ(std::string(buf, n), "ECHO_TROJAN:PING_TROJAN");

    ::close(fd);
}

TEST(SingBoxInteropTest, SingBoxOutboundTrojanToMynetInbound)
{
    ASSERT_FALSE(findSingBoxBinary().empty()) << "sing-box binary not found";

    EchoServer echo("ECHO_MYNET_TROJAN:");
    ASSERT_TRUE(echo.isRunning());

    InboundTrojan mynetIn("m-trojan-in", "127.0.0.1", 0, "secretpass");
    ASSERT_TRUE(mynetIn.listen().has_value());
    uint16_t mynetPort = mynetIn.port();

    // Sing-box 配置 Trojan 出站指向 Mynet InboundTrojan
    std::string sbConfig = R"({
      "log": {"level": "warn"},
      "route": {"auto_detect_interface": false},
      "inbounds": [{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 14005}],
      "outbounds": [{"type": "trojan", "tag": "trojan-out", "server": "127.0.0.1", "server_port": )" +
                           std::to_string(mynetPort) + R"(, "password": "secretpass"}]
    })";

    SingBoxRunner sb(sbConfig);
    ASSERT_TRUE(sb.isRunning());

    std::thread mynetWorker(
        [&]()
        {
            auto acc = mynetIn.acceptOne();
            int retries = 0;
            while (!acc && retries < 20)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                acc = mynetIn.acceptOne();
                retries++;
            }
            if (!acc)
                return;
            int clientFd = acc->first;

            HandlerInboundTrojan h("secretpass");
            if (!inbound::driveHandshake(clientFd, h, 2000))
            {
                ::close(clientFd);
                return;
            }

            int echoFd = dialTcpClient("127.0.0.1", echo.port());
            if (echoFd >= 0)
            {
                if (h.requestBytes() > 0)
                {
                    [[maybe_unused]] auto _ = ::send(echoFd, h.requestBegin(), h.requestBytes(), MSG_NOSIGNAL);
                    h.requestConsume(h.requestBytes());
                }
                pollfd pfds[2] = {{clientFd, POLLIN, 0}, {echoFd, POLLIN, 0}};
                for (int i = 0; i < 50; ++i)
                {
                    int prc = ::poll(pfds, 2, 100);
                    if (prc <= 0)
                        continue;
                    if (pfds[0].revents & POLLIN)
                    {
                        char buf[1024];
                        ssize_t n = ::read(clientFd, buf, sizeof(buf));
                        if (n <= 0)
                            break;
                        [[maybe_unused]] auto _ = ::send(echoFd, buf, n, MSG_NOSIGNAL);
                    }
                    if (pfds[1].revents & POLLIN)
                    {
                        char buf[1024];
                        ssize_t n = ::read(echoFd, buf, sizeof(buf));
                        if (n <= 0)
                            break;
                        [[maybe_unused]] auto _ = ::send(clientFd, buf, n, MSG_NOSIGNAL);
                    }
                }
                ::close(echoFd);
            }
            ::close(clientFd);
        });

    int client = dialTcpClient("127.0.0.1", 14005);
    ASSERT_GE(client, 0);
    ThreadJoiner joiner(mynetWorker);

    // SOCKS5 握手
    char greeting[] = {0x05, 0x01, 0x00};
    [[maybe_unused]] auto _ = ::send(client, greeting, 3, MSG_NOSIGNAL);
    char gResp[2];
    ASSERT_EQ(readFull(client, gResp, 2), 2);

    uint16_t eport = echo.port();
    std::vector<uint8_t> connReq = {
        0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, static_cast<uint8_t>(eport >> 8), static_cast<uint8_t>(eport & 0xFF)};
    [[maybe_unused]] auto _c = ::send(client, connReq.data(), connReq.size(), MSG_NOSIGNAL);
    char cResp[10];
    ASSERT_EQ(readFull(client, cResp, 10), 10);

    std::string msg = "HELLO_TROJAN_ROUNDTRIP";
    [[maybe_unused]] auto _m = ::send(client, msg.data(), msg.size(), MSG_NOSIGNAL);

    char echoBuf[512];
    int n = readSome(client, echoBuf, sizeof(echoBuf));
    ASSERT_GT(n, 0);
    EXPECT_EQ(std::string(echoBuf, n), "ECHO_MYNET_TROJAN:HELLO_TROJAN_ROUNDTRIP");

    ::close(client);
}

// =============================================================================
// 4. VLESS 互通测试 (VLESS Mutual Interoperability)
// =============================================================================

TEST(SingBoxInteropTest, MynetOutboundVlessToSingBoxInbound)
{
    ASSERT_FALSE(findSingBoxBinary().empty()) << "sing-box binary not found";

    EchoServer echo("ECHO_VLESS:");
    ASSERT_TRUE(echo.isRunning());

    std::string testUuid = "de04add9-5c1a-4b08-8e65-244e45cf5483";

    // Sing-box 配置 VLESS 入站 (无 TLS)，端口 14006
    std::string sbConfig = R"({
      "log": {"level": "warn"},
      "route": {"auto_detect_interface": false},
      "inbounds": [{"type": "vless", "tag": "vless-in", "listen": "127.0.0.1", "listen_port": 14006, "users": [{"uuid": ")" +
                           testUuid + R"("}]}],
      "outbounds": [{"type": "direct", "tag": "direct", "bind_interface": "lo"}]
    })";

    SingBoxRunner sb(sbConfig);
    ASSERT_TRUE(sb.isRunning());

    OutboundVless outbound("sb-vless", "127.0.0.1", 14006, testUuid);
    auto target = ProxyAddress::fromIPv4(htonl(INADDR_LOOPBACK), echo.port());

    auto dialRes = outbound.dialStream(target);
    ASSERT_TRUE(dialRes.has_value());
    int fd = dialRes->fd;
    ASSERT_GE(fd, 0);

    auto &handler = *dialRes->handler;
    while (handler.hasResponse())
    {
        std::string resp = handler.takeResponse();
        [[maybe_unused]] auto _ = ::send(fd, resp.data(), resp.size(), MSG_NOSIGNAL);
    }

    std::string payload = "PING_VLESS";
    [[maybe_unused]] auto _ = ::send(fd, payload.data(), payload.size(), MSG_NOSIGNAL);

    pollfd pfd{fd, POLLIN, 0};
    ASSERT_GT(::poll(&pfd, 1, 2000), 0);
    char buf[512];
    ssize_t n = ::read(fd, buf, sizeof(buf));
    ASSERT_GT(n, 0);
    [[maybe_unused]] auto _a = handler.appendRequest(buf, n);
    handler.handle();
    EXPECT_TRUE(handler.isEstablished());

    std::string received(handler.requestBegin(), handler.requestBytes());
    EXPECT_EQ(received, "ECHO_VLESS:PING_VLESS");

    ::close(fd);
}

TEST(SingBoxInteropTest, SingBoxOutboundVlessToMynetInbound)
{
    ASSERT_FALSE(findSingBoxBinary().empty()) << "sing-box binary not found";

    EchoServer echo("ECHO_MYNET_VLESS:");
    ASSERT_TRUE(echo.isRunning());

    std::string testUuid = "de04add9-5c1a-4b08-8e65-244e45cf5483";

    InboundVless mynetIn("m-vless-in", "127.0.0.1", 0, testUuid);
    ASSERT_TRUE(mynetIn.listen().has_value());
    uint16_t mynetPort = mynetIn.port();

    // Sing-box 配置 VLESS 出站指向 Mynet InboundVless
    std::string sbConfig = R"({
      "log": {"level": "warn"},
      "route": {"auto_detect_interface": false},
      "inbounds": [{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 14007}],
      "outbounds": [{"type": "vless", "tag": "vless-out", "server": "127.0.0.1", "server_port": )" +
                           std::to_string(mynetPort) + R"(, "uuid": ")" + testUuid + R"("}]
    })";

    SingBoxRunner sb(sbConfig);
    ASSERT_TRUE(sb.isRunning());

    std::thread mynetWorker(
        [&]()
        {
            auto acc = mynetIn.acceptOne();
            int retries = 0;
            while (!acc && retries < 20)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                acc = mynetIn.acceptOne();
                retries++;
            }
            if (!acc)
                return;
            int clientFd = acc->first;

            HandlerInboundVless h(testUuid);
            if (!inbound::driveHandshake(clientFd, h, 2000))
            {
                ::close(clientFd);
                return;
            }

            int echoFd = dialTcpClient("127.0.0.1", echo.port());
            if (echoFd >= 0)
            {
                if (h.requestBytes() > 0)
                {
                    [[maybe_unused]] auto _ = ::send(echoFd, h.requestBegin(), h.requestBytes(), MSG_NOSIGNAL);
                    h.requestConsume(h.requestBytes());
                }
                pollfd pfds[2] = {{clientFd, POLLIN, 0}, {echoFd, POLLIN, 0}};
                for (int i = 0; i < 50; ++i)
                {
                    int prc = ::poll(pfds, 2, 100);
                    if (prc <= 0)
                        continue;
                    if (pfds[0].revents & POLLIN)
                    {
                        char buf[1024];
                        ssize_t n = ::read(clientFd, buf, sizeof(buf));
                        if (n <= 0)
                            break;
                        [[maybe_unused]] auto _ = ::send(echoFd, buf, n, MSG_NOSIGNAL);
                    }
                    if (pfds[1].revents & POLLIN)
                    {
                        char buf[1024];
                        ssize_t n = ::read(echoFd, buf, sizeof(buf));
                        if (n <= 0)
                            break;
                        [[maybe_unused]] auto _ = ::send(clientFd, buf, n, MSG_NOSIGNAL);
                    }
                }
                ::close(echoFd);
            }
            ::close(clientFd);
        });

    int client = dialTcpClient("127.0.0.1", 14007);
    ASSERT_GE(client, 0);
    ThreadJoiner joiner(mynetWorker);

    char greeting[] = {0x05, 0x01, 0x00};
    [[maybe_unused]] auto _ = ::send(client, greeting, 3, MSG_NOSIGNAL);
    char gResp[2];
    ASSERT_EQ(readFull(client, gResp, 2), 2);

    uint16_t eport = echo.port();
    std::vector<uint8_t> connReq = {
        0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, static_cast<uint8_t>(eport >> 8), static_cast<uint8_t>(eport & 0xFF)};
    [[maybe_unused]] auto _c = ::send(client, connReq.data(), connReq.size(), MSG_NOSIGNAL);
    char cResp[10];
    ASSERT_EQ(readFull(client, cResp, 10), 10);

    std::string msg = "HELLO_VLESS_ROUNDTRIP";
    [[maybe_unused]] auto _m = ::send(client, msg.data(), msg.size(), MSG_NOSIGNAL);

    char echoBuf[512];
    int n = readSome(client, echoBuf, sizeof(echoBuf));
    ASSERT_GT(n, 0);
    EXPECT_EQ(std::string(echoBuf, n), "ECHO_MYNET_VLESS:HELLO_VLESS_ROUNDTRIP");

    ::close(client);
}

// =============================================================================
// 5. Shadowsocks 互通测试 (Shadowsocks AEAD Interoperability)
// =============================================================================

TEST(SingBoxInteropTest, MynetOutboundShadowsocksToSingBoxInbound)
{
    ASSERT_FALSE(findSingBoxBinary().empty()) << "sing-box binary not found";

    EchoServer echo("ECHO_SS:");
    ASSERT_TRUE(echo.isRunning());

    std::string sbConfig = R"({
      "log": {"level": "warn"},
      "route": {"auto_detect_interface": false},
      "inbounds": [{"type": "shadowsocks", "tag": "ss-in", "listen": "127.0.0.1", "listen_port": 14008, "method": "aes-128-gcm", "password": "sspassword"}],
      "outbounds": [{"type": "direct", "tag": "direct", "bind_interface": "lo"}]
    })";

    SingBoxRunner sb(sbConfig);
    ASSERT_TRUE(sb.isRunning());

    OutboundShadowsocks outbound("sb-ss", "127.0.0.1", 14008, "aes-128-gcm", "sspassword");
    auto target = ProxyAddress::fromIPv4(htonl(INADDR_LOOPBACK), echo.port());

    auto dialRes = outbound.dialStream(target);
    ASSERT_TRUE(dialRes.has_value());
    int fd = dialRes->fd;
    ASSERT_GE(fd, 0);

    auto &handler = *dialRes->handler;
    while (handler.hasResponse())
    {
        std::string resp = handler.takeResponse();
        [[maybe_unused]] auto _ = ::send(fd, resp.data(), resp.size(), MSG_NOSIGNAL);
    }
    EXPECT_TRUE(handler.isEstablished());

    ::close(fd);
}

TEST(SingBoxInteropTest, SingBoxOutboundShadowsocksToMynetInbound)
{
    ASSERT_FALSE(findSingBoxBinary().empty()) << "sing-box binary not found";

    InboundShadowsocks mynetIn("m-ss-in", "127.0.0.1", 0, "aes-128-gcm", "sspassword");
    ASSERT_TRUE(mynetIn.listen().has_value());
    uint16_t mynetPort = mynetIn.port();

    // Sing-box 配置 Shadowsocks 出站指向 Mynet InboundShadowsocks
    std::string sbConfig = R"({
      "log": {"level": "warn"},
      "route": {"auto_detect_interface": false},
      "inbounds": [{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 14013}],
      "outbounds": [{"type": "shadowsocks", "tag": "ss-out", "server": "127.0.0.1", "server_port": )" +
                           std::to_string(mynetPort) + R"(, "method": "aes-128-gcm", "password": "sspassword"}]
    })";

    SingBoxRunner sb(sbConfig);
    ASSERT_TRUE(sb.isRunning());

    std::atomic<bool> handshakeOk{false};
    uint16_t resolvedPort = 0;

    std::thread mynetWorker(
        [&]()
        {
            auto acc = mynetIn.acceptOne();
            int retries = 0;
            while (!acc && retries < 20)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                acc = mynetIn.acceptOne();
                retries++;
            }
            if (!acc)
                return;
            int clientFd = acc->first;

            HandlerInboundShadowsocks h("aes-128-gcm", "sspassword");
            if (inbound::driveHandshake(clientFd, h, 2000))
            {
                handshakeOk = h.isEstablished();
                if (h.targetAddress().has_value())
                {
                    resolvedPort = h.targetAddress()->port;
                }
            }
            ::close(clientFd);
        });

    int client = dialTcpClient("127.0.0.1", 14013);
    ASSERT_GE(client, 0);
    ThreadJoiner joiner(mynetWorker);

    // SOCKS5 握手并通过 Sing-Box 触发 Shadowsocks 出站连接
    char greeting[] = {0x05, 0x01, 0x00};
    [[maybe_unused]] auto _ = ::send(client, greeting, 3, MSG_NOSIGNAL);
    char gResp[2];
    ASSERT_EQ(readFull(client, gResp, 2), 2);

    std::vector<uint8_t> connReq = {0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x1F, 0x90}; // 8080 端口
    [[maybe_unused]] auto _c = ::send(client, connReq.data(), connReq.size(), MSG_NOSIGNAL);

    if (mynetWorker.joinable())
    {
        mynetWorker.join();
    }

    EXPECT_TRUE(handshakeOk.load());
    EXPECT_EQ(resolvedPort, 8080);

    ::close(client);
}

TEST(SingBoxInteropTest, SingBoxOutboundSocksToMynetMuxInbound)
{
    ASSERT_FALSE(findSingBoxBinary().empty()) << "sing-box binary not found";

    EchoServer echo("ECHO_MUX_SOCKS5:");
    ASSERT_TRUE(echo.isRunning());

    InboundMux mynetIn("m-mux-in", "127.0.0.1", 0);
    ASSERT_TRUE(mynetIn.listen().has_value());
    uint16_t mynetPort = mynetIn.port();

    // Sing-box 配置 SOCKS5 出站指向 Mynet InboundMux
    std::string sbConfig = R"({
      "log": {"level": "warn"},
      "route": {"auto_detect_interface": false},
      "inbounds": [{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 14014}],
      "outbounds": [{"type": "socks", "tag": "socks-out", "server": "127.0.0.1", "server_port": )" +
                           std::to_string(mynetPort) + R"(, "version": "5"}]
    })";

    SingBoxRunner sb(sbConfig);
    ASSERT_TRUE(sb.isRunning());

    std::thread mynetWorker(
        [&]()
        {
            auto acc = mynetIn.acceptOne();
            int retries = 0;
            while (!acc && retries < 20)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                acc = mynetIn.acceptOne();
                retries++;
            }
            if (!acc)
                return;
            int clientFd = acc->first;

            HandlerInboundMux h;
            if (!inbound::driveHandshake(clientFd, h, 2000))
            {
                ::close(clientFd);
                return;
            }

            int echoFd = dialTcpClient("127.0.0.1", echo.port());
            if (echoFd >= 0)
            {
                if (h.requestBytes() > 0)
                {
                    [[maybe_unused]] auto _ = ::send(echoFd, h.requestBegin(), h.requestBytes(), MSG_NOSIGNAL);
                    h.requestConsume(h.requestBytes());
                }
                pollfd pfds[2] = {{clientFd, POLLIN, 0}, {echoFd, POLLIN, 0}};
                for (int i = 0; i < 50; ++i)
                {
                    int prc = ::poll(pfds, 2, 100);
                    if (prc <= 0)
                        continue;
                    if (pfds[0].revents & POLLIN)
                    {
                        char buf[1024];
                        ssize_t n = ::read(clientFd, buf, sizeof(buf));
                        if (n <= 0)
                            break;
                        [[maybe_unused]] auto _ = ::send(echoFd, buf, n, MSG_NOSIGNAL);
                    }
                    if (pfds[1].revents & POLLIN)
                    {
                        char buf[1024];
                        ssize_t n = ::read(echoFd, buf, sizeof(buf));
                        if (n <= 0)
                            break;
                        [[maybe_unused]] auto _ = ::send(clientFd, buf, n, MSG_NOSIGNAL);
                    }
                }
                ::close(echoFd);
            }
            ::close(clientFd);
        });

    int client = dialTcpClient("127.0.0.1", 14014);
    ASSERT_GE(client, 0);
    ThreadJoiner joiner(mynetWorker);

    char greeting[] = {0x05, 0x01, 0x00};
    [[maybe_unused]] auto _ = ::send(client, greeting, 3, MSG_NOSIGNAL);
    char gResp[2];
    ASSERT_EQ(readFull(client, gResp, 2), 2);

    uint16_t eport = echo.port();
    std::vector<uint8_t> connReq = {
        0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, static_cast<uint8_t>(eport >> 8), static_cast<uint8_t>(eport & 0xFF)};
    [[maybe_unused]] auto _c = ::send(client, connReq.data(), connReq.size(), MSG_NOSIGNAL);
    char cResp[10];
    ASSERT_EQ(readFull(client, cResp, 10), 10);

    std::string msg = "HELLO_MUX_SOCKS5";
    [[maybe_unused]] auto _m = ::send(client, msg.data(), msg.size(), MSG_NOSIGNAL);

    char echoBuf[512];
    int n = readSome(client, echoBuf, sizeof(echoBuf));
    ASSERT_GT(n, 0);
    EXPECT_EQ(std::string(echoBuf, n), "ECHO_MUX_SOCKS5:HELLO_MUX_SOCKS5");

    ::close(client);
}

TEST(SingBoxInteropTest, SingBoxOutboundHttpToMynetMuxInbound)
{
    ASSERT_FALSE(findSingBoxBinary().empty()) << "sing-box binary not found";

    EchoServer echo("ECHO_MUX_HTTP:");
    ASSERT_TRUE(echo.isRunning());

    InboundMux mynetIn("m-mux-in2", "127.0.0.1", 0);
    ASSERT_TRUE(mynetIn.listen().has_value());
    uint16_t mynetPort = mynetIn.port();

    // Sing-box 配置 HTTP 出站指向 Mynet InboundMux
    std::string sbConfig = R"({
      "log": {"level": "warn"},
      "route": {"auto_detect_interface": false},
      "inbounds": [{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 14015}],
      "outbounds": [{"type": "http", "tag": "http-out", "server": "127.0.0.1", "server_port": )" +
                           std::to_string(mynetPort) + R"(}]
    })";

    SingBoxRunner sb(sbConfig);
    ASSERT_TRUE(sb.isRunning());

    std::thread mynetWorker(
        [&]()
        {
            auto acc = mynetIn.acceptOne();
            int retries = 0;
            while (!acc && retries < 20)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                acc = mynetIn.acceptOne();
                retries++;
            }
            if (!acc)
                return;
            int clientFd = acc->first;

            HandlerInboundMux h;
            if (!inbound::driveHandshake(clientFd, h, 2000))
            {
                ::close(clientFd);
                return;
            }

            int echoFd = dialTcpClient("127.0.0.1", echo.port());
            if (echoFd >= 0)
            {
                if (h.requestBytes() > 0)
                {
                    [[maybe_unused]] auto _ = ::send(echoFd, h.requestBegin(), h.requestBytes(), MSG_NOSIGNAL);
                    h.requestConsume(h.requestBytes());
                }
                pollfd pfds[2] = {{clientFd, POLLIN, 0}, {echoFd, POLLIN, 0}};
                for (int i = 0; i < 50; ++i)
                {
                    int prc = ::poll(pfds, 2, 100);
                    if (prc <= 0)
                        continue;
                    if (pfds[0].revents & POLLIN)
                    {
                        char buf[1024];
                        ssize_t n = ::read(clientFd, buf, sizeof(buf));
                        if (n <= 0)
                            break;
                        [[maybe_unused]] auto _ = ::send(echoFd, buf, n, MSG_NOSIGNAL);
                    }
                    if (pfds[1].revents & POLLIN)
                    {
                        char buf[1024];
                        ssize_t n = ::read(echoFd, buf, sizeof(buf));
                        if (n <= 0)
                            break;
                        [[maybe_unused]] auto _ = ::send(clientFd, buf, n, MSG_NOSIGNAL);
                    }
                }
                ::close(echoFd);
            }
            ::close(clientFd);
        });

    int client = dialTcpClient("127.0.0.1", 14015);
    ASSERT_GE(client, 0);
    ThreadJoiner joiner(mynetWorker);

    char greeting[] = {0x05, 0x01, 0x00};
    [[maybe_unused]] auto _ = ::send(client, greeting, 3, MSG_NOSIGNAL);
    char gResp[2];
    ASSERT_EQ(readFull(client, gResp, 2), 2);

    uint16_t eport = echo.port();
    std::vector<uint8_t> connReq = {
        0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, static_cast<uint8_t>(eport >> 8), static_cast<uint8_t>(eport & 0xFF)};
    [[maybe_unused]] auto _c = ::send(client, connReq.data(), connReq.size(), MSG_NOSIGNAL);
    char cResp[10];
    ASSERT_EQ(readFull(client, cResp, 10), 10);

    std::string msg = "HELLO_MUX_HTTP";
    [[maybe_unused]] auto _m = ::send(client, msg.data(), msg.size(), MSG_NOSIGNAL);

    char echoBuf[512];
    int n = readSome(client, echoBuf, sizeof(echoBuf));
    ASSERT_GT(n, 0);
    EXPECT_EQ(std::string(echoBuf, n), "ECHO_MUX_HTTP:HELLO_MUX_HTTP");

    ::close(client);
}
