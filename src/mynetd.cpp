/**
 * @file mynetd.cpp
 * @brief mynet 生产级统一代理内核守护进程入口 (mynetd Daemon Entrypoint)。
 *
 * 完全复用 mynet 现有代码架构：
 * 1. 采用 AcceptorBase<KernelProxyHandler> 接入混合代理（SOCKS4/SOCKS5/HTTP）；
 * 2. 支持根据 server.engine 动态运行 Reactor (epoll) 或 Proactor (io_uring)；
 * 3. 联动 Core 完成策略路由分流、域名嗅探、eBPF 旁路过滤与出站拨号；
 * 4. 联动 Forwarder 实现 Linux splice 零拷贝双向流中继与流量统计；
 * 5. 支持 -t 拓扑语法校验、-d 后台守护运行、SIGHUP 沙箱化 Lua 配置热重载与 SIGINT/SIGTERM 平滑停机。
 */

#include "controller.hpp"
#include "core.hpp"
#include "reactor.hpp"
#if defined(MYNET_ENABLE_URING)
#include "proactor.hpp"
#endif
#include "config/log.hpp"
#include "config/lua.hpp"
#include "configHolder.hpp"
#include "http/http.hpp"
#include "inbound.hpp"
#include "socks/socks4.hpp"
#include "socks/socks5.hpp"
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <getopt.h>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <unistd.h>

namespace mynet::handler
{

    enum class MixedProtocolType : uint8_t
    {
        UNKNOWN,
        SOCKS4,
        SOCKS5,
        HTTP
    };

    /**
     * @brief 混合协议入站服务端处理器 (Mixed Inbound)
     *
     * 在同一监听端口上自动根据客户端首字节分流：
     * - 0x04 -> SOCKS4 / SOCKS4a
     * - 0x05 -> SOCKS5
     * - 'C', 'G', 'P', 'H', 'D', 'O', 'T' 等 ASCII 字符 -> HTTP CONNECT / 明文代理
     */
    class HandlerInboundMixed : public HandlerInboundConnection
    {
    public:
        using AuthCallback = std::function<bool(std::string_view user, std::string_view pass)>;

    private:
        MixedProtocolType protocol_{MixedProtocolType::UNKNOWN};
        HandlerInboundSocks4 s4_{};
        HandlerInboundSocks5 s5_{};
        HandlerInboundHttpProxy http_{};
        AuthCallback authCallback_{nullptr};

    public:
        HandlerInboundMixed() noexcept = default;
        explicit HandlerInboundMixed(const ProxyConfig &cfg) noexcept
            : s4_(cfg),
              s5_(cfg)
        {
        }
        ~HandlerInboundMixed() noexcept override = default;

        HandlerInboundMixed(const HandlerInboundMixed &) = delete;
        HandlerInboundMixed &operator=(const HandlerInboundMixed &) = delete;
        HandlerInboundMixed(HandlerInboundMixed &&) = delete;
        HandlerInboundMixed &operator=(HandlerInboundMixed &&) = delete;

        void setAuthenticator(AuthCallback cb) noexcept
        {
            authCallback_ = cb;
            s5_.setAuthenticator(cb);
            s4_.setAuthenticator([cb](std::string_view uid) { return cb(uid, ""); });
            http_.setAuthenticator(cb);
        }

        [[nodiscard]] MixedProtocolType protocol() const noexcept { return protocol_; }

        [[nodiscard]] bool isEstablished() const noexcept
        {
            switch (protocol_)
            {
            case MixedProtocolType::SOCKS4:
                return s4_.isEstablished();
            case MixedProtocolType::SOCKS5:
                return s5_.isEstablished();
            case MixedProtocolType::HTTP:
                return http_.isEstablished();
            default:
                return false;
            }
        }

        [[nodiscard]] const std::optional<ProxyAddress> &targetAddress() const noexcept
        {
            switch (protocol_)
            {
            case MixedProtocolType::SOCKS4:
                return s4_.targetAddress();
            case MixedProtocolType::SOCKS5:
                return s5_.targetAddress();
            case MixedProtocolType::HTTP:
                return http_.targetAddress();
            default:
                return targetAddress_;
            }
        }

        void configure(const ProxyConfig &cfg) noexcept
        {
            s4_.configure(cfg);
            s5_.configure(cfg);
        }

        void reset() noexcept override
        {
            HandlerInboundConnection::reset();
            protocol_ = MixedProtocolType::UNKNOWN;
            s4_.reset();
            s5_.reset();
            http_.reset();
        }

        void onMessageComplete() noexcept {}
        void onParseError(const char *reason) noexcept { (void)reason; }

        void handle() override
        {
            if (protocol_ == MixedProtocolType::UNKNOWN)
            {
                if (requestBytes() == 0)
                {
                    return;
                }
                const uint8_t b = static_cast<uint8_t>(*requestBegin());
                if (b == socks4::kVersion)
                {
                    protocol_ = MixedProtocolType::SOCKS4;
                }
                else if (b == socks5::kVersion)
                {
                    protocol_ = MixedProtocolType::SOCKS5;
                }
                else if (isHttpChar(b))
                {
                    protocol_ = MixedProtocolType::HTTP;
                }
                else
                {
                    onParseError("Mixed: Unrecognized protocol byte");
                    setCloseAfterResponse(true);
                    return;
                }
            }

            switch (protocol_)
            {
            case MixedProtocolType::SOCKS4:
                syncToChild(s4_);
                s4_.handle();
                syncFromChild(s4_);
                if (s4_.isEstablished())
                {
                    stage_ = InboundStage::STREAMING;
                    targetAddress_ = s4_.targetAddress();
                    command_ = s4_.command();
                }
                break;
            case MixedProtocolType::SOCKS5:
                syncToChild(s5_);
                s5_.handle();
                syncFromChild(s5_);
                if (s5_.isEstablished())
                {
                    stage_ = InboundStage::STREAMING;
                    targetAddress_ = s5_.targetAddress();
                    command_ = s5_.command();
                }
                break;
            case MixedProtocolType::HTTP:
                syncToChild(http_);
                http_.handle();
                syncFromChild(http_);
                if (http_.isEstablished())
                {
                    stage_ = InboundStage::STREAMING;
                    targetAddress_ = http_.targetAddress();
                    command_ = http_.command();
                }
                break;
            default:
                break;
            }
        }

    private:
        static bool isHttpChar(uint8_t b) noexcept
        {
            return (b == 'C' || b == 'G' || b == 'P' || b == 'H' || b == 'D' || b == 'O' || b == 'T' ||
                    (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z'));
        }

        void syncToChild(HandlerConnection &child)
        {
            const size_t avail = requestBytes();
            if (avail > child.requestBytes())
            {
                const size_t diff = avail - child.requestBytes();
                const char *p = requestBegin() + child.requestBytes();
                [[maybe_unused]] auto _ = child.appendRequest(p, static_cast<ssize_t>(diff));
            }
        }

        void syncFromChild(HandlerConnection &child)
        {
            const size_t childAvail = child.requestBytes();
            if (requestBytes() > childAvail)
            {
                requestConsume(requestBytes() - childAvail);
            }

            while (child.hasResponse())
            {
                std::string resp = child.takeResponse();
                [[maybe_unused]] auto _ = pushResponse(resp);
            }

            if (child.closeAfterResponse())
            {
                setCloseAfterResponse(true);
            }

            if (child.isSpliceActive())
            {
                setSpliceTarget(child.spliceTarget());
            }
        }
    };

} // namespace mynet::handler

namespace mynet
{

    /**
     * @brief 自动多协议自适应入站端点 (InboundMixed)
     */
    class InboundMixed : public InboundBase
    {
    private:
        std::string username_{};
        std::string password_{};

    public:
        InboundMixed(std::string tag, std::string host, uint16_t port, std::string username = "",
                     std::string password = "", bool enableSniffing = true)
            : InboundBase(std::move(tag), "mixed", std::move(host), port, enableSniffing),
              username_(std::move(username)),
              password_(std::move(password))
        {
        }

        [[nodiscard]] std::unique_ptr<handler::HandlerInboundConnection> createHandler() override
        {
            auto h = std::make_unique<handler::HandlerInboundMixed>();
            if (!username_.empty() || !password_.empty())
            {
                std::string u = username_;
                std::string p = password_;
                h->setAuthenticator([u, p](std::string_view user, std::string_view pass)
                                    { return user == u && (p.empty() || pass == p); });
            }
            return h;
        }
    };

} // namespace mynet

namespace
{

    class KernelProxyHandler : public mynet::handler::HandlerInboundMixed
    {
    public:
        inline static mynet::Core *g_core = nullptr;

        KernelProxyHandler() noexcept = default;

        void handle()
        {
            mynet::handler::HandlerInboundMixed::handle();
            if (isEstablished() && !dispatched_ && g_core != nullptr)
            {
                dispatched_ = true;
                auto res = g_core->dispatch(*this, fd(), "default-mixed", true);
                if (res.ok() && res.session != nullptr)
                {
                    session_ = res.session;
                    if (session_->outboundFd() >= 0)
                    {
                        enableSpliceForward(session_->outboundFd());
                    }
                }
                else
                {
                    setCloseAfterResponse(true);
                }
            }
        }

        void reset() noexcept override
        {
            mynet::handler::HandlerInboundMixed::reset();
            dispatched_ = false;
            if (session_ != nullptr)
            {
                session_->close(true);
                session_.reset();
            }
        }

    private:
        bool dispatched_{false};
        std::shared_ptr<mynet::ForwarderStreamSession> session_{nullptr};
    };

    std::function<void()> g_stopHandler{nullptr};
    std::function<void()> g_reloadHandler{nullptr};

    void handleSignal(int sig) noexcept
    {
        if (sig == SIGHUP)
        {
            if (g_reloadHandler)
            {
                g_reloadHandler();
            }
        }
        else if (sig == SIGINT || sig == SIGTERM)
        {
            if (g_stopHandler)
            {
                g_stopHandler();
            }
        }
    }

    void printBanner()
    {
        std::cout << R"(
  __  __ __   __ _   _ _____ _____     ____ ___  ____  _____ 
 |  \/  |\ \ / /| \ | | ____|_   _|   / ___/ _ \|  _ \| ____|
 | |\/| | \ V / |  \| |  _|   | |    | |  | | | | |_) |  _|  
 | |  | |  | |  | |\  | |___  | |    | |__| |_| |  _ <| |___ 
 |_|  |_|  |_|  |_| \_|_____| |_|     \____\___/|_| \_\_____|
)" << '\n';
        std::cout << " Modern, High-Performance Proxy Kernel in C++26 (Linux)\n";
        std::cout << " Version: 1.0.0 | Release: 2026.11\n";
        std::cout << " Built with: GCC " << __GNUC__ << "." << __GNUC_MINOR__ << "." << __GNUC_PATCHLEVEL__
                  << " | -std=c++26 -fno-exceptions\n\n";
    }

    void printUsage(const char *progName)
    {
        std::cout << "Usage: " << progName << " [options]\n\n"
                  << "Options:\n"
                  << "  -c, --config <file>     Path to configuration file (default: config/config.lua)\n"
                  << "  -t, --test              Test configuration file syntax and core topology validity, then exit\n"
                  << "  -v, --version           Display kernel version, build parameters and capabilities\n"
                  << "  -h, --help              Display this help message\n"
                  << "  -d, --daemon            Run in background as a daemon\n\n"
                  << "Signals:\n"
                  << "  SIGINT, SIGTERM         Graceful shutdown\n"
                  << "  SIGHUP                  Live reload Lua configuration without service interruption\n\n";
    }

    template <template <typename> class EngineType>
    int runServer(mynet::Core &core, const mynet::MynetConfig &cfg, const std::string &engineName)
    {
        KernelProxyHandler::g_core = &core;

        using Server = EngineType<mynet::AcceptorBase<KernelProxyHandler>>;
        Server server;

        g_stopHandler = [&server]() { server.stop(); };

        LOG_INFO("I/O Engine active: {}", engineName);

        // 统一纳管 Core 中全部已启动的 Inbound 节点监听接收器到当前引擎的事件循环中
        for (const auto &inbound : core.inbounds().inbounds())
        {
            if (inbound->listenFd() >= 0 && inbound->listenFd() != server.acceptor().fd)
            {
                if constexpr (requires { server.addListener(0, {}); })
                {
                    auto addRes =
                        server.addListener(inbound->listenFd(),
                                           [&core, inbound](int clientFd, const sockaddr_in &clientAddr)
                                           {
                                               (void)clientAddr;
                                               auto handler = inbound->createHandler();
                                               if (handler != nullptr)
                                               {
                                                   if (mynet::inbound::driveHandshake(clientFd, *handler, 2000))
                                                   {
                                                       auto res = core.dispatch(*handler, clientFd, inbound->tag(),
                                                                                inbound->isSniffingEnabled());
                                                       if (!res.ok() || res.session == nullptr)
                                                       {
                                                           ::close(clientFd);
                                                       }
                                                   }
                                                   else
                                                   {
                                                       ::close(clientFd);
                                                   }
                                               }
                                               else
                                               {
                                                   ::close(clientFd);
                                               }
                                           });
                    if (!addRes)
                    {
                        LOG_WARN("runServer: failed to attach inbound '{}' to engine: {}", inbound->tag(),
                                 mynet::toString(addRes.error()));
                    }
                }
            }
        }

        // 启动后台流式转发泵送与空闲会话超时排空任务
        std::atomic<bool> pumpRunning{true};
        std::thread pumpThread(
            [&core, &pumpRunning]()
            {
                while (pumpRunning.load(std::memory_order_relaxed))
                {
                    core.tick();
                    core.sweepIdleSessions(60);
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                }
            });

        auto res = server.runTcp(cfg.server.host.c_str(), static_cast<int>(cfg.server.port));

        pumpRunning.store(false, std::memory_order_release);
        if (pumpThread.joinable())
        {
            pumpThread.join();
        }
        g_stopHandler = nullptr;

        if (!res)
        {
            LOG_ERROR("Server engine error: {}", mynet::toString(res.error()));
            return 1;
        }
        return 0;
    }

} // namespace

int main(int argc, char *argv[])
{
    std::string configPath = "config/config.lua";
    bool testConfigOnly = false;
    bool runDaemon = false;

    static struct option longOptions[] = {
        {"config", required_argument, nullptr, 'c'}, {"test", no_argument, nullptr, 't'},
        {"version", no_argument, nullptr, 'v'},      {"help", no_argument, nullptr, 'h'},
        {"daemon", no_argument, nullptr, 'd'},       {nullptr, 0, nullptr, 0}};

    int opt = 0;
    while ((opt = getopt_long(argc, argv, "c:tvhd", longOptions, nullptr)) != -1)
    {
        switch (opt)
        {
        case 'c':
            configPath = optarg;
            break;
        case 't':
            testConfigOnly = true;
            break;
        case 'v':
            printBanner();
            return 0;
        case 'h':
            printBanner();
            printUsage(argv[0]);
            return 0;
        case 'd':
            runDaemon = true;
            break;
        default:
            printUsage(argv[0]);
            return 1;
        }
    }

    // 检查配置文件是否存在
    if (::access(configPath.c_str(), R_OK) != 0)
    {
        if (::access("config/config.lua", R_OK) == 0)
        {
            configPath = "config/config.lua";
        }
        else if (::access("../config/config.lua", R_OK) == 0)
        {
            configPath = "../config/config.lua";
        }
        else
        {
            std::cerr << "[ERROR] Cannot open configuration file: " << configPath << " (" << std::strerror(errno)
                      << ")\n";
            return 1;
        }
    }

    // 加载并解析 Lua 脚本，统一初始化至 ConfigHolder
#ifdef MYNET_HAVE_LUA
    if (!mynet::reloadConfig(configPath, false))
    {
        std::cerr << "[FATAL] Failed to parse configuration from: " << configPath << "\n";
        return 1;
    }
#else
    std::cerr << "[WARN] Built without Lua support; running with compiled-in baseline configuration\n";
#endif

    const mynet::MynetConfig cfg = mynet::getMynetConfig();

    // 模式 1：配置校验模式 (-t / --test)
    if (testConfigOnly)
    {
        std::cout << "[INFO] Validating configuration: " << configPath << " ...\n";
        mynet::Core testCore(cfg);
        for (const auto &inCfg : cfg.inbounds)
        {
            if (inCfg.protocol == "mixed")
            {
                testCore.inbounds().registerInbound(std::make_shared<mynet::InboundMixed>(
                    inCfg.tag, inCfg.host, inCfg.port, inCfg.username, inCfg.password, inCfg.enableSniffing));
            }
        }

        // 执行拓扑闭包校验 (Fail-Fast)
        if (auto res = testCore.start(); !res)
        {
            std::cerr << "[ERROR] Configuration topology check FAILED: " << mynet::toString(res.error()) << "\n";
            return 1;
        }

        std::cout << "[OK] Configuration syntax is valid.\n"
                  << "[OK] Topology check PASSED:\n"
                  << "     - Engine selected:    " << cfg.server.engine << "\n"
                  << "     - Inbounds declared:  " << testCore.inbounds().size() << "\n"
                  << "     - Outbounds declared: " << testCore.outbounds().size() << "\n"
                  << "     - Route rules loaded: " << testCore.router().rules().size() << "\n"
                  << "     - Default outbound:   '" << testCore.router().defaultOutbound() << "'\n"
                  << "     - Splice zero-copy:   " << (cfg.forwarder.enableSplice ? "ENABLED" : "DISABLED") << "\n";
        if (testCore.ebpf() != nullptr)
        {
            std::cout << "     - dae eBPF engine:    ENABLED (iface: " << cfg.ebpf.wanInterface << ")\n";
        }
        if (cfg.controller.enabled)
        {
            std::cout << "     - Control API:        ENABLED (" << cfg.controller.host << ":" << cfg.controller.port
                      << ")\n";
        }
        testCore.stop();
        return 0;
    }

    // 模式 2：守护进程后台化 (-d / --daemon)
    if (runDaemon)
    {
        if (::daemon(1, 0) < 0)
        {
            std::cerr << "[FATAL] daemon() failed: " << std::strerror(errno) << "\n";
            return 1;
        }
    }

    printBanner();
    LOG_INFO("Starting mynet proxy kernel (PID: {})", ::getpid());
    LOG_INFO("Loaded configuration from '{}'", configPath);

    // 注册信号处理器
    struct sigaction sa{};
    sa.sa_handler = handleSignal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    ::sigaction(SIGINT, &sa, nullptr);
    ::sigaction(SIGTERM, &sa, nullptr);
    ::sigaction(SIGHUP, &sa, nullptr);

    // 忽略 SIGPIPE 避免对端异常断开导致进程崩溃
    struct sigaction saPipe{};
    saPipe.sa_handler = SIG_IGN;
    sigemptyset(&saPipe.sa_mask);
    ::sigaction(SIGPIPE, &saPipe, nullptr);

    // 构建内核主体并应用配置
    mynet::Core core(cfg);
    for (const auto &inCfg : cfg.inbounds)
    {
        if (inCfg.protocol == "mixed")
        {
            core.inbounds().registerInbound(std::make_shared<mynet::InboundMixed>(
                inCfg.tag, inCfg.host, inCfg.port, inCfg.username, inCfg.password, inCfg.enableSniffing));
        }
    }

    g_reloadHandler = [&core, &configPath]()
    {
        LOG_INFO("SIGHUP received: live reloading Lua configuration from '{}'...", configPath);
#ifdef MYNET_HAVE_LUA
        if (mynet::reloadConfig(configPath, false))
        {
            const auto reloadedCfg = mynet::getMynetConfig();
            core.applyConfig(reloadedCfg);
            for (const auto &inCfg : reloadedCfg.inbounds)
            {
                if (inCfg.protocol == "mixed" && !core.inbounds().has(inCfg.tag))
                {
                    core.inbounds().registerInbound(std::make_shared<mynet::InboundMixed>(
                        inCfg.tag, inCfg.host, inCfg.port, inCfg.username, inCfg.password, inCfg.enableSniffing));
                }
            }
            LOG_INFO("Configuration live reloaded successfully");
        }
        else
        {
            LOG_ERROR("Configuration reload failed, keeping current running config");
        }
#endif
    };

    if (core.ebpf() != nullptr)
    {
        LOG_INFO("dae eBPF Engine: initialized on interface '{}' (Kernel BPF: {}, Mode: {})", cfg.ebpf.wanInterface,
                 core.ebpf()->isKernelBpfActive() ? "ACTIVE" : "EMULATION",
                 core.ebpf()->isKernelBpfActive() ? "Kernel TC Hook" : "User-space LPM Trie");
    }

    // 启动入站监听与出站管理器
    if (auto res = core.start(cfg.server.backlog); !res)
    {
        LOG_FATAL("Failed to start mynet core engine: {}", mynet::toString(res.error()));
        return 1;
    }

    // 打印就绪状态
    LOG_INFO("Core engine started successfully. Active listeners:");
    for (const auto &inbound : core.inbounds().inbounds())
    {
        LOG_INFO("  * Inbound [{}] protocol='{}' listening on {}:{} (fd: {})", inbound->tag(), inbound->type(),
                 inbound->host(), inbound->port(), inbound->listenFd());
    }
    LOG_INFO("Default outbound: '{}', active route rules: {}", core.router().defaultOutbound(),
             core.router().rules().size());

    // 启动可选的 Clash-compatible 控制 API
    std::unique_ptr<mynet::Controller> apiController{nullptr};
    if (cfg.controller.enabled)
    {
        apiController = std::make_unique<mynet::Controller>(&core, cfg.controller);
        if (auto res = apiController->startBackground(); res)
        {
            LOG_INFO("Clash-compatible RESTful Control API listening on {}:{}", cfg.controller.host,
                     cfg.controller.port);
        }
        else
        {
            LOG_ERROR("Failed to start Control API on {}:{}: {}", cfg.controller.host, cfg.controller.port,
                      mynet::toString(res.error()));
        }
    }

    // 根据配置调度执行选定的 I/O 运行引擎 (Reactor 或 Proactor)
    int exitCode = 0;
#if defined(MYNET_ENABLE_URING)
    if (cfg.server.engine == "proactor")
    {
        exitCode = runServer<mynet::Proactor>(core, cfg, "Proactor (io_uring)");
    }
    else
    {
        exitCode = runServer<mynet::Reactor>(core, cfg, "Reactor (epoll)");
    }
#else
    if (cfg.server.engine == "proactor")
    {
        LOG_WARN("Proactor (io_uring) is not enabled in this build; falling back to Reactor (epoll)");
    }
    exitCode = runServer<mynet::Reactor>(core, cfg, "Reactor (epoll)");
#endif

    // 优雅关断
    LOG_INFO("Shutting down mynet proxy kernel gracefully...");
    g_reloadHandler = nullptr;
    if (apiController != nullptr)
    {
        apiController->stop();
    }
    core.stop();

    LOG_INFO("mynet kernel stopped. Statistics summary:");
    LOG_INFO("  - Total Bytes Uploaded:   {} bytes", core.totalBytesUp());
    LOG_INFO("  - Total Bytes Downloaded: {} bytes", core.totalBytesDown());
    LOG_INFO("  - Total Traffic Forwarded: {} bytes", core.totalBytes());
    return exitCode;
}
