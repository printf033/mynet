/**
 * @file mynetd.cpp
 * @brief mynet 生产级统一代理内核守护进程入口 (mynetd Daemon Entrypoint)。
 *
 * 完全复用 mynet 现有代码架构：
 * 1. 采用 AcceptorMixed 接入混合代理（SOCKS4/SOCKS5/HTTP）；
 * 2. 支持根据 server.engine 动态运行 Reactor (epoll) 或 Proactor (io_uring)；
 * 3. 联动 Core 完成策略路由分流、域名嗅探、eBPF 旁路过滤与出站拨号；
 * 4. 联动 Forwarder 实现 Linux splice 零拷贝双向流中继与流量统计；
 * 5. 支持 -t 拓扑语法校验、-d 后台守护运行、SIGHUP 沙箱化 Lua 配置热重载与 SIGINT/SIGTERM 平滑停机。
 */

#include "clash/controller.hpp"
#include "core.hpp"
#include "reactor.hpp"
#include "nekobox/service.hpp"
#if defined(MYNET_ENABLE_URING)
#include "proactor.hpp"
#endif
#include "config/log.hpp"
#if defined(MYNET_HAVE_LUA)
#include "config/lua.hpp"
#endif
#include "config/singbox.hpp"
#include "configHolder.hpp"
#include "connection.hpp"
#include "http/http.hpp"
#include "socks/socks4.hpp"
#include "socks/socks5.hpp"
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <getopt.h>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <unistd.h>

namespace
{

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

    template <typename Server>
    void attachCoreAcceptorsToServer(Server &server, mynet::Core &core, std::vector<int> &watchedAcceptors)
    {
        for (const auto &acc : core.acceptors().acceptors())
        {
            if (acc == nullptr || !acc->isRunning() || acc->listenFd() < 0 || acc->type() == "tun")
            {
                continue;
            }

            const int listenFd = acc->listenFd();
            if (acc->type() == "datagram" || acc->type() == "udp")
            {
                auto *dgramAcc = static_cast<mynet::AcceptorDatagram *>(acc.get());
                auto dgramHandler = std::make_shared<mynet::Handler>();
                dgramHandler->onConnect(listenFd);
                const std::string tag = acc->tag();
                const bool sniff = acc->isSniffingEnabled();
                if (server.loop().addWatch(
                        listenFd, EPOLLIN,
                        [&core, dgramAcc, dgramHandler, tag, sniff](uint32_t events)
                        {
                            if (!(events & EPOLLIN))
                            {
                                return;
                            }
                            char buf[4096];
                            for (;;)
                            {
                                sockaddr_in peer{};
                                sockaddr_in origDst{};
                                auto r = dgramAcc->datagram().recvWithDst(buf, sizeof(buf), peer, origDst);
                                if (!r || *r == 0)
                                {
                                    break;
                                }
                                if (origDst.sin_port != 0)
                                {
                                    const auto target = mynet::Address::fromIPv4(
                                        origDst.sin_addr.s_addr, ntohs(origDst.sin_port));
                                    [[maybe_unused]] auto tx = core.dispatchDatagram(
                                        *dgramHandler, peer, target, std::string_view(buf, *r), tag, sniff);
                                }
                            }
                        }))
                {
                    watchedAcceptors.push_back(listenFd);
                }
                continue;
            }

            if (server.loop().addWatch(
                    listenFd, EPOLLIN,
                    [&server, &core, acc](uint32_t events)
                    {
                        if (!(events & EPOLLIN))
                        {
                            return;
                        }
                        for (;;)
                        {
                            auto accRes = acc->acceptOne();
                            if (!accRes)
                            {
                                break;
                            }
                            const int clientFd = accRes->first;
                            const sockaddr_in clientAddr = accRes->second;
                            mynet::Connection *conn = nullptr;
                            if (acc->acceptConnection(clientFd, conn) != mynet::HandshakeStatus::SUCCESS ||
                                conn == nullptr)
                            {
                                ::close(clientFd);
                                continue;
                            }

                            conn->setFd(clientFd);
                            conn->setPeerAddr(clientAddr);
                            conn->setTransport(mynet::TransportType::TCP);

                            if (mynet::Handler *h = conn->handler(); h != nullptr)
                            {
                                const std::string inboundTag = acc->tag();
                                auto dispatched = std::make_shared<bool>(false);
                                h->setOnRequest(
                                    [&core, h, inboundTag, dispatched](uint8_t cmd,
                                                                       const mynet::Address &target)
                                    {
                                        (void)cmd;
                                        (void)target;
                                        if (*dispatched || h->fd() < 0)
                                        {
                                            return;
                                        }
                                        *dispatched = true;
                                        auto res = core.dispatch(*h, h->fd(), inboundTag, true, true);
                                        if (res.ok() && res.session != nullptr)
                                        {
                                            LOG_INFO(
                                                "Acceptor [{}]: Dispatched target '{}' to outbound '{}' (mode: {})",
                                                inboundTag,
                                                h->targetAddress().has_value() ? h->targetAddress()->toString()
                                                                               : "unknown",
                                                res.outboundTag, mynet::forwardModeName(res.session->activeMode()));
                                        }
                                        else
                                        {
                                            LOG_ERROR("Acceptor [{}]: Failed to dispatch target: status {}", inboundTag,
                                                      static_cast<int>(res.status));
                                            h->setCloseAfterResponse(true);
                                        }
                                    });
                            }

                            if (!server.adoptConnection(conn))
                            {
                                continue;
                            }
                            // 立即驱动一次状态机（使 tproxy !enableSniffing / direct 零等待进入出站拨号）
                            conn->handle();
                        }
                    }))
            {
                watchedAcceptors.push_back(listenFd);
            }
        }
    }

    template <template <typename...> class EngineType>
    int runServer(mynet::Core &core, const mynet::MynetConfig &cfg, const std::string &engineName)
    {
        using Server = EngineType<>;
        Server server;

        g_stopHandler = [&server]() { server.stop(); };

        LOG_INFO("I/O Engine active: {}", engineName);

        core.attachEventLoop(server.loop());
        std::vector<int> watchedAcceptors;
        attachCoreAcceptorsToServer(server, core, watchedAcceptors);
        const uint64_t loopSweepTimerId =
            server.loop().runEvery(std::chrono::seconds(1), [&core]() { core.sweepIdleSessions(60); });

        mynet::Result<> res{};
        if constexpr (requires { server.serve(cfg.server, cfg.reactor); })
        {
            res = server.serve(cfg.server, cfg.reactor);
        }
        else
        {
            res = server.serve(cfg.server, cfg.proactor);
        }
        server.reset();

        for (int fd : watchedAcceptors)
        {
            server.loop().delWatch(fd);
        }
        if (loopSweepTimerId != 0)
        {
            [[maybe_unused]] auto _ = server.loop().cancelTimer(loopSweepTimerId);
        }
        core.clearEventLoop();
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
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::setvbuf(stderr, nullptr, _IONBF, 0);

    // 1. 兼容 sing-box 风格子命令 (version, run, check)
    if (argc >= 2)
    {
        std::string_view subcmd = argv[1];
        if (subcmd == "version")
        {
            printBanner();
            std::cout << "mynet core version 1.0.0 (sing-box / nekobox compatible)\n";
            return 0;
        }
    }

    std::string configPath = "config/config.lua";
    std::string nekoboxSocket = mynet::nekobox::NekoBoxIpcService::getSocketPathFromEnv();
    bool testConfigOnly = false;
    bool runDaemon = false;

    static struct option longOptions[] = {
        {"config", required_argument, nullptr, 'c'}, {"test", no_argument, nullptr, 't'},
        {"version", no_argument, nullptr, 'v'},      {"help", no_argument, nullptr, 'h'},
        {"daemon", no_argument, nullptr, 'd'},       {"socket", required_argument, nullptr, 's'},
        {nullptr, 0, nullptr, 0}};

    if (argc >= 2 && (std::string_view(argv[1]) == "run" || std::string_view(argv[1]) == "check"))
    {
        if (std::string_view(argv[1]) == "check")
        {
            testConfigOnly = true;
        }
        optind = 2;
    }

    int opt = 0;
    while ((opt = getopt_long(argc, argv, "c:tvhds:", longOptions, nullptr)) != -1)
    {
        switch (opt)
        {
        case 'c':
            configPath = optarg;
            break;
        case 's':
            nekoboxSocket = optarg;
            break;
        case 't':
            testConfigOnly = true;
            break;
        case 'v':
            printBanner();
            std::cout << "mynet core version 1.0.0 (sing-box / nekobox compatible)\n";
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

    // 2. 优先检测 NekoBox UDS IPC 环境变量与启动参数 (彻底解耦本地配置文件依赖)
    if (!nekoboxSocket.empty())
    {
        LOG_INFO("==================================================================");
        LOG_INFO(" mynet proxy kernel running in NekoBox IPC Core mode");
        LOG_INFO(" Connecting to NekoBox UDS: {}", nekoboxSocket);
        LOG_INFO("==================================================================");

        auto core = std::make_shared<mynet::Core>();
        mynet::nekobox::NekoBoxIpcService service(core);

        static mynet::nekobox::NekoBoxIpcService *g_nekoboxPtr = nullptr;
        g_nekoboxPtr = &service;

        std::signal(SIGINT, [](int) {
            if (g_nekoboxPtr != nullptr)
                g_nekoboxPtr->stop();
        });
        std::signal(SIGTERM, [](int) {
            if (g_nekoboxPtr != nullptr)
                g_nekoboxPtr->stop();
        });

        // 阻塞同步接入 NekoBox UDS 守护循环，等待 GUI 调度生命周期
        service.runSync(nekoboxSocket);
        LOG_INFO("NekoBox IPC Core stopped cleanly");
        return 0;
    }

    // 3. 独立模式运行：加载配置文件 (支持 sing-box JSON 与 Lua 脚本)
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
        else if (::access("config.json", R_OK) == 0)
        {
            configPath = "config.json";
        }
        else
        {
            std::cerr << "[ERROR] Cannot open configuration file: " << configPath << " (" << std::strerror(errno)
                      << ")\n";
            return 1;
        }
    }

    mynet::MynetConfig cfg{};
    const bool isJsonConfig = configPath.ends_with(".json") || configPath.ends_with(".json5");

    if (isJsonConfig)
    {
        std::string jsonStr;
        std::ifstream ifs(configPath);
        if (ifs)
        {
            std::stringstream ss;
            ss << ifs.rdbuf();
            jsonStr = ss.str();
        }
        auto parsed = mynet::config::singbox::parseSingBoxConfig(jsonStr);
        if (!parsed)
        {
            std::cerr << "[FATAL] Failed to parse sing-box JSON configuration: " << parsed.error() << "\n";
            return 1;
        }
        cfg = std::move(*parsed);
    }
    else
    {
#ifdef MYNET_HAVE_LUA
        if (!mynet::reloadConfig(configPath, false))
        {
            std::cerr << "[FATAL] Failed to parse configuration from: " << configPath << "\n";
            return 1;
        }
        cfg = mynet::getMynetConfig();
#else
        std::cerr << "[WARN] Built without Lua support; running with compiled-in baseline configuration\n";
        cfg = mynet::getMynetConfig();
#endif
    }

    // 模式 1：配置校验模式 (-t / --test)
    if (testConfigOnly)
    {
        std::cout << "[INFO] Validating configuration: " << configPath << " ...\n";
        mynet::Core testCore(cfg);

        // 执行拓扑闭包校验 (Fail-Fast)
        if (auto res = testCore.start(); !res)
        {
            std::cerr << "[ERROR] Configuration topology check FAILED: " << mynet::toString(res.error()) << "\n";
            return 1;
        }

        std::cout << "[OK] Configuration syntax is valid.\n"
                  << "[OK] Topology check PASSED:\n"
                  << "     - Engine selected:    " << cfg.server.engine << "\n"
                  << "     - Inbounds declared:  " << testCore.acceptors().size() << "\n"
                  << "     - Outbounds declared: " << testCore.dialers().size() << "\n"
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

    g_reloadHandler = [&core, &configPath]()
    {
        LOG_INFO("SIGHUP received: live reloading Lua configuration from '{}'...", configPath);
#ifdef MYNET_HAVE_LUA
        if (mynet::reloadConfig(configPath, false))
        {
            const auto reloadedCfg = mynet::getMynetConfig();
            core.applyConfig(reloadedCfg);
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

    // 若配置未显式占用 cfg.server.port，则由 Core 自动补齐默认 mixed 入站，彻底统一到单一事件循环分发路径
    {
        bool hasMainTcpInbound = false;
        for (const auto &inbound : core.acceptors().acceptors())
        {
            if (inbound == nullptr)
            {
                continue;
            }
            const bool sameHost = (cfg.server.host == "0.0.0.0" || inbound->host() == "0.0.0.0" ||
                                   inbound->host() == cfg.server.host);
            if (inbound->type() != "datagram" && inbound->type() != "udp" && inbound->type() != "tun" && sameHost &&
                inbound->port() == cfg.server.port)
            {
                hasMainTcpInbound = true;
                break;
            }
        }
        if (!hasMainTcpInbound && cfg.server.port > 0)
        {
            core.acceptors().registerAcceptor(
                std::make_shared<mynet::AcceptorMixed>("default-mixed", cfg.server.host, cfg.server.port));
        }
    }

    // 启动入站监听与出站管理器
    if (auto res = core.start(cfg.server.backlog); !res)
    {
        LOG_FATAL("Failed to start mynet core engine: {}", mynet::toString(res.error()));
        return 1;
    }

    // 打印就绪状态
    LOG_INFO("Core engine started successfully. Active listeners:");
    for (const auto &inbound : core.acceptors().acceptors())
    {
        LOG_INFO("  * Inbound [{}] protocol='{}' listening on {}:{} (fd: {})", inbound->tag(), inbound->type(),
                 inbound->host(), inbound->port(), inbound->listenFd());
    }
    LOG_INFO("Default outbound: '{}', active route rules: {}", core.router().defaultOutbound(),
             core.router().rules().size());

    // 启动可选的 Clash-compatible 控制 API
    std::unique_ptr<mynet::clash::Controller> apiController{nullptr};
    if (cfg.controller.enabled)
    {
        apiController = std::make_unique<mynet::clash::Controller>(&core, cfg.controller);
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

    // 启动可选的 NekoBox UDS RPC 服务
    std::unique_ptr<mynet::nekobox::NekoBoxIpcService> nekoboxService{nullptr};
    if (!nekoboxSocket.empty())
    {
        LOG_INFO("Starting NekoBox UDS IPC service on: {}", nekoboxSocket);
        nekoboxService = std::make_unique<mynet::nekobox::NekoBoxIpcService>(
            std::shared_ptr<mynet::Core>(&core, [](auto *) {}));
        nekoboxService->start(nekoboxSocket);
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
    if (nekoboxService != nullptr)
    {
        nekoboxService->stop();
    }
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
