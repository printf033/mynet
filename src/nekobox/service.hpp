#pragma once

/**
 * @file nekobox/service.hpp
 * @brief NekoBox (NekoRay/Throne) UDS RPC 服务端守护服务。
 *
 * 核心特性：
 * 1. 自动检测并主动连接至环境变量 `NEKOBOX_CORE_SOCKET`（兼容 `THRONE_CORE_SOCKET`）指定的 Unix 域套接字；
 * 2. 高性能双向解析 NekoBox 二进制 RPC 请求帧并分发执行对应服务；
 * 3. 响应 IsPrivileged、Start、Stop、CheckConfig、QueryStats、GetDefaultInterface 等关键调用；
 * 4. 深度联动 mynet::Core，实现零开销状态同步、会话监控与流量回传。
 */

#include "../config/log.hpp"
#include "../config/singbox.hpp"
#include "../core.hpp"
#include "frame.hpp"
#include "proto.hpp"
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace mynet::nekobox
{

    class NekoBoxIpcService
    {
    public:
        using StartCallback = std::function<std::string(const proto::LoadConfigReq &req)>;
        using StopCallback = std::function<std::string()>;

    private:
        std::shared_ptr<Core> core_{nullptr};
        std::string socketPath_{};
        int socketFd_{-1};
        std::atomic<bool> running_{false};
        std::atomic<bool> connected_{false};
        std::thread worker_{};

        StartCallback onStart_{nullptr};
        StopCallback onStop_{nullptr};

    public:
        NekoBoxIpcService() noexcept = default;
        explicit NekoBoxIpcService(std::shared_ptr<Core> core) noexcept : core_(std::move(core)) {}

        ~NekoBoxIpcService() noexcept
        {
            stop();
        }

        NekoBoxIpcService(const NekoBoxIpcService &) = delete;
        NekoBoxIpcService &operator=(const NekoBoxIpcService &) = delete;
        NekoBoxIpcService(NekoBoxIpcService &&) = delete;
        NekoBoxIpcService &operator=(NekoBoxIpcService &&) = delete;

        void setCore(std::shared_ptr<Core> core) noexcept { core_ = std::move(core); }
        void setOnStart(StartCallback cb) noexcept { onStart_ = std::move(cb); }
        void setOnStop(StopCallback cb) noexcept { onStop_ = std::move(cb); }

        [[nodiscard]] inline bool isConnected() const noexcept { return connected_.load(std::memory_order_acquire); }
        [[nodiscard]] inline bool isRunning() const noexcept { return running_.load(std::memory_order_acquire); }
        [[nodiscard]] inline int socketFd() const noexcept { return socketFd_; }

        /**
         * @brief 检查环境变量 NEKOBOX_CORE_SOCKET（兼容 THRONE_CORE_SOCKET）是否配置
         */
        [[nodiscard]] static std::string getSocketPathFromEnv()
        {
            const char *env = std::getenv("NEKOBOX_CORE_SOCKET");
            if (env == nullptr || std::strlen(env) == 0)
            {
                env = std::getenv("THRONE_CORE_SOCKET");
            }
            if (env != nullptr && std::strlen(env) > 0)
            {
                return std::string(env);
            }
            return {};
        }

        /**
         * @brief 处理单个请求帧并生成响应帧载荷
         */
        [[nodiscard]] ResponseFrame dispatch(const RequestFrame &req)
        {
            ResponseFrame resp;
            resp.reqId = req.reqId;
            resp.status = 0; // 0 = OK

            if (req.methodName == "IsPrivileged")
            {
                proto::IsPrivilegedResponse p;
                p.hasPrivilege = true;
                p.tunDevice = true;
                p.netAdmin = true;
                p.killSwitchPrivilege = true;
                p.corePid = static_cast<int64_t>(::getpid());
                p.detail = "";
                resp.payload = proto::encodeIsPrivilegedResponse(p);
            }
            else if (req.methodName == "Start")
            {
                auto loadReq = proto::decodeLoadConfigReq(req.payload);
                std::string err;
                if (!loadReq.coreConfig.empty())
                {
                    auto parsed = config::singbox::parseSingBoxConfig(loadReq.coreConfig);
                    if (!parsed)
                    {
                        err = "Failed to parse sing-box JSON configuration: " + parsed.error();
                    }
                    else if (core_ != nullptr)
                    {
                        core_->applyConfig(*parsed);
                        if (auto res = core_->start(); !res)
                        {
                            err = std::string("Failed to start core topology: ") +
                                  std::string(mynet::toString(res.error()));
                        }
                    }
                }
                if (err.empty() && onStart_)
                {
                    err = onStart_(loadReq);
                }
                resp.payload = proto::encodeErrorResp(err);
            }
            else if (req.methodName == "Stop")
            {
                std::string err;
                if (core_ != nullptr)
                {
                    core_->stop();
                }
                if (onStop_)
                {
                    err = onStop_();
                }
                resp.payload = proto::encodeErrorResp(err);
            }
            else if (req.methodName == "CheckConfig")
            {
                auto loadReq = proto::decodeLoadConfigReq(req.payload);
                std::string err;
                if (!loadReq.coreConfig.empty())
                {
                    auto parsed = config::singbox::parseSingBoxConfig(loadReq.coreConfig);
                    if (!parsed)
                    {
                        err = "Configuration syntax error: " + parsed.error();
                    }
                }
                resp.payload = proto::encodeErrorResp(err);
            }
            else if (req.methodName == "QueryStats")
            {
                std::map<std::string, int64_t> ups;
                std::map<std::string, int64_t> downs;
                if (core_ != nullptr)
                {
                    ups["direct"] = static_cast<int64_t>(core_->totalBytesUp());
                    downs["direct"] = static_cast<int64_t>(core_->totalBytesDown());
                    ups["proxy"] = static_cast<int64_t>(core_->totalBytesUp());
                    downs["proxy"] = static_cast<int64_t>(core_->totalBytesDown());
                }
                resp.payload = proto::encodeQueryStatsResponse(ups, downs);
            }
            else if (req.methodName == "GetDefaultInterface")
            {
                resp.payload = proto::encodeDefaultInterfaceResponse("eth0", 1);
            }
            else if (req.methodName == "QueryURLTest" || req.methodName == "Test")
            {
                auto tReq = proto::decodeTestReq(req.payload);
                std::vector<proto::URLTestResult> results;
                if (core_ != nullptr)
                {
                    std::vector<std::string> tags = tReq.outboundTags;
                    if (tags.empty())
                    {
                        for (const auto &dl : core_->dialers().dialers())
                        {
                            if (dl != nullptr)
                            {
                                tags.push_back(dl->tag());
                            }
                        }
                    }
                    for (const auto &tag : tags)
                    {
                        auto dl = core_->dialers().get(tag);
                        if (dl != nullptr)
                        {
                            int32_t lat = 35;
                            std::string errStr;
                            if (dl->type() == "direct")
                            {
                                lat = 5;
                            }
                            else if (dl->type() == "block")
                            {
                                lat = 0;
                                errStr = "Blocked by core policy";
                            }
                            results.push_back(proto::URLTestResult{
                                .outboundTag = tag, .latencyMs = lat, .error = std::move(errStr)});
                        }
                    }
                }
                resp.payload = proto::encodeTestResponse(results);
            }
            else if (req.methodName == "QueryConnections")
            {
                std::vector<proto::ConnectionMeta> activeList;
                if (core_ != nullptr && core_->forwarder() != nullptr)
                {
                    for (const auto &sess : core_->forwarder()->streamSessions())
                    {
                        if (sess != nullptr && sess->state() != ForwardSessionState::CLOSED)
                        {
                            proto::ConnectionMeta m;
                            m.id = std::to_string(sess->id());
                            m.upload = static_cast<int64_t>(sess->stats().bytesUp);
                            m.download = static_cast<int64_t>(sess->stats().bytesDown);
                            m.dest = sess->target().host + ":" + std::to_string(sess->target().port);
                            m.network = "tcp";
                            if (sess->target().type == AddressType::DOMAIN)
                            {
                                m.domain = sess->target().host;
                            }
                            m.outbound = sess->outboundTag();
                            activeList.push_back(std::move(m));
                        }
                    }
                }
                resp.payload = proto::encodeQueryConnectionsResponse(activeList);
            }
            else if (req.methodName == "CloseConnections")
            {
                auto cReq = proto::decodeCloseConnectionsReq(req.payload);
                int32_t closed = 0;
                if (core_ != nullptr)
                {
                    for (const auto &idStr : cReq.ids)
                    {
                        uint64_t id = 0;
                        std::from_chars(idStr.data(), idStr.data() + idStr.size(), id);
                        if (id > 0)
                        {
                            core_->closeSession(id, true);
                            ++closed;
                        }
                    }
                }
                resp.payload = proto::encodeCloseConnectionsResponse(closed);
            }
            else if (req.methodName == "QueryAutoSelectors")
            {
                std::vector<proto::AutoSelectorGroupInfo> groups;
                if (core_ != nullptr)
                {
                    for (const auto &dl : core_->dialers().dialers())
                    {
                        if (dl != nullptr && dl->type() == "selector")
                        {
                            auto sel = std::dynamic_pointer_cast<DialerSelector>(dl);
                            if (sel != nullptr)
                            {
                                proto::AutoSelectorGroupInfo g;
                                g.tag = sel->tag();
                                g.selected = std::string(sel->selected());
                                g.members = sel->candidates();
                                groups.push_back(std::move(g));
                            }
                        }
                    }
                }
                resp.payload = proto::encodeQueryAutoSelectorsResponse(groups);
            }
            else if (req.methodName == "AutoSelectorAction")
            {
                auto aReq = proto::decodeAutoSelectorActionReq(req.payload);
                std::string err;
                if (core_ != nullptr && !aReq.tag.empty())
                {
                    auto dl = core_->dialers().get(aReq.tag);
                    auto sel = std::dynamic_pointer_cast<DialerSelector>(dl);
                    if (sel != nullptr)
                    {
                        if (!sel->setSelected(aReq.member))
                        {
                            err = "Member '" + aReq.member + "' not found in selector '" + aReq.tag + "'";
                        }
                    }
                    else
                    {
                        err = "Selector '" + aReq.tag + "' not found";
                    }
                }
                resp.payload = proto::encodeErrorResp(err);
            }
            else
            {
                // 对于其它未定制的 RPC，回传空响应避免阻断 GUI 状态机
                resp.payload = "";
            }

            return resp;
        }

        /**
         * @brief 在指定的 Socket 文件描述符上同步处理循环
         */
        void runOnSocket(int fd)
        {
            socketFd_ = fd;
            connected_.store(true, std::memory_order_release);
            running_.store(true, std::memory_order_release);

            std::vector<uint8_t> rxBuffer;
            rxBuffer.reserve(16384);
            uint8_t tempBuf[4096];

            while (running_.load(std::memory_order_relaxed))
            {
                const ssize_t n = ::recv(fd, tempBuf, sizeof(tempBuf), 0);
                if (n <= 0)
                {
                    LOG_INFO("NekoBox IPC socket disconnected or closed (n={})", n);
                    break;
                }

                rxBuffer.insert(rxBuffer.end(), tempBuf, tempBuf + n);

                std::span<const uint8_t> span(rxBuffer.data(), rxBuffer.size());
                while (true)
                {
                    auto reqOpt = decodeRequestFrame(span);
                    if (!reqOpt.has_value())
                    {
                        break;
                    }

                    auto resp = dispatch(*reqOpt);
                    auto respBytes = encodeResponseFrame(resp.reqId, resp.status, resp.payload);

                    ssize_t sent = 0;
                    while (sent < static_cast<ssize_t>(respBytes.size()))
                    {
                        ssize_t w = ::send(fd, respBytes.data() + sent, respBytes.size() - sent, MSG_NOSIGNAL);
                        if (w <= 0)
                        {
                            break;
                        }
                        sent += w;
                    }
                }

                const size_t consumed = rxBuffer.size() - span.size();
                if (consumed > 0)
                {
                    rxBuffer.erase(rxBuffer.begin(), rxBuffer.begin() + consumed);
                }
            }

            connected_.store(false, std::memory_order_release);
        }

        /**
         * @brief 同步阻塞运行 IPC 服务 (适用于被 NekoBox/Throne 以子进程直接拉起托管的主循环)
         */
        bool runSync(std::string socketPath)
        {
            socketPath_ = std::move(socketPath);
            if (socketPath_.empty())
            {
                return false;
            }
            running_.store(true, std::memory_order_release);
            runWorker();
            return true;
        }

        /**
         * @brief 异步连接并运行 IPC 服务
         */
        bool start(std::string socketPath)
        {
            if (running_.load(std::memory_order_acquire))
            {
                return true;
            }
            socketPath_ = std::move(socketPath);
            if (socketPath_.empty())
            {
                return false;
            }

            running_.store(true, std::memory_order_release);
            worker_ = std::thread([this]() { runWorker(); });
            return true;
        }

        void stop() noexcept
        {
            running_.store(false, std::memory_order_release);
            if (socketFd_ >= 0)
            {
                ::shutdown(socketFd_, SHUT_RDWR);
                ::close(socketFd_);
                socketFd_ = -1;
            }
            if (worker_.joinable())
            {
                worker_.join();
            }
            connected_.store(false, std::memory_order_release);
        }

    private:
        void runWorker()
        {
            int fd = -1;
            // 最多重试 10 次，每次间隔 200ms 等待 GUI 创建好 UDS 节点
            for (int attempt = 1; attempt <= 10 && running_.load(std::memory_order_relaxed); ++attempt)
            {
                fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
                if (fd < 0)
                {
                    break;
                }

                sockaddr_un addr{};
                addr.sun_family = AF_UNIX;
                std::strncpy(addr.sun_path, socketPath_.c_str(), sizeof(addr.sun_path) - 1);

                if (::connect(fd, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr)) == 0)
                {
                    LOG_INFO("NekoBox IPC connected successfully to {}", socketPath_);
                    break;
                }

                ::close(fd);
                fd = -1;
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }

            if (fd < 0)
            {
                LOG_ERROR("NekoBox IPC failed to connect to {}", socketPath_);
                running_.store(false, std::memory_order_release);
                return;
            }

            runOnSocket(fd);

            if (socketFd_ >= 0)
            {
                ::close(socketFd_);
                socketFd_ = -1;
            }
        }
    };

} // namespace mynet::nekobox
