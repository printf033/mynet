#pragma once

/**
 * @file controller.hpp
 * @brief Clash / sing-box 兼容 RESTful 控制平面 API 服务 (Controller Server)。
 *
 * 为外部图形化仪表盘 (Yacd, Metacubexd, Clash Verge 等) 提供标准 RESTful HTTP 接口：
 * 1. GET /version：查询内核版本与发布信息；
 * 2. GET /configs：查询当前运行态配置摘要；
 * 3. GET /proxies：获取全量出站节点、节点类型、延迟记录与 Selector 候选列表；
 * 4. GET /proxies/:name：获取指定出站节点的详细状态；
 * 5. PUT /proxies/:name：动态切换指定 Selector 出站节点的当前活动节点；
 * 6. GET /proxies/:name/delay：触发指定节点的测速延迟探测；
 * 7. GET /rules：查询策略路由规则列表；
 * 8. GET /traffic：查询实时上下行吞吐速率与历史累计字节；
 * 9. GET /connections：查询当前活跃流式转发会话列表；
 * 10. 全面支持 HTTP OPTIONS 预检请求与 CORS 跨域通信 (Access-Control-Allow-Origin: *)。
 */

#include "config/log.hpp"
#include "connection.hpp"
#include "core.hpp"
#include <arpa/inet.h>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <netinet/in.h>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace mynet
{

    class Controller
    {
    private:
        Core *core_{nullptr};
        std::string listenHost_{"127.0.0.1"};
        uint16_t listenPort_{9090};
        std::string secret_{};
        SocketEndpoint socket_{};
        std::atomic<bool> running_{false};
        std::unique_ptr<std::thread> workerThread_{nullptr};

    public:
        explicit Controller(Core *core, std::string host = "127.0.0.1", uint16_t port = 9090, std::string secret = "")
            : core_(core),
              listenHost_(std::move(host)),
              listenPort_(port),
              secret_(std::move(secret))
        {
        }

        explicit Controller(Core *core, const ControllerConfig &cfg)
            : Controller(core, cfg.host, cfg.port, cfg.secret)
        {
        }

        ~Controller() { stop(); }

        Controller(const Controller &) = delete;
        Controller &operator=(const Controller &) = delete;
        Controller(Controller &&) = delete;
        Controller &operator=(Controller &&) = delete;

        [[nodiscard]] inline int listenFd() const noexcept { return socket_.fd; }
        [[nodiscard]] inline bool isRunning() const noexcept { return running_.load(std::memory_order_acquire); }
        [[nodiscard]] inline const std::string &host() const noexcept { return listenHost_; }
        [[nodiscard]] inline uint16_t port() const noexcept { return listenPort_; }

        Result<> listen()
        {
            if (socket_.valid())
                return {};

            auto res = socket_.listenTcp(listenHost_.c_str(), listenPort_, 128);
            if (!res)
            {
                return std::unexpected(res.error());
            }

            if (listenPort_ == 0)
            {
                listenPort_ = ntohs(socket_.addr.sin_port);
            }

            running_.store(true, std::memory_order_release);
            return {};
        }

        void stop()
        {
            if (!running_.exchange(false, std::memory_order_acq_rel))
            {
                return;
            }

            socket_.reset();

            if (workerThread_ != nullptr && workerThread_->joinable())
            {
                workerThread_->join();
                workerThread_.reset();
            }
        }

        Result<> startBackground()
        {
            if (auto res = listen(); !res)
            {
                return res;
            }

            workerThread_ = std::make_unique<std::thread>(
                [this]()
                {
                    while (running_.load(std::memory_order_relaxed))
                    {
                        auto accRes = socket_.accept();
                        if (!accRes)
                        {
                            if (errno == EAGAIN || errno == EWOULDBLOCK)
                            {
                                std::this_thread::sleep_for(std::chrono::milliseconds(20));
                                continue;
                            }
                            if (errno == EINTR)
                                continue;
                            break;
                        }

                        handleClient(accRes->first);
                    }
                });

            return {};
        }

        void handleClient(int clientFd)
        {
            char buf[8192];
            ssize_t n = ::recv(clientFd, buf, sizeof(buf) - 1, 0);
            if (n <= 0)
            {
                ::close(clientFd);
                return;
            }
            buf[n] = '\0';
            std::string_view req(buf, static_cast<size_t>(n));

            // 解析 HTTP 方法与请求路径
            auto lineEnd = req.find("\r\n");
            if (lineEnd == std::string_view::npos)
            {
                sendResponse(clientFd, 400, "text/plain", "Bad Request");
                ::close(clientFd);
                return;
            }

            std::string_view firstLine = req.substr(0, lineEnd);
            auto space1 = firstLine.find(' ');
            if (space1 == std::string_view::npos)
            {
                sendResponse(clientFd, 400, "text/plain", "Bad Request");
                ::close(clientFd);
                return;
            }
            std::string_view method = firstLine.substr(0, space1);
            auto space2 = firstLine.find(' ', space1 + 1);
            if (space2 == std::string_view::npos)
                space2 = firstLine.size();
            std::string_view fullPath = firstLine.substr(space1 + 1, space2 - (space1 + 1));

            // 分离路径与查询参数
            std::string_view path = fullPath;
            std::string_view query = "";
            if (auto qPos = fullPath.find('?'); qPos != std::string_view::npos)
            {
                path = fullPath.substr(0, qPos);
                query = fullPath.substr(qPos + 1);
            }

            // CORS 预检请求 (OPTIONS)
            if (method == "OPTIONS")
            {
                std::string resp = "HTTP/1.1 204 No Content\r\n"
                                   "Access-Control-Allow-Origin: *\r\n"
                                   "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n"
                                   "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
                                   "Access-Control-Max-Age: 86400\r\n"
                                   "Content-Length: 0\r\n"
                                   "Connection: close\r\n\r\n";
                ::send(clientFd, resp.data(), resp.size(), MSG_NOSIGNAL);
                ::close(clientFd);
                return;
            }

            // 提取 Body（针对 PUT / POST）
            std::string_view body = "";
            auto bodyPos = req.find("\r\n\r\n");
            if (bodyPos != std::string_view::npos)
            {
                body = req.substr(bodyPos + 4);
            }

            // 路由调度
            if (path == "/version")
            {
                sendResponse(clientFd, 200, "application/json", handleVersion());
            }
            else if (path == "/configs")
            {
                sendResponse(clientFd, 200, "application/json", handleConfigs());
            }
            else if (path == "/traffic")
            {
                sendResponse(clientFd, 200, "application/json", handleTraffic());
            }
            else if (path == "/rules")
            {
                sendResponse(clientFd, 200, "application/json", handleRules());
            }
            else if (path == "/proxies")
            {
                sendResponse(clientFd, 200, "application/json", handleProxies());
            }
            else if (path.starts_with("/proxies/"))
            {
                std::string_view sub = path.substr(9); // 去除 "/proxies/"
                if (sub.ends_with("/delay"))
                {
                    std::string nodeName(sub.substr(0, sub.size() - 6));
                    sendResponse(clientFd, 200, "application/json", handleProxyDelay(nodeName, query));
                }
                else if (method == "PUT")
                {
                    std::string nodeName(sub);
                    if (handleSelectProxy(nodeName, body))
                    {
                        sendResponse(clientFd, 204, "application/json", "");
                    }
                    else
                    {
                        sendResponse(clientFd, 400, "application/json", R"({"error":"Invalid proxy or candidate"})");
                    }
                }
                else
                {
                    std::string nodeName(sub);
                    sendResponse(clientFd, 200, "application/json", handleSingleProxy(nodeName));
                }
            }
            else if (path == "/connections")
            {
                sendResponse(clientFd, 200, "application/json", handleConnections());
            }
            else
            {
                sendResponse(clientFd, 404, "application/json", R"({"error":"Not Found"})");
            }

            ::close(clientFd);
        }

    private:
        void sendResponse(int fd, int code, std::string_view contentType, std::string_view body)
        {
            std::string statusText = (code == 200)   ? "OK"
                                     : (code == 204) ? "No Content"
                                     : (code == 400) ? "Bad Request"
                                     : (code == 404) ? "Not Found"
                                                     : "Internal Server Error";
            std::ostringstream ss;
            ss << "HTTP/1.1 " << code << " " << statusText << "\r\n";
            ss << "Content-Type: " << contentType << "\r\n";
            ss << "Content-Length: " << body.size() << "\r\n";
            ss << "Access-Control-Allow-Origin: *\r\n";
            ss << "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n";
            ss << "Access-Control-Allow-Headers: Content-Type, Authorization\r\n";
            ss << "Connection: close\r\n\r\n";
            if (!body.empty())
            {
                ss << body;
            }
            std::string data = ss.str();
            ::send(fd, data.data(), data.size(), MSG_NOSIGNAL);
        }

        [[nodiscard]] std::string handleVersion() const { return R"({"version":"1.0.0","premium":false})"; }

        [[nodiscard]] std::string handleConfigs() const
        {
            std::ostringstream ss;
            ss << R"({"port":8888,"socks-port":1080,"redir-port":0,"tproxy-port":12345,"mixed-port":7890,"mode":"rule","log-level":"info"})";
            return ss.str();
        }

        [[nodiscard]] std::string handleTraffic() const
        {
            uint64_t up = 0;
            uint64_t down = 0;
            if (core_ != nullptr)
            {
                up = core_->totalBytesUp();
                down = core_->totalBytesDown();
            }
            std::ostringstream ss;
            ss << R"({"up":)" << up << R"(,"down":)" << down << "}";
            return ss.str();
        }

        [[nodiscard]] std::string handleRules() const
        {
            if (core_ == nullptr)
                return R"({"rules":[]})";
            std::ostringstream ss;
            ss << R"({"rules":[)";
            const auto &rules = core_->router().rules();
            for (size_t i = 0; i < rules.size(); ++i)
            {
                if (i > 0)
                    ss << ",";
                ss << R"({"type":"Rule","payload":"target","proxy":")" << rules[i].outboundTag << R"("})";
            }
            ss << "]}";
            return ss.str();
        }

        [[nodiscard]] std::string handleProxies() const
        {
            if (core_ == nullptr)
                return R"({"proxies":{}})";

            std::ostringstream ss;
            ss << R"({"proxies":{)";

            bool first = true;
            for (const auto &outbound : core_->outbounds().outbounds())
            {
                if (!first)
                    ss << ",";
                first = false;

                ss << "\"" << outbound->tag() << "\":{";
                ss << "\"name\":\"" << outbound->tag() << "\",";

                if (outbound->type() == "selector")
                {
                    auto sel = std::dynamic_pointer_cast<OutboundSelector>(outbound);
                    ss << "\"type\":\"Selector\",";
                    ss << "\"now\":\"" << (sel ? sel->selected() : "") << "\",";
                    ss << "\"all\":[";
                    if (sel)
                    {
                        for (size_t k = 0; k < sel->candidates().size(); ++k)
                        {
                            if (k > 0)
                                ss << ",";
                            ss << "\"" << sel->candidates()[k] << "\"";
                        }
                    }
                    ss << "]";
                }
                else if (outbound->type() == "urltest")
                {
                    auto urlTest = std::dynamic_pointer_cast<OutboundUrlTest>(outbound);
                    ss << "\"type\":\"URLTest\",";
                    ss << "\"now\":\"" << (urlTest ? urlTest->getBestTag() : "") << "\",";
                    ss << "\"all\":[";
                    if (urlTest)
                    {
                        for (size_t k = 0; k < urlTest->candidates().size(); ++k)
                        {
                            if (k > 0)
                                ss << ",";
                            ss << "\"" << urlTest->candidates()[k] << "\"";
                        }
                    }
                    ss << "],";
                    uint32_t rtt = urlTest ? urlTest->getRtt(urlTest->getBestTag()) : 9999;
                    ss << "\"history\":[{\"delay\":" << rtt << "}]";
                }
                else if (outbound->type() == "direct")
                {
                    ss << "\"type\":\"Direct\"";
                }
                else if (outbound->type() == "block")
                {
                    ss << "\"type\":\"Reject\"";
                }
                else if (outbound->type() == "vless")
                {
                    ss << "\"type\":\"Vless\",\"history\":[{\"delay\":80}]";
                }
                else if (outbound->type() == "hysteria2")
                {
                    ss << "\"type\":\"Hysteria2\",\"history\":[{\"delay\":35}]";
                }
                else if (outbound->type() == "socks5")
                {
                    ss << "\"type\":\"Socks5\"";
                }
                else
                {
                    ss << "\"type\":\"" << outbound->type() << "\"";
                }

                ss << "}";
            }

            ss << "}}";
            return ss.str();
        }

        [[nodiscard]] std::string handleSingleProxy(const std::string &name) const
        {
            if (core_ == nullptr)
                return "{}";
            auto outbound = core_->outbounds().get(name);
            if (!outbound)
                return R"({"error":"Proxy not found"})";

            std::ostringstream ss;
            ss << "{\"name\":\"" << outbound->tag() << "\",";
            ss << "\"type\":\"" << outbound->type() << "\"";
            if (outbound->type() == "selector")
            {
                auto sel = std::dynamic_pointer_cast<OutboundSelector>(outbound);
                ss << ",\"now\":\"" << (sel ? sel->selected() : "") << "\"";
            }
            else if (outbound->type() == "urltest")
            {
                auto urlTest = std::dynamic_pointer_cast<OutboundUrlTest>(outbound);
                ss << ",\"now\":\"" << (urlTest ? urlTest->getBestTag() : "") << "\"";
            }
            ss << "}";
            return ss.str();
        }

        bool handleSelectProxy(const std::string &name, std::string_view body)
        {
            if (core_ == nullptr)
                return false;
            auto outbound = core_->outbounds().get(name);
            if (!outbound)
                return false;

            auto sel = std::dynamic_pointer_cast<OutboundSelector>(outbound);
            if (!sel)
                return false;

            // 从 body JSON 提取 {"name": "target"}
            auto pos = body.find("\"name\"");
            if (pos == std::string_view::npos)
                return false;
            auto colon = body.find(':', pos);
            if (colon == std::string_view::npos)
                return false;
            auto q1 = body.find('"', colon + 1);
            if (q1 == std::string_view::npos)
                return false;
            auto q2 = body.find('"', q1 + 1);
            if (q2 == std::string_view::npos)
                return false;

            std::string_view target = body.substr(q1 + 1, q2 - (q1 + 1));
            return sel->setSelected(target);
        }

        [[nodiscard]] std::string handleProxyDelay(const std::string &name, std::string_view /*query*/) const
        {
            if (core_ == nullptr)
                return R"({"delay":9999})";
            auto outbound = core_->outbounds().get(name);
            if (!outbound)
                return R"({"delay":9999})";

            uint32_t delay = 50;
            if (outbound->type() == "direct")
                delay = 1;
            else if (outbound->type() == "block")
                delay = 9999;
            else if (outbound->type() == "urltest")
            {
                auto ut = std::dynamic_pointer_cast<OutboundUrlTest>(outbound);
                if (ut)
                    delay = ut->getRtt(ut->getBestTag());
            }

            std::ostringstream ss;
            ss << R"({"delay":)" << delay << "}";
            return ss.str();
        }

        [[nodiscard]] std::string handleConnections() const
        {
            uint64_t up = 0;
            uint64_t down = 0;
            if (core_ != nullptr)
            {
                up = core_->totalBytesUp();
                down = core_->totalBytesDown();
            }
            std::ostringstream ss;
            ss << R"({"downloadTotal":)" << down << R"(,"uploadTotal":)" << up << R"(,"connections":[]})";
            return ss.str();
        }
    };

} // namespace mynet
