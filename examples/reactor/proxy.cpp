#include "proxy/proxy.hpp"
#include "common/endpoint.hpp"
#include "error.hpp"
#include "log_config.hpp"
#include "reactor/reactor.hpp"
#include <string>
#include <string_view>

// epoll 驱动的多协议代理服务端 (支持 SOCKS4/SOCKS5/HTTP 混合入站)。用法：
//
//     ./reactor_proxy                        # 监听 0.0.0.0:1080 (Mixed 入站，自动识别 HTTP 与 SOCKS)
//     ./reactor_proxy 127.0.0.1:1080         # 监听 127.0.0.1:1080
//     ./reactor_proxy 127.0.0.1:1080 admin:pass123 # 开启 Basic / RFC 1929 认证
//
// 验证方式：
//     curl -v -x http://127.0.0.1:1080 http://test/
//     curl -v --socks5 127.0.0.1:1080 http://test/
//     curl -v --socks4 127.0.0.1:1080 http://test/
//     curl -v -U admin:pass123 -x http://127.0.0.1:1080 http://test/

namespace mynet::example
{
    class MixedProxyServerHandler : public proxy::HandlerMixed
    {
    public:
        inline static std::string g_user;
        inline static std::string g_pass;

        MixedProxyServerHandler()
        {
            if (!g_user.empty())
            {
                setAuthenticator([](std::string_view u, std::string_view p)
                                 { return u == g_user && (g_pass.empty() || p == g_pass); });
            }
        }

        void process()
        {
            proxy::HandlerMixed::process();
            if (isEstablished() && requestBytes() > 0)
            {
                std::string_view req(requestBegin(), requestBytes());
                if (req.starts_with("GET ") || req.starts_with("POST ") || req.starts_with("HEAD ") ||
                    req.starts_with("PUT "))
                {
                    std::string body = "Hello from mynet multi-protocol proxy tunnel!\n";
                    std::string resp = "HTTP/1.1 200 OK\r\n"
                                       "Server: mynet-proxy\r\n"
                                       "Content-Type: text/plain\r\n"
                                       "Content-Length: " +
                                       std::to_string(body.size()) +
                                       "\r\n"
                                       "Connection: close\r\n\r\n" +
                                       body;
                    [[maybe_unused]] auto _ = pushResponse(resp);
                    requestConsume(requestBytes());
                    setCloseAfterResponse(true);
                }
                else
                {
                    // 普通 TCP 数据回显
                    [[maybe_unused]] auto _ = pushResponse(req);
                    requestConsume(requestBytes());
                }
            }
        }

        void reset() noexcept override
        {
            proxy::HandlerMixed::reset();
            if (!g_user.empty())
            {
                setAuthenticator([](std::string_view u, std::string_view p)
                                 { return u == g_user && (g_pass.empty() || p == g_pass); });
            }
        }
    };
} // namespace mynet::example

int main(int argc, char *argv[])
{
    mynet::log::init();

    mynet::example::Endpoint listen;
    if (!mynet::example::resolveEndpoint(argc > 1 ? argv[1] : nullptr, "0.0.0.0:1080", SOCK_STREAM, listen))
    {
        LOG_ERROR("mynet: cannot resolve endpoint '{}' (expected host:port)", argc > 1 ? argv[1] : "0.0.0.0:1080");
        return EXIT_FAILURE;
    }

    if (argc > 2)
    {
        std::string auth(argv[2]);
        if (auto pos = auth.find(':'); pos != std::string::npos)
        {
            mynet::example::MixedProxyServerHandler::g_user = auth.substr(0, pos);
            mynet::example::MixedProxyServerHandler::g_pass = auth.substr(pos + 1);
        }
        else
        {
            mynet::example::MixedProxyServerHandler::g_user = auth;
        }
        LOG_INFO("proxy auth enabled: user={}", mynet::example::MixedProxyServerHandler::g_user);
    }

    LOG_INFO("listening on {} (multi-protocol proxy: SOCKS4/SOCKS5/HTTP, reactor)", listen.text);

    using namespace mynet;
    if (auto res = Reactor<AcceptorSocket<example::MixedProxyServerHandler>>().runTcp(listen.ip, listen.port()); !res)
    {
        LOG_ERROR("mynet: {}", toString(res.error()));
        return toExitCode(res.error());
    }
    return 0;
}
