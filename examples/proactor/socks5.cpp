#include "common/endpoint.hpp"
#include "error.hpp"
#include "log_config.hpp"
#include "proactor/proactor.hpp"
#include "proxy/socks5.hpp"
#include <string>
#include <string_view>

// io_uring 驱动的 SOCKS5 代理服务端。用法：
//
//     ./proactor_socks5                        # 监听 0.0.0.0:1080 (免密认证)
//     ./proactor_socks5 127.0.0.1:1080          # 监听 127.0.0.1:1080 (免密认证)
//     ./proactor_socks5 127.0.0.1:1080 admin:pass123  # 开启 RFC 1929 用户名密码认证

namespace mynet::example
{
    class Socks5ServerHandler : public proxy::HandlerSocks5
    {
    public:
        inline static std::string g_user;
        inline static std::string g_pass;

        Socks5ServerHandler()
        {
            if (!g_user.empty())
            {
                setAuthenticator([](std::string_view u, std::string_view p) {
                    return u == g_user && p == g_pass;
                });
            }
        }

        void process()
        {
            proxy::HandlerSocks5::process();
            if (stage() == proxy::Socks5Stage::STREAMING && requestBytes() > 0)
            {
                std::string_view req(requestBegin(), requestBytes());
                if (req.starts_with("GET ") || req.starts_with("POST ") || req.starts_with("HEAD ") || req.starts_with("PUT "))
                {
                    std::string body = "Hello from mynet SOCKS5 proxy tunnel!\n";
                    std::string resp = "HTTP/1.1 200 OK\r\n"
                                       "Server: mynet-socks5\r\n"
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
                    [[maybe_unused]] auto _ = pushResponse(req);
                    requestConsume(requestBytes());
                }
            }
        }

        void reset() noexcept override
        {
            proxy::HandlerSocks5::reset();
            if (!g_user.empty())
            {
                setAuthenticator([](std::string_view u, std::string_view p) {
                    return u == g_user && p == g_pass;
                });
            }
        }
    };
} // namespace mynet::example

int main(int argc, char *argv[])
{
    // 在产生任何日志之前把 mylog 输出重定向到 stderr：
    // 本程序在 stdout 上流式传输的数据必须保持纯净且不受污染。
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
            mynet::example::Socks5ServerHandler::g_user = auth.substr(0, pos);
            mynet::example::Socks5ServerHandler::g_pass = auth.substr(pos + 1);
            LOG_INFO("socks5 auth enabled: user={}", mynet::example::Socks5ServerHandler::g_user);
        }
    }

    LOG_INFO("listening on {} (socks5, proactor)", listen.text);

    using namespace mynet;
    if (auto res = Proactor<AcceptorSocket<example::Socks5ServerHandler>>().runTcp(listen.ip, listen.port()); !res)
    {
        LOG_ERROR("mynet: {}", toString(res.error()));
        return toExitCode(res.error());
    }
    return 0;
}
