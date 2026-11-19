#include "controller.hpp"
#include "core.hpp"
#include "geo.hpp"
#include "process.hpp"
#include <arpa/inet.h>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

using namespace mynet;

namespace
{

    std::string httpExchange(uint16_t port, const std::string &request)
    {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return "";

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

        if (::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0)
        {
            ::close(fd);
            return "";
        }

        ::send(fd, request.data(), request.size(), 0);

        std::string response;
        char buf[4096];
        while (true)
        {
            ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            response.append(buf, static_cast<size_t>(n));
        }

        ::close(fd);
        return response;
    }

} // namespace

// =============================================================================
// 1. Controller REST API 全量端点测试
// =============================================================================

TEST(ControllerTest, RestApiEndpoints)
{
    Core core;
    core.outbounds().registerOutbound(std::make_shared<OutboundDirect>("direct"));
    core.outbounds().registerOutbound(std::make_shared<OutboundBlock>("block"));
    auto sel = std::make_shared<OutboundSelector>(
        "proxy", std::vector<std::string>{"direct", "block"}, &core.outbounds());
    core.outbounds().registerOutbound(sel);

    auto urltest = std::make_shared<OutboundUrlTest>(
        "auto", std::vector<std::string>{"direct", "block"}, &core.outbounds());
    core.outbounds().registerOutbound(urltest);

    // 绑定端口 19890
    const uint16_t apiPort = 19890;
    Controller ctrl(&core, "127.0.0.1", apiPort);
    ASSERT_TRUE(ctrl.startBackground().has_value());
    EXPECT_TRUE(ctrl.isRunning());

    // 等待服务监听线程就绪
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // 1. GET /version
    {
        std::string resp = httpExchange(apiPort, "GET /version HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        EXPECT_NE(resp.find("200 OK"), std::string::npos);
        EXPECT_NE(resp.find(R"("version":"1.0.0")"), std::string::npos);
        EXPECT_NE(resp.find("Access-Control-Allow-Origin: *"), std::string::npos);
    }

    // 2. GET /configs
    {
        std::string resp = httpExchange(apiPort, "GET /configs HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        EXPECT_NE(resp.find("200 OK"), std::string::npos);
        EXPECT_NE(resp.find(R"("mode":"rule")"), std::string::npos);
    }

    // 3. GET /proxies
    {
        std::string resp = httpExchange(apiPort, "GET /proxies HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        EXPECT_NE(resp.find("200 OK"), std::string::npos);
        EXPECT_NE(resp.find(R"("proxy")"), std::string::npos);
        EXPECT_NE(resp.find(R"("Selector")"), std::string::npos);
        EXPECT_NE(resp.find(R"("direct")"), std::string::npos);
    }

    // 4. PUT /proxies/proxy 动态切换出站节点
    {
        EXPECT_EQ(sel->selected(), "direct");
        std::string putReq =
            "PUT /proxies/proxy HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "Content-Length: 17\r\n\r\n"
            R"({"name":"block"})";
        std::string resp = httpExchange(apiPort, putReq);
        EXPECT_NE(resp.find("204 No Content"), std::string::npos);
        EXPECT_EQ(sel->selected(), "block");
    }

    // 5. GET /proxies/direct/delay
    {
        std::string resp = httpExchange(apiPort, "GET /proxies/direct/delay HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        EXPECT_NE(resp.find("200 OK"), std::string::npos);
        EXPECT_NE(resp.find(R"("delay":1)"), std::string::npos);
    }

    // 6. GET /traffic 与 GET /rules
    {
        std::string respTraffic = httpExchange(apiPort, "GET /traffic HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        EXPECT_NE(respTraffic.find("200 OK"), std::string::npos);
        EXPECT_NE(respTraffic.find(R"("up":)"), std::string::npos);

        std::string respRules = httpExchange(apiPort, "GET /rules HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        EXPECT_NE(respRules.find("200 OK"), std::string::npos);
        EXPECT_NE(respRules.find(R"("rules":[)"), std::string::npos);
    }

    // 7. OPTIONS 跨域预检
    {
        std::string resp = httpExchange(apiPort, "OPTIONS /proxies HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        EXPECT_NE(resp.find("204 No Content"), std::string::npos);
        EXPECT_NE(resp.find("Access-Control-Allow-Origin: *"), std::string::npos);
        EXPECT_NE(resp.find("Access-Control-Allow-Methods:"), std::string::npos);
    }

    ctrl.stop();
    EXPECT_FALSE(ctrl.isRunning());
}

// =============================================================================
// 2. GeoIP / GeoSite 外部规则文件动态加载测试
// =============================================================================

TEST(ControllerTest, GeoExternalFileLoading)
{
    const std::string cidrFile = "/tmp/test_custom_geoip.txt";
    const std::string siteFile = "/tmp/test_custom_geosite.txt";

    // 写入测试 CIDR 文件 (含注释与空格)
    {
        std::ofstream ofs(cidrFile);
        ofs << "# Custom Country IP CIDR list\n";
        ofs << "  8.8.8.0/24  \n";
        ofs << "\n";
        ofs << "1.1.1.0/24\n";
    }

    // 写入测试 GeoSite 域名文件
    {
        std::ofstream ofs(siteFile);
        ofs << "# Custom Domain categories\n";
        ofs << "domain:custom-portal.org\n";
        ofs << "suffix:service.internal\n";
        ofs << "  mycorp.net  \n";
    }

    auto &geoip = GeoIpMatcher::instance();
    EXPECT_TRUE(geoip.loadFromFile(cidrFile, "custom_country"));

    in_addr ip1{}, ip2{}, ip3{};
    ::inet_pton(AF_INET, "8.8.8.8", &ip1);
    ::inet_pton(AF_INET, "1.1.1.1", &ip2);
    ::inet_pton(AF_INET, "9.9.9.9", &ip3);

    EXPECT_TRUE(geoip.matches(ip1, "custom_country"));
    EXPECT_TRUE(geoip.matches(ip2, "custom_country"));
    EXPECT_FALSE(geoip.matches(ip3, "custom_country"));

    auto &geosite = GeoSiteMatcher::instance();
    EXPECT_TRUE(geosite.loadFromFile(siteFile, "custom_cat"));

    EXPECT_TRUE(geosite.matches("custom-portal.org", "custom_cat"));
    EXPECT_TRUE(geosite.matches("api.service.internal", "custom_cat"));
    EXPECT_TRUE(geosite.matches("mail.mycorp.net", "custom_cat"));
    EXPECT_FALSE(geosite.matches("google.com", "custom_cat"));

    std::filesystem::remove(cidrFile);
    std::filesystem::remove(siteFile);
}

// =============================================================================
// 3. ProcessResolver 进程名解析测试
// =============================================================================

TEST(ControllerTest, ProcessResolverCurrentPid)
{
    pid_t myPid = ::getpid();
    std::string procName = ProcessResolver::getProcessNameByPid(myPid);
    EXPECT_FALSE(procName.empty());
    // 进程名通常为测试执行文件名 (test_controller)
    EXPECT_NE(procName.find("test_controller"), std::string::npos);
}

// =============================================================================
// 4. OutboundUrlTest 自动健康探测测试
// =============================================================================

TEST(ControllerTest, UrlTestProbeDirect)
{
    OutboundManager mgr;
    mgr.registerOutbound(std::make_shared<OutboundDirect>("direct-node"));
    mgr.registerOutbound(std::make_shared<OutboundBlock>("block-node"));

    auto urltest = std::make_shared<OutboundUrlTest>(
        "auto-probe", std::vector<std::string>{"direct-node", "block-node"}, &mgr);
    mgr.registerOutbound(urltest);

    // 探测 direct-node
    uint32_t rttDirect = urltest->probeNode("direct-node");
    EXPECT_EQ(rttDirect, 1u);
    EXPECT_EQ(urltest->getRtt("direct-node"), 1u);

    // 探测 block-node (失败返回 9999)
    uint32_t rttBlock = urltest->probeNode("block-node");
    EXPECT_EQ(rttBlock, 9999u);
    EXPECT_EQ(urltest->getRtt("block-node"), 9999u);

    // probeAll 批处理
    urltest->probeAll();
    EXPECT_EQ(urltest->getBestTag(), "direct-node");
}
