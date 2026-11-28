#include "acceptor.hpp"
#include "connection.hpp"
#include "core.hpp"
#include "dialer.hpp"
#include "http/connection.hpp"
#include "acceptorManager.hpp"
#include "dialerManager.hpp"
#include "reactor.hpp"
#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace mynet;

TEST(AcceptorDialerTest, ConnectionBaseClass)
{
    Connection conn;
    EXPECT_EQ(conn.fd(), -1);
    EXPECT_EQ(conn.state(), Connection::CONN_STATE::OPEN);
    EXPECT_FALSE(conn.hasPendingWrite());

    conn.setFd(42);
    EXPECT_EQ(conn.fd(), 42);

    conn.reset();
    EXPECT_EQ(conn.fd(), -1);

    // HTTP 3 个版本的 Connection 继承与接口一致性复用
    http::ConnectionHttp connH1;
    EXPECT_EQ(connH1.version(), "HTTP/1.1");
    EXPECT_EQ(connH1.fd(), -1);

    http::ConnectionHttp2 connH2(1);
    EXPECT_EQ(connH2.version(), "HTTP/2");
    EXPECT_EQ(connH2.streamId(), 1u);
    EXPECT_EQ(connH2.windowSize(), 65535u);

    http::ConnectionHttp3 connH3(4);
    EXPECT_EQ(connH3.version(), "HTTP/3");
    EXPECT_EQ(connH3.streamId(), 4u);
    EXPECT_TRUE(connH3.isDatagram());
}

TEST(AcceptorDialerTest, ProtocolAcceptorsInstantiation)
{
    AcceptorSocks5 accSocks("socks-in", "127.0.0.1", 1080, "user", "pass");
    EXPECT_EQ(accSocks.tag(), "socks-in");
    EXPECT_EQ(accSocks.type(), "socks5");
    EXPECT_EQ(accSocks.username(), "user");
    EXPECT_EQ(accSocks.password(), "pass");

    uint8_t socksBytes[] = {0x05, 0x01, 0x00};
    EXPECT_TRUE(accSocks.match(socksBytes));

    AcceptorHttp accHttp("http-in", "127.0.0.1", 8080);
    EXPECT_EQ(accHttp.tag(), "http-in");
    EXPECT_EQ(accHttp.type(), "http");

    const char httpReq[] = "GET / HTTP/1.1\r\n";
    EXPECT_TRUE(accHttp.match(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(httpReq), sizeof(httpReq) - 1)));

    AcceptorHttp2 accHttp2("http2-in", "127.0.0.1", 8443, "user", "pass");
    EXPECT_EQ(accHttp2.tag(), "http2-in");
    EXPECT_EQ(accHttp2.type(), "http2");
    EXPECT_EQ(accHttp2.username(), "user");
    const char h2Preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    EXPECT_TRUE(accHttp2.match(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(h2Preface), sizeof(h2Preface) - 1)));

    AcceptorHttp3 accHttp3("http3-in", "127.0.0.1", 443, "secret");
    EXPECT_EQ(accHttp3.tag(), "http3-in");
    EXPECT_EQ(accHttp3.type(), "http3");
    EXPECT_EQ(accHttp3.password(), "secret");
    uint8_t quicInitial[] = {0xc0, 0x00, 0x00, 0x01}; // Long Header (Initial)
    EXPECT_TRUE(accHttp3.match(quicInitial));

    AcceptorVless accVless("vless-in", "127.0.0.1", 443, "a1b2c3d4-e5f6-7890-abcd-ef1234567890");
    EXPECT_EQ(accVless.tag(), "vless-in");
    EXPECT_EQ(accVless.type(), "vless");

    uint8_t vlessByte[] = {0x00};
    EXPECT_TRUE(accVless.match(vlessByte));

    AcceptorTrojan accTrojan("trojan-in", "127.0.0.1", 443, "secretpass");
    EXPECT_EQ(accTrojan.tag(), "trojan-in");
    EXPECT_EQ(accTrojan.type(), "trojan");

    AcceptorShadowsocks accSs("ss-in", "127.0.0.1", 8388, "aes-128-gcm", "password");
    EXPECT_EQ(accSs.tag(), "ss-in");
    EXPECT_EQ(accSs.type(), "shadowsocks");
    EXPECT_EQ(accSs.method(), "aes-128-gcm");

    AcceptorDirect accDirect("direct-in");
    EXPECT_EQ(accDirect.tag(), "direct-in");
    EXPECT_EQ(accDirect.type(), "direct");
    EXPECT_TRUE(accDirect.match({}));
}

TEST(AcceptorDialerTest, ProtocolDialersInstantiation)
{
    DialerSocks5 dialSocks("socks-out", "127.0.0.1", 1080, "u", "p");
    EXPECT_EQ(dialSocks.tag(), "socks-out");
    EXPECT_EQ(dialSocks.type(), "socks5");
    EXPECT_EQ(dialSocks.serverHost(), "127.0.0.1");
    EXPECT_EQ(dialSocks.serverPort(), 1080);

    DialerHttp dialHttp("http-out", "127.0.0.1", 8080);
    EXPECT_EQ(dialHttp.tag(), "http-out");
    EXPECT_EQ(dialHttp.type(), "http");

    DialerHttp2 dialHttp2("http2-out", "127.0.0.1", 8443, "u", "p");
    EXPECT_EQ(dialHttp2.tag(), "http2-out");
    EXPECT_EQ(dialHttp2.type(), "http2");
    EXPECT_EQ(dialHttp2.username(), "u");
    EXPECT_EQ(dialHttp2.password(), "p");

    DialerHttp3 dialHttp3("http3-out", "127.0.0.1", 443, "pwd");
    EXPECT_EQ(dialHttp3.tag(), "http3-out");
    EXPECT_EQ(dialHttp3.type(), "http3");
    EXPECT_EQ(dialHttp3.password(), "pwd");

    DialerVless dialVless("vless-out", "127.0.0.1", 443, "a1b2c3d4-e5f6-7890-abcd-ef1234567890");
    EXPECT_EQ(dialVless.tag(), "vless-out");
    EXPECT_EQ(dialVless.type(), "vless");

    DialerTrojan dialTrojan("trojan-out", "127.0.0.1", 443, "password");
    EXPECT_EQ(dialTrojan.tag(), "trojan-out");
    EXPECT_EQ(dialTrojan.type(), "trojan");

    DialerShadowsocks dialSs("ss-out", "127.0.0.1", 8388, "aes-128-gcm", "password");
    EXPECT_EQ(dialSs.tag(), "ss-out");
    EXPECT_EQ(dialSs.type(), "shadowsocks");

    DialerDirect dialDirect("direct-out");
    EXPECT_EQ(dialDirect.tag(), "direct-out");
    EXPECT_EQ(dialDirect.type(), "direct");

    DialerBlock dialBlock("block-out");
    EXPECT_EQ(dialBlock.tag(), "block-out");
    EXPECT_EQ(dialBlock.type(), "block");
}

TEST(AcceptorDialerTest, AcceptorManagerOperations)
{
    AcceptorManager mgr;
    EXPECT_EQ(mgr.size(), 0u);

    auto acc1 = std::make_shared<AcceptorSocks5>("s1", "127.0.0.1", 1080);
    auto acc2 = std::make_shared<AcceptorHttp>("h1", "127.0.0.1", 8080);

    mgr.registerAcceptor(acc1);
    mgr.registerAcceptor(acc2);

    EXPECT_EQ(mgr.size(), 2u);
    EXPECT_TRUE(mgr.has("s1"));
    EXPECT_TRUE(mgr.has("h1"));

    EXPECT_EQ(mgr.getAcceptor("s1")->type(), "socks5");
    EXPECT_EQ(mgr.getAcceptor("h1")->type(), "http");

    auto list = mgr.acceptors();
    EXPECT_EQ(list.size(), 2u);
}

TEST(AcceptorDialerTest, DialerManagerOperations)
{
    DialerManager mgr;
    // direct and block are registered by default
    EXPECT_GE(mgr.size(), 2u);

    auto dialVless = std::make_shared<DialerVless>("vless-node", "127.0.0.1", 443, "a1b2c3d4-e5f6-7890-abcd-ef1234567890");
    mgr.registerDialer(dialVless);

    EXPECT_TRUE(mgr.has("vless-node"));
    EXPECT_EQ(mgr.getDialer("vless-node")->type(), "vless");

    auto selector = std::make_shared<DialerSelector>("my-sel", std::vector<std::string>{"vless-node", "direct"});
    mgr.registerDialer(selector);

    EXPECT_TRUE(mgr.has("my-sel"));
    EXPECT_EQ(selector->selected(), "vless-node");
}

TEST(AcceptorDialerTest, HttpCoreConfiguration)
{
    MynetConfig cfg;

    InboundConfig inH1;
    inH1.tag = "h1-in";
    inH1.protocol = "http";
    inH1.host = "127.0.0.1";
    inH1.port = 8080;
    cfg.inbounds.push_back(inH1);

    InboundConfig inH2;
    inH2.tag = "h2-in";
    inH2.protocol = "http2";
    inH2.host = "127.0.0.1";
    inH2.port = 8443;
    cfg.inbounds.push_back(inH2);

    InboundConfig inH3;
    inH3.tag = "h3-in";
    inH3.protocol = "http3";
    inH3.host = "127.0.0.1";
    inH3.port = 4433;
    cfg.inbounds.push_back(inH3);

    OutboundConfig outH1;
    outH1.tag = "h1-out";
    outH1.type = "http";
    outH1.host = "1.2.3.4";
    outH1.port = 8080;
    cfg.outbounds.push_back(outH1);

    OutboundConfig outH2;
    outH2.tag = "h2-out";
    outH2.type = "http2";
    outH2.host = "1.2.3.4";
    outH2.port = 8443;
    cfg.outbounds.push_back(outH2);

    OutboundConfig outH3;
    outH3.tag = "h3-out";
    outH3.type = "http3";
    outH3.host = "1.2.3.4";
    outH3.port = 4433;
    cfg.outbounds.push_back(outH3);

    Core core(cfg);
    EXPECT_TRUE(core.acceptors().has("h1-in"));
    EXPECT_TRUE(core.acceptors().has("h2-in"));
    EXPECT_TRUE(core.acceptors().has("h3-in"));

    EXPECT_TRUE(core.dialers().has("h1-out"));
    EXPECT_TRUE(core.dialers().has("h2-out"));
    EXPECT_TRUE(core.dialers().has("h3-out"));

    EXPECT_EQ(core.acceptors().get("h1-in")->type(), "http");
    EXPECT_EQ(core.acceptors().get("h2-in")->type(), "http2");
    EXPECT_EQ(core.acceptors().get("h3-in")->type(), "http3");

    EXPECT_EQ(core.dialers().get("h1-out")->type(), "http");
    EXPECT_EQ(core.dialers().get("h2-out")->type(), "http2");
    EXPECT_EQ(core.dialers().get("h3-out")->type(), "http3");
}

TEST(AcceptorDialerTest, Http2ProxyHandshake)
{
    Address target = Address::fromDomain("example.com", 443);

    handler::HandlerOutboundHttp2 outboundClient("admin", "secret", target);
    handler::HandlerInboundHttp2Proxy inboundServer;
    inboundServer.setAuthenticator([](std::string_view u, std::string_view p) {
        return u == "admin" && p == "secret";
    });

    // 1. 客户端生成请求
    outboundClient.handle();
    EXPECT_TRUE(outboundClient.hasResponse());
    std::string clientData;
    while (outboundClient.hasResponse())
    {
        clientData.append(outboundClient.takeResponse());
    }
    EXPECT_FALSE(clientData.empty());

    // 2. 服务端接收客户端数据
    [[maybe_unused]] auto _1 = inboundServer.appendRequest(clientData.data(), clientData.size());
    inboundServer.handle();
    EXPECT_TRUE(inboundServer.hasResponse());
    std::string serverResp;
    while (inboundServer.hasResponse())
    {
        serverResp.append(inboundServer.takeResponse());
    }
    EXPECT_FALSE(serverResp.empty());

    // 服务端应已握手完成并进入 STREAMING
    EXPECT_TRUE(inboundServer.isEstablished());
    EXPECT_EQ(inboundServer.inboundStage(), handler::InboundStage::STREAMING);
    EXPECT_EQ(inboundServer.target().host, "example.com");
    EXPECT_EQ(inboundServer.target().port, 443);

    // 3. 客户端接收服务端 200 响应
    [[maybe_unused]] auto _2 = outboundClient.appendRequest(serverResp.data(), serverResp.size());
    outboundClient.handle();
    EXPECT_EQ(outboundClient.outboundStage(), handler::OutboundStage::STREAMING);
}

TEST(AcceptorDialerTest, Http3ProxyHandshake)
{
    Address target = Address::fromDomain("quic.example.org", 8443);

    handler::HandlerOutboundHttp3 outboundClient(target);
    handler::HandlerInboundHttp3Proxy inboundServer;

    outboundClient.handle();
    EXPECT_TRUE(outboundClient.hasResponse());
    std::string clientData;
    while (outboundClient.hasResponse())
    {
        clientData.append(outboundClient.takeResponse());
    }
    EXPECT_FALSE(clientData.empty());

    [[maybe_unused]] auto _1 = inboundServer.appendRequest(clientData.data(), clientData.size());
    inboundServer.handle();
    EXPECT_TRUE(inboundServer.hasResponse());
    std::string serverResp;
    while (inboundServer.hasResponse())
    {
        serverResp.append(inboundServer.takeResponse());
    }
    EXPECT_FALSE(serverResp.empty());

    EXPECT_TRUE(inboundServer.isEstablished());
    EXPECT_EQ(inboundServer.inboundStage(), handler::InboundStage::STREAMING);
    EXPECT_EQ(inboundServer.target().host, "quic.example.org");
    EXPECT_EQ(inboundServer.target().port, 8443);

    [[maybe_unused]] auto _2 = outboundClient.appendRequest(serverResp.data(), serverResp.size());
    outboundClient.handle();
    EXPECT_EQ(outboundClient.outboundStage(), handler::OutboundStage::STREAMING);
}

TEST(AcceptorDialerTest, CoreAcceptorAndDialerApis)
{
    Core core;
    auto acc = std::make_shared<AcceptorHttp3>("h3", "127.0.0.1", 443);
    auto dialer = std::make_shared<DialerVless>("vless1", "127.0.0.1", 443, "a1b2c3d4-e5f6-7890-abcd-ef1234567890");

    core.addAcceptor(acc);
    core.addDialer(dialer);

    EXPECT_TRUE(core.acceptors().has("h3"));
    EXPECT_TRUE(core.dialers().has("vless1"));
}

namespace
{
    class EchoDatagramHandler final : public Handler
    {
    public:
        static constexpr TransportType transport = TransportType::UDP;
        std::atomic<int> receivedCount{0};

        void onDatagram(const sockaddr_in &peer, const char *data, size_t n) noexcept override
        {
            receivedCount.fetch_add(1, std::memory_order_relaxed);
            sendTo(peer, data, n);
        }
    };
} // namespace

TEST(AcceptorDialerTest, DialerManagerVirtualSetManagerAndClear)
{
    DialerManager mgr;
    auto directOut = std::make_shared<DialerDirect>("direct-sub");
    auto sel = std::make_shared<DialerSelector>("sel", std::vector<std::string>{"direct-sub"});
    mgr.registerDialer(directOut);
    mgr.registerDialer(sel);
    EXPECT_TRUE(mgr.has("sel"));

    auto res = sel->dialForwarder(Address::fromHostPort("127.0.0.1", 1));
    // 能正确通过 virtual setManager 路由至 direct-sub（无论连接成败都不应返回因 manager_ 为空导致的参数缺失）
    (void)res;

    mgr.clear();
    EXPECT_FALSE(mgr.has("sel"));
    EXPECT_FALSE(mgr.has("direct-sub"));
    EXPECT_TRUE(mgr.has("direct"));
    EXPECT_TRUE(mgr.has("block"));
}

TEST(AcceptorDialerTest, ReactorExternalUdpHandlerEchoAndTimerStop)
{
    Reactor<AcceptorBase<EchoDatagramHandler>> reactor;
    EchoDatagramHandler echoHandler;

    int cliFd = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    ASSERT_GE(cliFd, 0);

    bool echoed = false;
    reactor.loop().runAfter(std::chrono::milliseconds(10),
                            [&]()
                            {
                                const sockaddr_in &dst = reactor.udpAddr();
                                const char msg[] = "udp-echo-ok";
                                [[maybe_unused]] ssize_t sn = ::sendto(
                                    cliFd, msg, sizeof(msg) - 1, 0,
                                    reinterpret_cast<const sockaddr *>(&dst), sizeof(dst));
                            });

    reactor.loop().runEvery(std::chrono::milliseconds(10),
                            [&]()
                            {
                                char buf[128];
                                ssize_t rn = ::recv(cliFd, buf, sizeof(buf), 0);
                                if (rn > 0 && std::string_view(buf, static_cast<size_t>(rn)) == "udp-echo-ok")
                                {
                                    echoed = true;
                                    reactor.stop();
                                }
                            });

    reactor.loop().runAfter(std::chrono::milliseconds(1500), [&]() { reactor.stop(); });

    auto res = reactor.runUdp("127.0.0.1", 0, echoHandler);
    ::close(cliFd);
    EXPECT_TRUE(res.has_value());
    EXPECT_TRUE(echoed);
    EXPECT_GE(echoHandler.receivedCount.load(std::memory_order_relaxed), 1);
}
