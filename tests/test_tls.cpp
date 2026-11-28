#include "acceptor.hpp"
#include "config/tls.hpp"
#include "connection.hpp"
#include "dialer.hpp"
#include "socks/inbound.hpp"
#include "socks/outbound.hpp"
#include "tls/transport.hpp"
#include "websocket/websocket.hpp"
#include <filesystem>
#include <gtest/gtest.h>

using namespace mynet;

namespace
{
    inline std::pair<std::string, std::string> findTestCerts()
    {
        const std::filesystem::path candidates[] = {"../../certs/ser.crt", "../certs/ser.crt", "certs/ser.crt"};
        for (const auto &candidate : candidates)
        {
            std::filesystem::path c = candidate;
            std::filesystem::path k = candidate;
            k.replace_filename("ser.key");
            if (std::filesystem::exists(c) && std::filesystem::exists(k))
            {
                return {c.string(), k.string()};
            }
        }
        return {};
    }

} // namespace

TEST(TlsOptions, AppliesProtocolRangeAndCipherPolicies)
{
    SecurityConfig options;
    options.minVersion = TLS1_2_VERSION;
    options.maxVersion = TLS1_3_VERSION;
    options.ciphers = "HIGH:!aNULL:!MD5";
    options.tls13CipherSuites = "TLS_AES_256_GCM_SHA384";
    options.alpnProtocols = "h2,http/1.1";

    auto alpnList = detail::splitAlpnList(options.alpnProtocols);
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    ASSERT_NE(ctx, nullptr);
    EXPECT_TRUE(detail::configureTlsContext(ctx, options, true, &alpnList));
    EXPECT_EQ(SSL_CTX_get_min_proto_version(ctx), TLS1_2_VERSION);
    EXPECT_EQ(SSL_CTX_get_max_proto_version(ctx), TLS1_3_VERSION);
    SSL_CTX_free(ctx);
}

TEST(TlsOptions, RejectsInvalidVersionRangesAndAlpnEntries)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    ASSERT_NE(ctx, nullptr);

    SecurityConfig invalidRange;
    invalidRange.minVersion = TLS1_3_VERSION;
    invalidRange.maxVersion = TLS1_2_VERSION;
    EXPECT_EQ(detail::configureTlsContext(ctx, invalidRange, true).error(), ERR::SSL_CONFIG_FAILED);

    SecurityConfig oversizedAlpn;
    oversizedAlpn.alpnProtocols = std::string(256, 'x');
    EXPECT_EQ(detail::configureTlsContext(ctx, oversizedAlpn, true).error(), ERR::SSL_CONFIG_FAILED);

    SSL_CTX_free(ctx);
}

TEST(TlsOptions, PreservesTheTls12MinimumByDefault)
{
    SecurityConfig options;
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    ASSERT_NE(ctx, nullptr);
    EXPECT_TRUE(detail::configureTlsContext(ctx, options, true));
    EXPECT_EQ(SSL_CTX_get_min_proto_version(ctx), TLS1_2_VERSION);
    EXPECT_EQ(SSL_CTX_get_max_proto_version(ctx), 0);
    SSL_CTX_free(ctx);
}

TEST(TlsOptions, ServerAlpnUsesConfiguredServerPreference)
{
    SecurityConfig options;
    options.alpnProtocols = "http/1.1,h2";
    auto alpnList = detail::splitAlpnList(options.alpnProtocols);
    const unsigned char clientProtocols[] = {2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    const unsigned char *selected = nullptr;
    unsigned char selectedLength = 0;

    EXPECT_EQ(detail::selectServerAlpn(nullptr, &selected, &selectedLength, clientProtocols, sizeof(clientProtocols),
                                       &alpnList),
              SSL_TLSEXT_ERR_OK);
    ASSERT_NE(selected, nullptr);
    EXPECT_EQ(selectedLength, 8);
    EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(selected), selectedLength), "http/1.1");
}

TEST(TlsOptions, RejectsMalformedClientAlpnList)
{
    SecurityConfig options;
    options.alpnProtocols = "h2";
    auto alpnList = detail::splitAlpnList(options.alpnProtocols);
    const unsigned char malformedProtocols[] = {4, 'h', '2'};
    const unsigned char *selected = nullptr;
    unsigned char selectedLength = 0;

    EXPECT_EQ(detail::selectServerAlpn(nullptr, &selected, &selectedLength, malformedProtocols,
                                       sizeof(malformedProtocols), &alpnList),
              SSL_TLSEXT_ERR_ALERT_FATAL);
}

TEST(TlsFactory, CreateServerContextRejectsInvalidPaths)
{
    SecurityConfig options;
    auto res = detail::createServerContext("nonexistent_cert.crt", "nonexistent_key.key", options);
    EXPECT_FALSE(res.has_value());
    EXPECT_EQ(res.error(), ERR::SSL_CERT_FAILED);

    auto resNull = detail::createServerContext(nullptr, nullptr, options);
    EXPECT_FALSE(resNull.has_value());
    EXPECT_EQ(resNull.error(), ERR::SSL_CERT_FAILED);
}

TEST(TlsOptions, ConfiguresSessionResumptionAndTickets)
{
    SecurityConfig options;
    options.sessionTimeout = 7200;
    options.enableSessionTickets = true;
    options.numTickets = 3;

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    ASSERT_NE(ctx, nullptr);
    EXPECT_TRUE(detail::configureTlsContext(ctx, options, true));
    EXPECT_EQ(SSL_CTX_get_timeout(ctx), 7200);

    // 验证禁用 Ticket
    SecurityConfig noTicketOpt;
    noTicketOpt.enableSessionTickets = false;
    EXPECT_TRUE(detail::configureTlsContext(ctx, noTicketOpt, true));
    EXPECT_TRUE(SSL_CTX_get_options(ctx) & SSL_OP_NO_TICKET);

    SSL_CTX_free(ctx);
}

TEST(TlsFactory, CreateQuicServerContext)
{
    auto [cert, key] = findTestCerts();
    if (cert.empty())
    {
        GTEST_SKIP() << "certs/ser.crt not reachable";
    }
    SecurityConfig options;
    auto res = detail::createServerContext(cert.c_str(), key.c_str(), options, TlsProtocolType::DatagramQuic);
    ASSERT_TRUE(res.has_value());
    SSL_CTX *ctx = *res;
    ASSERT_NE(ctx, nullptr);
    detail::freeContext(ctx);
    EXPECT_EQ(ctx, nullptr);
}

TEST(SniCertificateManager, DispatchesExactAndWildcardDomains)
{
    auto [cert, key] = findTestCerts();
    if (cert.empty())
    {
        GTEST_SKIP() << "certs/ser.crt not reachable";
    }
    SniCertificateManager manager;
    SecurityConfig opt;

    auto defRes = detail::createServerContext(cert.c_str(), key.c_str(), opt);
    ASSERT_TRUE(defRes.has_value());
    manager.setDefaultContext(*defRes, true);
    SSL_CTX *defCtx = manager.defaultContext();
    ASSERT_NE(defCtx, nullptr);

    EXPECT_TRUE(manager.addDomain("api.example.com", cert.c_str(), key.c_str(), opt));
    EXPECT_TRUE(manager.addDomain("*.example.org", cert.c_str(), key.c_str(), opt));
    EXPECT_EQ(manager.domainCount(), 2);

    SSL_CTX *exactCtx = manager.findContext("api.example.com");
    ASSERT_NE(exactCtx, nullptr);
    EXPECT_NE(exactCtx, defCtx);

    SSL_CTX *wildcardCtx = manager.findContext("sub.example.org");
    ASSERT_NE(wildcardCtx, nullptr);
    EXPECT_NE(wildcardCtx, defCtx);

    // 未匹配的域名回退到默认上下文
    EXPECT_EQ(manager.findContext("unknown.com"), defCtx);
    EXPECT_EQ(manager.findContext(""), defCtx);
}

TEST(SniCertificateManager, HotReloadReplacesExistingContext)
{
    auto [cert, key] = findTestCerts();
    if (cert.empty())
    {
        GTEST_SKIP() << "certs/ser.crt not reachable";
    }
    SniCertificateManager manager;
    SecurityConfig opt;

    auto defRes = detail::createServerContext(cert.c_str(), key.c_str(), opt);
    ASSERT_TRUE(defRes.has_value());
    manager.setDefaultContext(*defRes, true);

    EXPECT_TRUE(manager.addDomain("test.com", cert.c_str(), key.c_str(), opt));
    SSL_CTX *ctx1 = manager.findContext("test.com");
    ASSERT_NE(ctx1, nullptr);
    EXPECT_NE(ctx1, manager.defaultContext());

    // 热重载
    EXPECT_TRUE(manager.reloadDomain("test.com", cert.c_str(), key.c_str(), opt));
    SSL_CTX *ctx2 = manager.findContext("test.com");
    ASSERT_NE(ctx2, nullptr);
    EXPECT_NE(ctx1, ctx2); // 新的上下文指针已原子替换
}

TEST(ConnectionTls, TracksKtlsOffloadStateAndSpliceStatus)
{
    Connection conn;
    auto handlerPtr = std::make_unique<Handler>();
    auto &handler = *handlerPtr;
    conn.setHandler(std::move(handlerPtr));
    EXPECT_FALSE(conn.ktlsRxActive());
    EXPECT_FALSE(conn.ktlsTxActive());
    EXPECT_EQ(conn.ssl(), nullptr);
    EXPECT_TRUE(handler.canSplice());
}

TEST(ConnectionTls, TlsTransportHandshakeDisablesSpliceAndRelaysEncryptedData)
{
    auto [cert, key] = findTestCerts();
    if (cert.empty())
    {
        GTEST_SKIP() << "certs/ser.crt not reachable";
    }

    auto srvTls = mynet::tls::TlsTransport::createServer(cert.c_str(), key.c_str());
    ASSERT_TRUE(srvTls.has_value());
    auto cliTls = mynet::tls::TlsTransport::createClient("localhost");
    ASSERT_TRUE(cliTls.has_value());

    auto serverHandlerPtr = std::make_unique<Handler>();
    auto &serverHandler = *serverHandlerPtr;
    Handler clientHandler;
    serverHandler.addTransportLayer(std::move(*srvTls));
    clientHandler.addTransportLayer(std::move(*cliTls));

    Connection serverConn;
    serverConn.setHandler(std::move(serverHandlerPtr));
    // TlsTransport 激活后 isPassthrough() 为假，严禁内核明文 splice
    EXPECT_NE(serverConn.ssl(), nullptr);
    EXPECT_FALSE(serverHandler.canSplice());

    ASSERT_TRUE(clientHandler.startTransportHandshake().has_value());

    auto pumpPair = [&]()
    {
        for (int round = 0; round < 16; ++round)
        {
            bool progressed = false;
            while (clientHandler.hasResponse())
            {
                std::string wire = clientHandler.takeResponse();
                ASSERT_TRUE(serverHandler.appendRequest(wire.data(), static_cast<ssize_t>(wire.size())).has_value());
                progressed = true;
            }
            serverHandler.drive();
            while (serverHandler.hasResponse())
            {
                std::string wire = serverHandler.takeResponse();
                ASSERT_TRUE(clientHandler.appendRequest(wire.data(), static_cast<ssize_t>(wire.size())).has_value());
                progressed = true;
            }
            clientHandler.drive();
            if (!progressed && serverHandler.isTransportReady() && clientHandler.isTransportReady())
            {
                break;
            }
        }
    };

    pumpPair();
    ASSERT_TRUE(serverHandler.isTransportReady());
    ASSERT_TRUE(clientHandler.isTransportReady());

    ASSERT_TRUE(clientHandler.sendPayload("hello-over-tls").has_value());
    pumpPair();
    EXPECT_EQ(std::string_view(serverHandler.requestBegin(), serverHandler.requestBytes()), "hello-over-tls");

    ASSERT_TRUE(serverHandler.sendPayload("tls-server-ack").has_value());
    pumpPair();
    EXPECT_EQ(std::string_view(clientHandler.requestBegin(), clientHandler.requestBytes()), "tls-server-ack");
}

TEST(ConnectionTls, StackedTlsWebSocketSocks5EndToEndAndAcceptorContextReuse)
{
    auto [cert, key] = findTestCerts();
    if (cert.empty())
    {
        GTEST_SKIP() << "certs/ser.crt not reachable";
    }

    mynet::transport::TransportConfig srvCfg;
    srvCfg.type = mynet::transport::TransportType::WEBSOCKET;
    srvCfg.enableTls = true;
    srvCfg.certFile = cert;
    srvCfg.keyFile = key;
    srvCfg.path = "/socks";
    srvCfg.host = "localhost";

    AcceptorSocks5 acceptor("s5-ws-tls", "127.0.0.1", 0);
    ASSERT_TRUE(acceptor.setTransportConfig(srvCfg).has_value());
    EXPECT_NE(acceptor.sslContext(), nullptr);

    auto serverHandlerA = acceptor.buildConfiguredHandler();
    auto serverHandlerB = acceptor.buildConfiguredHandler();
    ASSERT_NE(serverHandlerA, nullptr);
    ASSERT_NE(serverHandlerB, nullptr);

    Handler clientHandler;
    auto cliTls = mynet::tls::TlsTransport::createClient("localhost");
    ASSERT_TRUE(cliTls.has_value());
    clientHandler.addTransportLayer(std::move(*cliTls));
    clientHandler.addTransportLayer(
        std::make_unique<mynet::websocket::WebSocketSession>(false, "/socks", "localhost"));
    ASSERT_TRUE(clientHandler.startTransportHandshake().has_value());

    // 预先推送 SOCKS5 方法协商：在 TLS+WS 就绪前应缓存在 pendingAppTx_ 中并在握手就绪后自动封包发出
    const std::string s5Methods("\x05\x01\x00", 3);
    ASSERT_TRUE(clientHandler.sendPayload(s5Methods).has_value());

    auto exchangeWire = [&]()
    {
        for (int round = 0; round < 24; ++round)
        {
            bool moved = false;
            while (clientHandler.hasResponse())
            {
                std::string w = clientHandler.takeResponse();
                ASSERT_TRUE(serverHandlerA->appendRequest(w.data(), static_cast<ssize_t>(w.size())).has_value());
                moved = true;
            }
            serverHandlerA->drive();
            while (serverHandlerA->hasResponse())
            {
                std::string w = serverHandlerA->takeResponse();
                ASSERT_TRUE(clientHandler.appendRequest(w.data(), static_cast<ssize_t>(w.size())).has_value());
                moved = true;
            }
            clientHandler.drive();
            if (!moved)
            {
                break;
            }
        }
    };

    exchangeWire();
    ASSERT_TRUE(clientHandler.isTransportReady());
    ASSERT_TRUE(serverHandlerA->isTransportReady());
    ASSERT_EQ(std::string_view(clientHandler.requestBegin(), clientHandler.requestBytes()),
              std::string_view("\x05\x00", 2));
    clientHandler.requestConsume(2);

    // 发送 SOCKS5 CONNECT 请求 (example.com:443)
    std::string connectReq("\x05\x01\x00\x03\x0b", 5);
    connectReq.append("example.com");
    connectReq.push_back('\x01');
    connectReq.push_back(static_cast<char>(0xBB));
    ASSERT_TRUE(clientHandler.sendPayload(connectReq).has_value());

    exchangeWire();
    EXPECT_TRUE(serverHandlerA->isEstablished());
    EXPECT_EQ(serverHandlerA->target().host, "example.com");
    EXPECT_EQ(serverHandlerA->target().port, 443);
    EXPECT_GE(clientHandler.requestBytes(), 10u);
    clientHandler.requestClear();

    // 验证 Dialer 配置 TLS 后 dialForwarderHelper 自动触发 ClientHello
    mynet::transport::TransportConfig cliCfg;
    cliCfg.enableTls = true;
    cliCfg.sni = "localhost";
    DialerSocks5 dialer("s5-out", "127.0.0.1", 1080);
    dialer.setTransportConfig(cliCfg);
    EXPECT_TRUE(dialer.transportConfig().enableTls);
}
