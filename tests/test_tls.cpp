#include "connection.hpp"
#include "config/tls.hpp"
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

    struct SpliceTestHandler : public HandlerConnection
    {
        static constexpr bool kEnableSplice = true;
    };
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
    TlsOptions options;
    auto res = detail::createServerContext("nonexistent_cert.crt", "nonexistent_key.key", options);
    EXPECT_FALSE(res.has_value());
    EXPECT_EQ(res.error(), ERR::SSL_CERT_FAILED);

    auto resNull = detail::createServerContext(nullptr, nullptr, options);
    EXPECT_FALSE(resNull.has_value());
    EXPECT_EQ(resNull.error(), ERR::SSL_CERT_FAILED);
}

TEST(TlsOptions, ConfiguresSessionResumptionAndTickets)
{
    TlsOptions options;
    options.sessionTimeout = 7200;
    options.enableSessionTickets = true;
    options.numTickets = 3;

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    ASSERT_NE(ctx, nullptr);
    EXPECT_TRUE(detail::configureTlsContext(ctx, options, true));
    EXPECT_EQ(SSL_CTX_get_timeout(ctx), 7200);

    // 验证禁用 Ticket
    TlsOptions noTicketOpt;
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
    TlsOptions options;
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
    TlsOptions opt;

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
    TlsOptions opt;

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
    Connection<SpliceTestHandler> conn;
    EXPECT_FALSE(conn.ktlsRxActive());
    EXPECT_FALSE(conn.ktlsTxActive());
    EXPECT_EQ(conn.ssl(), nullptr);

    // 默认未开启 splice target 时为 false
    EXPECT_FALSE(conn.isSpliceEnabled());

    // 开启 splice target
    conn.handler().setSpliceTarget(3);
    EXPECT_TRUE(conn.isSpliceEnabled());
}
