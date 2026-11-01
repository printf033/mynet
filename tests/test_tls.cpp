#include "tls.hpp"
#include <gtest/gtest.h>

using namespace mynet;

TEST(TlsOptions, AppliesProtocolRangeAndCipherPolicies)
{
    TlsOptions options;
    options.minVersion = TLS1_2_VERSION;
    options.maxVersion = TLS1_3_VERSION;
    options.cipherList = "HIGH:!aNULL:!MD5";
    options.tls13CipherSuites = "TLS_AES_256_GCM_SHA384";
    options.alpnProtocols = {"h2", "http/1.1"};

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    ASSERT_NE(ctx, nullptr);
    EXPECT_TRUE(detail::configureTlsContext(ctx, options, false));
    EXPECT_EQ(SSL_CTX_get_min_proto_version(ctx), TLS1_2_VERSION);
    EXPECT_EQ(SSL_CTX_get_max_proto_version(ctx), TLS1_3_VERSION);
    SSL_CTX_free(ctx);
}

TEST(TlsOptions, RejectsInvalidVersionRangesAndAlpnEntries)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    ASSERT_NE(ctx, nullptr);

    TlsOptions invalidRange;
    invalidRange.minVersion = TLS1_3_VERSION;
    invalidRange.maxVersion = TLS1_2_VERSION;
    EXPECT_EQ(detail::configureTlsContext(ctx, invalidRange, true).error(), ERR::SSL_CONFIG_FAILED);

    TlsOptions emptyAlpn;
    emptyAlpn.alpnProtocols = {""};
    EXPECT_EQ(detail::configureTlsContext(ctx, emptyAlpn, true).error(), ERR::SSL_CONFIG_FAILED);

    TlsOptions oversizedAlpn;
    oversizedAlpn.alpnProtocols = {std::string(256, 'x')};
    EXPECT_EQ(detail::configureTlsContext(ctx, oversizedAlpn, true).error(), ERR::SSL_CONFIG_FAILED);

    SSL_CTX_free(ctx);
}

TEST(TlsOptions, PreservesTheTls12MinimumByDefault)
{
    TlsOptions options;
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    ASSERT_NE(ctx, nullptr);
    EXPECT_TRUE(detail::configureTlsContext(ctx, options, true));
    EXPECT_EQ(SSL_CTX_get_min_proto_version(ctx), TLS1_2_VERSION);
    EXPECT_EQ(SSL_CTX_get_max_proto_version(ctx), 0);
    SSL_CTX_free(ctx);
}

TEST(TlsOptions, ServerAlpnUsesConfiguredServerPreference)
{
    TlsOptions options;
    options.alpnProtocols = {"http/1.1", "h2"};
    const unsigned char clientProtocols[] = {2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    const unsigned char *selected = nullptr;
    unsigned char selectedLength = 0;

    EXPECT_EQ(detail::selectServerAlpn(nullptr, &selected, &selectedLength, clientProtocols,
                                        sizeof(clientProtocols), &options),
              SSL_TLSEXT_ERR_OK);
    ASSERT_NE(selected, nullptr);
    EXPECT_EQ(selectedLength, 8);
    EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(selected), selectedLength), "http/1.1");
}

TEST(TlsOptions, RejectsMalformedClientAlpnList)
{
    TlsOptions options;
    options.alpnProtocols = {"h2"};
    const unsigned char malformedProtocols[] = {4, 'h', '2'};
    const unsigned char *selected = nullptr;
    unsigned char selectedLength = 0;

    EXPECT_EQ(detail::selectServerAlpn(nullptr, &selected, &selectedLength, malformedProtocols,
                                        sizeof(malformedProtocols), &options),
              SSL_TLSEXT_ERR_ALERT_FATAL);
}
