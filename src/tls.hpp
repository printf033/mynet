#pragma once

#include "error.hpp"
#include <openssl/ssl.h>
#include <cstring>
#include <string>
#include <vector>

namespace mynet
{

    /**
     * @brief Standard TLS negotiation settings.
     *
     * These options configure protocol policy and ALPN; they do not control
     * ClientHello extension ordering or emulate another TLS implementation.
     */
    struct TlsOptions
    {
        int minVersion = TLS1_2_VERSION;
        int maxVersion = 0;
        std::string cipherList{};
        std::string tls13CipherSuites{};
        std::vector<std::string> alpnProtocols{};
    };

    namespace detail
    {

        [[nodiscard]] inline bool validTlsOptions(const TlsOptions &options) noexcept
        {
            if (options.minVersion < TLS1_2_VERSION ||
                (options.maxVersion != 0 && options.maxVersion < options.minVersion))
            {
                return false;
            }

            size_t wireBytes = 0;
            for (const std::string &protocol : options.alpnProtocols)
            {
                if (protocol.empty() || protocol.size() > 255 || wireBytes > 65535 - protocol.size() - 1)
                {
                    return false;
                }
                wireBytes += protocol.size() + 1;
            }
            return true;
        }

        inline int selectServerAlpn(SSL *, const unsigned char **out, unsigned char *outLength,
                                    const unsigned char *clientProtocols, unsigned int clientLength,
                                    void *argument) noexcept
        {
            const auto &serverProtocols = *static_cast<const TlsOptions *>(argument);
            unsigned int offset = 0;
            while (offset < clientLength)
            {
                const unsigned int length = clientProtocols[offset++];
                if (length == 0 || offset + length > clientLength)
                {
                    return SSL_TLSEXT_ERR_ALERT_FATAL;
                }
                offset += length;
            }

            for (const std::string &serverProtocol : serverProtocols.alpnProtocols)
            {
                offset = 0;
                while (offset < clientLength)
                {
                    const unsigned int length = clientProtocols[offset++];
                    if (length == serverProtocol.size() &&
                        std::memcmp(clientProtocols + offset, serverProtocol.data(), length) == 0)
                    {
                        *out = clientProtocols + offset;
                        *outLength = static_cast<unsigned char>(length);
                        return SSL_TLSEXT_ERR_OK;
                    }
                    offset += length;
                }
            }
            return SSL_TLSEXT_ERR_NOACK;
        }

        [[nodiscard]] inline Result<> configureTlsContext(SSL_CTX *ctx, TlsOptions &options,
                                                          bool server) noexcept
        {
            if (!validTlsOptions(options) ||
                SSL_CTX_set_min_proto_version(ctx, options.minVersion) != 1 ||
                (options.maxVersion != 0 && SSL_CTX_set_max_proto_version(ctx, options.maxVersion) != 1))
            {
                return std::unexpected(ERR::SSL_CONFIG_FAILED);
            }

            SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
            if (server)
            {
                SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
            }
            if ((!options.cipherList.empty() &&
                 SSL_CTX_set_cipher_list(ctx, options.cipherList.c_str()) != 1) ||
                (!options.tls13CipherSuites.empty() &&
                 SSL_CTX_set_ciphersuites(ctx, options.tls13CipherSuites.c_str()) != 1))
            {
                return std::unexpected(ERR::SSL_CONFIG_FAILED);
            }
            if (server && !options.alpnProtocols.empty())
            {
                SSL_CTX_set_alpn_select_cb(ctx, selectServerAlpn, &options);
            }
            return {};
        }

        [[nodiscard]] inline Result<> configureClientAlpn(SSL *ssl, const TlsOptions &options)
        {
            if (!validTlsOptions(options))
            {
                return std::unexpected(ERR::SSL_CONFIG_FAILED);
            }
            if (options.alpnProtocols.empty())
            {
                return {};
            }

            std::vector<unsigned char> wire;
            size_t wireBytes = 0;
            for (const std::string &protocol : options.alpnProtocols)
            {
                wireBytes += protocol.size() + 1;
            }
            wire.reserve(wireBytes);
            for (const std::string &protocol : options.alpnProtocols)
            {
                wire.push_back(static_cast<unsigned char>(protocol.size()));
                wire.insert(wire.end(), protocol.begin(), protocol.end());
            }
            if (SSL_set_alpn_protos(ssl, wire.data(), static_cast<unsigned int>(wire.size())) != 0)
            {
                return std::unexpected(ERR::SSL_CONFIG_FAILED);
            }
            return {};
        }

    } // namespace detail

} // namespace mynet
