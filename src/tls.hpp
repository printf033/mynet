#pragma once

#include "configHolder.hpp"
#include "error.hpp"
#include <cstring>
#include <openssl/ssl.h>
#include <string>
#include <string_view>
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
        /// 服务端 CA 根证书束路径。非空时要求客户端出示证书并对其做校验
        /// （mTLS）；空表示不启用客户端认证。
        std::string caFile{};
    };

    namespace detail
    {

        /**
         * @brief 把 config.lua 中逗号分隔的 ALPN 列表拆成协议名序列。
         *
         * 容忍分隔符两侧的空白、连续逗号与空项，避免配置文件里多一个空格就
         * 变成一个长度为 1 的假协议名（那会让 ALPN 协商静默失败）。
         */
        [[nodiscard]] inline std::vector<std::string> splitAlpnList(std::string_view list)
        {
            std::vector<std::string> protocols{};
            size_t start = 0;
            while (start <= list.size())
            {
                const size_t comma = list.find(',', start);
                const size_t end = comma == std::string_view::npos ? list.size() : comma;
                size_t first = start;
                size_t last = end;
                while (first < last && (list[first] == ' ' || list[first] == '\t'))
                {
                    ++first;
                }
                while (last > first && (list[last - 1] == ' ' || list[last - 1] == '\t'))
                {
                    --last;
                }
                if (last > first)
                {
                    protocols.emplace_back(list.substr(first, last - first));
                }
                if (comma == std::string_view::npos)
                {
                    break;
                }
                start = comma + 1;
            }
            return protocols;
        }

        /**
         * @brief 由 security 配置节构造 TLS 协商选项。
         *
         * 引擎在调用方未显式传入 TlsOptions 时走这里，使 config.lua 的
         * security.ciphers / security.alpnProtocols 成为唯一默认真相来源，
         * 而不是在引擎头文件里另写一份默认值。
         */
        [[nodiscard]] inline TlsOptions tlsOptionsFrom(const SecurityConfig &security)
        {
            TlsOptions options{};
            options.caFile = security.caFile;
            // "DEFAULT" 与空串都归一为"不调用 SSL_CTX_set_cipher_list"。
            //
            // 这不是等价变换的偷懒，而是为了保住一条容易被忽略的性质：
            // 显式设置 "DEFAULT" 会**覆盖** libssl 从 openssl.cnf 读到的
            // system_default CipherString，把加固部署的套件策略顶掉；而不调用
            // 则让那些策略继续生效。重构前的 runSsl 默认走的就是"不调用"，
            // 这里保持逐项等价。
            if (!security.ciphers.empty() && security.ciphers != "DEFAULT")
            {
                options.cipherList = security.ciphers;
            }
            options.alpnProtocols = splitAlpnList(security.alpnProtocols);
            return options;
        }

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

        [[nodiscard]] inline Result<> configureTlsContext(SSL_CTX *ctx, TlsOptions &options, bool server) noexcept
        {
            if (!validTlsOptions(options) || SSL_CTX_set_min_proto_version(ctx, options.minVersion) != 1 ||
                (options.maxVersion != 0 && SSL_CTX_set_max_proto_version(ctx, options.maxVersion) != 1))
            {
                return std::unexpected(ERR::SSL_CONFIG_FAILED);
            }

            SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
            if (server)
            {
                SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
            }
            if ((!options.cipherList.empty() && SSL_CTX_set_cipher_list(ctx, options.cipherList.c_str()) != 1) ||
                (!options.tls13CipherSuites.empty() &&
                 SSL_CTX_set_ciphersuites(ctx, options.tls13CipherSuites.c_str()) != 1))
            {
                return std::unexpected(ERR::SSL_CONFIG_FAILED);
            }
            if (server && !options.alpnProtocols.empty())
            {
                SSL_CTX_set_alpn_select_cb(ctx, selectServerAlpn, &options);
            }
            // 服务端 CA：配置了就启用双向认证。此时客户端必须出示由该 CA 签发的证书，
            // 否则握手直接失败——这比"配置了 CA 但只是摆设"安全得多。
            if (server && !options.caFile.empty())
            {
                if (SSL_CTX_load_verify_locations(ctx, options.caFile.c_str(), nullptr) != 1)
                {
                    return std::unexpected(ERR::SSL_CA_FAILED);
                }
                SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
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
