#pragma once

#include "configHolder.hpp"
#include "error.hpp"
#include "log_config.hpp"
#include <cstring>
#include <mutex>
#include <openssl/ssl.h>
#if __has_include(<openssl/quic.h>) && !defined(OPENSSL_NO_QUIC)
#include <openssl/quic.h>
#define MYNET_HAVE_QUIC 1
#endif
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace mynet
{

    /**
     * @brief TLS 传输协议底层类型
     */
    enum class TlsProtocolType : uint8_t
    {
        StreamTcp = 0,   ///< 基于 TCP 的流式 TLS (TLS 1.2 / 1.3)
        DatagramQuic = 1 ///< 基于 UDP 的 QUIC TLS 1.3 (RFC 9001, HTTP/3)
    };

    /**
     * @brief Standard TLS negotiation settings alias.
     *
     * 统一收拢至 configHolder.hpp 中的 SecurityConfig，消除重复定义。
     */
    using TlsOptions = SecurityConfig;

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
        [[nodiscard]] inline SecurityConfig tlsOptionsFrom(const SecurityConfig &security)
        {
            return security;
        }

        [[nodiscard]] inline bool validTlsOptions(const SecurityConfig &options) noexcept
        {
            if (!validSecurityConfig(options))
            {
                return false;
            }

            const auto alpnList = splitAlpnList(options.alpnProtocols);
            size_t wireBytes = 0;
            for (const std::string &protocol : alpnList)
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
            if (argument == nullptr) [[unlikely]]
            {
                return SSL_TLSEXT_ERR_NOACK;
            }
            const auto &alpnList = *static_cast<const std::vector<std::string> *>(argument);
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

            for (const std::string &serverProtocol : alpnList)
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

        [[nodiscard]] inline Result<> configureTlsContext(SSL_CTX *ctx, SecurityConfig &options, bool server,
                                                          const std::vector<std::string> *alpnList = nullptr,
                                                          TlsProtocolType proto = TlsProtocolType::StreamTcp) noexcept
        {
            if (proto == TlsProtocolType::DatagramQuic)
            {
                // RFC 9001: QUIC 强制要求 TLS 1.3
                if (options.minVersion < 0x0304)
                {
                    options.minVersion = 0x0304;
                }
                if (options.alpnProtocols.empty())
                {
                    options.alpnProtocols = "h3";
                }
            }

            if (!validTlsOptions(options) || SSL_CTX_set_min_proto_version(ctx, options.minVersion) != 1 ||
                (options.maxVersion != 0 && SSL_CTX_set_max_proto_version(ctx, options.maxVersion) != 1))
            {
                return std::unexpected(ERR::SSL_CONFIG_FAILED);
            }

            SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
            if (server)
            {
                SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);

                // 开启服务端会话缓存与 Session ID 上下文（支持 Session Resumption 会话恢复）
                SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);
                const std::string_view sidCtx = options.sessionIdContext.empty() ? "mynet" : options.sessionIdContext;
                SSL_CTX_set_session_id_context(ctx, reinterpret_cast<const unsigned char *>(sidCtx.data()),
                                               static_cast<unsigned int>(sidCtx.size()));
                if (options.sessionTimeout > 0)
                {
                    SSL_CTX_set_timeout(ctx, options.sessionTimeout);
                }
                if (!options.enableSessionTickets)
                {
                    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
                }
                else
                {
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
                    SSL_CTX_set_num_tickets(ctx, options.numTickets);
#endif
                }
            }
            if ((!options.ciphers.empty() && options.ciphers != "DEFAULT" &&
                 SSL_CTX_set_cipher_list(ctx, options.ciphers.c_str()) != 1) ||
                (!options.tls13CipherSuites.empty() &&
                 SSL_CTX_set_ciphersuites(ctx, options.tls13CipherSuites.c_str()) != 1))
            {
                return std::unexpected(ERR::SSL_CONFIG_FAILED);
            }
            if (server && alpnList != nullptr && !alpnList->empty())
            {
                SSL_CTX_set_alpn_select_cb(ctx, selectServerAlpn, const_cast<std::vector<std::string> *>(alpnList));
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

        /**
         * @brief 释放 SSL_CTX 并安全置空指针
         */
        inline void freeContext(SSL_CTX *&ctx) noexcept
        {
            if (ctx != nullptr)
            {
                SSL_CTX_free(ctx);
                ctx = nullptr;
            }
        }

        /**
         * @brief 创建并配置服务端 SSL_CTX 上下文（统一工厂，消除引擎间冗余）
         *
         * 统一了证书链加载（支持中间 CA）、私钥加载与一致性校验、协议版本与套件配置、ALPN 及 mTLS。
         * 支持 TCP Stream TLS 与 QUIC (HTTP/3) Datagram TLS。
         */
        [[nodiscard]] inline Result<SSL_CTX *>
        createServerContext(const char *crt, const char *key, SecurityConfig &options,
                            const std::vector<std::string> *alpnList = nullptr,
                            TlsProtocolType proto = TlsProtocolType::StreamTcp) noexcept
        {
            if (crt == nullptr || crt[0] == '\0' || key == nullptr || key[0] == '\0') [[unlikely]]
            {
                return std::unexpected(ERR::SSL_CERT_FAILED);
            }

            SSL_CTX *ctx = nullptr;
            if (proto == TlsProtocolType::DatagramQuic)
            {
#ifdef MYNET_HAVE_QUIC
                ctx = SSL_CTX_new(OSSL_QUIC_server_method());
#else
                LOG_ERROR("createServerContext: QUIC is not supported by current OpenSSL build");
                return std::unexpected(ERR::SSL_CTX_FAILED);
#endif
            }
            else
            {
                ctx = SSL_CTX_new(TLS_server_method());
            }

            if (ctx == nullptr) [[unlikely]]
            {
                LOG_ERROR("createServerContext: SSL_CTX_new() failed: {}", sslText());
                return std::unexpected(ERR::SSL_CTX_FAILED);
            }
            if (auto err = configureTlsContext(ctx, options, true, alpnList, proto); !err) [[unlikely]]
            {
                LOG_ERROR("createServerContext: invalid TLS options: {}", sslText());
                SSL_CTX_free(ctx);
                return std::unexpected(err.error());
            }
            // 使用最新的 SSL_CTX_use_certificate_chain_file，支持包含中间 CA 的完整证书链
            if (SSL_CTX_use_certificate_chain_file(ctx, crt) <= 0) [[unlikely]]
            {
                LOG_ERROR("createServerContext: certificate file \"{}\" could not be loaded: {}", crt, sslText());
                SSL_CTX_free(ctx);
                return std::unexpected(ERR::SSL_CERT_FAILED);
            }
            if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0) [[unlikely]]
            {
                LOG_ERROR("createServerContext: private key file \"{}\" could not be loaded: {}", key, sslText());
                SSL_CTX_free(ctx);
                return std::unexpected(ERR::SSL_KEY_FAILED);
            }
            if (SSL_CTX_check_private_key(ctx) <= 0) [[unlikely]]
            {
                LOG_ERROR("createServerContext: private key \"{}\" does not match certificate \"{}\": {}", key, crt,
                          sslText());
                SSL_CTX_free(ctx);
                return std::unexpected(ERR::SSL_KEY_MISMATCH);
            }
            return ctx;
        }

        [[nodiscard]] inline Result<SSL_CTX *>
        createServerContext(const char *crt, const char *key, SecurityConfig &options,
                            TlsProtocolType proto) noexcept
        {
            return createServerContext(crt, key, options, nullptr, proto);
        }

    } // namespace detail

    /**
     * @brief SNI 多域名证书调度器与动态热重载管理器（无智能指针，线程安全）
     *
     * 架构特性：
     * 1. 域名分发：支持精确域名匹配与通配符泛域名匹配（*.example.com）；
     * 2. 热重载：支持在线无缝重新加载/替换特定域名的证书私钥，自动释放旧 CTX；
     * 3. 兜底回退：未匹配到 SNI 或客户端未传 SNI 时平滑回退到默认 defaultCtx_；
     * 4. 读写安全：使用 std::shared_mutex 保证高并发握手查表为读共享锁，热更新走独占写锁。
     */
    class SniCertificateManager
    {
    public:
        struct DomainEntry
        {
            SSL_CTX *ctx = nullptr;
            std::vector<std::string> alpnList{};
        };

        SniCertificateManager() noexcept = default;

        ~SniCertificateManager() noexcept { clear(); }

        SniCertificateManager(const SniCertificateManager &) = delete;
        SniCertificateManager &operator=(const SniCertificateManager &) = delete;

        SniCertificateManager(SniCertificateManager &&other) noexcept
        {
            std::unique_lock lock(other.rwLock_);
            defaultCtx_ = other.defaultCtx_;
            ownsDefaultCtx_ = other.ownsDefaultCtx_;
            contexts_ = std::move(other.contexts_);
            other.defaultCtx_ = nullptr;
            other.ownsDefaultCtx_ = false;
        }

        SniCertificateManager &operator=(SniCertificateManager &&other) noexcept
        {
            if (this != &other)
            {
                clear();
                std::scoped_lock lock(rwLock_, other.rwLock_);
                defaultCtx_ = other.defaultCtx_;
                ownsDefaultCtx_ = other.ownsDefaultCtx_;
                contexts_ = std::move(other.contexts_);
                other.defaultCtx_ = nullptr;
                other.ownsDefaultCtx_ = false;
            }
            return *this;
        }

        /**
         * @brief 设置默认 SSL_CTX 上下文（当客户端未提供 SNI 或无域名命中时使用）
         * @param ctx 目标上下文
         * @param takeOwnership 是否由本管理器在析构时负责释放
         */
        void setDefaultContext(SSL_CTX *ctx, bool takeOwnership = false) noexcept
        {
            std::unique_lock lock(rwLock_);
            if (ownsDefaultCtx_ && defaultCtx_ != nullptr && defaultCtx_ != ctx)
            {
                detail::freeContext(defaultCtx_);
            }
            defaultCtx_ = ctx;
            ownsDefaultCtx_ = takeOwnership;
            if (defaultCtx_ != nullptr)
            {
                attachTo(defaultCtx_);
            }
        }

        [[nodiscard]] SSL_CTX *defaultContext() const noexcept
        {
            std::shared_lock lock(rwLock_);
            return defaultCtx_;
        }

        /**
         * @brief 为指定域名添加证书并创建 SSL_CTX 上下文
         *
         * @param domain 域名（支持精确如 "api.example.com" 或泛域名 "*.example.com"）
         * @param crt 证书文件路径
         * @param key 私钥文件路径
         * @param options TLS 安全传输配置
         * @return 成功返回 {}，失败返回 ERR
         */
        [[nodiscard]] Result<> addDomain(std::string_view domain, const char *crt, const char *key,
                                         SecurityConfig &options)
        {
            DomainEntry entry;
            entry.alpnList = detail::splitAlpnList(options.alpnProtocols);
            auto res = detail::createServerContext(crt, key, options, &entry.alpnList);
            if (!res) [[unlikely]]
            {
                return std::unexpected(res.error());
            }
            entry.ctx = *res;
            std::unique_lock lock(rwLock_);
            auto it = contexts_.find(std::string(domain));
            if (it != contexts_.end())
            {
                detail::freeContext(it->second.ctx);
                it->second = std::move(entry);
            }
            else
            {
                contexts_.emplace(std::string(domain), std::move(entry));
            }
            return {};
        }

        /**
         * @brief 在线热重载 / 替换指定域名的证书与私钥（原子性指针替换，不中断服务）
         */
        [[nodiscard]] Result<> reloadDomain(std::string_view domain, const char *crt, const char *key,
                                            SecurityConfig &options)
        {
            return addDomain(domain, crt, key, options);
        }

        /**
         * @brief 根据客户端传入的 SNI 主机名匹配最合适的 SSL_CTX
         *
         * 匹配优先级：
         * 1. 域名完全匹配（如 "api.example.com"）
         * 2. 泛域名匹配（如 "*.example.com"）
         * 3. 回退默认 defaultCtx_
         */
        [[nodiscard]] SSL_CTX *findContext(std::string_view serverName) const noexcept
        {
            std::shared_lock lock(rwLock_);
            if (contexts_.empty())
            {
                return defaultCtx_;
            }

            // 1. 精确匹配
            auto it = contexts_.find(std::string(serverName));
            if (it != contexts_.end())
            {
                return it->second.ctx;
            }

            // 2. 泛域名匹配（查找一级前缀后的通配形式，如 foo.example.com -> *.example.com）
            const size_t dot = serverName.find('.');
            if (dot != std::string_view::npos)
            {
                std::string wildcard = "*";
                wildcard.append(serverName.substr(dot));
                auto wit = contexts_.find(wildcard);
                if (wit != contexts_.end())
                {
                    return wit->second.ctx;
                }
            }

            // 3. 回退默认
            return defaultCtx_;
        }

        /**
         * @brief 将本 SNI 管理器挂载到指定的 SSL_CTX（作为默认监听上下文的 SNI 回调）
         */
        void attachTo(SSL_CTX *ctx) noexcept
        {
            if (ctx == nullptr)
            {
                return;
            }
            SSL_CTX_set_tlsext_servername_callback(ctx, onSniCallback);
            SSL_CTX_set_tlsext_servername_arg(ctx, this);
        }

        /**
         * @brief 清空所有托管的域名上下文并释放内存
         */
        void clear() noexcept
        {
            std::unique_lock lock(rwLock_);
            for (auto &[domain, entry] : contexts_)
            {
                detail::freeContext(entry.ctx);
            }
            contexts_.clear();
            if (ownsDefaultCtx_ && defaultCtx_ != nullptr)
            {
                detail::freeContext(defaultCtx_);
            }
            defaultCtx_ = nullptr;
            ownsDefaultCtx_ = false;
        }

        [[nodiscard]] size_t domainCount() const noexcept
        {
            std::shared_lock lock(rwLock_);
            return contexts_.size();
        }

    private:
        static int onSniCallback(SSL *ssl, [[maybe_unused]] int *al, void *arg) noexcept
        {
            if (arg == nullptr || ssl == nullptr)
            {
                return SSL_TLSEXT_ERR_OK;
            }
            const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
            if (servername == nullptr || servername[0] == '\0')
            {
                return SSL_TLSEXT_ERR_OK;
            }
            auto *manager = static_cast<SniCertificateManager *>(arg);
            SSL_CTX *matched = manager->findContext(servername);
            if (matched != nullptr)
            {
                SSL_set_SSL_CTX(ssl, matched);
            }
            return SSL_TLSEXT_ERR_OK;
        }

        mutable std::shared_mutex rwLock_{};
        std::unordered_map<std::string, DomainEntry> contexts_{};
        SSL_CTX *defaultCtx_{nullptr};
        bool ownsDefaultCtx_{false};
    };

} // namespace mynet
