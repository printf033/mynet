#pragma once

/**
 * @file tls/transport.hpp
 * @brief 基于 OpenSSL 内存 BIO 的可堆叠 TLS 传输层插件 (TlsTransport : public ITransport)
 *
 * 将 OpenSSL TLS 状态机与底层套接字 fd 解耦，使其既可以直接承载在 TCP socket 上，
 * 也可以与其他传输层 / 用户态通道 / Proactor(io_uring) 无缝组合。
 */

#include "../config/tls.hpp"
#include "../transport.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <span>
#include <string>
#include <string_view>

namespace mynet::tls
{

    class TlsTransport final : public mynet::transport::ITransport
    {
    private:
        bool isServer_{false};
        SSL_CTX *ctx_{nullptr};
        bool ownsCtx_{false};
        SSL *ssl_{nullptr};
        BIO *rbio_{nullptr};
        BIO *wbio_{nullptr};
        mynet::transport::TransportState state_{mynet::transport::TransportState::INITIAL};
        std::string sni_{};

        [[nodiscard]] Result<> flushWbio(ResponseQueue &wireOut) noexcept
        {
            if (wbio_ == nullptr)
            {
                return {};
            }
            std::array<char, 16384> buf{};
            while (BIO_ctrl_pending(wbio_) > 0)
            {
                const int n = BIO_read(wbio_, buf.data(), static_cast<int>(buf.size()));
                if (n <= 0)
                {
                    break;
                }
                if (auto res = wireOut.emplace(buf.data(), static_cast<size_t>(n)); !res)
                {
                    return res;
                }
            }
            return {};
        }

        [[nodiscard]] std::string flushWbioToString()
        {
            std::string out;
            if (wbio_ == nullptr)
            {
                return out;
            }
            std::array<char, 4096> buf{};
            while (BIO_ctrl_pending(wbio_) > 0)
            {
                const int n = BIO_read(wbio_, buf.data(), static_cast<int>(buf.size()));
                if (n <= 0)
                {
                    break;
                }
                out.append(buf.data(), static_cast<size_t>(n));
            }
            return out;
        }

        void releaseSsl() noexcept
        {
            if (ssl_ != nullptr)
            {
                SSL_free(ssl_); // frees attached rbio_ and wbio_
                ssl_ = nullptr;
                rbio_ = nullptr;
                wbio_ = nullptr;
            }
            if (ownsCtx_ && ctx_ != nullptr)
            {
                SSL_CTX_free(ctx_);
            }
            ctx_ = nullptr;
            ownsCtx_ = false;
        }

        bool initSslInstance() noexcept
        {
            if (ctx_ == nullptr)
            {
                return false;
            }
            ssl_ = SSL_new(ctx_);
            if (ssl_ == nullptr)
            {
                return false;
            }
            rbio_ = BIO_new(BIO_s_mem());
            wbio_ = BIO_new(BIO_s_mem());
            if (rbio_ == nullptr || wbio_ == nullptr)
            {
                if (rbio_ != nullptr)
                    BIO_free(rbio_);
                if (wbio_ != nullptr)
                    BIO_free(wbio_);
                rbio_ = nullptr;
                wbio_ = nullptr;
                SSL_free(ssl_);
                ssl_ = nullptr;
                return false;
            }
            BIO_set_mem_eof_return(rbio_, -1);
            BIO_set_mem_eof_return(wbio_, -1);
            SSL_set_bio(ssl_, rbio_, wbio_);

            if (isServer_)
            {
                SSL_set_accept_state(ssl_);
            }
            else
            {
                if (!sni_.empty())
                {
                    SSL_set_tlsext_host_name(ssl_, sni_.c_str());
                }
                SSL_set_connect_state(ssl_);
            }
            return true;
        }

    public:
        TlsTransport(bool isServer, SSL_CTX *ctx, bool ownsCtx, std::string sni = "") noexcept
            : isServer_(isServer),
              ctx_(ctx),
              ownsCtx_(ownsCtx),
              sni_(std::move(sni))
        {
            if (!initSslInstance())
            {
                state_ = mynet::transport::TransportState::FAILED;
            }
        }

        ~TlsTransport() noexcept override { releaseSsl(); }

        TlsTransport(const TlsTransport &) = delete;
        TlsTransport &operator=(const TlsTransport &) = delete;

        /**
         * @brief 从共享服务端 SSL_CTX 创建服务端 TLS 传输实例（不接管 ctx 生命周期）
         */
        [[nodiscard]] static std::unique_ptr<TlsTransport> fromServerContext(SSL_CTX *ctx)
        {
            return std::make_unique<TlsTransport>(true, ctx, false);
        }

        /**
         * @brief 根据证书路径与安全配置创建服务端 TLS 传输实例
         */
        [[nodiscard]] static Result<std::unique_ptr<TlsTransport>>
        createServer(const char *crt, const char *key, SecurityConfig options = {})
        {
            auto alpnList = mynet::detail::splitAlpnList(options.alpnProtocols);
            auto ctxRes = mynet::detail::createServerContext(
                crt, key, options, alpnList.empty() ? nullptr : &alpnList, TlsProtocolType::StreamTcp);
            if (!ctxRes)
            {
                return std::unexpected(ctxRes.error());
            }
            auto t = std::make_unique<TlsTransport>(true, *ctxRes, true);
            if (t->state() == mynet::transport::TransportState::FAILED)
            {
                return std::unexpected(ERR::SSL_NEW_FAILED);
            }
            return t;
        }

        /**
         * @brief 创建客户端 TLS 传输实例（默认跳过或按 CA 验证证书，支持 SNI 与 ALPN）
         */
        [[nodiscard]] static Result<std::unique_ptr<TlsTransport>>
        createClient(std::string sni = "", SecurityConfig options = {})
        {
            SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
            if (ctx == nullptr)
            {
                return std::unexpected(ERR::SSL_CTX_FAILED);
            }
            auto alpnList = mynet::detail::splitAlpnList(options.alpnProtocols);
            if (auto cfgRes = mynet::detail::configureTlsContext(ctx, options, false,
                                                                 alpnList.empty() ? nullptr : &alpnList,
                                                                 TlsProtocolType::StreamTcp);
                !cfgRes)
            {
                SSL_CTX_free(ctx);
                return std::unexpected(cfgRes.error());
            }
            if (!alpnList.empty())
            {
                std::vector<uint8_t> wireAlpn;
                for (const auto &proto : alpnList)
                {
                    if (!proto.empty() && proto.size() <= 255)
                    {
                        wireAlpn.push_back(static_cast<uint8_t>(proto.size()));
                        wireAlpn.insert(wireAlpn.end(), proto.begin(), proto.end());
                    }
                }
                if (!wireAlpn.empty())
                {
                    SSL_CTX_set_alpn_protos(ctx, wireAlpn.data(), static_cast<unsigned int>(wireAlpn.size()));
                }
            }
            auto t = std::make_unique<TlsTransport>(false, ctx, true, std::move(sni));
            if (t->state() == mynet::transport::TransportState::FAILED)
            {
                return std::unexpected(ERR::SSL_NEW_FAILED);
            }
            return t;
        }

        [[nodiscard]] mynet::transport::TransportType type() const noexcept override
        {
            return mynet::transport::TransportType::TLS;
        }

        [[nodiscard]] mynet::transport::TransportState state() const noexcept override { return state_; }

        [[nodiscard]] bool isReady() const noexcept override
        {
            return state_ == mynet::transport::TransportState::STREAMING;
        }

        [[nodiscard]] void *nativeSslHandle() const noexcept override { return ssl_; }

        [[nodiscard]] bool ktlsRxActive() const noexcept override
        {
#if defined(MYNET_HAVE_KTLS) && defined(BIO_get_ktls_recv)
            return ssl_ != nullptr && rbio_ != nullptr && BIO_get_ktls_recv(rbio_) == 1;
#else
            return false;
#endif
        }

        [[nodiscard]] bool ktlsTxActive() const noexcept override
        {
#if defined(MYNET_HAVE_KTLS) && defined(BIO_get_ktls_send)
            return ssl_ != nullptr && wbio_ != nullptr && BIO_get_ktls_send(wbio_) == 1;
#else
            return false;
#endif
        }

        void reset() noexcept override
        {
            if (ssl_ != nullptr)
            {
                SSL_free(ssl_);
                ssl_ = nullptr;
                rbio_ = nullptr;
                wbio_ = nullptr;
            }
            if (ctx_ != nullptr && initSslInstance())
            {
                state_ = mynet::transport::TransportState::INITIAL;
            }
            else
            {
                state_ = mynet::transport::TransportState::FAILED;
            }
        }

        [[nodiscard]] std::optional<std::string> startHandshake() override
        {
            if (ssl_ == nullptr || isServer_)
            {
                return std::nullopt;
            }
            state_ = mynet::transport::TransportState::HANDSHAKING;
            const int rc = SSL_do_handshake(ssl_);
            if (rc == 1)
            {
                state_ = mynet::transport::TransportState::STREAMING;
            }
            else
            {
                const int err = SSL_get_error(ssl_, rc);
                if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
                {
                    state_ = mynet::transport::TransportState::FAILED;
                    return std::nullopt;
                }
            }
            std::string out = flushWbioToString();
            if (out.empty())
            {
                return std::nullopt;
            }
            return out;
        }

        [[nodiscard]] Result<> onWireInput(std::span<const uint8_t> wireIn, RequestBuffer &appOut,
                                           ResponseQueue &wireOut) override
        {
            if (ssl_ == nullptr || state_ == mynet::transport::TransportState::FAILED)
            {
                return std::unexpected(ERR::SSL_NEW_FAILED);
            }

            size_t offset = 0;
            while (offset < wireIn.size())
            {
                const int written =
                    BIO_write(rbio_, wireIn.data() + offset, static_cast<int>(wireIn.size() - offset));
                if (written <= 0)
                {
                    state_ = mynet::transport::TransportState::FAILED;
                    return std::unexpected(ERR::CONNECT_FAILED);
                }
                offset += static_cast<size_t>(written);
            }

            if (state_ == mynet::transport::TransportState::INITIAL ||
                state_ == mynet::transport::TransportState::HANDSHAKING)
            {
                state_ = mynet::transport::TransportState::HANDSHAKING;
                const int rc = SSL_do_handshake(ssl_);
                if (auto r = flushWbio(wireOut); !r)
                {
                    return r;
                }
                if (rc == 1)
                {
                    state_ = mynet::transport::TransportState::STREAMING;
                }
                else
                {
                    const int err = SSL_get_error(ssl_, rc);
                    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
                    {
                        state_ = mynet::transport::TransportState::FAILED;
                        return std::unexpected(ERR::SSL_CONFIG_FAILED);
                    }
                    return {};
                }
            }

            if (state_ == mynet::transport::TransportState::STREAMING)
            {
                std::array<char, 16384> buf{};
                while (true)
                {
                    const int rn = SSL_read(ssl_, buf.data(), static_cast<int>(buf.size()));
                    if (rn > 0)
                    {
                        if (auto r = appOut.append(buf.data(), static_cast<size_t>(rn)); !r)
                        {
                            return r;
                        }
                        continue;
                    }
                    const int err = SSL_get_error(ssl_, rn);
                    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                    {
                        break;
                    }
                    if (err == SSL_ERROR_ZERO_RETURN)
                    {
                        state_ = mynet::transport::TransportState::CLOSED;
                        break;
                    }
                    state_ = mynet::transport::TransportState::FAILED;
                    return std::unexpected(ERR::CONNECT_FAILED);
                }
                if (auto r = flushWbio(wireOut); !r)
                {
                    return r;
                }
            }
            return {};
        }

        [[nodiscard]] Result<> onAppOutput(std::span<const uint8_t> appIn, ResponseQueue &wireOut) override
        {
            if (ssl_ == nullptr || state_ != mynet::transport::TransportState::STREAMING)
            {
                return std::unexpected(ERR::NOT_INITIALISED);
            }
            size_t offset = 0;
            while (offset < appIn.size())
            {
                const int wn = SSL_write(ssl_, appIn.data() + offset, static_cast<int>(appIn.size() - offset));
                if (wn > 0)
                {
                    offset += static_cast<size_t>(wn);
                    continue;
                }
                const int err = SSL_get_error(ssl_, wn);
                if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ)
                {
                    if (auto r = flushWbio(wireOut); !r)
                    {
                        return r;
                    }
                    continue;
                }
                state_ = mynet::transport::TransportState::FAILED;
                return std::unexpected(ERR::CONNECT_FAILED);
            }
            return flushWbio(wireOut);
        }
    };

} // namespace mynet::tls
