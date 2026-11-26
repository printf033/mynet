#pragma once

/**
 * @file transportStack.hpp
 * @brief TransportConfig 到 Handler::TransportPipeline 的统一装配器
 *
 * 收拢 Acceptor 与 Dialer 的重复传输栈装配逻辑：
 *   Line <-> TLS (可选) <-> WebSocket / gRPC (可选) <-> Proxy Protocol Handler
 */

#include "connection.hpp"
#include "grpc/grpc.hpp"
#include "tls/transport.hpp"
#include "websocket/websocket.hpp"
#include <memory>
#include <string>

namespace mynet::transport
{

    /**
     * @brief 为开启服务端 TLS 的 TransportConfig 预构建可跨连接共享的 OpenSSL SSL_CTX
     */
    [[nodiscard]] inline Result<SSL_CTX *> createSharedServerSslContext(const TransportConfig &cfg)
    {
        if (cfg.certFile.empty() || cfg.keyFile.empty())
        {
            return std::unexpected(ERR::SSL_CONFIG_FAILED);
        }
        SecurityConfig sec{};
        sec.alpnProtocols = cfg.alpnProtocols;
        sec.caFile = cfg.caFile;
        auto alpnList = mynet::detail::splitAlpnList(sec.alpnProtocols);
        return mynet::detail::createServerContext(
            cfg.certFile.c_str(), cfg.keyFile.c_str(), sec, alpnList.empty() ? nullptr : &alpnList,
            TlsProtocolType::StreamTcp);
    }

    /**
     * @brief 按 TransportConfig 为协议 Handler 统一装配外层至内层可叠加传输栈
     */
    [[nodiscard]] inline Result<> attachConfiguredTransport(Handler &handler, const TransportConfig &cfg,
                                                            bool isServer, SSL_CTX *sharedServerCtx = nullptr)
    {
        const bool useTls = cfg.enableTls || cfg.type == TransportType::TLS;
        if (useTls)
        {
            SecurityConfig sec{};
            sec.alpnProtocols = cfg.alpnProtocols;
            sec.caFile = cfg.caFile;

            if (isServer)
            {
                if (sharedServerCtx != nullptr)
                {
                    handler.addTransportLayer(mynet::tls::TlsTransport::fromServerContext(sharedServerCtx));
                }
                else
                {
                    if (cfg.certFile.empty() || cfg.keyFile.empty())
                    {
                        return std::unexpected(ERR::SSL_CONFIG_FAILED);
                    }
                    auto tlsRes =
                        mynet::tls::TlsTransport::createServer(cfg.certFile.c_str(), cfg.keyFile.c_str(), sec);
                    if (!tlsRes)
                    {
                        return std::unexpected(tlsRes.error());
                    }
                    handler.addTransportLayer(std::move(*tlsRes));
                }
            }
            else
            {
                std::string sni = !cfg.sni.empty() ? cfg.sni : cfg.host;
                auto tlsRes = mynet::tls::TlsTransport::createClient(std::move(sni), sec);
                if (!tlsRes)
                {
                    return std::unexpected(tlsRes.error());
                }
                handler.addTransportLayer(std::move(*tlsRes));
            }
        }

        if (cfg.type == TransportType::WEBSOCKET)
        {
            std::string wsHost = !cfg.host.empty() ? cfg.host : cfg.sni;
            std::string wsPath = cfg.path.empty() ? "/" : cfg.path;
            handler.addTransportLayer(
                std::make_unique<mynet::websocket::WebSocketSession>(isServer, std::move(wsPath), std::move(wsHost)));
        }
        else if (cfg.type == TransportType::GRPC)
        {
            std::string svc = !cfg.serviceName.empty()
                                  ? cfg.serviceName
                                  : ((!cfg.path.empty() && cfg.path != "/") ? cfg.path : std::string("GunService"));
            std::string authority = !cfg.host.empty() ? cfg.host : cfg.sni;
            handler.addTransportLayer(
                std::make_unique<mynet::grpc::GrpcSession>(isServer, std::move(svc), std::move(authority)));
        }

        return {};
    }

} // namespace mynet::transport
