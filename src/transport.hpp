#pragma once

/**
 * @file transport.hpp
 * @brief 通用传输层与可叠加管道抽象 (Universal Transport & Pipeline Abstraction)
 *
 * 支持 TCP、TLS、WebSocket (RFC 6455) 与 gRPC / Gun-lite (HTTP/2 流式封包) 的多态叠加拼装。
 */

#include "error.hpp"
#include "requestBuffer.hpp"
#include "responseQueue.hpp"
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mynet::transport
{

    /**
     * @brief 传输协议类型
     */
    enum class TransportType : uint8_t
    {
        TCP = 0,
        TLS = 1,
        WEBSOCKET = 2,
        GRPC = 3
    };

    [[nodiscard]] constexpr std::string_view toString(TransportType type) noexcept
    {
        switch (type)
        {
        case TransportType::TCP:
            return "tcp";
        case TransportType::TLS:
            return "tls";
        case TransportType::WEBSOCKET:
            return "websocket";
        case TransportType::GRPC:
            return "grpc";
        default:
            return "unknown";
        }
    }

    /**
     * @brief 传输通道状态机阶段
     */
    enum class TransportState : uint8_t
    {
        INITIAL = 0,
        HANDSHAKING = 1,
        STREAMING = 2,
        CLOSED = 3,
        FAILED = 4
    };

    /**
     * @brief 传输层统一配置参数
     */
    struct TransportConfig
    {
        TransportType type{TransportType::TCP};
        std::string path{"/"};               ///< WebSocket 路径或 gRPC service 名
        std::string host{""};                ///< HTTP Host / SNI 报头覆盖
        std::string serviceName{""};         ///< gRPC 专属 service 命名 (如 "TunService")
        uint32_t maxEarlyData{0};            ///< 0-RTT Early-Data 限制 (WebSocket / TLS 1.3)
        std::string earlyDataHeaderName{""}; ///< Early Data 携带 HTTP 请求头名 (如 "Sec-WebSocket-Protocol")
        bool enableTls{false};               ///< 是否在该传输链最外层启用 TLS
        std::string sni{""};                 ///< 客户端 SNI 主机名（空则回退 host）
        std::string alpnProtocols{""};       ///< TLS ALPN 协商列表（逗号分隔）
        std::string certFile{""};            ///< 服务端 TLS 证书路径
        std::string keyFile{""};             ///< 服务端 TLS 私钥路径
        std::string caFile{""};              ///< CA 根证书路径（可选）

        TransportConfig() = default;
    };

    /**
     * @brief 传输层协议状态与异步数据面封包抽象接口
     *
     * 所有传输层插件（TLS / WebSocket / gRPC 等）统一实现本契约，
     * 使得任意代理协议可零入侵、多层正交叠加以适配各种载体。
     */
    class ITransport
    {
    public:
        virtual ~ITransport() noexcept = default;

        [[nodiscard]] virtual TransportType type() const noexcept = 0;
        [[nodiscard]] virtual TransportState state() const noexcept = 0;
        [[nodiscard]] virtual bool isReady() const noexcept = 0;
        virtual void reset() noexcept = 0;

        [[nodiscard]] virtual bool isPassthrough() const noexcept { return false; }
        [[nodiscard]] virtual void *nativeSslHandle() const noexcept { return nullptr; }
        [[nodiscard]] virtual bool ktlsRxActive() const noexcept { return false; }
        [[nodiscard]] virtual bool ktlsTxActive() const noexcept { return false; }

        /**
         * @brief 客户端主动发起传输层握手时产出初始发送字节（例如 TLS ClientHello / HTTP Upgrade）
         */
        [[nodiscard]] virtual std::optional<std::string> startHandshake() { return std::nullopt; }

        /**
         * @brief 摄入来自下层/网络的原始字节：推进握手，将需回写的握手或控制帧推入 wireOut，将解包出的上层字节追加至 appOut
         */
        [[nodiscard]] virtual Result<> onWireInput(std::span<const uint8_t> wireIn, RequestBuffer &appOut,
                                                   ResponseQueue &wireOut)
        {
            (void)wireOut;
            if (!wireIn.empty())
            {
                return appOut.append(reinterpret_cast<const char *>(wireIn.data()), wireIn.size());
            }
            return {};
        }

        /**
         * @brief 包装来自上层的明文载荷为本传输层线格式，并推入 wireOut
         */
        [[nodiscard]] virtual Result<> onAppOutput(std::span<const uint8_t> appIn, ResponseQueue &wireOut)
        {
            if (!appIn.empty())
            {
                return wireOut.emplace(reinterpret_cast<const char *>(appIn.data()), appIn.size());
            }
            return {};
        }
    };

    /**
     * @brief 可组合的多层传输栈 (TransportPipeline)
     *
     * 层序约定：layers_[0] 最接近物理线缆（如 TLS），layers_.back() 最接近代理状态机（如 WebSocket / gRPC）。
     * - 入站方向：wireIn -> layers_[0] -> ... -> layers_[N-1] -> appOut
     * - 出站方向：appIn  -> layers_[N-1] -> ... -> layers_[0] -> wireOut
     * - 中间层自动产出的控制包/握手后续帧（如 PONG、TLS ServerHello/Finished）自动经由更外层封装后进入 wireOut。
     */
    class TransportPipeline
    {
    private:
        std::vector<std::unique_ptr<ITransport>> layers_{};
        RequestBuffer scratchA_{};
        RequestBuffer scratchB_{};
        ResponseQueue queueA_{};
        ResponseQueue queueB_{};
        bool queuesInit_{false};

        [[nodiscard]] Result<> ensureScratchQueues() noexcept
        {
            if (queuesInit_) [[likely]]
            {
                return {};
            }
            if (auto r1 = queueA_.init(128); !r1)
            {
                return r1;
            }
            if (auto r2 = queueB_.init(128); !r2)
            {
                return r2;
            }
            queuesInit_ = true;
            return {};
        }

    public:
        TransportPipeline() noexcept = default;
        ~TransportPipeline() noexcept = default;

        TransportPipeline(const TransportPipeline &) = delete;
        TransportPipeline &operator=(const TransportPipeline &) = delete;
        TransportPipeline(TransportPipeline &&) noexcept = default;
        TransportPipeline &operator=(TransportPipeline &&) noexcept = default;

        inline void addLayer(std::unique_ptr<ITransport> layer)
        {
            if (layer != nullptr)
            {
                layers_.push_back(std::move(layer));
            }
        }

        inline void clear() noexcept
        {
            layers_.clear();
            scratchA_.reset();
            scratchB_.reset();
            if (queuesInit_)
            {
                queueA_.reset();
                queueB_.reset();
            }
        }

        inline void reset() noexcept
        {
            for (auto &l : layers_)
            {
                if (l != nullptr)
                {
                    l->reset();
                }
            }
            scratchA_.reset();
            scratchB_.reset();
            if (queuesInit_)
            {
                queueA_.reset();
                queueB_.reset();
            }
        }

        [[nodiscard]] inline bool empty() const noexcept { return layers_.empty(); }
        [[nodiscard]] inline size_t layerCount() const noexcept { return layers_.size(); }

        [[nodiscard]] inline bool isPassthrough() const noexcept
        {
            for (const auto &l : layers_)
            {
                if (l != nullptr && !l->isPassthrough())
                {
                    return false;
                }
            }
            return true;
        }

        [[nodiscard]] inline bool isReady() const noexcept
        {
            for (const auto &l : layers_)
            {
                if (l != nullptr && !l->isReady())
                {
                    return false;
                }
            }
            return true;
        }

        [[nodiscard]] inline bool hasFailed() const noexcept
        {
            for (const auto &l : layers_)
            {
                if (l != nullptr && l->state() == TransportState::FAILED)
                {
                    return true;
                }
            }
            return false;
        }

        [[nodiscard]] inline void *nativeSslHandle() const noexcept
        {
            for (const auto &l : layers_)
            {
                if (l != nullptr)
                {
                    if (void *ssl = l->nativeSslHandle(); ssl != nullptr)
                    {
                        return ssl;
                    }
                }
            }
            return nullptr;
        }

        [[nodiscard]] inline bool ktlsRxActive() const noexcept
        {
            for (const auto &l : layers_)
            {
                if (l != nullptr && l->ktlsRxActive())
                {
                    return true;
                }
            }
            return false;
        }

        [[nodiscard]] inline bool ktlsTxActive() const noexcept
        {
            for (const auto &l : layers_)
            {
                if (l != nullptr && l->ktlsTxActive())
                {
                    return true;
                }
            }
            return false;
        }

        [[nodiscard]] Result<> startHandshake(ResponseQueue &wireOut) noexcept
        {
            for (size_t i = 0; i < layers_.size(); ++i)
            {
                auto &layer = layers_[i];
                if (layer == nullptr)
                {
                    continue;
                }
                if (layer->state() == TransportState::INITIAL)
                {
                    auto hs = layer->startHandshake();
                    if (hs.has_value() && !hs->empty())
                    {
                        std::span<const uint8_t> sp(reinterpret_cast<const uint8_t *>(hs->data()), hs->size());
                        if (auto r = pushDownFromLayer(i, sp, wireOut); !r)
                        {
                            return r;
                        }
                    }
                }
                if (!layer->isReady())
                {
                    break;
                }
            }
            return {};
        }

        [[nodiscard]] Result<> processInbound(RequestBuffer &wireRx, RequestBuffer &appOut,
                                              ResponseQueue &wireOut) noexcept
        {
            if (layers_.empty())
            {
                if (wireRx.readableBytes() > 0)
                {
                    auto r = appOut.append(wireRx.readableBegin(), wireRx.readableBytes());
                    wireRx.retrieve(wireRx.readableBytes());
                    return r;
                }
                return {};
            }

            if (auto r = ensureScratchQueues(); !r)
            {
                return r;
            }

            scratchA_.reset();
            scratchB_.reset();
            ResponseQueue localReplies;
            if (auto r = localReplies.init(64); !r)
            {
                return r;
            }

            const char *wirePtr = wireRx.readableBegin();
            const size_t wireLen = wireRx.readableBytes();

            for (size_t i = 0; i < layers_.size(); ++i)
            {
                auto &layer = layers_[i];
                if (layer == nullptr)
                {
                    continue;
                }

                if (i > 0 && layers_[i - 1]->isReady() && layer->state() == TransportState::INITIAL)
                {
                    auto hs = layer->startHandshake();
                    if (hs.has_value() && !hs->empty())
                    {
                        std::span<const uint8_t> hsp(reinterpret_cast<const uint8_t *>(hs->data()), hs->size());
                        if (auto r = pushDownFromLayer(i, hsp, wireOut); !r)
                        {
                            return r;
                        }
                    }
                }

                std::span<const uint8_t> inSpan;
                if (i == 0)
                {
                    inSpan = std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(wirePtr), wireLen);
                }
                else
                {
                    inSpan = std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(scratchA_.readableBegin()),
                                                      scratchA_.readableBytes());
                }

                localReplies.reset();
                scratchB_.reset();
                if (!inSpan.empty())
                {
                    if (auto r = layer->onWireInput(inSpan, scratchB_, localReplies); !r)
                    {
                        if (i == 0 && wireLen > 0)
                        {
                            wireRx.retrieve(wireLen);
                        }
                        return r;
                    }
                    if (i == 0 && wireLen > 0)
                    {
                        wireRx.retrieve(wireLen);
                    }
                }

                while (!localReplies.empty())
                {
                    auto pkt = std::move(localReplies.front());
                    localReplies.pop();
                    if (!pkt.bytes.empty())
                    {
                        std::span<const uint8_t> rsp(reinterpret_cast<const uint8_t *>(pkt.bytes.data()),
                                                     pkt.bytes.size());
                        if (auto r = pushDownFromLayer(i, rsp, wireOut); !r)
                        {
                            return r;
                        }
                    }
                }

                if (layer->state() == TransportState::FAILED)
                {
                    return std::unexpected(ERR::CONNECT_FAILED);
                }

                scratchA_.swap(scratchB_);
                scratchB_.reset();

                if (layer->isReady() && (i + 1) < layers_.size() &&
                    layers_[i + 1] != nullptr && layers_[i + 1]->state() == TransportState::INITIAL)
                {
                    auto nextHs = layers_[i + 1]->startHandshake();
                    if (nextHs.has_value() && !nextHs->empty())
                    {
                        std::span<const uint8_t> hsp(reinterpret_cast<const uint8_t *>(nextHs->data()),
                                                     nextHs->size());
                        if (auto r = pushDownFromLayer(i + 1, hsp, wireOut); !r)
                        {
                            return r;
                        }
                    }
                }
            }

            if (scratchA_.readableBytes() > 0)
            {
                return appOut.append(scratchA_.readableBegin(), scratchA_.readableBytes());
            }
            return {};
        }

        [[nodiscard]] Result<> processOutbound(std::span<const uint8_t> appIn, ResponseQueue &wireOut) noexcept
        {
            if (appIn.empty())
            {
                return {};
            }
            return pushDownFromLayer(layers_.size(), appIn, wireOut);
        }

    private:
        [[nodiscard]] Result<> pushDownFromLayer(size_t upperExclusive, std::span<const uint8_t> payload,
                                                 ResponseQueue &wireOut) noexcept
        {
            if (payload.empty())
            {
                return {};
            }
            if (upperExclusive == 0)
            {
                return wireOut.emplace(reinterpret_cast<const char *>(payload.data()), payload.size());
            }
            if (upperExclusive == 1)
            {
                return layers_[0]->onAppOutput(payload, wireOut);
            }

            if (auto r = ensureScratchQueues(); !r)
            {
                return r;
            }
            queueA_.reset();
            queueB_.reset();

            if (auto r = layers_[upperExclusive - 1]->onAppOutput(payload, queueA_); !r)
            {
                return r;
            }

            ResponseQueue *src = &queueA_;
            ResponseQueue *dst = &queueB_;
            for (size_t idx = upperExclusive - 1; idx-- > 0;)
            {
                ResponseQueue &target = (idx == 0) ? wireOut : *dst;
                while (!src->empty())
                {
                    auto pkt = std::move(src->front());
                    src->pop();
                    if (!pkt.bytes.empty())
                    {
                        std::span<const uint8_t> sp(reinterpret_cast<const uint8_t *>(pkt.bytes.data()),
                                                    pkt.bytes.size());
                        if (auto r = layers_[idx]->onAppOutput(sp, target); !r)
                        {
                            return r;
                        }
                    }
                }
                if (idx > 0)
                {
                    std::swap(src, dst);
                    dst->reset();
                }
            }
            return {};
        }
    };

} // namespace mynet::transport
