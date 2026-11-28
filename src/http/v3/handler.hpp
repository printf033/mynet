#pragma once

/**
 * @file handler/http/v3/handler.hpp
 * @brief RFC 9114 HTTP/3 统一协议处理器实现（基于 QUIC/UDP 数据报与逻辑流多路复用）。
 *
 * 架构参考 HTTP/2 模块成熟设计，全面基于 mynet 基础库基础设施：
 * 1. 纯粹数据报多路复用：纯粹继承 HandlerDatagram，专职负责 UDP 数据报、QUIC 报文分发与双向/单向逻辑流；
 * 2. 泛型逻辑流对象池：支持 HandlerHttp3<StreamHandler>，每条独立逻辑流绑定一个独立的流处理器，零动态堆分配复用；
 * 3. 定容平坦流表：复用 mux::StreamTable 开放寻址平坦哈希表算法，消除 std::unordered_map 分配；
 * 4. 零拷贝分帧与解码：基于 RequestBuffer 与 FrameView (std::string_view) 切片分帧，QPACK 零拷贝解压缩；
 * 5. 统一生命周期钩子：提供与 HTTP/2 对齐的 onStreamOpen / onStreamHeadersDecoded / onStreamData / onStreamEnd /
 * onStreamClose 钩子。
 */

#include "../../quic/quic.hpp"
#include "../../quic/varint.hpp"
#include "../../streamTable.hpp"
#include "../common.hpp"
#include "connection.hpp"
#include "frame.hpp"
#include "objectPool.hpp"
#include "qpack.hpp"
#include <algorithm>
#include <cstdint>
#include <limits>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace mynet
{
    namespace http::v3
    {
        using namespace mynet::quic;

        /**
         * @brief RFC 9114 Section 6.2 单向流类型标识符
         */
        namespace streamtype
        {
            inline constexpr uint64_t kControl = 0x00;
            inline constexpr uint64_t kPush = 0x01;
            inline constexpr uint64_t kQpackEncoder = 0x02;
            inline constexpr uint64_t kQpackDecoder = 0x03;
        } // namespace streamtype

        /**
         * @brief 流生命周期状态枚举
         */
        enum class STREAM_STATE : uint8_t
        {
            IDLE = 0,
            OPEN = 1,
            HALF_CLOSED_REMOTE = 2,
            HALF_CLOSED_LOCAL = 3,
            CLOSED = 4
        };

        /**
         * @brief 判断流是否为单向流 (直接复用 quic::isUnidirectionalStream)
         */
        using quic::isClientBidirectionalStream;
        using quic::isUnidirectionalStream;

        /**
         * @brief HTTP/3 单条逻辑流上下文槽位
         */
        template <typename StreamHandler = Handler>
        struct StreamSlot
        {
            StreamHandler *handler = nullptr;
            uint64_t streamId = 0;
            STREAM_STATE state = STREAM_STATE::IDLE;
            bool isUnidirectional = false;
            bool uniTypeIdentified = false;
            uint64_t uniType = 0;
            RequestBuffer inBuffer{};
            bool finReceived = false;
            bool headersComplete = false;
            bool headersReceived = false;
            bool localEnded = false;
            std::vector<Header> requestHeaders{};
            std::string requestBody{};
            std::string pendingResponse{};
            uint32_t pendingOffset = 0;

            StreamSlot() noexcept = default;
            StreamSlot(const StreamSlot &) = delete;
            StreamSlot &operator=(const StreamSlot &) = delete;
            StreamSlot(StreamSlot &&) noexcept = default;
            StreamSlot &operator=(StreamSlot &&) noexcept = default;

            void reset() noexcept
            {
                handler = nullptr;
                streamId = 0;
                state = STREAM_STATE::IDLE;
                isUnidirectional = false;
                uniTypeIdentified = false;
                uniType = 0;
                inBuffer.reset();
                finReceived = false;
                headersComplete = false;
                headersReceived = false;
                localEnded = false;
                requestHeaders.clear();
                requestBody.clear();
                pendingResponse.clear();
                pendingOffset = 0;
            }
        };

        /**
         * @brief HTTP/3 流上下文定容平坦哈希表管理器（基于公共 mux::StreamTable 算法）
         */
        template <typename Slot = StreamSlot<Handler>>
        class StreamTable
        {
        public:
            static constexpr uint64_t kNilStreamId = std::numeric_limits<uint64_t>::max();

            explicit StreamTable(size_t maxStreams = 128) noexcept
                : maxStreams_(maxStreams == 0 ? 1 : maxStreams)
            {
                [[maybe_unused]] auto _ = streams_.init(maxStreams_);
            }

            ~StreamTable() noexcept = default;
            StreamTable(const StreamTable &) = delete;
            StreamTable &operator=(const StreamTable &) = delete;
            StreamTable(StreamTable &&) noexcept = default;
            StreamTable &operator=(StreamTable &&) noexcept = default;

            void setMaxStreams(size_t maxStreams) noexcept
            {
                maxStreams_ = maxStreams == 0 ? 1 : maxStreams;
                if (!streams_.ready() || streams_.size() == 0)
                {
                    [[maybe_unused]] auto _ = streams_.init(maxStreams_);
                }
            }

            [[nodiscard]] size_t maxStreams() const noexcept { return maxStreams_; }
            [[nodiscard]] size_t size() const noexcept { return streams_.size(); }
            [[nodiscard]] size_t capacity() const noexcept { return streams_.capacity(); }
            [[nodiscard]] bool empty() const noexcept { return streams_.size() == 0; }
            [[nodiscard]] bool ready() const noexcept { return streams_.ready(); }

            template <typename F>
            void clear(F &&fn) noexcept
            {
                streams_.clear(std::forward<F>(fn));
            }

            void reset() noexcept
            {
                streams_.clear([]([[maybe_unused]] uint64_t id, Slot &slot) { slot.reset(); });
            }

            [[nodiscard]] Slot *getOrCreate(uint64_t streamId)
            {
                if (!streams_.ready()) [[unlikely]]
                {
                    if (auto res = streams_.init(maxStreams_); !res) [[unlikely]]
                    {
                        return nullptr;
                    }
                }
                Slot *slot = streams_.find(streamId);
                if (slot != nullptr)
                {
                    return slot;
                }
                if (streams_.size() >= maxStreams_) [[unlikely]]
                {
                    return nullptr;
                }
                slot = streams_.open(streamId);
                if (slot != nullptr)
                {
                    slot->streamId = streamId;
                    slot->state = STREAM_STATE::OPEN;
                    slot->isUnidirectional = isUnidirectionalStream(streamId);
                }
                return slot;
            }

            [[nodiscard]] Slot *find(uint64_t streamId) noexcept { return streams_.find(streamId); }
            [[nodiscard]] const Slot *find(uint64_t streamId) const noexcept
            {
                return const_cast<StreamTable *>(this)->find(streamId);
            }

            void close(uint64_t streamId) noexcept { streams_.erase(streamId); }

            [[nodiscard]] const uint64_t &keyAt(size_t i) const noexcept { return streams_.keyAt(i); }
            [[nodiscard]] Slot *slotAt(size_t i) noexcept { return streams_.slotAt(i); }
            [[nodiscard]] const Slot *slotAt(size_t i) const noexcept { return streams_.slotAt(i); }

        private:
            size_t maxStreams_ = 128;
            mux::StreamTable<Slot, uint64_t, kNilStreamId> streams_{};
        };

        /**
         * @class HandlerHttp3
         * @brief RFC 9114 HTTP/3 极速编解码与多路复用协议处理器主模板
         *
         * 架构特性：
         * 1. 纯粹数据报多路复用：纯粹继承 HandlerDatagram，专职负责 UDP 数据报、QUIC 报文分发与双向/单向逻辑流；
         * 2. 泛型逻辑流对象池：支持
         * HandlerHttp3<StreamHandler>，每条独立逻辑流绑定一个独立的流处理器，零动态堆分配复用；
         * 3. 定容平坦流表：复用 mux::StreamTable 开放寻址平坦哈希表算法，消除 std::unordered_map 分配；
         * 4. 零拷贝分帧与解码：基于 RequestBuffer 与 FrameView (std::string_view) 切片分帧，QPACK 零拷贝解压缩；
         * 5. 统一生命周期钩子：提供与 HTTP/2 对齐的 onStreamOpen / onStreamHeadersDecoded / onStreamData / onStreamEnd
         * / onStreamClose 钩子。
         *
         * @tparam StreamHandler 每条独立逻辑流所绑定的协议处理器类型，默认复用 HandlerConnection。
         */
        template <typename StreamHandler = Handler>
            requires MandatoryMethodConnection<StreamHandler>
        class HandlerHttp3 : public Handler
        {
        public:
            static constexpr TransportType transport = TransportType::UDP;
            using Stream = StreamHandler;
            using StreamSlotType = http::v3::StreamSlot<StreamHandler>;
            using StreamTableType = http::v3::StreamTable<StreamSlotType>;

            struct SessionKey
            {
                uint32_t addr = 0;
                uint16_t port = 0;
                http::v3::ConnectionId dcid{};

                bool operator==(const SessionKey &o) const noexcept
                {
                    return addr == o.addr && port == o.port && dcid == o.dcid;
                }
            };

            struct SessionKeyHash
            {
                size_t operator()(const SessionKey &k) const noexcept
                {
                    size_t h = static_cast<size_t>(k.addr) ^ (static_cast<size_t>(k.port) << 16);
                    for (size_t i = 0; i < k.dcid.length; ++i)
                    {
                        h = (h * 131) ^ k.dcid.data[i];
                    }
                    return h;
                }
            };

            struct QuicSession
            {
                http::v3::ConnectionId dcid{};
                sockaddr_in peer{};
                StreamTableType streamTable;
                http::v3::FrameDecoder frameDecoder{};
                uint32_t nextPacketNumber = 1;
                quic::AntiAmplificationGuard antiAmplification{};
                quic::AckTracker ackTracker{};
                quic::RttEstimator rttEstimator{};
                size_t &bytesReceived = antiAmplification.bytesReceived;
                size_t &bytesSent = antiAmplification.bytesSent;
                bool &addressValidated = antiAmplification.addressValidated;

                explicit QuicSession(size_t maxStreams = 128)
                    : streamTable(maxStreams)
                {
                }
            };

            explicit HandlerHttp3(size_t maxStreams = 128, const DatagramConfig &config = getDatagramConfig()) noexcept
                : Handler(config),
                  maxStreams_(maxStreams == 0 ? 1 : maxStreams),
                  streamTable_(maxStreams_ == 0 ? 1 : maxStreams_)
            {
                ensureStreamPool();
            }

            ~HandlerHttp3() noexcept override { clearAllStreams(); }

            HandlerHttp3(const HandlerHttp3 &) = delete; // an http3 handler owns socket, streams and parser state
            HandlerHttp3 &
            operator=(const HandlerHttp3 &) = delete;          // an http3 handler owns socket, streams and parser state
            HandlerHttp3(HandlerHttp3 &&) = delete;            // an http3 handler owns socket, streams and parser state
            HandlerHttp3 &operator=(HandlerHttp3 &&) = delete; // an http3 handler owns socket, streams and parser state

            void reset() noexcept override
            {
                Handler::reset();
                clearAllStreams();
                sessions_.clear();
                ensureStreamPool();
                nextPacketNumber_ = 1;
                controlStreamSent_ = false;
                peerSettings_ = http::v3::Settings{};
            }

            void onMessageComplete() noexcept override { Handler::onMessageComplete(); }

            void onParseError(const char *reason) noexcept override { Handler::onParseError(reason); }

            [[nodiscard]] const http::v3::Settings &localSettings() const noexcept { return localSettings_; }
            [[nodiscard]] const http::v3::Settings &peerSettings() const noexcept { return peerSettings_; }

            inline void setMaxConcurrentStreams(size_t n)
            {
                maxStreams_ = n == 0 ? 1 : n;
                streamTable_.setMaxStreams(maxStreams_);
                if (streamPool_.capacity() == 0)
                {
                    ensureStreamPool();
                }
            }

            [[nodiscard]] inline size_t maxConcurrentStreams() const noexcept { return maxStreams_; }
            [[nodiscard]] inline size_t openStreams() const noexcept { return activeStreams(); }
            [[nodiscard]] inline size_t streamPoolCapacity() const noexcept { return streamPool_.capacity(); }

            [[nodiscard]] inline StreamHandler *streamHandler(uint64_t streamId) noexcept
            {
                auto *slot = streamTable_.find(streamId);
                return (slot != nullptr) ? slot->handler : nullptr;
            }

            [[nodiscard]] inline const StreamHandler *streamHandler(uint64_t streamId) const noexcept
            {
                const auto *slot = streamTable_.find(streamId);
                return (slot != nullptr) ? slot->handler : nullptr;
            }

            [[nodiscard]] inline StreamSlotType *stream(uint64_t streamId) noexcept
            {
                return streamTable_.find(streamId);
            }

            [[nodiscard]] inline const StreamSlotType *stream(uint64_t streamId) const noexcept
            {
                return streamTable_.find(streamId);
            }

            [[nodiscard]] size_t activeStreams() const noexcept
            {
                size_t total = streamTable_.size();
                for (const auto &[_, sess] : sessions_)
                {
                    total += sess->streamTable.size();
                }
                return total;
            }

            [[nodiscard]] size_t activeSessions() const noexcept { return sessions_.size(); }

            void validateAddress(const sockaddr_in &peer, const http::v3::ConnectionId &dcid = {}) noexcept
            {
                for (auto &[k, sess] : sessions_)
                {
                    if (k.addr == peer.sin_addr.s_addr && k.port == peer.sin_port)
                    {
                        if (dcid.length == 0 || k.dcid == dcid)
                        {
                            sess->addressValidated = true;
                        }
                    }
                }
            }

            [[nodiscard]] bool isAddressValidated(const sockaddr_in &peer,
                                                  const http::v3::ConnectionId &dcid = {}) const noexcept
            {
                for (const auto &[k, sess] : sessions_)
                {
                    if (k.addr == peer.sin_addr.s_addr && k.port == peer.sin_port)
                    {
                        if (dcid.length == 0 || k.dcid == dcid)
                        {
                            return sess->addressValidated;
                        }
                    }
                }
                return false;
            }

            // ---- 协议前端可重写的钩子函数（对齐 HTTP/2 设计） ----

            virtual void onStreamOpen([[maybe_unused]] uint64_t id) noexcept {}

            virtual void onStreamHeaders([[maybe_unused]] uint64_t id, [[maybe_unused]] std::string_view block) noexcept
            {
            }

            virtual void onStreamHeadersDecoded([[maybe_unused]] uint64_t id,
                                                [[maybe_unused]] const std::vector<http::v3::Header> &headers) noexcept
            {
            }

            virtual void onStreamTrailers([[maybe_unused]] uint64_t id,
                                          [[maybe_unused]] const std::vector<http::v3::Header> &headers) noexcept
            {
            }

            virtual void onStreamData([[maybe_unused]] uint64_t id, [[maybe_unused]] std::string_view bytes) noexcept {}

            virtual void onStreamEnd([[maybe_unused]] uint64_t id) noexcept {}

            virtual void onStreamClose([[maybe_unused]] uint64_t id) noexcept {}

            virtual void onProtocolError([[maybe_unused]] http::v3::H3_ERROR code,
                                         [[maybe_unused]] std::string_view why) noexcept
            {
            }

            /**
             * @brief 业务请求处理钩子（可由派生类定制覆盖，保持 100% 现有用法兼容）
             *
             * @param streamId 逻辑流 ID
             * @param headers 请求首部列表
             * @param body 请求体数据
             * @param responseBody 待填充的响应体内容（默认为回显或问候语）
             */
            virtual void onRequest([[maybe_unused]] uint64_t streamId,
                                   [[maybe_unused]] const std::vector<http::v3::Header> &headers, std::string_view body,
                                   std::string &responseBody)
            {
                if (!body.empty())
                {
                    responseBody.assign(body);
                }
                else
                {
                    responseBody.assign("Hello from mynet HTTP/3!");
                }
            }

            /**
             * @brief UDP 数据报处理逻辑 (RFC 9000 QUIC + RFC 9114 HTTP/3)
             */
            void onDatagram(const sockaddr_in &peer, const char *data, size_t n) noexcept override
            {
                if (data == nullptr || n == 0) [[unlikely]]
                {
                    return;
                }

                ensureStreamPool();
                std::string_view packet(data, n);

                // 尝试作为 QUIC 短首部报文解析
                auto shpRes = http::v3::parseShortHeaderPacket(packet, 8);
                if (shpRes)
                {
                    auto &shp = *shpRes;
                    QuicSession *session = getOrCreateSession(peer, shp.dcid);
                    if (!session)
                    {
                        return;
                    }
                    session->antiAmplification.recordReceived(n);
                    session->ackTracker.onPacketReceived(shp.packetNumber, true);
                    handleQuicPacket(peer, shp, *session);
                    return;
                }

                // 备选路径：直接承载裸 HTTP/3 分帧的数据报（轻量/测试回环）
                QuicSession *session = getOrCreateSession(peer, http::v3::ConnectionId{});
                if (!session)
                {
                    return;
                }
                session->bytesReceived += n;

                RequestBuffer directBuf;
                [[maybe_unused]] auto _ = directBuf.append(data, n);
                while (true)
                {
                    auto frameRes = session->frameDecoder.nextView(directBuf);
                    if (!frameRes || !frameRes->has_value())
                    {
                        break;
                    }
                    auto &frame = **frameRes;
                    auto slot = session->streamTable.getOrCreate(0);
                    if (!slot)
                    {
                        continue;
                    }
                    if (slot->handler == nullptr)
                    {
                        slot->handler = streamPool_.acquire();
                        onStreamOpen(0);
                    }

                    if (frame.type == std::to_underlying(http::v3::FRAME_TYPE::HEADERS))
                    {
                        onStreamHeaders(0, frame.payload);
                        auto hRes = http::v3::decodeHeaders(frame.payload);
                        if (hRes)
                        {
                            slot->requestHeaders = std::move(*hRes);
                            slot->headersComplete = true;
                            slot->headersReceived = true;
                            onStreamHeadersDecoded(0, slot->requestHeaders);
                        }
                    }
                    else if (frame.type == std::to_underlying(http::v3::FRAME_TYPE::DATA))
                    {
                        onStreamData(0, frame.payload);
                        if (slot->handler != nullptr)
                        {
                            [[maybe_unused]] auto _a =
                                slot->handler->appendRequest(frame.payload.data(), frame.payload.size());
                            slot->handler->handle();
                        }
                        if (slot->requestBody.size() + frame.payload.size() <= maxRequestBodyBytes())
                        {
                            slot->requestBody.append(frame.payload);
                        }
                    }
                }

                auto slot = session->streamTable.find(0);
                if (slot && slot->headersComplete)
                {
                    onStreamEnd(0);
                    std::string body = slot->requestBody;
                    if (body.empty() && slot->handler != nullptr && slot->handler->requestBytes() > 0)
                    {
                        body.assign(slot->handler->requestBegin(), slot->handler->requestBytes());
                    }
                    std::string responseBody;
                    onRequest(0, slot->requestHeaders, body, responseBody);

                    std::vector<http::v3::Header> finalHeaders;
                    finalHeaders.reserve(3);
                    finalHeaders.push_back({":status", "200"});
                    finalHeaders.push_back({"server", "mynet-http3"});
                    finalHeaders.push_back({"content-type", "text/plain; charset=utf-8"});

                    std::string headerPayload;
                    http::v3::encodeHeaders(headerPayload, finalHeaders);

                    std::string frameBytes;
                    http::v3::appendFrame(frameBytes, std::to_underlying(http::v3::FRAME_TYPE::HEADERS), headerPayload);
                    if (!responseBody.empty())
                    {
                        http::v3::appendFrame(frameBytes, std::to_underlying(http::v3::FRAME_TYPE::DATA), responseBody);
                    }

                    // RFC 9000 Section 8.1 抗反射放大防护：复用 quic::AntiAmplificationGuard
                    if (!session->antiAmplification.canSend(frameBytes.size()))
                    {
                        LOG_WARN(
                            "HandlerHttp3: direct fallback anti-amplification limit exceeded (received {}, sent {})",
                            session->antiAmplification.bytesReceived,
                            session->antiAmplification.bytesSent + frameBytes.size());
                    }
                    else
                    {
                        session->antiAmplification.recordSent(frameBytes.size());
                        this->sendTo(peer, std::move(frameBytes));
                    }
                    if (slot->handler != nullptr)
                    {
                        streamPool_.release(slot->handler);
                        slot->handler = nullptr;
                    }
                    onStreamClose(0);
                    session->streamTable.close(0);
                }
            }

            /**
             * @brief 构造 QUIC 报文并推入 UDP 回复队列发送给指定对端（基于对应会话）
             */
            void sendQuicReply(const sockaddr_in &peer, QuicSession &session, uint64_t streamId, int statusCode,
                               std::span<const http::v3::Header> headers = {}, std::string_view body = {})
            {
                std::vector<http::v3::Header> finalHeaders;
                finalHeaders.reserve(headers.size() + 3);
                finalHeaders.push_back({":status", std::to_string(statusCode)});
                finalHeaders.push_back({"server", "mynet-http3"});
                finalHeaders.push_back({"content-type", "text/plain; charset=utf-8"});
                for (const auto &h : headers)
                {
                    finalHeaders.push_back(h);
                }

                std::string headerPayload;
                http::v3::encodeHeaders(headerPayload, finalHeaders);

                std::string h3Frames;
                http::v3::appendFrame(h3Frames, std::to_underlying(http::v3::FRAME_TYPE::HEADERS), headerPayload);
                if (!body.empty())
                {
                    http::v3::appendFrame(h3Frames, std::to_underlying(http::v3::FRAME_TYPE::DATA), body);
                }

                // 打包进 QUIC STREAM 帧 (FIN 标记表示响应完成)
                std::string quicPayload;
                http::v3::appendStreamFrame(quicPayload, streamId, 0, h3Frames, true);

                // 封装为 QUIC 1-RTT 短首部报文
                std::string packet;
                http::v3::appendShortHeaderPacket(packet, session.dcid, session.nextPacketNumber++, quicPayload);

                // RFC 9000 Section 8.1: 复用 quic::AntiAmplificationGuard
                if (!session.antiAmplification.canSend(packet.size()))
                {
                    LOG_WARN(
                        "HandlerHttp3: anti-amplification limit exceeded for peer {} (received={}, sent={}, packet={})",
                        datagramPeerText(peer), session.antiAmplification.bytesReceived,
                        session.antiAmplification.bytesSent, packet.size());
                    return;
                }

                session.antiAmplification.recordSent(packet.size());
                this->sendTo(peer, std::move(packet));
            }

            void sendQuicReply(const sockaddr_in &peer, const http::v3::ConnectionId &dcid, uint64_t streamId,
                               int statusCode, std::span<const http::v3::Header> headers = {},
                               std::string_view body = {})
            {
                QuicSession *sess = getOrCreateSession(peer, dcid);
                if (sess != nullptr)
                {
                    sendQuicReply(peer, *sess, streamId, statusCode, headers, body);
                }
            }

            inline void forwardDatagram(const sockaddr_in &upstream, const char *data, size_t n)
            {
                this->forwardTo(upstream, data, n);
            }

            inline void broadcastDatagram(const std::vector<sockaddr_in> &targets, const char *data, size_t n)
            {
                this->broadcastTo(targets, data, n);
            }

            QuicSession *getOrCreateSession(const sockaddr_in &peer, const http::v3::ConnectionId &dcid)
            {
                SessionKey key{peer.sin_addr.s_addr, peer.sin_port, dcid};
                auto it = sessions_.find(key);
                if (it != sessions_.end())
                {
                    return it->second.get();
                }
                if (sessions_.size() >= maxSessions_) [[unlikely]]
                {
                    for (auto sIt = sessions_.begin(); sIt != sessions_.end();)
                    {
                        if (sIt->second->streamTable.empty())
                        {
                            sIt = sessions_.erase(sIt);
                        }
                        else
                        {
                            ++sIt;
                        }
                    }
                    if (sessions_.size() >= maxSessions_)
                    {
                        LOG_WARN("HandlerHttp3: max sessions limit reached ({})", maxSessions_);
                        return nullptr;
                    }
                }
                auto sess = std::make_unique<QuicSession>(maxStreams_);
                sess->dcid = dcid;
                sess->peer = peer;
                auto *ptr = sess.get();
                sessions_.emplace(key, std::move(sess));
                return ptr;
            }

        private:
            void handleQuicPacket(const sockaddr_in &peer, const http::v3::ShortHeaderPacket &shp, QuicSession &session)
            {
                const auto *ptr = reinterpret_cast<const uint8_t *>(shp.payload.data());
                size_t rem = shp.payload.size();

                while (rem > 0)
                {
                    const uint8_t frameType = *ptr;
                    if (frameType >= 0x08 && frameType <= 0x0f)
                    {
                        // QUIC STREAM 帧
                        auto sfRes = http::v3::parseStreamFrame(ptr, rem);
                        if (!sfRes)
                        {
                            break;
                        }

                        auto &sf = *sfRes;
                        // RFC 9000 Section 2.1: 客户端发起的流编号必须为偶数 (复用 quic::isServerInitiatedStream)
                        if (quic::isServerInitiatedStream(sf.streamId)) [[unlikely]]
                        {
                            LOG_WARN("HandlerHttp3: peer sent stream {} which is server-initiated", sf.streamId);
                            continue;
                        }

                        auto slot = session.streamTable.getOrCreate(sf.streamId);
                        if (!slot)
                        {
                            continue;
                        }
                        if (slot->handler == nullptr)
                        {
                            slot->handler = streamPool_.acquire();
                            onStreamOpen(sf.streamId);
                        }

                        if (slot->inBuffer.readableBytes() + sf.data.size() > maxStreamBufferBytes()) [[unlikely]]
                        {
                            LOG_WARN("HandlerHttp3: stream {} buffer exceeded maximum limit", sf.streamId);
                            if (slot->handler != nullptr)
                            {
                                streamPool_.release(slot->handler);
                                slot->handler = nullptr;
                            }
                            session.streamTable.close(sf.streamId);
                            continue;
                        }

                        [[maybe_unused]] auto _ = slot->inBuffer.append(sf.data.data(), sf.data.size());
                        if (sf.fin)
                        {
                            slot->finReceived = true;
                        }

                        // 从该会话专属流输入缓冲区中零拷贝解码 HTTP/3 帧
                        while (true)
                        {
                            auto h3Res = session.frameDecoder.nextView(slot->inBuffer);
                            if (!h3Res || !h3Res->has_value())
                            {
                                break;
                            }
                            auto &h3Frame = **h3Res;
                            if (h3Frame.type == std::to_underlying(http::v3::FRAME_TYPE::HEADERS))
                            {
                                onStreamHeaders(sf.streamId, h3Frame.payload);
                                auto hRes = http::v3::decodeHeaders(h3Frame.payload);
                                if (hRes)
                                {
                                    slot->requestHeaders = std::move(*hRes);
                                    slot->headersComplete = true;
                                    slot->headersReceived = true;
                                    onStreamHeadersDecoded(sf.streamId, slot->requestHeaders);
                                }
                            }
                            else if (h3Frame.type == std::to_underlying(http::v3::FRAME_TYPE::DATA))
                            {
                                onStreamData(sf.streamId, h3Frame.payload);
                                if (slot->handler != nullptr)
                                {
                                    [[maybe_unused]] auto _a =
                                        slot->handler->appendRequest(h3Frame.payload.data(), h3Frame.payload.size());
                                    slot->handler->handle();
                                }
                                if (slot->requestBody.size() + h3Frame.payload.size() <= maxRequestBodyBytes())
                                {
                                    slot->requestBody.append(h3Frame.payload);
                                }
                            }
                        }

                        // 当收到 FIN 时表示请求流结束，构造 QUIC 回复并关闭该流
                        if (slot->finReceived)
                        {
                            onStreamEnd(sf.streamId);
                            std::string body = slot->requestBody;
                            if (body.empty() && slot->handler != nullptr && slot->handler->requestBytes() > 0)
                            {
                                body.assign(slot->handler->requestBegin(), slot->handler->requestBytes());
                            }
                            std::string responseBody;
                            onRequest(sf.streamId, slot->requestHeaders, body, responseBody);
                            sendQuicReply(peer, session, sf.streamId, 200, {}, responseBody);
                            if (slot->handler != nullptr)
                            {
                                streamPool_.release(slot->handler);
                                slot->handler = nullptr;
                            }
                            onStreamClose(sf.streamId);
                            session.streamTable.close(sf.streamId);
                        }
                    }
                    else if (!quic::skipFrame(ptr, rem))
                    {
                        // 未知或非完整帧类型，中止解析
                        break;
                    }
                }
            }

            inline void ensureStreamPool()
            {
                if (streamPool_.capacity() == 0)
                {
                    if (auto poolRes = streamPool_.init(maxStreams_); !poolRes) [[unlikely]]
                    {
                        LOG_ERROR("HandlerHttp3::ensureStreamPool: initialising stream pool ({} slots) failed",
                                  maxStreams_);
                    }
                }
                if (!streamTable_.ready())
                {
                    streamTable_.setMaxStreams(maxStreams_);
                }
            }

            void clearAllStreams() noexcept
            {
                streamTable_.clear(
                    [this]([[maybe_unused]] uint64_t id, StreamSlotType &slot)
                    {
                        if (slot.handler != nullptr)
                        {
                            streamPool_.release(slot.handler);
                            slot.handler = nullptr;
                        }
                        slot.reset();
                    });
                for (auto &[_, sess] : sessions_)
                {
                    sess->streamTable.clear(
                        [this]([[maybe_unused]] uint64_t id, StreamSlotType &slot)
                        {
                            if (slot.handler != nullptr)
                            {
                                streamPool_.release(slot.handler);
                                slot.handler = nullptr;
                            }
                            slot.reset();
                        });
                }
            }

            [[nodiscard]] static inline size_t maxRequestBodyBytes() noexcept
            {
                return getHttp3Config().maxRequestBodyBytes;
            }
            [[nodiscard]] static inline size_t maxStreamBufferBytes() noexcept
            {
                return getHttp3Config().maxStreamBufferBytes;
            }

            size_t maxStreams_ = 128;
            size_t maxSessions_ = 1024;
            ObjectPool<StreamHandler> streamPool_{};
            StreamTableType streamTable_{128};
            http::v3::FrameDecoder frameDecoder_{};
            std::unordered_map<SessionKey, std::unique_ptr<QuicSession>, SessionKeyHash> sessions_{};
            http::v3::Settings localSettings_{};
            http::v3::Settings peerSettings_{};
            uint32_t nextPacketNumber_ = 1;
            bool controlStreamSent_ = false;
        };

    } // namespace http::v3

} // namespace mynet
