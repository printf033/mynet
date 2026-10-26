#pragma once

/**
 * @file http/v3/handler.hpp
 * @brief RFC 9114 HTTP/3 统一协议处理器实现（支持 QUIC/UDP 数据报与流式传输）。
 */

#include "../../handler.hpp"
#include "frame.hpp"
#include "qpack.hpp"
#include "quic.hpp"
#include "streamTable.hpp"
#include "varint.hpp"
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace mynet
{
    namespace http::v3
    {
        /**
         * @class HandlerHttp3
         * @brief RFC 9114 HTTP/3 极速编解码与多路复用协议处理器
         *
         * 架构特性：
         * 1. 传输层双重绑定：具备 HandlerBase（流式/单连接会话生命周期）与 DatagramHandler（UDP
         * 无连接数据报）双重能力；
         * 2. QUIC 原生支持：内置 RFC 9000 1-RTT 短首部报文解析、STREAM 传输帧打包与连接关闭通知；
         * 3. QPACK 压缩与解压：支持静态表快速索引与字面量编码；
         * 4. 逻辑流多路复用：跟踪控制流与客户端双向请求流状态，支持流水线化应答。
         */
        class HandlerHttp3 : public HandlerBase, public DatagramHandler
        {
        public:
            struct SessionKey
            {
                uint32_t addr = 0;
                uint16_t port = 0;
                ConnectionId dcid{};

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
                ConnectionId dcid{};
                sockaddr_in peer{};
                StreamTable streamTable;
                FrameDecoder frameDecoder{};
                uint32_t nextPacketNumber = 1;
                size_t bytesReceived = 0;
                size_t bytesSent = 0;
                bool addressValidated = false;

                explicit QuicSession(size_t maxStreams = 128)
                    : streamTable(maxStreams)
                {
                }
            };

            explicit HandlerHttp3(size_t responseCapacity = 64, size_t maxStreams = 128) noexcept
                : HandlerBase(responseCapacity),
                  maxStreams_(maxStreams),
                  streamTable_(maxStreams)
            {
            }

            ~HandlerHttp3() noexcept override = default;

            HandlerHttp3(const HandlerHttp3 &) = delete("an http3 handler owns socket, streams and parser state");
            HandlerHttp3 &
            operator=(const HandlerHttp3 &) = delete("an http3 handler owns socket, streams and parser state");
            HandlerHttp3(HandlerHttp3 &&) = delete("an http3 handler owns socket, streams and parser state");
            HandlerHttp3 &
            operator=(HandlerHttp3 &&) = delete("an http3 handler owns socket, streams and parser state");

            void reset() noexcept override
            {
                HandlerBase::reset();
                DatagramHandler::reset();
                streamTable_.reset();
                sessions_.clear();
                nextPacketNumber_ = 1;
                controlStreamSent_ = false;
                peerSettings_ = Settings{};
            }

            [[nodiscard]] const Settings &localSettings() const noexcept { return localSettings_; }
            [[nodiscard]] const Settings &peerSettings() const noexcept { return peerSettings_; }

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

            void validateAddress(const sockaddr_in &peer, const ConnectionId &dcid = {}) noexcept
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

            [[nodiscard]] bool isAddressValidated(const sockaddr_in &peer, const ConnectionId &dcid = {}) const noexcept
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

            /**
             * @brief 业务请求处理钩子（可由派生类定制覆盖）
             *
             * @param streamId 逻辑流 ID
             * @param headers 请求首部列表
             * @param body 请求体数据
             * @param responseBody 待填充的响应体内容（默认为回显或就绪问候语）
             */
            virtual void onRequest([[maybe_unused]] uint64_t streamId,
                                   [[maybe_unused]] const std::vector<Header> &headers, std::string_view body,
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
             * @brief 流式报文处理逻辑 (TCP / 管道流仿真)
             *
             * 从 requestBuffer_ 中提取 HTTP/3 协议帧并驱动当前流的请求应答
             */
            void process()
            {
                if (requestBuffer_.empty()) [[unlikely]]
                {
                    return;
                }

                while (true)
                {
                    auto frameRes = frameDecoder_.next(requestBuffer_);
                    if (!frameRes)
                    {
                        LOG_WARN("HandlerHttp3::process: frame decode error: {}", toString(frameRes.error()));
                        requestBuffer_.retrieveAll();
                        break;
                    }
                    if (!frameRes->has_value())
                    {
                        break;
                    }

                    auto &frame = **frameRes;
                    auto slot = streamTable_.getOrCreate(0);
                    if (!slot)
                    {
                        continue;
                    }

                    if (frame.type == std::to_underlying(FRAME_TYPE::SETTINGS))
                    {
                        auto setRes = Settings::decode(frame.payload);
                        if (setRes)
                        {
                            peerSettings_ = *setRes;
                            LOG_INFO("HandlerHttp3: peer SETTINGS received (maxFieldSectionSize={})",
                                     peerSettings_.maxFieldSectionSize);
                        }
                    }
                    else if (frame.type == std::to_underlying(FRAME_TYPE::HEADERS))
                    {
                        auto hRes = decodeHeaders(frame.payload);
                        if (hRes)
                        {
                            slot->requestHeaders = std::move(*hRes);
                            slot->headersComplete = true;
                        }
                    }
                    else if (frame.type == std::to_underlying(FRAME_TYPE::DATA))
                    {
                        if (slot->requestBody.size() + frame.payload.size() <= kMaxRequestBodyBytes)
                        {
                            slot->requestBody.append(frame.payload);
                        }
                    }
                }

                // 排空一轮解析后，对已就绪的流生成应答
                auto slot = streamTable_.find(0);
                if (slot && slot->headersComplete)
                {
                    std::string responseBody;
                    onRequest(0, slot->requestHeaders, slot->requestBody, responseBody);
                    sendResponse(0, 200, {}, responseBody);
                    slot->reset();
                }
            }

            /**
             * @brief UDP 数据报处理逻辑 (RFC 9000 QUIC + RFC 9114 HTTP/3)
             *
             * 解析传入的 UDP 数据报，识别 QUIC 1-RTT 短首部报文与 STREAM 帧，
             * 解复用 HTTP/3 请求并在同一 UDP 端点原路构造应答数据报回写。
             * 按照 SessionKey (peer + dcid) 实现严格的 per-connection 会话隔离与
             * RFC 9000 Section 8.1 3x 抗反射放大保护。
             */
            void onDatagram(const sockaddr_in &peer, const char *data, size_t n) noexcept override
            {
                if (data == nullptr || n == 0) [[unlikely]]
                {
                    return;
                }

                std::string_view packet(data, n);

                // 尝试作为 QUIC 短首部报文解析
                auto shpRes = parseShortHeaderPacket(packet, 8);
                if (shpRes)
                {
                    auto &shp = *shpRes;
                    QuicSession *session = getOrCreateSession(peer, shp.dcid);
                    if (!session)
                    {
                        return;
                    }
                    session->bytesReceived += n;
                    handleQuicPacket(peer, shp, *session);
                    return;
                }

                // 备选路径：直接承载裸 HTTP/3 分帧的数据报（轻量/测试回环）
                QuicSession *session = getOrCreateSession(peer, ConnectionId{});
                if (!session)
                {
                    return;
                }
                session->bytesReceived += n;

                Buffer directBuf;
                [[maybe_unused]] auto _ = directBuf.append(data, n);
                while (true)
                {
                    auto frameRes = session->frameDecoder.next(directBuf);
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

                    if (frame.type == std::to_underlying(FRAME_TYPE::HEADERS))
                    {
                        auto hRes = decodeHeaders(frame.payload);
                        if (hRes)
                        {
                            slot->requestHeaders = std::move(*hRes);
                            slot->headersComplete = true;
                        }
                    }
                    else if (frame.type == std::to_underlying(FRAME_TYPE::DATA))
                    {
                        if (slot->requestBody.size() + frame.payload.size() <= kMaxRequestBodyBytes)
                        {
                            slot->requestBody.append(frame.payload);
                        }
                    }
                }

                auto slot = session->streamTable.find(0);
                if (slot && slot->headersComplete)
                {
                    std::string responseBody;
                    onRequest(0, slot->requestHeaders, slot->requestBody, responseBody);

                    std::vector<Header> finalHeaders;
                    finalHeaders.reserve(3);
                    finalHeaders.push_back({":status", "200"});
                    finalHeaders.push_back({"server", "mynet-http3"});
                    finalHeaders.push_back({"content-type", "text/plain; charset=utf-8"});

                    std::string headerPayload;
                    encodeHeaders(headerPayload, finalHeaders);

                    std::string frameBytes;
                    appendFrame(frameBytes, std::to_underlying(FRAME_TYPE::HEADERS), headerPayload);
                    if (!responseBody.empty())
                    {
                        appendFrame(frameBytes, std::to_underlying(FRAME_TYPE::DATA), responseBody);
                    }

                    // RFC 9000 Section 8.1 抗反射放大防护：未验证地址发送字节不得超过接收字节的 3 倍
                    if (!session->addressValidated &&
                        session->bytesSent + frameBytes.size() > 3 * session->bytesReceived)
                    {
                        LOG_WARN("HandlerHttp3: direct fallback anti-amplification limit exceeded (received {}, sent {})",
                                 session->bytesReceived, session->bytesSent + frameBytes.size());
                    }
                    else
                    {
                        session->bytesSent += frameBytes.size();
                        pushReply(peer, std::move(frameBytes));
                    }
                    session->streamTable.close(0);
                }
            }

            /**
             * @brief 构造 HTTP/3 响应帧并写入流式响应队列
             */
            void sendResponse(uint64_t streamId, int statusCode, const std::vector<Header> &headers,
                              std::string_view body)
            {
                std::vector<Header> finalHeaders;
                finalHeaders.reserve(headers.size() + 3);
                finalHeaders.push_back({":status", std::to_string(statusCode)});
                finalHeaders.push_back({"server", "mynet-http3"});
                finalHeaders.push_back({"content-type", "text/plain; charset=utf-8"});
                for (const auto &h : headers)
                {
                    finalHeaders.push_back(h);
                }

                std::string headerPayload;
                encodeHeaders(headerPayload, finalHeaders);

                std::string frameBytes;
                appendFrame(frameBytes, std::to_underlying(FRAME_TYPE::HEADERS), headerPayload);
                if (!body.empty())
                {
                    appendFrame(frameBytes, std::to_underlying(FRAME_TYPE::DATA), body);
                }

                [[maybe_unused]] auto _ = pushResponse(std::move(frameBytes));
                [[maybe_unused]] auto stream = streamId;
            }

            /**
             * @brief 构造 QUIC 报文并推入 UDP 回复队列发送给指定对端（基于对应会话）
             */
            void sendQuicReply(const sockaddr_in &peer, QuicSession &session, uint64_t streamId, int statusCode,
                               const std::vector<Header> &headers, std::string_view body)
            {
                std::vector<Header> finalHeaders;
                finalHeaders.reserve(headers.size() + 3);
                finalHeaders.push_back({":status", std::to_string(statusCode)});
                finalHeaders.push_back({"server", "mynet-http3"});
                finalHeaders.push_back({"content-type", "text/plain; charset=utf-8"});
                for (const auto &h : headers)
                {
                    finalHeaders.push_back(h);
                }

                std::string headerPayload;
                encodeHeaders(headerPayload, finalHeaders);

                std::string h3Frames;
                appendFrame(h3Frames, std::to_underlying(FRAME_TYPE::HEADERS), headerPayload);
                if (!body.empty())
                {
                    appendFrame(h3Frames, std::to_underlying(FRAME_TYPE::DATA), body);
                }

                // 打包进 QUIC STREAM 帧 (FIN 标记表示响应完成)
                std::string quicPayload;
                appendStreamFrame(quicPayload, streamId, 0, h3Frames, true);

                // 封装为 QUIC 1-RTT 短首部报文
                std::string packet;
                appendShortHeaderPacket(packet, session.dcid, session.nextPacketNumber++, quicPayload);

                // RFC 9000 Section 8.1: 地址验证前响应字节数不得超过接收字节数的 3 倍 (Anti-Amplification Limit)
                if (!session.addressValidated && session.bytesSent + packet.size() > 3 * session.bytesReceived)
                {
                    LOG_WARN("HandlerHttp3: anti-amplification limit exceeded for peer {} (received={}, sent={}, packet={})",
                             datagramPeerText(peer), session.bytesReceived, session.bytesSent, packet.size());
                    return;
                }

                session.bytesSent += packet.size();
                pushReply(peer, std::move(packet));
            }

            /**
             * @brief 构造 QUIC 报文并推入 UDP 回复队列发送给指定对端（兼容重载）
             */
            void sendQuicReply(const sockaddr_in &peer, const ConnectionId &dcid, uint64_t streamId, int statusCode,
                               const std::vector<Header> &headers, std::string_view body)
            {
                QuicSession *sess = getOrCreateSession(peer, dcid);
                if (sess != nullptr)
                {
                    sendQuicReply(peer, *sess, streamId, statusCode, headers, body);
                }
            }

            QuicSession *getOrCreateSession(const sockaddr_in &peer, const ConnectionId &dcid)
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
            void handleQuicPacket(const sockaddr_in &peer, const ShortHeaderPacket &shp, QuicSession &session)
            {
                const auto *ptr = reinterpret_cast<const uint8_t *>(shp.payload.data());
                size_t rem = shp.payload.size();

                while (rem > 0)
                {
                    const uint8_t frameType = *ptr;
                    if (frameType >= 0x08 && frameType <= 0x0f)
                    {
                        // QUIC STREAM 帧
                        auto sfRes = parseStreamFrame(ptr, rem);
                        if (!sfRes)
                        {
                            break;
                        }

                        auto &sf = *sfRes;
                        // RFC 9000 Section 2.1: 客户端发起的流编号必须为偶数 (0x00 bidi, 0x02 uni)
                        if ((sf.streamId & 1u) != 0) [[unlikely]]
                        {
                            LOG_WARN("HandlerHttp3: peer sent stream {} which is server-initiated", sf.streamId);
                            continue;
                        }

                        auto slot = session.streamTable.getOrCreate(sf.streamId);
                        if (!slot)
                        {
                            continue;
                        }

                        if (slot->inBuffer.readableBytes() + sf.data.size() > kMaxStreamBufferBytes) [[unlikely]]
                        {
                            LOG_WARN("HandlerHttp3: stream {} buffer exceeded maximum limit", sf.streamId);
                            session.streamTable.close(sf.streamId);
                            continue;
                        }

                        [[maybe_unused]] auto _ = slot->inBuffer.append(sf.data.data(), sf.data.size());
                        if (sf.fin)
                        {
                            slot->finReceived = true;
                        }

                        // 从该会话专属流输入缓冲区中解码 HTTP/3 帧
                        while (true)
                        {
                            auto h3Res = session.frameDecoder.next(slot->inBuffer);
                            if (!h3Res || !h3Res->has_value())
                            {
                                break;
                            }
                            auto &h3Frame = **h3Res;
                            if (h3Frame.type == std::to_underlying(FRAME_TYPE::HEADERS))
                            {
                                auto hRes = decodeHeaders(h3Frame.payload);
                                if (hRes)
                                {
                                    slot->requestHeaders = std::move(*hRes);
                                    slot->headersComplete = true;
                                }
                            }
                            else if (h3Frame.type == std::to_underlying(FRAME_TYPE::DATA))
                            {
                                if (slot->requestBody.size() + h3Frame.payload.size() <= kMaxRequestBodyBytes)
                                {
                                    slot->requestBody.append(h3Frame.payload);
                                }
                            }
                        }

                        // 当收到 FIN 时表示请求流结束，构造 QUIC 回复并关闭该流
                        if (slot->finReceived)
                        {
                            std::string responseBody;
                            onRequest(sf.streamId, slot->requestHeaders, slot->requestBody, responseBody);
                            sendQuicReply(peer, session, sf.streamId, 200, {}, responseBody);
                            session.streamTable.close(sf.streamId);
                        }
                    }
                    else if (frameType == 0x01)
                    {
                        // PING 帧，消耗 1 字节
                        ++ptr;
                        --rem;
                    }
                    else if (frameType == 0x00)
                    {
                        // PADDING 帧，消耗 1 字节
                        ++ptr;
                        --rem;
                    }
                    else
                    {
                        // 未知或非 STREAM 帧，跳过剩余部分
                        break;
                    }
                }
            }

            static constexpr size_t kMaxRequestBodyBytes = 16 << 20;  // 16 MiB
            static constexpr size_t kMaxStreamBufferBytes = 16 << 20; // 16 MiB

            size_t maxStreams_ = 128;
            size_t maxSessions_ = 1024;
            StreamTable streamTable_;
            FrameDecoder frameDecoder_{};
            std::unordered_map<SessionKey, std::unique_ptr<QuicSession>, SessionKeyHash> sessions_{};
            Settings localSettings_{};
            Settings peerSettings_{};
            uint32_t nextPacketNumber_ = 1;
            bool controlStreamSent_ = false;
        };

    } // namespace http::v3

    using HandlerHttp3 = http::v3::HandlerHttp3;

} // namespace mynet
