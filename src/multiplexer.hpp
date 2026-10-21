#pragma once

/**
 * @file multiplexer.hpp
 * @brief HTTP/2 frame multiplexer for carrying multiple independent logical exchanges over a single connection.
 */

#include "buffer.hpp"
#include "concepts.hpp"
#include "frame.hpp"
#include "handler.hpp"
#include "log.hpp"
#include "objectPool.hpp"
#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace mynet
{

    /**
     * @namespace mux
     * @brief Protocol constants and setting identifiers for stream multiplexing.
     */
    namespace mux
    {
        inline constexpr uint32_t kInitialWindowSize = (64 << 10) - 1;
        inline constexpr uint32_t kWindowUpdateThreshold = kInitialWindowSize / 2;
        inline constexpr uint32_t kDefaultMaxStreams = 128;
        inline constexpr uint16_t kSettingMaxConcurrentStreams = 0x3;
        inline constexpr uint16_t kSettingInitialWindowSize = 0x4;
        inline constexpr uint16_t kSettingMaxFrameSize = 0x5;
    } // namespace mux

    /**
     * @enum STREAM_ERROR
     * @brief The reason a multiplexed stream or connection was terminated early.
     */
    enum class STREAM_ERROR : uint8_t
    {
        NO_ERROR = 0x0,
        PROTOCOL_ERROR = 0x1,
        INTERNAL_ERROR = 0x2,
        FLOW_CONTROL_ERROR = 0x3,
        STREAM_CLOSED = 0x5,
        FRAME_SIZE_ERROR = 0x6,
        REFUSED_STREAM = 0x7,
        CANCEL = 0x8
    };

    /**
     * @class Multiplexer
     * @brief Demultiplexes a single byte stream into multiple independent exchanges.
     *
     * Implements the HandlerBase concept so it can be held concretely inside Connection<Multiplexer<H>>.
     * Manages frame decoding, flow control windows, stream lifecycle, and response serialization.
     *
     * @tparam StreamHandler The protocol handler type instantiated per stream.
     */
    template <typename StreamHandler>
        requires ProtocolHandler<StreamHandler>
    class Multiplexer : public HandlerBase
    {
    public:
        using Stream = StreamHandler;

        Multiplexer() noexcept = default;
        ~Multiplexer() noexcept override = default;
        Multiplexer(const Multiplexer &) = delete ("a multiplexer owns the stream table and the frames bound to it");
        Multiplexer &
        operator=(const Multiplexer &) = delete ("a multiplexer owns the stream table and the frames bound to it");
        Multiplexer(Multiplexer &&) = delete ("a multiplexer owns the stream table and the frames bound to it");
        Multiplexer &
        operator=(Multiplexer &&) = delete ("a multiplexer owns the stream table and the frames bound to it");

        /**
         * @brief Set the maximum allowed concurrent active streams.
         * @param n Maximum number of concurrent streams.
         */
        inline void setMaxConcurrentStreams(size_t n)
        {
            maxStreams_ = n == 0 ? 1 : n;
            if (streams_.empty())
            {
                streamPool_.init(maxStreams_);
            }
        }

        [[nodiscard]] inline size_t maxConcurrentStreams() const noexcept { return maxStreams_; }

        [[nodiscard]] inline size_t openStreams() const noexcept { return streams_.size(); }

        [[nodiscard]] inline size_t streamPoolCapacity() const noexcept { return streamPool_.capacity(); }

        [[nodiscard]] inline uint32_t lastPeerStreamId() const noexcept { return lastPeerStreamId_; }

        [[nodiscard]] inline uint32_t connectionSendWindow() const noexcept
        {
            return connSendWindow_ < 0 ? 0u : static_cast<uint32_t>(connSendWindow_);
        }

        [[nodiscard]] inline bool goawayReceived() const noexcept { return goawayReceived_; }

        /**
         * @brief Reset the multiplexer state, reclaiming pooled streams.
         */
        void reset() noexcept override
        {
            HandlerBase::reset();
            for (auto &entry : streams_)
            {
                if (entry.second.handler != nullptr)
                {
                    streamPool_.release(entry.second.handler);
                }
            }
            streams_.clear();
            ensureStreamPool();
            connSendWindow_ = mux::kInitialWindowSize;
            connRecvWindow_ = mux::kInitialWindowSize;
            lastPeerStreamId_ = 0;
            settingsSent_ = false;
            goawayReceived_ = false;
            outScratch_.clear();
        }

        // ---- Hooks a protocol front end may override ----

        /**
         * @brief Hook called when a new stream is opened.
         * @param id The stream identifier.
         */
        virtual void onStreamOpen(uint32_t id) noexcept { (void)id; }

        /**
         * @brief Hook called when headers arrive for a stream.
         * @param id The stream identifier.
         * @param block Unparsed header payload block.
         */
        virtual void onStreamHeaders(uint32_t id, std::string_view block) noexcept
        {
            (void)id;
            (void)block;
        }

        /**
         * @brief Hook called when DATA payload arrives for a stream.
         * @param id The stream identifier.
         * @param bytes Payload data chunk.
         */
        virtual void onStreamData(uint32_t id, std::string_view bytes) noexcept
        {
            (void)id;
            (void)bytes;
        }

        /**
         * @brief Hook called when a stream is terminated or closed.
         * @param id The stream identifier.
         */
        virtual void onStreamClose(uint32_t id) noexcept { (void)id; }

        /**
         * @brief Hook called when an unrecoverable protocol error occurs.
         * @param code The error code.
         * @param why Human-readable explanation.
         */
        virtual void onProtocolError(STREAM_ERROR code, std::string_view why) noexcept
        {
            (void)code;
            (void)why;
        }

        /**
         * @brief Parse arriving request bytes frame by frame and dispatch them.
         */
        void process()
        {
            ensureStreamPool();
            if (!settingsSent_) [[unlikely]]
            {
                sendSettings();
            }
            while (true)
            {
                std::expected<std::optional<Frame>, FRAME_ERROR> parsed = decoder_.next(requestBuffer_);
                if (!parsed) [[unlikely]]
                {
                    protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, toString(parsed.error()));
                    return;
                }
                if (!parsed->has_value())
                {
                    return; // Partial frame waiting for more wire data
                }
                handleFrame(std::move(parsed->value()));
                if (closeAfterResponse_) [[unlikely]]
                {
                    return;
                }
            }
        }

    private:
        inline void ensureStreamPool()
        {
            if (streamPool_.capacity() == 0) [[unlikely]]
            {
                streamPool_.init(maxStreams_);
            }
        }

        struct StreamSlot
        {
            StreamHandler *handler = nullptr;
            int64_t sendWindow = mux::kInitialWindowSize;
            uint32_t recvWindow = mux::kInitialWindowSize;
            bool remoteEnded = false;
            bool finalSent = false;
            std::deque<std::string> pending{};
        };

        // ---- Frame dispatch ----

        inline void handleFrame(Frame frame)
        {
            LOG_DEBUG("Multiplexer: frame type {} flags {} on stream {} ({} payload byte(s))",
                      std::to_underlying(frame.type), frame.flags, frame.streamId, frame.payload.size());
            switch (frame.type)
            {
            case FRAME_TYPE::HEADERS:
                handleHeaders(frame);
                break;
            case FRAME_TYPE::DATA:
                handleData(frame);
                break;
            case FRAME_TYPE::SETTINGS:
                handleSettings(frame);
                break;
            case FRAME_TYPE::PING:
                handlePing(frame);
                break;
            case FRAME_TYPE::WINDOW_UPDATE:
                handleWindowUpdate(frame);
                break;
            case FRAME_TYPE::RESET:
                handleReset(frame);
                break;
            case FRAME_TYPE::GOAWAY:
                handleGoaway(frame);
                break;
            case FRAME_TYPE::PRIORITY:
                if (frame.streamId == 0) [[unlikely]]
                {
                    protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "PRIORITY on the connection stream");
                }
                break;
            case FRAME_TYPE::PUSH_PROMISE:
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "PUSH_PROMISE arrived on a server-side connection");
                break;
            case FRAME_TYPE::CONTINUATION:
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "unexpected CONTINUATION frame");
                break;
            }
        }

        inline void handleHeaders(Frame &frame)
        {
            if (!canOpenStream(frame.streamId, "HEADERS")) [[unlikely]]
            {
                return;
            }
            StreamSlot *slot = stream(frame.streamId);
            if (slot == nullptr)
            {
                slot = openStream(frame.streamId);
                if (slot == nullptr) [[unlikely]]
                {
                    sendResetStream(frame.streamId, STREAM_ERROR::REFUSED_STREAM);
                    return;
                }
            }
            else if (slot->remoteEnded) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "HEADERS after END_STREAM on the same stream");
                return;
            }

            std::string_view block;
            if (!unframePayload(frame, block)) [[unlikely]]
            {
                return;
            }
            if (frame.hasFlag(FrameFlags::kPriority))
            {
                if (block.size() < 5) [[unlikely]]
                {
                    protocolFailure(STREAM_ERROR::PROTOCOL_ERROR,
                                    "HEADERS carries a priority field that is not 5 bytes");
                    return;
                }
                block.remove_prefix(5);
            }
            onStreamHeaders(frame.streamId, block);
            if (frame.hasFlag(FrameFlags::kEndStream))
            {
                endRemoteSide(frame.streamId, *slot);
            }
        }

        inline void handleData(Frame &frame)
        {
            if (frame.streamId == 0) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "DATA on the connection stream");
                return;
            }
            StreamSlot *slot = stream(frame.streamId);
            if (slot == nullptr) [[unlikely]]
            {
                if (frame.streamId > lastPeerStreamId_)
                {
                    protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "DATA on a stream that was never opened");
                }
                else
                {
                    sendResetStream(frame.streamId, STREAM_ERROR::STREAM_CLOSED);
                }
                return;
            }
            if (slot->remoteEnded) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "DATA after END_STREAM on the same stream");
                return;
            }

            std::string_view bytes;
            if (!unframePayload(frame, bytes)) [[unlikely]]
            {
                return;
            }
            if (bytes.size() > connRecvWindow_ || bytes.size() > slot->recvWindow) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::FLOW_CONTROL_ERROR,
                                "a DATA frame larger than the receive window it counts against");
                return;
            }
            connRecvWindow_ -= static_cast<uint32_t>(bytes.size());
            slot->recvWindow -= static_cast<uint32_t>(bytes.size());

            onStreamData(frame.streamId, bytes);
            slot->handler->appendRequest(bytes.data(), static_cast<ssize_t>(bytes.size()));
            slot->handler->process();
            collectResponses(frame.streamId, *slot);

            if (frame.hasFlag(FrameFlags::kEndStream))
            {
                endRemoteSide(frame.streamId, *slot);
                return;
            }
            creditReceiveWindow(frame.streamId, *slot);
        }

        inline void handleSettings(Frame &frame)
        {
            if (frame.streamId != 0) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "SETTINGS on a stream other than zero");
                return;
            }
            if (frame.hasFlag(FrameFlags::kAck))
            {
                if (!frame.payload.empty()) [[unlikely]]
                {
                    protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "SETTINGS ACK with a payload");
                }
                return;
            }
            if (frame.payload.size() % 6 != 0) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR,
                                "SETTINGS payload is not a whole number of 6 byte entries");
                return;
            }
            for (size_t off = 0; off + 6 <= frame.payload.size(); off += 6)
            {
                uint16_t idRaw = 0;
                std::memcpy(&idRaw, frame.payload.data() + off, sizeof(idRaw));
                const uint16_t id = std::byteswap(idRaw);
                const uint32_t value = frame::readBigEndian32(frame.payload.data() + off + 2);
                switch (id)
                {
                case mux::kSettingMaxFrameSize:
                    if (value < frame::kDefaultMaxFrameSize || value > 0x00ffffffu) [[unlikely]]
                    {
                        protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "invalid SETTINGS_MAX_FRAME_SIZE value");
                        return;
                    }
                    decoder_.setMaxFrameSize(value);
                    break;
                case mux::kSettingInitialWindowSize:
                {
                    if (value > frame::kStreamIdMask) [[unlikely]]
                    {
                        protocolFailure(STREAM_ERROR::FLOW_CONTROL_ERROR, "initial window size exceeds 2^31 - 1");
                        return;
                    }
                    const int64_t delta = static_cast<int64_t>(value) - static_cast<int64_t>(initialSendWindow_);
                    initialSendWindow_ = value;
                    for (auto &entry : streams_)
                    {
                        int64_t newWin = entry.second.sendWindow + delta;
                        if (newWin > static_cast<int64_t>(frame::kStreamIdMask)) [[unlikely]]
                        {
                            protocolFailure(STREAM_ERROR::FLOW_CONTROL_ERROR, "stream window overflow on SETTINGS");
                            return;
                        }
                        entry.second.sendWindow = newWin;
                    }
                    pumpAll();
                    break;
                }
                default:
                    break;
                }
            }
            sendSettingsAck();
        }

        inline void handlePing(Frame &frame)
        {
            if (frame.streamId != 0) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "PING on a stream other than zero");
                return;
            }
            if (frame.payload.size() != 8) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "PING payload is not 8 bytes");
                return;
            }
            if (frame.hasFlag(FrameFlags::kAck))
            {
                return;
            }
            Frame ack;
            ack.type = FRAME_TYPE::PING;
            ack.flags = FrameFlags::kAck;
            ack.payload = frame.payload;
            appendFrame(outScratch_, ack);
            flushOut();
        }

        inline void handleWindowUpdate(Frame &frame)
        {
            if (frame.payload.size() != 4) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "WINDOW_UPDATE payload is not 4 bytes");
                return;
            }
            const uint32_t increment = frame::readBigEndian32(frame.payload.data()) & frame::kStreamIdMask;
            if (increment == 0) [[unlikely]]
            {
                if (frame.streamId == 0)
                {
                    protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "a zero connection WINDOW_UPDATE");
                }
                else
                {
                    sendResetStream(frame.streamId, STREAM_ERROR::PROTOCOL_ERROR);
                }
                return;
            }
            if (frame.streamId == 0)
            {
                if (connSendWindow_ + static_cast<int64_t>(increment) > static_cast<int64_t>(frame::kStreamIdMask))
                    [[unlikely]]
                {
                    protocolFailure(STREAM_ERROR::FLOW_CONTROL_ERROR, "connection flow-control window overflow");
                    return;
                }
                connSendWindow_ += increment;
                pumpAll();
                return;
            }
            StreamSlot *slot = stream(frame.streamId);
            if (slot == nullptr)
            {
                if (frame.streamId > lastPeerStreamId_) [[unlikely]]
                {
                    protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "WINDOW_UPDATE on an idle stream");
                }
                return;
            }
            if (slot->sendWindow + static_cast<int64_t>(increment) > static_cast<int64_t>(frame::kStreamIdMask))
                [[unlikely]]
            {
                sendResetStream(frame.streamId, STREAM_ERROR::FLOW_CONTROL_ERROR);
                return;
            }
            slot->sendWindow += increment;
            pumpStream(frame.streamId, *slot);
        }

        inline void handleReset(Frame &frame)
        {
            if (frame.payload.size() != 4) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "RST_STREAM payload is not 4 bytes");
                return;
            }
            if (frame.streamId == 0) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "RST_STREAM on the connection stream");
                return;
            }
            if (frame.streamId > lastPeerStreamId_) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "RST_STREAM on an idle stream");
                return;
            }
            closeStream(frame.streamId);
        }

        inline void handleGoaway(Frame &frame)
        {
            if (frame.streamId != 0) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "GOAWAY on a stream other than zero");
                return;
            }
            if (frame.payload.size() < 8) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "GOAWAY payload is shorter than its 8 byte prefix");
                return;
            }
            goawayReceived_ = true;
            const uint32_t lastId = frame::readBigEndian32(frame.payload.data()) & frame::kStreamIdMask;
            const auto code = static_cast<STREAM_ERROR>(frame::readBigEndian32(frame.payload.data() + 4));
            LOG_INFO("Multiplexer: peer sent GOAWAY (last stream {}, code {})", lastId, std::to_underlying(code));
        }

        // ---- Stream lifecycle ----

        inline bool canOpenStream(uint32_t id, const char *what)
        {
            if (id == 0 || (id % 2) == 0) [[unlikely]]
            {
                std::string why = what;
                why += " on a stream the peer may not open";
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, why);
                return false;
            }
            if (goawayReceived_) [[unlikely]]
            {
                LOG_WARN("Multiplexer: refusing a new stream after GOAWAY from the peer");
                sendResetStream(id, STREAM_ERROR::REFUSED_STREAM);
                return false;
            }
            if (stream(id) != nullptr)
            {
                return true;
            }
            if (id <= lastPeerStreamId_) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "a stream identifier that does not increase");
                return false;
            }
            return true;
        }

        inline StreamSlot *openStream(uint32_t id)
        {
            StreamHandler *handler = streamPool_.acquire();
            if (handler == nullptr) [[unlikely]]
            {
                LOG_WARN("Multiplexer: the stream pool is exhausted at {} streams, refusing stream {}", maxStreams_,
                         id);
                lastPeerStreamId_ = id;
                return nullptr;
            }
            handler->reset();
            lastPeerStreamId_ = id;
            StreamSlot &slot = streams_[id];
            slot.handler = handler;
            slot.sendWindow = static_cast<int64_t>(initialSendWindow_);
            slot.recvWindow = mux::kInitialWindowSize;
            onStreamOpen(id);
            return &slot;
        }

        inline void endRemoteSide(uint32_t id, StreamSlot &slot)
        {
            slot.remoteEnded = true;
            creditReceiveWindow(id, slot);
            collectResponses(id, slot);
        }

        inline void closeStream(uint32_t id)
        {
            auto it = streams_.find(id);
            if (it == streams_.end())
            {
                return;
            }
            if (it->second.handler != nullptr)
            {
                streamPool_.release(it->second.handler);
            }
            streams_.erase(it);
            onStreamClose(id);
        }

        // ---- Response path ----

        inline void collectResponses(uint32_t id, StreamSlot &slot)
        {
            while (slot.handler->hasResponse())
            {
                slot.pending.push_back(slot.handler->takeResponse());
            }
            pumpStream(id, slot);
        }

        inline void pumpStream(uint32_t id, StreamSlot &slot)
        {
            while (!slot.pending.empty())
            {
                if (slot.sendWindow <= 0 || connSendWindow_ <= 0)
                {
                    return;
                }
                std::string &chunk = slot.pending.front();
                const size_t allowed =
                    std::min({chunk.size(), static_cast<size_t>(slot.sendWindow), static_cast<size_t>(connSendWindow_),
                              static_cast<size_t>(decoder_.maxFrameSize())});
                if (allowed == 0)
                {
                    return;
                }
                Frame frame;
                frame.streamId = id;
                frame.type = FRAME_TYPE::DATA;
                frame.payload.assign(chunk, 0, allowed);
                appendFrame(outScratch_, frame);
                flushOut();
                slot.sendWindow -= static_cast<int64_t>(allowed);
                connSendWindow_ -= static_cast<int64_t>(allowed);
                if (allowed == chunk.size())
                {
                    slot.pending.pop_front();
                }
                else
                {
                    chunk.erase(0, allowed);
                }
            }
            if (!slot.remoteEnded || slot.finalSent)
            {
                return;
            }
            Frame last;
            last.streamId = id;
            last.type = FRAME_TYPE::DATA;
            last.flags = FrameFlags::kEndStream;
            appendFrame(outScratch_, last);
            flushOut();
            slot.finalSent = true;
            closeStream(id);
        }

        inline void pumpAll()
        {
            std::vector<uint32_t> ids;
            ids.reserve(streams_.size());
            for (const auto &entry : streams_)
            {
                ids.push_back(entry.first);
            }
            std::sort(ids.begin(), ids.end());
            for (uint32_t id : ids)
            {
                auto it = streams_.find(id);
                if (it != streams_.end())
                {
                    pumpStream(id, it->second);
                }
            }
        }

        inline void creditReceiveWindow(uint32_t id, StreamSlot &slot)
        {
            if (slot.recvWindow < mux::kWindowUpdateThreshold)
            {
                const uint32_t increment = mux::kInitialWindowSize - slot.recvWindow;
                slot.recvWindow += increment;
                sendWindowUpdate(id, increment);
            }
            if (connRecvWindow_ < mux::kWindowUpdateThreshold)
            {
                const uint32_t increment = mux::kInitialWindowSize - connRecvWindow_;
                connRecvWindow_ += increment;
                sendWindowUpdate(0, increment);
            }
        }

        // ---- Outbound frames ----

        inline void sendSettings()
        {
            Frame frame;
            frame.type = FRAME_TYPE::SETTINGS;
            appendSetting(frame.payload, mux::kSettingMaxConcurrentStreams, static_cast<uint32_t>(maxStreams_));
            appendSetting(frame.payload, mux::kSettingInitialWindowSize, mux::kInitialWindowSize);
            appendSetting(frame.payload, mux::kSettingMaxFrameSize, decoder_.maxFrameSize());
            appendFrame(outScratch_, frame);
            flushOut();
            settingsSent_ = true;
        }

        inline void sendSettingsAck()
        {
            Frame frame;
            frame.type = FRAME_TYPE::SETTINGS;
            frame.flags = FrameFlags::kAck;
            appendFrame(outScratch_, frame);
            flushOut();
        }

        inline void sendWindowUpdate(uint32_t id, uint32_t increment)
        {
            Frame frame;
            frame.type = FRAME_TYPE::WINDOW_UPDATE;
            frame.streamId = id;
            frame::appendBigEndian32(frame.payload, increment & frame::kStreamIdMask);
            appendFrame(outScratch_, frame);
            flushOut();
        }

        inline void sendResetStream(uint32_t id, STREAM_ERROR code)
        {
            Frame frame;
            frame.type = FRAME_TYPE::RESET;
            frame.streamId = id;
            frame::appendBigEndian32(frame.payload, std::to_underlying(code));
            appendFrame(outScratch_, frame);
            flushOut();
        }

        inline void protocolFailure(STREAM_ERROR code, std::string_view why)
        {
            if (closeAfterResponse_) [[unlikely]]
            {
                return;
            }
            LOG_ERROR("Multiplexer: protocol error on stream {}: {}", lastPeerStreamId_, why);
            Frame frame;
            frame.type = FRAME_TYPE::GOAWAY;
            frame::appendBigEndian32(frame.payload, lastPeerStreamId_ & frame::kStreamIdMask);
            frame::appendBigEndian32(frame.payload, std::to_underlying(code));
            frame.payload.append(why);
            appendFrame(outScratch_, frame);
            flushOut();
            closeAfterResponse_ = true;
            onProtocolError(code, why);
        }

        inline void flushOut()
        {
            if (outScratch_.empty()) [[unlikely]]
            {
                return;
            }
            pushResponse(std::move(outScratch_));
            outScratch_.clear();
        }

        static inline void appendSetting(std::string &out, uint16_t id, uint32_t value)
        {
            const uint16_t beId = std::byteswap(id);
            out.append(reinterpret_cast<const char *>(&beId), sizeof(beId));
            frame::appendBigEndian32(out, value);
        }

        inline bool unframePayload(Frame &frame, std::string_view &out)
        {
            std::string_view body(frame.payload);
            if (frame.hasFlag(FrameFlags::kPadded))
            {
                if (body.empty()) [[unlikely]]
                {
                    protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "PADDED with an empty payload");
                    return false;
                }
                const size_t pad = static_cast<unsigned char>(body.front());
                body.remove_prefix(1);
                if (pad > body.size()) [[unlikely]]
                {
                    protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "padding longer than the payload it is padding");
                    return false;
                }
                body.remove_suffix(pad);
            }
            out = body;
            return true;
        }

        [[nodiscard]] inline StreamSlot *stream(uint32_t id)
        {
            auto it = streams_.find(id);
            return it == streams_.end() ? nullptr : &it->second;
        }

        ObjectPool<StreamHandler> streamPool_{};
        std::unordered_map<uint32_t, StreamSlot> streams_{};
        FrameDecoder decoder_{};
        std::string outScratch_{};
        size_t maxStreams_ = mux::kDefaultMaxStreams;
        int64_t connSendWindow_ = mux::kInitialWindowSize;
        uint32_t connRecvWindow_ = mux::kInitialWindowSize;
        uint32_t initialSendWindow_ = mux::kInitialWindowSize;
        uint32_t lastPeerStreamId_ = 0;
        bool settingsSent_ = false;
        bool goawayReceived_ = false;
    };

} // namespace mynet

// 命名空间别名
namespace mynetmux = mynet::mux;
