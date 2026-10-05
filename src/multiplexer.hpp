#pragma once

#include "buffer.hpp"
#include "frame.hpp"
#include "handler.hpp"
#include "log.hpp"
#include "myconcepts.hpp"
#include "objectPool.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

// The numbers a multiplexed connection agrees on before it can carry
// anything. They are HTTP/2's own defaults, because a peer that speaks h2 is
// the peer this layer most wants to be readable by, and a private value here
// would mean a private dialect everywhere the framing is reused.
namespace mynetmux
{
    inline constexpr uint32_t kInitialWindowSize = 65535;
    inline constexpr uint32_t kWindowUpdateThreshold = kInitialWindowSize / 2;
    inline constexpr uint32_t kDefaultMaxStreams = 128;
    inline constexpr uint16_t kSettingMaxConcurrentStreams = 0x3;
    inline constexpr uint16_t kSettingInitialWindowSize = 0x4;
    inline constexpr uint16_t kSettingMaxFrameSize = 0x5;
} // namespace mynetmux

// The reason one stream ended early. The numbering is HTTP/2's, for the same
// reason the frame header is: a peer that already knows these codes needs no
// translation table, and one that does not can still read the number in a log.
enum class StreamError : uint8_t
{
    noError = 0x0,
    protocolError = 0x1,
    internalError = 0x2,
    flowControlError = 0x3,
    streamClosed = 0x5,
    refusedStream = 0x7,
    cancel = 0x8,
};

// Turns one byte stream into many independent exchanges.
//
// This is the layer an ordinary request/response handler cannot provide. A
// HandlerBase sees a socket as one conversation: bytes in, bytes out, and when
// two logical exchanges are in flight the responses queue behind each other.
// A multiplexer keeps the socket, but not the conversation -- it demultiplexes
// by stream identifier, gives every stream its own StreamHandler instance, and
// interleaves their responses back onto the one wire.
//
// It is itself a handler, and that is the point. Connection<Multiplexer<H>>
// works unchanged: TLS, the write queue and readCredit()'s back pressure apply
// to a multiplexed connection exactly as to a plain one, because from the
// transport's side nothing has changed -- it is still bytes in and bytes out.
// The structure that multiplies lives one layer up, where it belongs.
//
//   Connection<Multiplexer<Echo>>          one socket, one TLS session
//        |
//        +-- Multiplexer<Echo>             one frame decoder, N streams
//              +-- Echo  (stream 1)        independent request/response
//              +-- Echo  (stream 3)
//              +-- Echo  (stream 7)
//
// What is deliberately *not* here: HPACK and the header-list semantics of
// HTTP/2. Compressing a header block (and refusing one that decompresses past
// a limit) is a codec in its own right, and folding it in would tie a general
// stream layer to one protocol's header encoding. HEADERS payloads are handed
// to onStreamHeaders() as opaque bytes -- a real h2 front end is a
// StreamHandler whose job is to decode them, and this layer routes the stream
// either way.
template <typename StreamHandler>
    requires mustHandleProtocol<StreamHandler>
class Multiplexer : public HandlerBase
{
public:
    using Stream = StreamHandler;

    Multiplexer() noexcept = default;
    ~Multiplexer() noexcept override = default;
    Multiplexer(const Multiplexer &) = delete("a multiplexer owns the stream table and the frames bound to it");
    Multiplexer &operator=(const Multiplexer &) = delete("a multiplexer owns the stream table and the frames bound to it");
    Multiplexer(Multiplexer &&) = delete("a multiplexer owns the stream table and the frames bound to it");
    Multiplexer &operator=(Multiplexer &&) = delete("a multiplexer owns the stream table and the frames bound to it");

    // The admission limit, and the value advertised as
    // SETTINGS_MAX_CONCURRENT_STREAMS. Streams beyond it are refused with
    // RST_STREAM rather than queued: a peer that opens them has not read the
    // setting, and holding the bytes would only move the problem.
    //
    // The pool is only rebuilt while no stream is open: freeing the handlers a
    // live stream points at would leave the stream table dangling. A limit
    // lowered mid-connection therefore governs the next connection, and the
    // SETTINGS sent to the current peer govern this one.
    inline void setMaxConcurrentStreams(size_t n)
    {
        maxStreams_ = n == 0 ? 1 : n;
        if (streams_.empty())
            streamPool_.init(maxStreams_);
    }
    [[nodiscard]] inline size_t maxConcurrentStreams() const noexcept { return maxStreams_; }
    [[nodiscard]] inline size_t openStreams() const noexcept { return streams_.size(); }
    [[nodiscard]] inline size_t streamPoolCapacity() const noexcept { return streamPool_.capacity(); }
    [[nodiscard]] inline uint32_t lastPeerStreamId() const noexcept { return lastPeerStreamId_; }
    [[nodiscard]] inline uint32_t connectionSendWindow() const noexcept { return connSendWindow_; }
    [[nodiscard]] inline bool goawayReceived() const noexcept { return goawayReceived_; }

    void reset() noexcept override
    {
        HandlerBase::reset();
        for (auto &entry : streams_)
        {
            if (entry.second.handler != nullptr)
                streamPool_.release(entry.second.handler);
        }
        streams_.clear();
        // Capacity is a property of the connection, not of one run: a pooled
        // Connection<Multiplexer> calls reset() between peers, and the streams
        // it had open are gone but the room for the ones the next peer opens
        // must still be there. Initialising only when empty also keeps this
        // reset() from rebuilding every handler object on every recycle.
        ensureStreamPool();
        connSendWindow_ = mynetmux::kInitialWindowSize;
        connRecvWindow_ = mynetmux::kInitialWindowSize;
        lastPeerStreamId_ = 0;
        settingsSent_ = false;
        goawayReceived_ = false;
        outScratch_.clear();
    }

    // ---- hooks a protocol front end may override ----

    // A stream exists now. Called before anything is routed to it.
    virtual void onStreamOpen(uint32_t id) noexcept { (void)id; }

    // One header block, as the peer framed it and no further interpreted.
    virtual void onStreamHeaders(uint32_t id, std::string_view block) noexcept
    {
        (void)id;
        (void)block;
    }

    // Each DATA payload, in arrival order.
    virtual void onStreamData(uint32_t id, std::string_view bytes) noexcept
    {
        (void)id;
        (void)bytes;
    }

    // The stream is gone: fully finished, reset by the peer, or refused.
    virtual void onStreamClose(uint32_t id) noexcept { (void)id; }

    // The connection is out of contract. The frame layer has already sent
    // GOAWAY and marked the connection for closing; this is for the record.
    virtual void onProtocolError(StreamError code, std::string_view why) noexcept
    {
        (void)code;
        (void)why;
    }

    // A frame at a time, from whatever bytes the connection has delivered.
    //
    // Nothing here is virtual: Connection<> holds this type concretely, so
    // hiding HandlerBase::process() is enough and the call is still direct.
    void process()
    {
        ensureStreamPool();
        if (!settingsSent_)
            sendSettings();
        while (true)
        {
            std::expected<std::optional<Frame>, FrameError> parsed = decoder_.next(requestBuffer_);
            if (!parsed)
            {
                protocolFailure(StreamError::protocolError, to_string(parsed.error()));
                return;
            }
            if (!parsed->has_value())
                return; // a partial frame: the rest has not arrived yet
            handleFrame(std::move(parsed->value()));
            if (closeAfterResponse_)
                return;
        }
    }

private:
    // A Connection is default-constructed and only reset() when it is recycled,
    // so the first peer on a fresh connection arrives before any reset() has
    // run. Building the pool here on first use is both what makes the
    // constructor's noexcept promise hold and what keeps the pool's cost off
    // connections that never speak this protocol.
    inline void ensureStreamPool()
    {
        if (streamPool_.capacity() == 0)
            streamPool_.init(maxStreams_);
    }

    struct StreamSlot
    {
        StreamHandler *handler = nullptr;
        uint32_t sendWindow = mynetmux::kInitialWindowSize;
        uint32_t recvWindow = mynetmux::kInitialWindowSize;
        bool remoteEnded = false; // the peer sent END_STREAM
        bool finalSent = false;   // our END_STREAM is on the wire
        std::deque<std::string> pending{};
    };

    // ---- frame dispatch ----

    inline void handleFrame(Frame frame)
    {
        LOG_DEBUG("Multiplexer: frame type {} flags {} on stream {} ({} payload byte(s))",
                  std::to_underlying(frame.type), frame.flags, frame.streamId, frame.payload.size());
        switch (frame.type)
        {
        case FrameType::headers:
            handleHeaders(frame);
            break;
        case FrameType::data:
            handleData(frame);
            break;
        case FrameType::settings:
            handleSettings(frame);
            break;
        case FrameType::ping:
            handlePing(frame);
            break;
        case FrameType::windowUpdate:
            handleWindowUpdate(frame);
            break;
        case FrameType::reset:
            handleReset(frame);
            break;
        case FrameType::goaway:
            handleGoaway(frame);
            break;
        case FrameType::priority:
            // A hint about scheduling, never about correctness. We keep
            // serving every stream in the order it was opened, which is a
            // valid answer to a peer that expressed a preference.
            break;
        case FrameType::pushPromise:
            // We are a server: a peer sending PUSH_PROMISE is confused about
            // who is who, and pretending otherwise would hide that.
            protocolFailure(StreamError::protocolError, "PUSH_PROMISE arrived on a server-side connection");
            break;
        }
    }

    inline void handleHeaders(Frame &frame)
    {
        if (!canOpenStream(frame.streamId, "HEADERS"))
            return;
        StreamSlot *slot = stream(frame.streamId);
        if (slot == nullptr)
        {
            slot = openStream(frame.streamId);
            if (slot == nullptr)
            {
                sendResetStream(frame.streamId, StreamError::refusedStream);
                return;
            }
        }
        else if (slot->remoteEnded)
        {
            protocolFailure(StreamError::protocolError, "HEADERS after END_STREAM on the same stream");
            return;
        }

        std::string_view block;
        if (!unframePayload(frame, block))
            return;
        if (frame.hasFlag(FrameFlags::kPriority))
        {
            if (block.size() < 5)
            {
                protocolFailure(StreamError::protocolError, "HEADERS carries a priority field that is not 5 bytes");
                return;
            }
            block.remove_prefix(5);
        }
        onStreamHeaders(frame.streamId, block);
        if (frame.hasFlag(FrameFlags::kEndStream))
            endRemoteSide(frame.streamId, *slot);
    }

    inline void handleData(Frame &frame)
    {
        StreamSlot *slot = stream(frame.streamId);
        if (slot == nullptr)
        {
            // A DATA frame for a stream that never existed is a protocol
            // error; one for a stream that already finished is a race the
            // peer can recover from, so it is only a reset.
            if (frame.streamId > lastPeerStreamId_)
                protocolFailure(StreamError::protocolError, "DATA on a stream that was never opened");
            else
                sendResetStream(frame.streamId, StreamError::streamClosed);
            return;
        }
        if (slot->remoteEnded)
        {
            protocolFailure(StreamError::protocolError, "DATA after END_STREAM on the same stream");
            return;
        }

        std::string_view bytes;
        if (!unframePayload(frame, bytes))
            return;
        if (bytes.size() > connRecvWindow_ || bytes.size() > slot->recvWindow)
        {
            protocolFailure(StreamError::flowControlError, "a DATA frame larger than the receive window it counts against");
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
        if (frame.streamId != 0)
        {
            protocolFailure(StreamError::protocolError, "SETTINGS on a stream other than zero");
            return;
        }
        if (frame.hasFlag(FrameFlags::kAck))
        {
            if (!frame.payload.empty())
                protocolFailure(StreamError::protocolError, "SETTINGS ACK with a payload");
            return;
        }
        if (frame.payload.size() % 6 != 0)
        {
            protocolFailure(StreamError::protocolError, "SETTINGS payload is not a whole number of 6 byte entries");
            return;
        }
        for (size_t off = 0; off + 6 <= frame.payload.size(); off += 6)
        {
            const auto *p = reinterpret_cast<const unsigned char *>(frame.payload.data() + off);
            const uint16_t id = static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
            const uint32_t value = mynetframe::readBigEndian32(frame.payload.data() + off + 2);
            switch (id)
            {
            case mynetmux::kSettingMaxFrameSize:
                // The peer will not send bigger than this, and neither will
                // we: it is an upper bound on one frame, not a buffer size.
                if (value >= mynetframe::kDefaultMaxFrameSize)
                    decoder_.setMaxFrameSize(value);
                break;
            case mynetmux::kSettingInitialWindowSize:
                // Applies to streams opened from now on. A live stream's
                // window is only ever enlarged, so nothing already in flight
                // is invalidated by a smaller value here.
                initialSendWindow_ = value;
                break;
            default:
                break; // a setting we do not implement is one we may ignore
            }
        }
        sendSettingsAck();
    }

    inline void handlePing(Frame &frame)
    {
        if (frame.streamId != 0)
        {
            protocolFailure(StreamError::protocolError, "PING on a stream other than zero");
            return;
        }
        if (frame.payload.size() != 8)
        {
            protocolFailure(StreamError::protocolError, "PING payload is not 8 bytes");
            return;
        }
        if (frame.hasFlag(FrameFlags::kAck))
            return; // the peer's answer to a ping we sent: nothing left to do
        Frame ack;
        ack.type = FrameType::ping;
        ack.flags = FrameFlags::kAck;
        ack.payload = frame.payload;
        appendFrame(outScratch_, ack);
        flushOut();
    }

    inline void handleWindowUpdate(Frame &frame)
    {
        if (frame.payload.size() != 4)
        {
            protocolFailure(StreamError::protocolError, "WINDOW_UPDATE payload is not 4 bytes");
            return;
        }
        const uint32_t increment = mynetframe::readBigEndian32(frame.payload.data()) & mynetframe::kStreamIdMask;
        if (increment == 0)
        {
            if (frame.streamId == 0)
                protocolFailure(StreamError::protocolError, "a zero connection WINDOW_UPDATE");
            else
                sendResetStream(frame.streamId, StreamError::protocolError);
            return;
        }
        if (frame.streamId == 0)
        {
            connSendWindow_ += increment;
            pumpAll();
            return;
        }
        StreamSlot *slot = stream(frame.streamId);
        if (slot == nullptr)
            return; // for a stream we have already finished: harmless
        slot->sendWindow += increment;
        pumpStream(frame.streamId, *slot);
    }

    inline void handleReset(Frame &frame)
    {
        if (frame.payload.size() != 4)
        {
            protocolFailure(StreamError::protocolError, "RST_STREAM payload is not 4 bytes");
            return;
        }
        if (frame.streamId == 0)
        {
            protocolFailure(StreamError::protocolError, "RST_STREAM on the connection stream");
            return;
        }
        // The peer is done with this stream, not with the connection. What
        // may still be in flight for it is now the peer's problem to discard.
        closeStream(frame.streamId);
    }

    inline void handleGoaway(Frame &frame)
    {
        if (frame.streamId != 0)
        {
            protocolFailure(StreamError::protocolError, "GOAWAY on a stream other than zero");
            return;
        }
        if (frame.payload.size() < 8)
        {
            protocolFailure(StreamError::protocolError, "GOAWAY payload is shorter than its 8 byte prefix");
            return;
        }
        goawayReceived_ = true;
        const uint32_t lastId = mynetframe::readBigEndian32(frame.payload.data()) & mynetframe::kStreamIdMask;
        const auto code = static_cast<StreamError>(mynetframe::readBigEndian32(frame.payload.data() + 4));
        LOG_INFO("Multiplexer: peer sent GOAWAY (last stream {}, code {})", lastId, std::to_underlying(code));
    }

    // ---- stream lifecycle ----

    // Zero is the connection, not a stream, and even numbers are streams this
    // side may have pushed -- neither can be opened by the peer. Returning
    // false means an answer has already been sent.
    inline bool canOpenStream(uint32_t id, const char *what)
    {
        if (id == 0 || (id % 2) == 0)
        {
            std::string why = what;
            why += " on a stream the peer may not open";
            protocolFailure(StreamError::protocolError, why);
            return false;
        }
        if (goawayReceived_)
        {
            LOG_WARN("Multiplexer: refusing a new stream after GOAWAY from the peer");
            sendResetStream(id, StreamError::refusedStream);
            return false;
        }
        if (stream(id) != nullptr)
            return true;
        if (id <= lastPeerStreamId_)
        {
            // Stream identifiers only ever increase. Reusing one would mean
            // routing frames to an exchange the peer already finished.
            protocolFailure(StreamError::protocolError, "a stream identifier that does not increase");
            return false;
        }
        return true;
    }

    inline StreamSlot *openStream(uint32_t id)
    {
        StreamHandler *handler = streamPool_.acquire();
        if (handler == nullptr)
        {
            LOG_WARN("Multiplexer: the stream pool is exhausted at {} streams, refusing stream {}", maxStreams_, id);
            return nullptr;
        }
        handler->reset();
        lastPeerStreamId_ = id;
        StreamSlot &slot = streams_[id];
        slot.handler = handler;
        slot.sendWindow = initialSendWindow_;
        slot.recvWindow = mynetmux::kInitialWindowSize;
        onStreamOpen(id);
        return &slot;
    }

    inline void endRemoteSide(uint32_t id, StreamSlot &slot)
    {
        slot.remoteEnded = true;
        // Credited first, because the slot is about to be erased: once both
        // directions are done and nothing is left to send, pumpStream()
        // closes the stream, and every read from the reference after that
        // point would be a use after free.
        creditReceiveWindow(id, slot);
        // A handler that answers only once the request is complete gets its
        // chance here; one that answered earlier has already been drained.
        // Nothing may touch "slot" once this returns.
        collectResponses(id, slot);
    }

    inline void closeStream(uint32_t id)
    {
        auto it = streams_.find(id);
        if (it == streams_.end())
            return;
        if (it->second.handler != nullptr)
            streamPool_.release(it->second.handler);
        streams_.erase(it);
        onStreamClose(id);
    }

    // ---- response path ----

    // Take everything the stream's handler has produced, then push as much of
    // it as both flow-control windows allow.
    inline void collectResponses(uint32_t id, StreamSlot &slot)
    {
        while (slot.handler->hasResponse())
            slot.pending.push_back(slot.handler->takeResponse());
        pumpStream(id, slot);
    }

    inline void pumpStream(uint32_t id, StreamSlot &slot)
    {
        while (!slot.pending.empty())
        {
            std::string &chunk = slot.pending.front();
            const size_t allowed =
                std::min({chunk.size(), static_cast<size_t>(slot.sendWindow), static_cast<size_t>(connSendWindow_),
                          static_cast<size_t>(decoder_.maxFrameSize())});
            if (allowed == 0)
                return; // a window is closed: the rest waits for WINDOW_UPDATE
            Frame frame;
            frame.streamId = id;
            frame.type = FrameType::data;
            frame.payload.assign(chunk, 0, allowed);
            appendFrame(outScratch_, frame);
            flushOut();
            slot.sendWindow -= static_cast<uint32_t>(allowed);
            connSendWindow_ -= static_cast<uint32_t>(allowed);
            if (allowed == chunk.size())
                slot.pending.pop_front();
            else
                chunk.erase(0, allowed);
        }
        if (!slot.remoteEnded || slot.finalSent)
            return;
        // Both directions are done and nothing is left to send: close the
        // stream with the END_STREAM flag that tells the peer so.
        Frame last;
        last.streamId = id;
        last.type = FrameType::data;
        last.flags = FrameFlags::kEndStream;
        appendFrame(outScratch_, last);
        flushOut();
        slot.finalSent = true;
        closeStream(id);
    }

    inline void pumpAll()
    {
        // WINDOW_UPDATE for the connection unblocks every stream at once, so
        // each one gets the chance to drain. The stream table is walked by
        // identifier so the order is stable across runs -- a reproduction that
        // depends on hash order is not a reproduction.
        std::vector<uint32_t> ids;
        ids.reserve(streams_.size());
        for (const auto &entry : streams_)
            ids.push_back(entry.first);
        std::sort(ids.begin(), ids.end());
        for (uint32_t id : ids)
        {
            auto it = streams_.find(id);
            if (it != streams_.end())
                pumpStream(id, it->second);
        }
    }

    // Give the peer back the room it has used, in one increment per window
    // that has fallen past the threshold. A window that is topped up only
    // when it runs dry stalls a stream for one round trip per threshold.
    inline void creditReceiveWindow(uint32_t id, StreamSlot &slot)
    {
        if (slot.recvWindow < mynetmux::kWindowUpdateThreshold)
        {
            const uint32_t increment = mynetmux::kInitialWindowSize - slot.recvWindow;
            slot.recvWindow += increment;
            sendWindowUpdate(id, increment);
        }
        if (connRecvWindow_ < mynetmux::kWindowUpdateThreshold)
        {
            const uint32_t increment = mynetmux::kInitialWindowSize - connRecvWindow_;
            connRecvWindow_ += increment;
            sendWindowUpdate(0, increment);
        }
    }

    // ---- outbound frames ----

    inline void sendSettings()
    {
        Frame frame;
        frame.type = FrameType::settings;
        appendSetting(frame.payload, mynetmux::kSettingMaxConcurrentStreams, static_cast<uint32_t>(maxStreams_));
        appendSetting(frame.payload, mynetmux::kSettingInitialWindowSize, mynetmux::kInitialWindowSize);
        appendSetting(frame.payload, mynetmux::kSettingMaxFrameSize, decoder_.maxFrameSize());
        appendFrame(outScratch_, frame);
        flushOut();
        settingsSent_ = true;
    }

    inline void sendSettingsAck()
    {
        Frame frame;
        frame.type = FrameType::settings;
        frame.flags = FrameFlags::kAck;
        appendFrame(outScratch_, frame);
        flushOut();
    }

    inline void sendWindowUpdate(uint32_t id, uint32_t increment)
    {
        Frame frame;
        frame.type = FrameType::windowUpdate;
        frame.streamId = id;
        mynetframe::appendBigEndian32(frame.payload, increment & mynetframe::kStreamIdMask);
        appendFrame(outScratch_, frame);
        flushOut();
    }

    inline void sendResetStream(uint32_t id, StreamError code)
    {
        Frame frame;
        frame.type = FrameType::reset;
        frame.streamId = id;
        mynetframe::appendBigEndian32(frame.payload, std::to_underlying(code));
        appendFrame(outScratch_, frame);
        flushOut();
    }

    // A protocol failure ends the connection, not one stream: the peer and we
    // no longer agree on where frames begin, so anything further would be
    // read against the wrong offsets. GOAWAY names the last stream that was
    // safe to serve, then closeAfterResponse() lets the write queue drain it
    // before the socket goes away.
    inline void protocolFailure(StreamError code, std::string_view why)
    {
        if (closeAfterResponse_)
            return; // already failing; one GOAWAY is enough
        LOG_ERROR("Multiplexer: protocol error on stream {}: {}", lastPeerStreamId_, why);
        Frame frame;
        frame.type = FrameType::goaway;
        mynetframe::appendBigEndian32(frame.payload, lastPeerStreamId_ & mynetframe::kStreamIdMask);
        mynetframe::appendBigEndian32(frame.payload, std::to_underlying(code));
        frame.payload.append(why);
        appendFrame(outScratch_, frame);
        flushOut();
        closeAfterResponse_ = true;
        onProtocolError(code, why);
    }

    inline void flushOut()
    {
        if (outScratch_.empty())
            return;
        pushResponse(std::move(outScratch_));
        outScratch_.clear();
    }

    static inline void appendSetting(std::string &out, uint16_t id, uint32_t value)
    {
        out.push_back(static_cast<char>((id >> 8) & 0xffu));
        out.push_back(static_cast<char>(id & 0xffu));
        mynetframe::appendBigEndian32(out, value);
    }

    // A PADDED payload carries a length prefix and that many trailing bytes
    // which are not content. Removing them here keeps every reader above this
    // point from re-deriving the same arithmetic.
    inline bool unframePayload(Frame &frame, std::string_view &out)
    {
        std::string_view body(frame.payload);
        if (frame.hasFlag(FrameFlags::kPadded))
        {
            if (body.empty())
            {
                protocolFailure(StreamError::protocolError, "PADDED with an empty payload");
                return false;
            }
            const size_t pad = static_cast<unsigned char>(body.front());
            body.remove_prefix(1);
            if (pad > body.size())
            {
                protocolFailure(StreamError::protocolError, "padding longer than the payload it is padding");
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
    size_t maxStreams_ = mynetmux::kDefaultMaxStreams;
    uint32_t connSendWindow_ = mynetmux::kInitialWindowSize;
    uint32_t connRecvWindow_ = mynetmux::kInitialWindowSize;
    uint32_t initialSendWindow_ = mynetmux::kInitialWindowSize;
    uint32_t lastPeerStreamId_ = 0;
    bool settingsSent_ = false;
    bool goawayReceived_ = false;
};
