#pragma once

#include "buffer.hpp"
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

// Stream framing, in the shape HTTP/2 defines it.
//
// A multiplexed connection carries many logical exchanges over one byte
// stream, and the only way that works is if every byte belongs to exactly one
// of them. That is what a frame header buys: a length, a type, a flag byte and
// a stream identifier, so a reader can skip or route a frame it does not
// understand without guessing where it ends.
//
// The header is HTTP/2's, byte for byte, and that is deliberate. The hard part
// of h2 is not this struct -- it is HPACK, the settings dance and the state
// machine -- and none of those are baked in here. What is baked in is the one
// layout the rest of the world already parses, so an h3 (or custom) protocol
// on top of this codec stays a wire-compatible cousin rather than a private
// dialect nobody else can read.
//
//   +-----------------------------------------------+
//   |                 Length (24)                   |
//   +---------------+---------------+---------------+
//   |   Type (8)    |   Flags (8)   |               |
//   +-+-------------+---------------+---------------+
//   |R|            Stream Identifier (31)           |
//   +=+=============================================+
//   |                   Frame Payload (0...)      ...
//   +-----------------------------------------------+
//
// The reserved bit must be zero on the wire; a reader that meets it reports an
// error instead of masking it away, because a peer that sets it is speaking a
// different protocol than the one this decoder was told to read.
namespace mynetframe
{
    // Nine bytes of header, then the payload it counts.
    inline constexpr size_t kHeaderBytes = 9;

    // 16 KiB is HTTP/2's own default maximum frame size, and the value both
    // ends advertise in SETTINGS. A larger frame is not "bigger data", it is a
    // claim about a protocol this decoder has not agreed to.
    inline constexpr uint32_t kDefaultMaxFrameSize = 16384;

    // The reserved bit of the stream identifier field.
    inline constexpr uint8_t kStreamIdReservedMask = 0x80;
    inline constexpr uint32_t kStreamIdMask = 0x7fffffffu;

    inline void appendBigEndian32(std::string &out, uint32_t value)
    {
        out.push_back(static_cast<char>((value >> 24) & 0xffu));
        out.push_back(static_cast<char>((value >> 16) & 0xffu));
        out.push_back(static_cast<char>((value >> 8) & 0xffu));
        out.push_back(static_cast<char>(value & 0xffu));
    }

    [[nodiscard]] inline uint32_t readBigEndian32(const char *p) noexcept
    {
        const auto *b = reinterpret_cast<const unsigned char *>(p);
        return (static_cast<uint32_t>(b[0]) << 24) | (static_cast<uint32_t>(b[1]) << 16) |
               (static_cast<uint32_t>(b[2]) << 8) | static_cast<uint32_t>(b[3]);
    }
} // namespace mynetframe

enum class FrameType : uint8_t
{
    data = 0x0,
    headers = 0x1,
    priority = 0x2,
    reset = 0x3,
    settings = 0x4,
    pushPromise = 0x5,
    ping = 0x6,
    goaway = 0x7,
    windowUpdate = 0x8,
};

// Flags are only flags in the company of a frame type: bit 0 means END_STREAM
// on DATA and ACK on SETTINGS and PING, which is why they share a namespace
// with the type's name spelled out.
namespace FrameFlags
{
    inline constexpr uint8_t kEndStream = 0x1;
    inline constexpr uint8_t kAck = 0x1;
    inline constexpr uint8_t kEndHeaders = 0x4;
    inline constexpr uint8_t kPadded = 0x8;
    inline constexpr uint8_t kPriority = 0x20;
} // namespace FrameFlags

enum class FrameError : uint8_t
{
    frameTooLarge,
    reservedBitSet,
};

[[nodiscard]] constexpr std::string_view to_string(FrameError err) noexcept
{
    switch (err)
    {
    case FrameError::frameTooLarge:
        return "frame length exceeds the configured maximum";
    case FrameError::reservedBitSet:
        return "the reserved bit of the stream identifier was set";
    }
    return "unknown framing error";
}

struct Frame
{
    uint32_t streamId = 0;
    FrameType type = FrameType::data;
    uint8_t flags = 0;
    std::string payload{};

    [[nodiscard]] inline bool hasFlag(uint8_t flag) const noexcept { return (flags & flag) != 0; }
};

// One frame at a time, out of whatever bytes have arrived so far.
//
// The decoder is stateless by design: a frame is a prefix of the buffer or it
// is not, so an interrupted read needs no bookkeeping to resume -- the bytes
// stay where they were and the next call re-reads the same header. That is
// also why it reports three outcomes rather than two. "Not yet" and "not ever"
// are different answers, and collapsing them into one empty result is how a
// peer gets a protocol error for arriving in two packets.
class FrameDecoder
{
public:
    FrameDecoder() noexcept = default;

    inline void setMaxFrameSize(uint32_t n) noexcept
    {
        maxFrameSize_ = n == 0 ? mynetframe::kDefaultMaxFrameSize : n;
    }
    [[nodiscard]] inline uint32_t maxFrameSize() const noexcept { return maxFrameSize_; }

    // nullopt  -- fewer bytes than one whole frame; read more and call again.
    // Frame    -- one whole frame, already consumed from `in`.
    // FrameError -- the byte stream cannot become a legal frame no matter how
    //               much more arrives, so the connection is out of contract.
    [[nodiscard]] inline std::expected<std::optional<Frame>, FrameError> next(Buffer &in) const
    {
        const size_t available = in.readableBytes();
        if (available < mynetframe::kHeaderBytes)
            return std::optional<Frame>{};

        const auto *p = reinterpret_cast<const unsigned char *>(in.readableBegin());
        const uint32_t length =
            (static_cast<uint32_t>(p[0]) << 16) | (static_cast<uint32_t>(p[1]) << 8) | static_cast<uint32_t>(p[2]);
        if (length > maxFrameSize_)
            return std::unexpected(FrameError::frameTooLarge);
        if (available < mynetframe::kHeaderBytes + static_cast<size_t>(length))
            return std::optional<Frame>{};
        if ((p[5] & mynetframe::kStreamIdReservedMask) != 0)
            return std::unexpected(FrameError::reservedBitSet);

        Frame frame;
        frame.streamId = (static_cast<uint32_t>(p[5] & 0x7fu) << 24) | (static_cast<uint32_t>(p[6]) << 16) |
                         (static_cast<uint32_t>(p[7]) << 8) | static_cast<uint32_t>(p[8]);
        frame.type = static_cast<FrameType>(p[3]);
        frame.flags = p[4];
        frame.payload.assign(in.readableBegin() + mynetframe::kHeaderBytes, length);
        in.retrieve(mynetframe::kHeaderBytes + static_cast<size_t>(length));
        return std::optional<Frame>{std::move(frame)};
    }

private:
    uint32_t maxFrameSize_ = mynetframe::kDefaultMaxFrameSize;
};

// Append one frame, header first, in network order -- most significant byte
// first, in the one layout every reader of this codec already knows.
inline void appendFrame(std::string &out, const Frame &frame)
{
    const uint32_t length = static_cast<uint32_t>(frame.payload.size());
    const uint32_t streamId = frame.streamId & mynetframe::kStreamIdMask;
    out.push_back(static_cast<char>((length >> 16) & 0xffu));
    out.push_back(static_cast<char>((length >> 8) & 0xffu));
    out.push_back(static_cast<char>(length & 0xffu));
    out.push_back(static_cast<char>(std::to_underlying(frame.type)));
    out.push_back(static_cast<char>(frame.flags));
    out.push_back(static_cast<char>((streamId >> 24) & 0x7fu));
    out.push_back(static_cast<char>((streamId >> 16) & 0xffu));
    out.push_back(static_cast<char>((streamId >> 8) & 0xffu));
    out.push_back(static_cast<char>(streamId & 0xffu));
    out.append(frame.payload);
}
