#pragma once

#include "hexdump.hpp"
#include "log.hpp"
#include <arpa/inet.h>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <utility>

// The sending half of a datagram, recorded so a reply knows where to go.
//
// A stream connection can be identified by its descriptor and the peer
// address treated as one of that connection's properties. A datagram socket
// has no connections to hang that on: every message carries its own sender,
// and two peers can interleave freely on one descriptor. Keeping the address
// beside the bytes is what makes an unconnected UDP server expressible at all,
// and it is why this pair -- not a bare string -- is what the reply queue
// holds.
struct DatagramReply
{
    sockaddr_in peer{};
    std::string bytes{};
};

// "192.0.2.7:5353", for a log line. A port that did not parse as IPv4 is shown
// as itself rather than silently dropped, because a datagram from an address
// nobody recognises is exactly the one worth seeing.
[[nodiscard]] inline std::string datagramPeerText(const sockaddr_in &peer)
{
    char host[INET_ADDRSTRLEN] = {};
    if (::inet_ntop(AF_INET, &peer.sin_addr, host, sizeof host) == nullptr)
        return std::string("<unnamed>:") + std::to_string(::ntohs(peer.sin_port));
    return std::string(host) + ":" + std::to_string(::ntohs(peer.sin_port));
}

// Protocol front end for one datagram socket.
//
// The same division as HandlerBase -- a handler owns interpretation and
// response production, the transport owns the socket -- with one difference
// the transport forces: onDatagram() arrives with the sender attached, because
// there is no per-connection state to have stashed it in.
//
// There is also no framing to own. UDP preserves message boundaries, so a
// handler is handed one whole datagram and never has to ask whether more bytes
// are coming. What it must decide instead is what to do with a message it will
// not answer, and the base class's answer is: nothing is lost, everything is
// counted. A reply queue that has run past its ceiling drops the newest reply
// and says so, because a socket that silently stops answering is worse to
// debug than one that admits it is behind.
class DatagramHandler
{
public:
    DatagramHandler() noexcept = default;
    virtual ~DatagramHandler() noexcept = default;
    DatagramHandler(const DatagramHandler &) = delete("a datagram handler owns the reply queue for one socket");
    DatagramHandler &operator=(const DatagramHandler &) = delete("a datagram handler owns the reply queue for one socket");
    DatagramHandler(DatagramHandler &&) = delete("a datagram handler owns the reply queue for one socket");
    DatagramHandler &operator=(DatagramHandler &&) = delete("a datagram handler owns the reply queue for one socket");

    // One whole message, and where it came from. Nothing waits for more.
    virtual void onDatagram(const sockaddr_in &peer, const char *data, size_t n) noexcept = 0;

    // Back to a fresh socket's state -- named the same as every other
    // resettable component so a pooled transport can treat it alike.
    virtual void reset() noexcept
    {
        replies_.clear();
        droppedReplies_ = 0;
    }

    // ---- reply side ----
    inline void pushReply(const sockaddr_in &peer, const char *buf, size_t n)
    {
        if (replies_.size() >= maxPendingReplies_)
        {
            ++droppedReplies_;
            LOG_WARN("DatagramHandler: reply queue full ({} pending), dropping a {} byte reply for {}", replies_.size(),
                     n, datagramPeerText(peer));
            return;
        }
        replies_.push_back(DatagramReply{peer, std::string(buf, n)});
    }
    inline void pushReply(const sockaddr_in &peer, std::string bytes)
    {
        if (replies_.size() >= maxPendingReplies_)
        {
            ++droppedReplies_;
            LOG_WARN("DatagramHandler: reply queue full ({} pending), dropping a {} byte reply for {}", replies_.size(),
                     bytes.size(), datagramPeerText(peer));
            return;
        }
        replies_.push_back(DatagramReply{peer, std::move(bytes)});
    }

    [[nodiscard]] inline bool hasReply() const noexcept { return !replies_.empty(); }
    [[nodiscard]] inline size_t replyCount() const noexcept { return replies_.size(); }
    [[nodiscard]] inline const DatagramReply &peekReply() const noexcept { return replies_.front(); }
    inline DatagramReply takeReply()
    {
        DatagramReply out = std::move(replies_.front());
        replies_.pop_front();
        return out;
    }

    // How many replies were refused because the queue was full. A non-zero
    // count is the transport running behind, not a protocol error.
    [[nodiscard]] inline size_t droppedReplies() const noexcept { return droppedReplies_; }

    // The largest datagram this handler will be shown. The socket still
    // receives what it receives; a transport that reads more than this reports
    // the truncated length rather than growing without bound.
    inline void setMaxDatagramBytes(size_t n) noexcept { maxDatagramBytes_ = n; }
    [[nodiscard]] inline size_t maxDatagramBytes() const noexcept { return maxDatagramBytes_; }
    inline void setMaxPendingReplies(size_t n) noexcept { maxPendingReplies_ = n; }
    [[nodiscard]] inline size_t maxPendingReplies() const noexcept { return maxPendingReplies_; }

protected:
    size_t maxDatagramBytes_ = 65535;
    size_t maxPendingReplies_ = 1024;
    size_t droppedReplies_ = 0;
    std::deque<DatagramReply> replies_{};
};

// A datagram front end that writes down whatever arrives, understood or not,
// and sends it back.
//
// The stream version of this (handler.hpp's HandlerTrace) exists for the case
// of a client that speaks something the listener cannot parse; over UDP the
// case is the same and more common, because a datagram socket is where a
// discovery protocol, a QUIC initial packet or a stray scanner all land with
// equal ceremony. Every byte is written down in full, with the sender named
// first, and nothing is truncated -- a deliberate trade for a port someone is
// watching, never a default for real traffic.
class DatagramTrace : public DatagramHandler
{
public:
    void onDatagram(const sockaddr_in &peer, const char *data, size_t n) noexcept override
    {
        LOG_INFO("DatagramTrace: {} sent {} byte(s)", datagramPeerText(peer), n);
        mynetdump::writeDown("DatagramTrace", reinterpret_cast<const unsigned char *>(data), n);
        pushReply(peer, data, n);
    }
};
