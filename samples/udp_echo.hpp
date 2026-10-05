#pragma once

#include "datagram.hpp"
#include "handler.hpp"

// The datagram samples' front end.
//
// An EventSocket's handler must derive from HandlerBase, and a datagram
// transport additionally requires DatagramHandler; one class answers to both,
// which is what lets the same handler be reached through the stream-shaped
// event type without the datagram transports being a separate world.
//
// The stream half is deliberately inert -- there is no stream protocol on a
// datagram socket -- and the datagram half does the work: every message is
// written down in full, sender included, and sent back unchanged.
class UdpEcho : public HandlerBase, public DatagramHandler
{
public:
    // Nothing on this socket is a stream, so no bytes accumulate here and the
    // base class's response queue is never the path a reply takes.
    void process() {}

    void reset() noexcept override
    {
        HandlerBase::reset();
        DatagramHandler::reset();
    }

    void onDatagram(const sockaddr_in &peer, const char *data, size_t n) noexcept override
    {
        LOG_INFO("UdpEcho: {} sent {} byte(s)", datagramPeerText(peer), n);
        mynetdump::writeDown("UdpEcho", reinterpret_cast<const unsigned char *>(data), n);
        pushReply(peer, data, n);
    }
};
