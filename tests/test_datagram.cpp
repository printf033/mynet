#include "datagram.hpp"
#include "direct/inbound.hpp"
#include "direct/outbound.hpp"
#include <arpa/inet.h>
#include <chrono>
#include <gtest/gtest.h>
#include <string>
#include <thread>
#include <vector>

using namespace mynet;

TEST(DatagramTest, DatagramViewInspection)
{
    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    peer.sin_port = htons(12345);
    ::inet_pton(AF_INET, "1.2.3.4", &peer.sin_addr);

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(53);
    ::inet_pton(AF_INET, "8.8.8.8", &dst.sin_addr);

    const std::string text = "dns_query_payload";
    std::span<const uint8_t> span(reinterpret_cast<const uint8_t *>(text.data()), text.size());

    DatagramView view{
        .peer = peer,
        .origDst = dst,
        .payload = span};

    EXPECT_FALSE(view.empty());
    EXPECT_EQ(view.size(), text.size());
    EXPECT_EQ(view.stringView(), "dns_query_payload");
    EXPECT_TRUE(view.hasOrigDst());

    auto peerAddr = view.peerAddress();
    EXPECT_EQ(peerAddr.host, "1.2.3.4");
    EXPECT_EQ(peerAddr.port, 12345);

    auto dstAddr = view.origDstAddress();
    EXPECT_EQ(dstAddr.host, "8.8.8.8");
    EXPECT_EQ(dstAddr.port, 53);
}

TEST(DatagramTest, DatagramPacketExtended)
{
    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    peer.sin_port = htons(1111);
    ::inet_pton(AF_INET, "10.0.0.1", &peer.sin_addr);

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(53);
    ::inet_pton(AF_INET, "1.1.1.1", &dst.sin_addr);

    Packet packet(peer, dst, "test-data");
    EXPECT_EQ(packet.peer.sin_port, htons(1111));
    EXPECT_EQ(packet.origDst.sin_port, htons(53));
    EXPECT_EQ(packet.bytes, "test-data");
    EXPECT_EQ(packet.size(), 9u);

    packet.clear();
    EXPECT_TRUE(packet.empty());
    EXPECT_EQ(packet.peer.sin_port, 0);
    EXPECT_EQ(packet.origDst.sin_port, 0);
}

TEST(DatagramTest, LifecycleAndSocketOptions)
{
    auto server = Datagram::bind("127.0.0.1", 0);
    ASSERT_TRUE(server.has_value());
    EXPECT_TRUE(server->valid());
    EXPECT_GE(server->fd(), 0);
    EXPECT_GT(server->localPort(), 0);

    EXPECT_TRUE(server->setNonBlocking(true).has_value());
    EXPECT_TRUE(server->setReuseAddr(true).has_value());
    EXPECT_TRUE(server->setReusePort(true).has_value());
    EXPECT_TRUE(server->setBroadcast(true).has_value());
    EXPECT_TRUE(server->setSendBufferSize(65536).has_value());
    EXPECT_TRUE(server->setRecvBufferSize(65536).has_value());

    // Move construct
    Datagram moved = std::move(*server);
    EXPECT_TRUE(moved.valid());
    EXPECT_FALSE(server->valid());

    // Release
    int rawFd = moved.release();
    EXPECT_GE(rawFd, 0);
    EXPECT_FALSE(moved.valid());
    ::close(rawFd);
}

TEST(DatagramTest, LoopbackSendAndRecv)
{
    auto server = Datagram::bind("127.0.0.1", 0);
    ASSERT_TRUE(server.has_value());

    auto client = Datagram::bind("127.0.0.1", 0);
    ASSERT_TRUE(client.has_value());

    const std::string msg = "ping_datagram_test";
    auto sendRes = client->sendTo(server->localAddr(), msg);
    ASSERT_TRUE(sendRes.has_value());
    EXPECT_EQ(*sendRes, msg.size());

    // Wait slightly for socket buffer
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    char buf[256];
    sockaddr_in fromPeer{};
    auto recvRes = server->recvFrom(buf, sizeof(buf), fromPeer);
    ASSERT_TRUE(recvRes.has_value());
    EXPECT_EQ(*recvRes, msg.size());
    EXPECT_EQ(std::string_view(buf, *recvRes), msg);
    EXPECT_EQ(fromPeer.sin_port, client->localAddr().sin_port);

    // Echo reply back
    const std::string reply = "pong_datagram_test";
    auto replyRes = server->sendTo(fromPeer, reply);
    ASSERT_TRUE(replyRes.has_value());
    EXPECT_EQ(*replyRes, reply.size());

    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    sockaddr_in replyPeer{};
    auto recvClient = client->recvFrom(buf, sizeof(buf), replyPeer);
    ASSERT_TRUE(recvClient.has_value());
    EXPECT_EQ(*recvClient, reply.size());
    EXPECT_EQ(std::string_view(buf, *recvClient), reply);
    EXPECT_EQ(replyPeer.sin_port, server->localAddr().sin_port);
}

TEST(DatagramTest, DrainEventLoop)
{
    auto server = Datagram::bind("127.0.0.1", 0);
    ASSERT_TRUE(server.has_value());

    auto client = Datagram::bind("127.0.0.1", 0);
    ASSERT_TRUE(client.has_value());

    // Client sends 3 datagrams
    for (int i = 0; i < 3; ++i)
    {
        std::string payload = "packet_" + std::to_string(i);
        auto s = client->sendTo(server->localAddr(), payload);
        ASSERT_TRUE(s.has_value());
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(15));

    std::vector<std::string> received;
    size_t drained = server->drain([&](const DatagramView &view) {
        received.emplace_back(view.stringView());
    });

    EXPECT_EQ(drained, 3u);
    ASSERT_EQ(received.size(), 3u);
    EXPECT_EQ(received[0], "packet_0");
    EXPECT_EQ(received[1], "packet_1");
    EXPECT_EQ(received[2], "packet_2");

    // Next drain should immediately be 0 (EAGAIN)
    EXPECT_EQ(server->drain([](const DatagramView &) {}), 0u);
}

TEST(DatagramTest, BatchSendAndRecv)
{
    auto server = Datagram::bind("127.0.0.1", 0);
    ASSERT_TRUE(server.has_value());

    auto client = Datagram::bind("127.0.0.1", 0);
    ASSERT_TRUE(client.has_value());

    std::vector<Packet> outgoing;
    for (int i = 0; i < 4; ++i)
    {
        outgoing.emplace_back(server->localAddr(), "batch_msg_" + std::to_string(i));
    }

    auto sentRes = client->sendBatch(outgoing);
    ASSERT_TRUE(sentRes.has_value());
    EXPECT_EQ(*sentRes, 4u);

    std::this_thread::sleep_for(std::chrono::milliseconds(15));

    std::vector<Packet> incoming(4);
    auto recvRes = server->recvBatch(incoming);
    ASSERT_TRUE(recvRes.has_value());
    EXPECT_EQ(*recvRes, 4u);

    for (int i = 0; i < 4; ++i)
    {
        EXPECT_EQ(incoming[i].bytes, "batch_msg_" + std::to_string(i));
        EXPECT_EQ(incoming[i].peer.sin_port, client->localAddr().sin_port);
    }
}

TEST(DatagramTest, AcceptorAndDialerDatagram)
{
    // AcceptorDatagram
    AcceptorDatagram acceptor("dgram-in", "127.0.0.1", 0);
    EXPECT_EQ(acceptor.tag(), "dgram-in");
    EXPECT_EQ(acceptor.type(), "datagram");
    EXPECT_FALSE(acceptor.running());

    auto listenRes = acceptor.listen();
    ASSERT_TRUE(listenRes.has_value());
    EXPECT_TRUE(acceptor.running());
    EXPECT_TRUE(acceptor.datagram().valid());
    EXPECT_GT(acceptor.port(), 0);

    acceptor.close();
    EXPECT_FALSE(acceptor.running());
    EXPECT_FALSE(acceptor.datagram().valid());

    // DialerDatagram
    DialerDatagram dialer("dgram-out");
    EXPECT_EQ(dialer.tag(), "dgram-out");
    EXPECT_EQ(dialer.type(), "datagram");

    Address target = Address::fromIPv4(0x08080808, 53);
    auto dialRes = dialer.dialDatagram(target);
    ASSERT_TRUE(dialRes.has_value());
    EXPECT_GE(*dialRes, 0);
    ::close(*dialRes);

    auto endpointRes = dialer.dialDatagramEndpoint(target);
    ASSERT_TRUE(endpointRes.has_value());
    EXPECT_TRUE(endpointRes->valid());
    endpointRes->close();

    // DialerDirect::dialDatagram
    DialerDirect directDialer("direct");
    auto directUdp = directDialer.dialDatagram(target);
    ASSERT_TRUE(directUdp.has_value());
    EXPECT_GE(*directUdp, 0);
    ::close(*directUdp);
}

TEST(DatagramTest, SharedFlushBatchAndDrainDatagramSocketReuse)
{
    auto server = Datagram::bind("127.0.0.1", 0);
    auto client = Datagram::bind("127.0.0.1", 0);
    ASSERT_TRUE(server.has_value());
    ASSERT_TRUE(client.has_value());

    // 测试 Datagram::sendPackets 复用 Datagram::sendBatch（并正确补全 fallbackPeer）
    Handler outHandler;
    sockaddr_in emptyPeer{};
    outHandler.sendTo(emptyPeer, "batch-0", 7);
    outHandler.sendTo(emptyPeer, "batch-1", 7);
    outHandler.sendTo(emptyPeer, "batch-2", 7);
    EXPECT_EQ(outHandler.outgoingCount(), 3u);

    auto batch = outHandler.takeAllOutgoing();
    client->sendPackets(batch, server->localAddr());
    EXPECT_FALSE(outHandler.hasOutgoing());

    std::vector<std::string> got;
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    (void)server->drain(
        [&](const DatagramView &v)
        {
            got.emplace_back(v.stringView());
        });
    ASSERT_EQ(got.size(), 3u);
    EXPECT_EQ(got[0], "batch-0");
    EXPECT_EQ(got[1], "batch-1");
    EXPECT_EQ(got[2], "batch-2");
}
