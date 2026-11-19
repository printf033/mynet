#include "transport/transport.hpp"
#include "transport/websocket.hpp"
#include "transport/grpc.hpp"
#include <gtest/gtest.h>
#include <string>
#include <vector>

using namespace mynet::transport;

TEST(TransportTest, WebSocketRfcTestVector)
{
    // RFC 6455 Section 1.3 测试用例
    // Key: "dGhlIHNhbXBsZSBub25jZQ=="
    // Expected Accept: "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    std::string key = "dGhlIHNhbXBsZSBub25jZQ==";
    std::string accept = ws::computeAccept(key);
    EXPECT_EQ(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

TEST(TransportTest, WebSocketHandshakeExchange)
{
    ws::WebSocketSession client(false, "/my-ws-path", "example.com");
    ws::WebSocketSession server(true);

    // 1. Client creates handshake HTTP request
    std::string clientReq = client.startClientHandshake();
    EXPECT_TRUE(clientReq.starts_with("GET /my-ws-path HTTP/1.1\r\n"));
    EXPECT_TRUE(clientReq.contains("Host: example.com\r\n"));
    EXPECT_TRUE(clientReq.contains("Upgrade: websocket\r\n"));
    EXPECT_TRUE(clientReq.contains("Sec-WebSocket-Key: "));

    // 2. Server receives client request and replies
    auto serverResp = server.feedClientRequest(clientReq);
    ASSERT_TRUE(serverResp.has_value());
    EXPECT_TRUE(serverResp->starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
    EXPECT_TRUE(serverResp->contains("Sec-WebSocket-Accept: "));
    EXPECT_TRUE(server.isReady());

    // 3. Client processes server response
    bool clientReady = client.feedServerResponse(*serverResp);
    EXPECT_TRUE(clientReady);
    EXPECT_TRUE(client.isReady());
}

TEST(TransportTest, WebSocketFrameMaskedRoundtrip)
{
    // Client sends masked binary frame, Server decodes it
    ws::WebSocketSession client(false, "/ws");
    ws::WebSocketSession server(true, "/ws");

    // Put sessions in streaming state
    auto req = client.startClientHandshake();
    auto resp = server.feedClientRequest(req);
    ASSERT_TRUE(resp.has_value());
    ASSERT_TRUE(client.feedServerResponse(*resp));

    std::string testPayload = "Hello, VLESS over WebSocket! Modern C++26 high-performance proxy transport.";
    std::span<const uint8_t> payloadSpan(reinterpret_cast<const uint8_t *>(testPayload.data()), testPayload.size());

    // Client wraps
    auto wrapped = client.wrapPayload(payloadSpan);
    EXPECT_GT(wrapped.size(), testPayload.size());
    // Client frames must have MASK bit set (byte 1 & 0x80)
    EXPECT_TRUE((wrapped[1] & 0x80) != 0);

    // Server feeds and receives
    std::vector<uint8_t> received;
    server.feedData(wrapped, received);
    std::string receivedStr(reinterpret_cast<const char *>(received.data()), received.size());
    EXPECT_EQ(receivedStr, testPayload);

    // Server sends unmasked binary frame back to Client
    std::string replyPayload = "Echo: Received your payload successfully!";
    std::span<const uint8_t> replySpan(reinterpret_cast<const uint8_t *>(replyPayload.data()), replyPayload.size());

    auto serverWrapped = server.wrapPayload(replySpan);
    // Server frames must NOT have MASK bit set
    EXPECT_FALSE((serverWrapped[1] & 0x80) != 0);

    std::vector<uint8_t> clientReceived;
    client.feedData(serverWrapped, clientReceived);
    std::string clientStr(reinterpret_cast<const char *>(clientReceived.data()), clientReceived.size());
    EXPECT_EQ(clientStr, replyPayload);
}

TEST(TransportTest, WebSocketPingPong)
{
    ws::WebSocketSession server(true);
    // Create streaming state
    std::string dummyReq = ws::buildClientHandshake("/ws", "localhost", "dummyKey123");
    [[maybe_unused]] auto _ = server.feedClientRequest(dummyReq);

    // Send a PING frame to server
    std::vector<uint8_t> pingFrame;
    std::string pingData = "ping-payload";
    ws::encodeFrame(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(pingData.data()), pingData.size()),
                    ws::Opcode::PING, true, pingFrame, {1, 2, 3, 4});

    std::vector<uint8_t> appData;
    server.feedData(pingFrame, appData);
    EXPECT_TRUE(appData.empty()); // Ping is not application data

    // Server should have queued a PONG response
    auto out = server.popOutbound();
    ASSERT_FALSE(out.empty());

    ws::Frame pongFrame;
    size_t consumed = ws::decodeFrame(out, pongFrame);
    EXPECT_GT(consumed, 0u);
    EXPECT_EQ(pongFrame.opcode, ws::Opcode::PONG);
    std::string pongStr(reinterpret_cast<const char *>(pongFrame.payload.data()), pongFrame.payload.size());
    EXPECT_EQ(pongStr, pingData);
}

TEST(TransportTest, GrpcFramingAndHeaders)
{
    // Test H2 headers
    auto h = grpc::buildHeaders("TunService", "grpc.example.com");
    EXPECT_EQ(h.method, "POST");
    EXPECT_EQ(h.scheme, "https");
    EXPECT_EQ(h.path, "/TunService/Tun");
    EXPECT_EQ(h.authority, "grpc.example.com");
    EXPECT_EQ(h.contentType, "application/grpc");

    // Test message encoding & decoding
    std::string sample = "gRPC Protobuf payload test with Gun-lite streaming!";
    std::vector<uint8_t> frame;
    grpc::encodeMessage(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(sample.data()), sample.size()), frame);

    // 5B prefix + 1B (0x0A) + 1B (varint length of sample ~51) + 51B
    EXPECT_EQ(frame[0], 0x00); // uncompressed
    EXPECT_EQ(frame[5], 0x0A); // tag 1, wire-type 2

    std::vector<uint8_t> decoded;
    size_t consumed = grpc::decodeMessage(frame, decoded);
    EXPECT_EQ(consumed, frame.size());
    std::string decodedStr(reinterpret_cast<const char *>(decoded.data()), decoded.size());
    EXPECT_EQ(decodedStr, sample);

    // Test Session wrapper
    grpc::GrpcSession client(false, "TunService", "example.com");
    grpc::GrpcSession server(true, "TunService", "example.com");

    auto msg = client.wrapPayload(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(sample.data()), sample.size()));
    std::vector<uint8_t> appReceived;
    server.feedData(msg, appReceived);
    EXPECT_EQ(std::string(reinterpret_cast<const char *>(appReceived.data()), appReceived.size()), sample);
}
