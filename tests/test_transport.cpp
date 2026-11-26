#include "cipher.hpp"
#include "encoding.hpp"
#include "grpc/grpc.hpp"
#include "requestBuffer.hpp"
#include "responseQueue.hpp"
#include "tls/fragmenter.hpp"
#include "transport.hpp"
#include "websocket/websocket.hpp"
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
    grpc::encodeMessage(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(sample.data()), sample.size()),
                        frame);

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

    auto msg =
        client.wrapPayload(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(sample.data()), sample.size()));
    std::vector<uint8_t> appReceived;
    server.feedData(msg, appReceived);
    EXPECT_EQ(std::string(reinterpret_cast<const char *>(appReceived.data()), appReceived.size()), sample);
}

TEST(TransportTest, EncodingBase64UrlRoundtrip)
{
    const std::vector<uint8_t> raw{0xFB, 0xFF, 0x3E, 0x00, 0x12, 0x89, 0xAB};
    const std::string noPad = mynet::encoding::base64UrlEncode(raw, false);
    const std::string withPad = mynet::encoding::base64UrlEncode(raw, true);
    EXPECT_EQ(noPad.find('+'), std::string::npos);
    EXPECT_EQ(noPad.find('/'), std::string::npos);
    EXPECT_EQ(noPad.find('='), std::string::npos);
    EXPECT_NE(withPad.find('='), std::string::npos);

    std::vector<uint8_t> decoded;
    ASSERT_TRUE(mynet::encoding::base64UrlDecode(noPad, decoded));
    EXPECT_EQ(decoded, raw);

    decoded.clear();
    ASSERT_TRUE(mynet::encoding::base64UrlDecode(withPad, decoded));
    EXPECT_EQ(decoded, raw);
}

TEST(TransportTest, AeadCipherContextStatefulReuseAndNonceIncrement)
{
    using namespace mynet::cipher;
    auto algo = parseAeadAlgorithm("aes-128-gcm");
    ASSERT_TRUE(algo.has_value());
    EXPECT_EQ(*algo, AeadAlgorithm::AES_128_GCM);
    const EVP_CIPHER *evp = resolveEvpCipher(*algo);
    ASSERT_NE(evp, nullptr);

    std::array<uint8_t, 16> key{};
    for (size_t i = 0; i < key.size(); ++i)
    {
        key[i] = static_cast<uint8_t>(i + 1);
    }

    AeadCipherContext encCtx;
    AeadCipherContext decCtx;
    ASSERT_TRUE(encCtx.init(evp, key, true, 12));
    ASSERT_TRUE(decCtx.init(evp, key, false, 12));
    EXPECT_TRUE(encCtx.valid());

    std::array<uint8_t, 12> encNonce{};
    std::array<uint8_t, 12> decNonce{};
    for (int round = 0; round < 3; ++round)
    {
        const std::string msg = "aead-reuse-round-" + std::to_string(round);
        std::span<const uint8_t> pt(reinterpret_cast<const uint8_t *>(msg.data()), msg.size());
        std::vector<uint8_t> ct;
        std::array<uint8_t, 16> tag{};
        ASSERT_TRUE(encCtx.encrypt(encNonce, {}, pt, ct, tag));
        incrementLittleEndianNonce(encNonce);

        std::vector<uint8_t> outPt;
        ASSERT_TRUE(decCtx.decrypt(decNonce, {}, ct, tag, outPt));
        incrementLittleEndianNonce(decNonce);
        EXPECT_EQ(std::string(reinterpret_cast<const char *>(outPt.data()), outPt.size()), msg);
    }

    // 篡改密文必须鉴权失败
    std::vector<uint8_t> ct;
    std::array<uint8_t, 16> tag{};
    const std::string msg = "tamper-test";
    ASSERT_TRUE(encCtx.encrypt(encNonce, {},
                               std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(msg.data()), msg.size()), ct,
                               tag));
    ct[0] ^= 0xFF;
    std::vector<uint8_t> badPt;
    EXPECT_FALSE(decCtx.decrypt(decNonce, {}, ct, tag, badPt));
}

TEST(TransportTest, TransportPipelineWebSocketAsyncHandshakeAndFraming)
{
    TransportPipeline clientPipe;
    TransportPipeline serverPipe;
    clientPipe.addLayer(std::make_unique<mynet::websocket::WebSocketSession>(false, "/tun", "cdn.example.com"));
    serverPipe.addLayer(std::make_unique<mynet::websocket::WebSocketSession>(true, "/tun", "cdn.example.com"));

    mynet::ResponseQueue clientWire;
    mynet::ResponseQueue serverWire;
    ASSERT_TRUE(clientWire.init(32));
    ASSERT_TRUE(serverWire.init(32));
    mynet::RequestBuffer clientAppRx;
    mynet::RequestBuffer serverAppRx;
    mynet::RequestBuffer clientWireRx;
    mynet::RequestBuffer serverWireRx;

    ASSERT_TRUE(clientPipe.startHandshake(clientWire));
    ASSERT_FALSE(clientWire.empty());

    // Client -> Server (HTTP Upgrade)
    while (!clientWire.empty())
    {
        auto pkt = std::move(clientWire.front());
        clientWire.pop();
        ASSERT_TRUE(serverWireRx.append(pkt.bytes.data(), pkt.bytes.size()));
    }
    ASSERT_TRUE(serverPipe.processInbound(serverWireRx, serverAppRx, serverWire));
    EXPECT_TRUE(serverPipe.isReady());
    EXPECT_FALSE(serverWire.empty());

    // Server -> Client (101 Switching Protocols)
    while (!serverWire.empty())
    {
        auto pkt = std::move(serverWire.front());
        serverWire.pop();
        ASSERT_TRUE(clientWireRx.append(pkt.bytes.data(), pkt.bytes.size()));
    }
    ASSERT_TRUE(clientPipe.processInbound(clientWireRx, clientAppRx, clientWire));
    EXPECT_TRUE(clientPipe.isReady());

    // App data Client -> Server & Server -> Client
    const std::string ping = "ws-pipeline-hello";
    ASSERT_TRUE(clientPipe.processOutbound(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(ping.data()), ping.size()), clientWire));
    while (!clientWire.empty())
    {
        auto pkt = std::move(clientWire.front());
        clientWire.pop();
        ASSERT_TRUE(serverWireRx.append(pkt.bytes.data(), pkt.bytes.size()));
    }
    ASSERT_TRUE(serverPipe.processInbound(serverWireRx, serverAppRx, serverWire));
    EXPECT_EQ(serverAppRx.readableView(), ping);
}

TEST(TransportTest, UnifiedClientHelloParserExtractsSniSessionAndKeyShare)
{
    std::vector<uint8_t> extensions;
    // SNI extension (0x0000): "cdn.test"
    const std::string host = "cdn.test";
    const uint16_t sniListLen = static_cast<uint16_t>(3 + host.size());
    const uint16_t sniExtLen = static_cast<uint16_t>(2 + sniListLen);
    extensions.insert(extensions.end(), {0x00, 0x00, static_cast<uint8_t>(sniExtLen >> 8),
                                         static_cast<uint8_t>(sniExtLen & 0xFF),
                                         static_cast<uint8_t>(sniListLen >> 8),
                                         static_cast<uint8_t>(sniListLen & 0xFF), 0x00,
                                         0x00, static_cast<uint8_t>(host.size())});
    extensions.insert(extensions.end(), host.begin(), host.end());

    // KeyShare extension (0x0033): X25519 (0x001D), 32 bytes filled with 0xAB
    extensions.insert(extensions.end(), {0x00, 0x33, 0x00, 38, 0x00, 36, 0x00, 0x1D, 0x00, 32});
    extensions.insert(extensions.end(), 32, 0xAB);

    std::vector<uint8_t> chBody;
    chBody.insert(chBody.end(), {0x03, 0x03});           // TLS 1.2 legacy version
    chBody.insert(chBody.end(), 32, 0x11);               // ClientRandom
    chBody.push_back(4);                                 // SessionID len = 4
    chBody.insert(chBody.end(), {0xCA, 0xFE, 0xBA, 0xBE});
    chBody.insert(chBody.end(), {0x00, 0x02, 0x13, 0x01}); // CipherSuites
    chBody.insert(chBody.end(), {0x01, 0x00});             // Compression
    chBody.push_back(static_cast<uint8_t>(extensions.size() >> 8));
    chBody.push_back(static_cast<uint8_t>(extensions.size() & 0xFF));
    chBody.insert(chBody.end(), extensions.begin(), extensions.end());

    std::vector<uint8_t> record;
    record.reserve(16 + chBody.size());
    record.push_back(0x16);
    record.push_back(0x03);
    record.push_back(0x01);
    const uint16_t recLen = static_cast<uint16_t>(4 + chBody.size());
    record.push_back(static_cast<uint8_t>(recLen >> 8));
    record.push_back(static_cast<uint8_t>(recLen & 0xFF));
    record.push_back(0x01); // ClientHello
    record.push_back(0x00);
    record.push_back(static_cast<uint8_t>(chBody.size() >> 8));
    record.push_back(static_cast<uint8_t>(chBody.size() & 0xFF));
    record.insert(record.end(), chBody.begin(), chBody.end());

    auto parsed = mynet::tls::TlsFragmenter::parseClientHello(record);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->serverName, "cdn.test");
    EXPECT_EQ(parsed->sessionIdLength, 4u);
    ASSERT_TRUE(parsed->hasKeyShare);
    EXPECT_EQ(parsed->keyShareX25519[0], 0xAB);
    EXPECT_EQ(parsed->keyShareX25519[31], 0xAB);
}
