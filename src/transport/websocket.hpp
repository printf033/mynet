#pragma once

/**
 * @file transport/websocket.hpp
 * @brief RFC 6455 WebSocket 协议编解码与会话实现
 */

#include "../digest.hpp"
#include "../encoding.hpp"
#include "transport.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <expected>
#include <openssl/rand.h>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mynet::transport::ws
{

    inline constexpr std::string_view kWsGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    enum class Opcode : uint8_t
    {
        CONTINUATION = 0x0,
        TEXT = 0x1,
        BINARY = 0x2,
        CLOSE = 0x8,
        PING = 0x9,
        PONG = 0xA
    };

    struct Frame
    {
        bool fin{true};
        Opcode opcode{Opcode::BINARY};
        bool masked{false};
        std::array<uint8_t, 4> maskKey{};
        std::vector<uint8_t> payload{};
    };

    /**
     * @brief 计算 WebSocket 握手 Sec-WebSocket-Accept 签名
     */
    [[nodiscard]] inline std::string computeAccept(std::string_view secKey)
    {
        std::string combined(secKey);
        combined.append(kWsGuid);
        auto hash = mynet::digest::sha1(
            std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(combined.data()), combined.size()));
        if (!hash.has_value())
        {
            return {};
        }
        return mynet::encoding::base64Encode(std::span<const uint8_t>(hash->data(), hash->size()));
    }

    /**
     * @brief 生成 16 字节随机 Sec-WebSocket-Key (Base64 字符串)
     */
    [[nodiscard]] inline std::string generateKey()
    {
        std::array<uint8_t, 16> randomBytes{};
        if (RAND_bytes(randomBytes.data(), static_cast<int>(randomBytes.size())) != 1)
        {
            // 降级使用伪随机
            for (auto &b : randomBytes)
            {
                b = static_cast<uint8_t>(rand() & 0xFF);
            }
        }
        return mynet::encoding::base64Encode(std::span<const uint8_t>(randomBytes.data(), randomBytes.size()));
    }

    /**
     * @brief 构建客户端 HTTP/1.1 Upgrade 握手报文
     */
    [[nodiscard]] inline std::string buildClientHandshake(std::string_view path, std::string_view host,
                                                          std::string_view key, std::string_view earlyData = {})
    {
        std::string req;
        req.reserve(256 + earlyData.size());
        req.append("GET ");
        req.append(path.empty() ? "/" : path);
        req.append(" HTTP/1.1\r\nHost: ");
        req.append(host);
        req.append("\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ");
        req.append(key);
        req.append("\r\nSec-WebSocket-Version: 13\r\n");
        if (!earlyData.empty())
        {
            req.append("Sec-WebSocket-Protocol: ");
            req.append(earlyData);
            req.append("\r\n");
        }
        req.append("\r\n");
        return req;
    }

    /**
     * @brief 解析客户端 HTTP/1.1 Upgrade 握手请求
     */
    struct ClientHandshakeInfo
    {
        std::string path{};
        std::string host{};
        std::string secKey{};
        std::string earlyData{};
    };

    [[nodiscard]] inline std::optional<ClientHandshakeInfo> parseClientHandshake(std::string_view request)
    {
        auto crlfPos = request.find("\r\n\r\n");
        if (crlfPos == std::string_view::npos)
        {
            return std::nullopt;
        }

        std::string_view headerBlock = request.substr(0, crlfPos);
        auto lineEnd = headerBlock.find("\r\n");
        if (lineEnd == std::string_view::npos)
        {
            return std::nullopt;
        }

        std::string_view reqLine = headerBlock.substr(0, lineEnd);
        if (!reqLine.starts_with("GET "))
        {
            return std::nullopt;
        }
        auto sp2 = reqLine.find(' ', 4);
        if (sp2 == std::string_view::npos)
        {
            return std::nullopt;
        }
        ClientHandshakeInfo info;
        info.path = std::string(reqLine.substr(4, sp2 - 4));

        std::string_view rest = headerBlock.substr(lineEnd + 2);
        bool isUpgradeWs = false;
        bool isConnectionUpgrade = false;

        while (!rest.empty())
        {
            auto nextLine = rest.find("\r\n");
            std::string_view line = (nextLine == std::string_view::npos) ? rest : rest.substr(0, nextLine);
            if (nextLine == std::string_view::npos)
            {
                rest = {};
            }
            else
            {
                rest = rest.substr(nextLine + 2);
            }

            auto colon = line.find(':');
            if (colon == std::string_view::npos)
            {
                continue;
            }
            std::string key(line.substr(0, colon));
            std::transform(key.begin(), key.end(), key.begin(), ::tolower);
            std::string_view val = line.substr(colon + 1);
            while (!val.empty() && (val.front() == ' ' || val.front() == '\t'))
            {
                val.remove_prefix(1);
            }

            if (key == "host")
            {
                info.host = std::string(val);
            }
            else if (key == "upgrade")
            {
                std::string vLower(val);
                std::transform(vLower.begin(), vLower.end(), vLower.begin(), ::tolower);
                if (vLower == "websocket")
                {
                    isUpgradeWs = true;
                }
            }
            else if (key == "connection")
            {
                std::string vLower(val);
                std::transform(vLower.begin(), vLower.end(), vLower.begin(), ::tolower);
                if (vLower.find("upgrade") != std::string::npos)
                {
                    isConnectionUpgrade = true;
                }
            }
            else if (key == "sec-websocket-key")
            {
                info.secKey = std::string(val);
            }
            else if (key == "sec-websocket-protocol")
            {
                info.earlyData = std::string(val);
            }
        }

        if (!isUpgradeWs || !isConnectionUpgrade || info.secKey.empty())
        {
            return std::nullopt;
        }
        return info;
    }

    /**
     * @brief 构建服务端 101 Switching Protocols 响应
     */
    [[nodiscard]] inline std::string buildServerHandshake(std::string_view secKey)
    {
        std::string accept = computeAccept(secKey);
        std::string resp;
        resp.reserve(160);
        resp.append("HTTP/1.1 101 Switching Protocols\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    "Sec-WebSocket-Accept: ");
        resp.append(accept);
        resp.append("\r\n\r\n");
        return resp;
    }

    /**
     * @brief 验证服务端响应是否为 101 Switching Protocols 且 Accept 签名正确
     */
    [[nodiscard]] inline bool validateServerHandshake(std::string_view response, std::string_view secKey)
    {
        if (!response.starts_with("HTTP/1.1 101") && !response.starts_with("HTTP/1.0 101"))
        {
            return false;
        }
        std::string expectedAccept = computeAccept(secKey);
        auto acceptPos = response.find("Sec-WebSocket-Accept:");
        if (acceptPos == std::string_view::npos)
        {
            acceptPos = response.find("sec-websocket-accept:");
        }
        if (acceptPos == std::string_view::npos)
        {
            return false;
        }
        auto lineEnd = response.find("\r\n", acceptPos);
        auto val = response.substr(acceptPos + 21, (lineEnd == std::string_view::npos) ? std::string_view::npos
                                                                                       : lineEnd - (acceptPos + 21));
        while (!val.empty() && (val.front() == ' ' || val.front() == '\t'))
        {
            val.remove_prefix(1);
        }
        while (!val.empty() && (val.back() == ' ' || val.back() == '\t' || val.back() == '\r'))
        {
            val.remove_suffix(1);
        }
        return val == expectedAccept;
    }

    /**
     * @brief RFC 6455 帧序列化
     */
    inline void encodeFrame(std::span<const uint8_t> payload, Opcode opcode, bool masked, std::vector<uint8_t> &out,
                            std::array<uint8_t, 4> maskKey = {0, 0, 0, 0})
    {
        const size_t payloadLen = payload.size();
        uint8_t b0 = 0x80 | (static_cast<uint8_t>(opcode) & 0x0F);
        out.push_back(b0);

        uint8_t maskBit = masked ? 0x80 : 0x00;
        if (payloadLen < 126)
        {
            out.push_back(maskBit | static_cast<uint8_t>(payloadLen));
        }
        else if (payloadLen <= 0xFFFF)
        {
            out.push_back(maskBit | 126);
            out.push_back(static_cast<uint8_t>((payloadLen >> 8) & 0xFF));
            out.push_back(static_cast<uint8_t>(payloadLen & 0xFF));
        }
        else
        {
            out.push_back(maskBit | 127);
            for (int i = 7; i >= 0; --i)
            {
                out.push_back(static_cast<uint8_t>((payloadLen >> (i * 8)) & 0xFF));
            }
        }

        if (masked)
        {
            if (maskKey[0] == 0 && maskKey[1] == 0 && maskKey[2] == 0 && maskKey[3] == 0)
            {
                if (RAND_bytes(maskKey.data(), 4) != 1)
                {
                    maskKey = {0x12, 0x34, 0x56, 0x78};
                }
            }
            out.insert(out.end(), maskKey.begin(), maskKey.end());
            const size_t startOffset = out.size();
            out.resize(startOffset + payloadLen);
            for (size_t i = 0; i < payloadLen; ++i)
            {
                out[startOffset + i] = payload[i] ^ maskKey[i % 4];
            }
        }
        else
        {
            out.insert(out.end(), payload.begin(), payload.end());
        }
    }

    /**
     * @brief RFC 6455 帧解析
     * @return 返回消费的字节数 (0 表示数据未完整)
     */
    inline size_t decodeFrame(std::span<const uint8_t> data, Frame &out)
    {
        if (data.size() < 2)
        {
            return 0;
        }

        const uint8_t b0 = data[0];
        const uint8_t b1 = data[1];

        out.fin = (b0 & 0x80) != 0;
        out.opcode = static_cast<Opcode>(b0 & 0x0F);
        out.masked = (b1 & 0x80) != 0;

        uint64_t payloadLen = b1 & 0x7F;
        size_t headerLen = 2;

        if (payloadLen == 126)
        {
            if (data.size() < 4)
            {
                return 0;
            }
            payloadLen = (static_cast<uint64_t>(data[2]) << 8) | data[3];
            headerLen += 2;
        }
        else if (payloadLen == 127)
        {
            if (data.size() < 10)
            {
                return 0;
            }
            payloadLen = 0;
            for (size_t i = 0; i < 8; ++i)
            {
                payloadLen = (payloadLen << 8) | data[2 + i];
            }
            headerLen += 8;
        }

        if (out.masked)
        {
            if (data.size() < headerLen + 4)
            {
                return 0;
            }
            std::memcpy(out.maskKey.data(), data.data() + headerLen, 4);
            headerLen += 4;
        }

        if (data.size() < headerLen + payloadLen)
        {
            return 0;
        }

        out.payload.resize(payloadLen);
        const uint8_t *rawPayload = data.data() + headerLen;
        if (out.masked)
        {
            for (size_t i = 0; i < payloadLen; ++i)
            {
                out.payload[i] = rawPayload[i] ^ out.maskKey[i % 4];
            }
        }
        else
        {
            std::memcpy(out.payload.data(), rawPayload, payloadLen);
        }

        return headerLen + payloadLen;
    }

    /**
     * @brief WebSocket 传输层会话处理器
     */
    class WebSocketSession : public ITransport
    {
    private:
        bool isServer_{false};
        TransportState state_{TransportState::INITIAL};
        std::string path_{"/"};
        std::string host_{};
        std::string secKey_{};

        std::vector<uint8_t> inBuffer_{};
        std::vector<uint8_t> outBuffer_{};

    public:
        explicit WebSocketSession(bool isServer, std::string path = "/", std::string host = "")
            : isServer_(isServer),
              state_(TransportState::INITIAL),
              path_(std::move(path)),
              host_(std::move(host))
        {
        }

        [[nodiscard]] TransportType type() const noexcept override { return TransportType::WEBSOCKET; }
        [[nodiscard]] TransportState state() const noexcept override { return state_; }
        [[nodiscard]] bool isReady() const noexcept override { return state_ == TransportState::STREAMING; }

        void reset() noexcept override
        {
            state_ = TransportState::INITIAL;
            secKey_.clear();
            inBuffer_.clear();
            outBuffer_.clear();
        }

        /**
         * @brief 发起客户端握手，生成发往服务端的 HTTP Upgrade 请求报文
         */
        [[nodiscard]] std::string startClientHandshake()
        {
            state_ = TransportState::HANDSHAKING;
            secKey_ = generateKey();
            return buildClientHandshake(path_, host_, secKey_);
        }

        /**
         * @brief 处理服务端响应数据
         */
        [[nodiscard]] bool feedServerResponse(std::string_view response)
        {
            if (state_ != TransportState::HANDSHAKING)
            {
                return false;
            }
            if (validateServerHandshake(response, secKey_))
            {
                state_ = TransportState::STREAMING;
                return true;
            }
            state_ = TransportState::FAILED;
            return false;
        }

        /**
         * @brief 服务端处理客户端握手请求，并生成 101 响应报文
         */
        [[nodiscard]] std::optional<std::string> feedClientRequest(std::string_view request)
        {
            auto info = parseClientHandshake(request);
            if (!info.has_value())
            {
                state_ = TransportState::FAILED;
                return std::nullopt;
            }
            secKey_ = info->secKey;
            path_ = info->path;
            host_ = info->host;
            state_ = TransportState::STREAMING;
            return buildServerHandshake(secKey_);
        }

        /**
         * @brief 将上层应用数据封装为 WebSocket 二进制帧
         */
        [[nodiscard]] std::vector<uint8_t> wrapPayload(std::span<const uint8_t> raw)
        {
            std::vector<uint8_t> out;
            // 客户端发出的帧必须 MASK；服务端发出的帧不加 MASK
            encodeFrame(raw, Opcode::BINARY, !isServer_, out);
            return out;
        }

        /**
         * @brief 输入底层字节流，解析提取出应用层有效载荷 (剥离 WS 帧头与控制帧)
         */
        void feedData(std::span<const uint8_t> incoming, std::vector<uint8_t> &appData)
        {
            if (state_ != TransportState::STREAMING)
            {
                return;
            }
            inBuffer_.insert(inBuffer_.end(), incoming.begin(), incoming.end());

            while (!inBuffer_.empty())
            {
                Frame frame;
                size_t consumed = decodeFrame(std::span<const uint8_t>(inBuffer_.data(), inBuffer_.size()), frame);
                if (consumed == 0)
                {
                    break;
                }
                inBuffer_.erase(inBuffer_.begin(), inBuffer_.begin() + consumed);

                if (frame.opcode == Opcode::BINARY || frame.opcode == Opcode::CONTINUATION ||
                    frame.opcode == Opcode::TEXT)
                {
                    appData.insert(appData.end(), frame.payload.begin(), frame.payload.end());
                }
                else if (frame.opcode == Opcode::PING)
                {
                    // 自动回复 Pong
                    std::vector<uint8_t> pongFrame;
                    encodeFrame(frame.payload, Opcode::PONG, !isServer_, pongFrame);
                    outBuffer_.insert(outBuffer_.end(), pongFrame.begin(), pongFrame.end());
                }
                else if (frame.opcode == Opcode::CLOSE)
                {
                    state_ = TransportState::CLOSED;
                    break;
                }
            }
        }

        [[nodiscard]] std::vector<uint8_t> popOutbound()
        {
            std::vector<uint8_t> res = std::move(outBuffer_);
            outBuffer_.clear();
            return res;
        }
    };

} // namespace mynet::transport::ws
