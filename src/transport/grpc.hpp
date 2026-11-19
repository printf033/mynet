#pragma once

/**
 * @file transport/grpc.hpp
 * @brief gRPC / Gun-lite (HTTP/2 流式封包) 协议传输抽象与消息帧编解码
 */

#include "transport.hpp"
#include "../uvarint.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mynet::transport::grpc
{

    namespace detail
    {
        inline size_t uvarintLen(uint64_t x) noexcept
        {
            return mynet::uvarint::encodedLen(x);
        }

        inline size_t putUvarint(uint8_t *buf, uint64_t x) noexcept
        {
            return mynet::uvarint::encode(buf, x);
        }

        inline std::pair<uint64_t, size_t> readUvarint(std::span<const uint8_t> data) noexcept
        {
            return mynet::uvarint::decode(data);
        }
    } // namespace detail

    /**
     * @brief 构建标准 gRPC HTTP/2 请求伪首部与元数据
     */
    struct GrpcHeader
    {
        std::string method{"POST"};
        std::string scheme{"https"};
        std::string path{};
        std::string authority{};
        std::string contentType{"application/grpc"};
        std::string te{"trailers"};
    };

    [[nodiscard]] inline GrpcHeader buildHeaders(std::string_view serviceName, std::string_view host)
    {
        GrpcHeader h;
        h.path = "/";
        if (!serviceName.empty())
        {
            h.path.append(serviceName);
            h.path.append("/Tun");
        }
        else
        {
            h.path.append("GunService/Tun");
        }
        h.authority = std::string(host);
        return h;
    }

    /**
     * @brief 编码单个 gRPC 消息帧 (兼容 Gun-lite / v2ray-grpc Protobuf 封装)
     *
     * 格式:
     * [0x00(1B)][BigEndian MsgLen(4B)][Protobuf Tag 0x0A(1B)][Uvarint DataLen(1-5B)][Payload...]
     */
    inline void encodeMessage(std::span<const uint8_t> payload, std::vector<uint8_t> &out)
    {
        const size_t dataLen = payload.size();
        const size_t varLen = detail::uvarintLen(dataLen);
        const uint32_t msgLen = static_cast<uint32_t>(1 + varLen + dataLen);

        const size_t originalSize = out.size();
        out.resize(originalSize + 5 + 1 + varLen + dataLen);

        uint8_t *p = out.data() + originalSize;
        // 1. gRPC 压缩标志位 (0 = uncompressed)
        p[0] = 0x00;
        // 2. 4 字节大端总长度
        p[1] = static_cast<uint8_t>((msgLen >> 24) & 0xFF);
        p[2] = static_cast<uint8_t>((msgLen >> 16) & 0xFF);
        p[3] = static_cast<uint8_t>((msgLen >> 8) & 0xFF);
        p[4] = static_cast<uint8_t>(msgLen & 0xFF);

        // 3. Protobuf 字段标签 0x0A (field 1, wire type 2 = length-delimited)
        p[5] = 0x0A;

        // 4. Uvarint 有效载荷长度
        detail::putUvarint(p + 6, dataLen);

        // 5. 有效载荷内容
        std::memcpy(p + 6 + varLen, payload.data(), dataLen);
    }

    /**
     * @brief 解码 gRPC 消息帧
     * @return 返回消费的总字节数 (0 表示数据未完整)
     */
    inline size_t decodeMessage(std::span<const uint8_t> data, std::vector<uint8_t> &outPayload)
    {
        if (data.size() < 5)
        {
            return 0;
        }

        const uint32_t msgLen = (static_cast<uint32_t>(data[1]) << 24) |
                                (static_cast<uint32_t>(data[2]) << 16) |
                                (static_cast<uint32_t>(data[3]) << 8) |
                                static_cast<uint32_t>(data[4]);

        if (data.size() < 5 + msgLen)
        {
            return 0; // 数据不完整
        }

        auto body = data.subspan(5, msgLen);
        if (!body.empty() && body[0] == 0x0A) // Protobuf 封装: [0x0A][Uvarint DataLen][Payload...]
        {
            auto [dataLen, n] = detail::readUvarint(body.subspan(1));
            if (n > 0 && body.size() >= 1 + n + dataLen)
            {
                outPayload.resize(dataLen);
                std::memcpy(outPayload.data(), body.data() + 1 + n, dataLen);
                return 5 + msgLen;
            }
        }

        // 原始无 Protobuf 封装的纯 gRPC 载荷
        outPayload.resize(msgLen);
        std::memcpy(outPayload.data(), body.data(), msgLen);
        return 5 + msgLen;
    }

    /**
     * @brief gRPC 传输会话
     */
    class GrpcSession : public ITransport
    {
    private:
        bool isServer_{false};
        TransportState state_{TransportState::INITIAL};
        std::string serviceName_{"GunService"};
        std::string host_{};
        std::vector<uint8_t> inBuffer_{};

    public:
        explicit GrpcSession(bool isServer, std::string serviceName = "GunService", std::string host = "")
            : isServer_(isServer),
              state_(TransportState::STREAMING), // gRPC 建立在已完成 HTTP/2 握手的流上
              serviceName_(std::move(serviceName)),
              host_(std::move(host))
        {
        }

        [[nodiscard]] TransportType type() const noexcept override { return TransportType::GRPC; }
        [[nodiscard]] TransportState state() const noexcept override { return state_; }
        [[nodiscard]] bool isReady() const noexcept override { return state_ == TransportState::STREAMING; }

        void reset() noexcept override
        {
            state_ = TransportState::STREAMING;
            inBuffer_.clear();
        }

        [[nodiscard]] const std::string &serviceName() const noexcept { return serviceName_; }
        [[nodiscard]] const std::string &host() const noexcept { return host_; }

        /**
         * @brief 将上层应用报文封装为 gRPC 消息流
         */
        [[nodiscard]] std::vector<uint8_t> wrapPayload(std::span<const uint8_t> raw)
        {
            std::vector<uint8_t> out;
            encodeMessage(raw, out);
            return out;
        }

        /**
         * @brief 解码 gRPC 底层消息并还原上层报文
         */
        void feedData(std::span<const uint8_t> incoming, std::vector<uint8_t> &appData)
        {
            inBuffer_.insert(inBuffer_.end(), incoming.begin(), incoming.end());

            while (!inBuffer_.empty())
            {
                std::vector<uint8_t> msg;
                size_t consumed = decodeMessage(std::span<const uint8_t>(inBuffer_.data(), inBuffer_.size()), msg);
                if (consumed == 0)
                {
                    break;
                }
                inBuffer_.erase(inBuffer_.begin(), inBuffer_.begin() + consumed);
                appData.insert(appData.end(), msg.begin(), msg.end());
            }
        }
    };

} // namespace mynet::transport::grpc
