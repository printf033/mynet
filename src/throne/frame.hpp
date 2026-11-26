#pragma once

/**
 * @file throne/frame.hpp
 * @brief Throne (NekoRay/NekoBox) 专属 UDS 二进制 RPC 帧编解码器。
 *
 * 协议二进制帧布局 (Little-Endian):
 * 请求帧 (Request Frame):
 *   [uint32_t reqId]      4 字节请求序号
 *   [uint16_t nameLen]    2 字节方法名长度
 *   [char methodName[]]   方法名字符串 (如 "Start", "QueryStats", "IsPrivileged")
 *   [uint32_t payloadLen] 4 字节 Protobuf 载荷长度
 *   [uint8_t payload[]]   Protobuf 序列化数据
 *
 * 响应帧 (Response Frame):
 *   [uint32_t reqId]      4 字节匹配的请求序号
 *   [uint8_t status]      1 字节状态码 (0 表示成功 OK，非 0 表示错误)
 *   [uint32_t dataLen]    4 字节响应载荷长度
 *   [uint8_t data[]]      Protobuf 序列化响应数据或错误字符串
 */

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mynet::throne
{

    inline constexpr size_t kMinRequestHeaderBytes = 4 + 2 + 0 + 4; // 10 字节最小请求帧头
    inline constexpr size_t kResponseHeaderBytes = 4 + 1 + 4;       // 9 字节固定响应帧头

    struct RequestFrame
    {
        uint32_t reqId = 0;
        std::string methodName{};
        std::string payload{};
    };

    struct ResponseFrame
    {
        uint32_t reqId = 0;
        uint8_t status = 0; // 0 = OK
        std::string payload{};
    };

    /**
     * @brief 编码 Throne 响应帧为二进制数据包 (小端序)
     */
    [[nodiscard]] inline std::string encodeResponseFrame(uint32_t reqId, uint8_t status, std::string_view payload)
    {
        std::string out;
        out.resize(kResponseHeaderBytes + payload.size());
        auto *p = reinterpret_cast<uint8_t *>(out.data());

        // 小端序写入 reqId (4 字节)
        p[0] = static_cast<uint8_t>(reqId & 0xff);
        p[1] = static_cast<uint8_t>((reqId >> 8) & 0xff);
        p[2] = static_cast<uint8_t>((reqId >> 16) & 0xff);
        p[3] = static_cast<uint8_t>((reqId >> 24) & 0xff);

        // 状态码 (1 字节, 0 = OK)
        p[4] = status;

        // 小端序写入 dataLen (4 字节)
        const auto len = static_cast<uint32_t>(payload.size());
        p[5] = static_cast<uint8_t>(len & 0xff);
        p[6] = static_cast<uint8_t>((len >> 8) & 0xff);
        p[7] = static_cast<uint8_t>((len >> 16) & 0xff);
        p[8] = static_cast<uint8_t>((len >> 24) & 0xff);

        if (!payload.empty())
        {
            std::memcpy(out.data() + kResponseHeaderBytes, payload.data(), payload.size());
        }
        return out;
    }

    /**
     * @brief 编码 Throne 请求帧为二进制数据包 (小端序)
     */
    [[nodiscard]] inline std::string encodeRequestFrame(uint32_t reqId, std::string_view methodName,
                                                        std::string_view payload)
    {
        std::string out;
        const size_t total = 4 + 2 + methodName.size() + 4 + payload.size();
        out.resize(total);
        auto *p = reinterpret_cast<uint8_t *>(out.data());

        // 小端序 reqId
        p[0] = static_cast<uint8_t>(reqId & 0xff);
        p[1] = static_cast<uint8_t>((reqId >> 8) & 0xff);
        p[2] = static_cast<uint8_t>((reqId >> 16) & 0xff);
        p[3] = static_cast<uint8_t>((reqId >> 24) & 0xff);

        // 小端序 nameLen (2 字节)
        const auto nlen = static_cast<uint16_t>(methodName.size());
        p[4] = static_cast<uint8_t>(nlen & 0xff);
        p[5] = static_cast<uint8_t>((nlen >> 8) & 0xff);

        size_t off = 6;
        if (!methodName.empty())
        {
            std::memcpy(out.data() + off, methodName.data(), methodName.size());
            off += methodName.size();
        }

        // 小端序 payloadLen (4 字节)
        const auto plen = static_cast<uint32_t>(payload.size());
        p = reinterpret_cast<uint8_t *>(out.data() + off);
        p[0] = static_cast<uint8_t>(plen & 0xff);
        p[1] = static_cast<uint8_t>((plen >> 8) & 0xff);
        p[2] = static_cast<uint8_t>((plen >> 16) & 0xff);
        p[3] = static_cast<uint8_t>((plen >> 24) & 0xff);
        off += 4;

        if (!payload.empty())
        {
            std::memcpy(out.data() + off, payload.data(), payload.size());
        }
        return out;
    }

    /**
     * @brief 从接收缓冲区解析下一个完整的 Throne 请求帧
     */
    [[nodiscard]] inline std::optional<RequestFrame> decodeRequestFrame(std::span<const uint8_t> &in)
    {
        if (in.size() < 6)
        {
            return std::nullopt;
        }

        const uint32_t reqId = static_cast<uint32_t>(in[0]) | (static_cast<uint32_t>(in[1]) << 8) |
                               (static_cast<uint32_t>(in[2]) << 16) | (static_cast<uint32_t>(in[3]) << 24);

        const uint16_t nameLen = static_cast<uint16_t>(in[4]) | (static_cast<uint16_t>(in[5]) << 8);

        const size_t minNeeded = 6 + nameLen + 4;
        if (in.size() < minNeeded)
        {
            return std::nullopt;
        }

        const uint8_t *p = in.data() + 6 + nameLen;
        const uint32_t payloadLen = static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
                                    (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);

        const size_t totalFrame = minNeeded + payloadLen;
        if (in.size() < totalFrame)
        {
            return std::nullopt;
        }

        RequestFrame frame;
        frame.reqId = reqId;
        frame.methodName = std::string(reinterpret_cast<const char *>(in.data() + 6), nameLen);
        frame.payload = std::string(reinterpret_cast<const char *>(in.data() + minNeeded), payloadLen);

        in = in.subspan(totalFrame);
        return frame;
    }

    /**
     * @brief 从接收缓冲区解析下一个完整的 Throne 响应帧
     */
    [[nodiscard]] inline std::optional<ResponseFrame> decodeResponseFrame(std::span<const uint8_t> &in)
    {
        if (in.size() < kResponseHeaderBytes)
        {
            return std::nullopt;
        }

        const uint32_t reqId = static_cast<uint32_t>(in[0]) | (static_cast<uint32_t>(in[1]) << 8) |
                               (static_cast<uint32_t>(in[2]) << 16) | (static_cast<uint32_t>(in[3]) << 24);

        const uint8_t status = in[4];

        const uint32_t dataLen = static_cast<uint32_t>(in[5]) | (static_cast<uint32_t>(in[6]) << 8) |
                                 (static_cast<uint32_t>(in[7]) << 16) | (static_cast<uint32_t>(in[8]) << 24);

        const size_t totalSize = kResponseHeaderBytes + dataLen;
        if (in.size() < totalSize)
        {
            return std::nullopt;
        }

        ResponseFrame frame;
        frame.reqId = reqId;
        frame.status = status;
        frame.payload = std::string(reinterpret_cast<const char *>(in.data() + kResponseHeaderBytes), dataLen);

        in = in.subspan(totalSize);
        return frame;
    }

} // namespace mynet::throne
