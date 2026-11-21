#pragma once

/**
 * @file vless/vision.hpp
 * @brief VLESS XTLS Vision (xtls-rprx-vision) 流式填充、握手探测与零拷贝直通 (Splice)
 */

#include "../inboundHandler.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <openssl/rand.h>
#include <span>
#include <string_view>
#include <vector>

namespace mynet::handler::vless::vision
{

    inline constexpr std::string_view kFlowVision = "xtls-rprx-vision";

    inline constexpr uint8_t kCommandPaddingContinue = 0x00;
    inline constexpr uint8_t kCommandPaddingEnd = 0x01;
    inline constexpr uint8_t kCommandPaddingDirect = 0x02;

    /**
     * @brief XTLS Vision 流状态上下文
     */
    class VisionContext
    {
    private:
        std::array<uint8_t, 16> uuid_{};
        bool writeUuid_{true};
        bool isTls_{false};
        bool isTls13_{false};
        bool xtlsDirect_{false};
        int packetsToFilter_{8};

        // 解包状态
        bool withinPadding_{true};
        int remainingContent_{-1};
        int remainingPadding_{-1};
        uint8_t currentCommand_{kCommandPaddingContinue};
        std::array<uint8_t, 5> paddingHeader_{};
        size_t paddingHeaderLen_{0};

    public:
        VisionContext() noexcept = default;
        explicit VisionContext(const std::array<uint8_t, 16> &uuid) noexcept
            : uuid_(uuid),
              writeUuid_(true)
        {
        }

        void setUuid(const std::array<uint8_t, 16> &uuid) noexcept
        {
            uuid_ = uuid;
            writeUuid_ = true;
        }

        [[nodiscard]] bool isTls() const noexcept { return isTls_; }
        [[nodiscard]] bool isTls13() const noexcept { return isTls13_; }
        [[nodiscard]] bool isDirectSpliceEnabled() const noexcept { return xtlsDirect_; }

        void reset() noexcept
        {
            writeUuid_ = true;
            isTls_ = false;
            isTls13_ = false;
            xtlsDirect_ = false;
            packetsToFilter_ = 8;
            withinPadding_ = true;
            remainingContent_ = -1;
            remainingPadding_ = -1;
            currentCommand_ = kCommandPaddingContinue;
            paddingHeaderLen_ = 0;
        }

        /**
         * @brief 过滤并嗅探内层 TLS 握手特征 (ClientHello / ServerHello / TLS 1.3)
         */
        void filterTls(std::span<const uint8_t> buffer)
        {
            if (packetsToFilter_ <= 0 || buffer.size() < 6)
            {
                return;
            }
            packetsToFilter_--;

            // TLS Record Header: [0x16(Handshake), 0x03, 0x01..0x03, Length 2B]
            if (buffer[0] == 0x16 && buffer[1] == 0x03)
            {
                isTls_ = true;
                const uint8_t handshakeType = buffer[5];
                if (handshakeType == 0x01) // ClientHello
                {
                    isTls_ = true;
                }
                else if (handshakeType == 0x02) // ServerHello
                {
                    // 检测 TLS 1.3 supported_versions 扩展 (0x002B)
                    // 在 ServerHello 中，若包含 0x00, 0x2B, 0x00, 0x02, 0x03, 0x04 则代表协商为 TLS 1.3
                    static constexpr uint8_t kSupportedVersionsTls13[6] = {0x00, 0x2B, 0x00, 0x02, 0x03, 0x04};
                    for (size_t i = 5; i + 6 <= buffer.size(); ++i)
                    {
                        if (std::memcmp(buffer.data() + i, kSupportedVersionsTls13, 6) == 0)
                        {
                            isTls13_ = true;
                            xtlsDirect_ = true; // 允许内核 splice 直通
                            packetsToFilter_ = 0;
                            break;
                        }
                    }
                }
            }
        }

        /**
         * @brief 封包：添加 Vision 长度混淆填充与协议头
         */
        [[nodiscard]] std::vector<uint8_t> pad(std::span<const uint8_t> payload,
                                               uint8_t command = kCommandPaddingContinue)
        {
            filterTls(payload);

            const size_t contentLen = payload.size();
            size_t paddingLen = 0;

            // 若探测到内层是 TLS ClientHello 且长度较小，填充至 900 ~ 1400 字节以混淆指纹
            if (isTls_ && contentLen < 900)
            {
                uint16_t r = 0;
                if (RAND_bytes(reinterpret_cast<uint8_t *>(&r), 2) == 1)
                {
                    paddingLen = (r % 500) + (900 - contentLen);
                }
                else
                {
                    paddingLen = 900 - contentLen;
                }
            }
            else
            {
                uint8_t r = 0;
                if (RAND_bytes(&r, 1) == 1)
                {
                    paddingLen = r;
                }
            }

            size_t totalLen = (writeUuid_ ? 16 : 0) + 5 + contentLen + paddingLen;
            std::vector<uint8_t> out;
            out.reserve(totalLen);

            // 1. 首包附带 16 字节 UUID
            if (writeUuid_)
            {
                out.insert(out.end(), uuid_.begin(), uuid_.end());
                writeUuid_ = false;
            }

            // 2. 5 字节 Header: [Cmd(1B)][ContentLen(2B BE)][PaddingLen(2B BE)]
            out.push_back(command);
            out.push_back(static_cast<uint8_t>((contentLen >> 8) & 0xFF));
            out.push_back(static_cast<uint8_t>(contentLen & 0xFF));
            out.push_back(static_cast<uint8_t>((paddingLen >> 8) & 0xFF));
            out.push_back(static_cast<uint8_t>(paddingLen & 0xFF));

            // 3. 有效内容载荷
            out.insert(out.end(), payload.begin(), payload.end());

            // 4. 随机填充数据
            if (paddingLen > 0)
            {
                const size_t curSize = out.size();
                out.resize(curSize + paddingLen);
                if (RAND_bytes(out.data() + curSize, static_cast<int>(paddingLen)) != 1)
                {
                    std::memset(out.data() + curSize, 0, paddingLen);
                }
            }

            return out;
        }

        /**
         * @brief 解包：解析 Vision 填充流，剥离首部与填充，还原上层载荷
         * @param in 输入的原始网络字节流
         * @param outPayload 输出的应用有效载荷
         * @return 消费的字节数
         */
        size_t unpad(std::span<const uint8_t> in, std::vector<uint8_t> &outPayload)
        {
            if (in.empty())
            {
                return 0;
            }

            size_t offset = 0;

            // 判定首包 UUID
            if (remainingContent_ == -1 && remainingPadding_ == -1)
            {
                if (in.size() >= 21 && std::memcmp(in.data(), uuid_.data(), 16) == 0)
                {
                    offset = 16;
                    remainingContent_ = 0;
                    remainingPadding_ = 0;
                    currentCommand_ = kCommandPaddingContinue;
                }
                else
                {
                    // 非 Vision 填充流，原样透传
                    outPayload.insert(outPayload.end(), in.begin(), in.end());
                    return in.size();
                }
            }

            while (offset < in.size())
            {
                if (remainingContent_ <= 0 && remainingPadding_ <= 0)
                {
                    if (currentCommand_ == kCommandPaddingEnd)
                    {
                        // 填充已彻底结束，后续全部为纯明文流
                        outPayload.insert(outPayload.end(), in.begin() + offset, in.end());
                        return in.size();
                    }

                    // 读取 5 字节 Header
                    size_t toCopy = std::min<size_t>(5 - paddingHeaderLen_, in.size() - offset);
                    std::memcpy(paddingHeader_.data() + paddingHeaderLen_, in.data() + offset, toCopy);
                    paddingHeaderLen_ += toCopy;
                    offset += toCopy;

                    if (paddingHeaderLen_ < 5)
                    {
                        break; // 头部尚未完整
                    }

                    paddingHeaderLen_ = 0;
                    currentCommand_ = paddingHeader_[0];
                    remainingContent_ = (static_cast<int>(paddingHeader_[1]) << 8) | paddingHeader_[2];
                    remainingPadding_ = (static_cast<int>(paddingHeader_[3]) << 8) | paddingHeader_[4];

                    if (currentCommand_ == kCommandPaddingDirect)
                    {
                        xtlsDirect_ = true; // 触发内核 splice 直通
                    }
                }
                else if (remainingContent_ > 0)
                {
                    size_t toExtract = std::min<size_t>(remainingContent_, in.size() - offset);
                    outPayload.insert(outPayload.end(), in.data() + offset, in.data() + offset + toExtract);
                    remainingContent_ -= static_cast<int>(toExtract);
                    offset += toExtract;
                }
                else if (remainingPadding_ > 0)
                {
                    size_t toSkip = std::min<size_t>(remainingPadding_, in.size() - offset);
                    remainingPadding_ -= static_cast<int>(toSkip);
                    offset += toSkip;
                }
            }

            return offset;
        }
    };

} // namespace mynet::handler::vless::vision
