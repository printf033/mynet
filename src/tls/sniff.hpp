#pragma once

#include "fragmenter.hpp"
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace mynet::handler::sniffing
{

    /**
     * @brief 嗅探 TLS ClientHello 中的 Server Name Indication (SNI)
     *
     * 支持两种输入（统一委托至 mynet::tls::TlsFragmenter::findSni 单一真实源）：
     * 1. 完整的 TLS 记录层报文（0x16 0x03 0x01..0x03 开头）；
     * 2. QUIC CRYPTO 帧解密出来的原始 TLS Handshake 报文（0x01 ClientHello 开头）。
     *
     * 全程基于内存切片，零堆内存分配。
     */
    [[nodiscard]] inline std::optional<std::string_view> sniffTlsSni(std::span<const uint8_t> data) noexcept
    {
        auto sniInfo = mynet::tls::TlsFragmenter::findSni(data);
        if (!sniInfo)
        {
            return std::nullopt;
        }
        return sniInfo->serverName;
    }

} // namespace mynet::handler::sniffing
