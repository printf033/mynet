#pragma once

/**
 * @file common/http2.hpp
 * @brief HTTP/2 示例共用的流处理器：把每条流的请求体原样作为 200 响应返回。
 *
 * HandlerHttp2 只负责分帧、流控与 HPACK；HTTP 语义（这里是"回显请求体"）
 * 属于应用层。该处理器因此：
 * - 保留请求体在其 per-stream 的 RequestBuffer 中，不在 DATA 帧到达时回显；
 * - 在 END_STREAM（请求体完整）后用 sendResponse 发出 :status 200 与请求体。
 *
 * 这样 `curl --http2-prior-knowledge`、`nghttp` 等标准客户端可以完成
 * 一次真正的 HTTP/2 请求/响应，而不是面对裸 DATA 帧。
 */

#include "connection.hpp"
#include "handler/http/v2/handler.hpp"
#include "config/log.hpp"
#include <cstdint>
#include <string_view>
#include <vector>

namespace mynet::example
{
    /**
     * @brief 保留请求体供 HTTP/2 上层处理的流处理器
     *
     * HandlerConnection::process() 默认无操作，因此请求体留在缓冲区中，
     * 由 onStreamEnd 统一处理。
     */
    class Http2BufferedHandler : public HandlerConnection
    {
    };

    /**
     * @brief HTTP/2 回显服务：200 + 请求体
     */
    class Http2EchoHandler : public HandlerHttp2<Http2BufferedHandler>
    {
    public:
        void onStreamHeadersDecoded(uint32_t id, const std::vector<http::v2::Header> &headers) noexcept override
        {
            for (const auto &header : headers)
            {
                if (header.name == ":path")
                {
                    LOG_DEBUG("HandlerHttp2: stream {} requested {}", id, header.value);
                }
            }
        }

        void onStreamEnd(uint32_t id) noexcept override
        {
            const Stream *stream = streamHandler(id);
            const std::string_view body = stream == nullptr
                                              ? std::string_view{}
                                              : std::string_view(stream->requestBegin(), stream->requestBytes());
            const http::v2::Header extra[] = {{"content-type", "text/plain; charset=utf-8"}};
            if (!sendResponse(id, 200, body, extra)) [[unlikely]]
            {
                // 响应首部超出对端宣告的上限、或流已不在表中：明确记录而不是静默丢响应
                LOG_WARN("HandlerHttp2: stream {} response could not be sent", id);
            }
        }
    };
} // namespace mynet::example
