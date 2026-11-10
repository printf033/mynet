#pragma once

/**
 * @file handler/dns/handler.hpp
 * @brief DNS 协议处理器（TCP 流式 HandlerConnection 与 UDP 数据报 HandlerDatagram）
 *
 * 满足零异常 (-fno-exceptions)、HandlerConstraint 与 DatagramConstraint 静态约束。
 * 支持自建高性能 DNS 服务器、DNS 转发代理及客户端异步解析驱动。
 */

#include "connection.hpp"
#include "datagram.hpp"
#include "dns.hpp"
#include "handler/inbound.hpp"
#include "handler/outbound.hpp"
#include <functional>
#include <optional>
#include <span>

namespace mynet::handler::dns
{
    /**
     * @brief TCP DNS 入站连接处理器 (RFC 1035 Section 4.2.2)
     *
     * 满足 HandlerConstraint 与 MandatoryMethodConnection。
     * 每个 TCP DNS 报文均拥有 2 字节大端序长度前缀。
     */
    class HandlerInboundConnectionDns : public HandlerInboundConnection
    {
    public:
        using QueryResponder = std::function<std::optional<DnsMessage>(const DnsMessage &)>;

    private:
        QueryResponder responder_{nullptr};
        std::optional<DnsMessage> lastQuery_{std::nullopt};
        std::optional<DnsMessage> lastResponse_{std::nullopt};

    public:
        HandlerInboundConnectionDns() noexcept = default;
        ~HandlerInboundConnectionDns() noexcept override = default;

        HandlerInboundConnectionDns(const HandlerInboundConnectionDns &) = delete;
        HandlerInboundConnectionDns &operator=(const HandlerInboundConnectionDns &) = delete;
        HandlerInboundConnectionDns(HandlerInboundConnectionDns &&) = delete;
        HandlerInboundConnectionDns &operator=(HandlerInboundConnectionDns &&) = delete;

        /**
         * @brief 设置自定义 DNS 查询应答处理器（服务端场景）
         */
        void setResponder(QueryResponder responder) noexcept
        {
            responder_ = std::move(responder);
        }

        [[nodiscard]] const std::optional<DnsMessage> &lastQuery() const noexcept { return lastQuery_; }
        [[nodiscard]] const std::optional<DnsMessage> &lastResponse() const noexcept { return lastResponse_; }

        void reset() noexcept override
        {
            HandlerConnection::reset();
            lastQuery_.reset();
            lastResponse_.reset();
        }

        void onMessageComplete() noexcept override {}

        void onParseError(const char *reason) noexcept override
        {
            (void)reason;
            setCloseAfterResponse(true);
        }

        /**
         * @brief 驱动协议解析状态机
         */
        void process()
        {
            while (requestBytes() >= 2)
            {
                const auto *raw = reinterpret_cast<const uint8_t *>(requestBegin());
                const uint16_t msgLen = (static_cast<uint16_t>(raw[0]) << 8) | raw[1];

                if (requestBytes() < static_cast<size_t>(2 + msgLen))
                {
                    return; // 报文载荷尚未收齐
                }

                // 提取报文体
                std::span<const uint8_t> payload(raw + 2, msgLen);
                auto parsed = DnsMessage::decode(payload);
                if (!parsed.has_value())
                {
                    onParseError("HandlerInboundConnectionDns: malformed DNS packet");
                    return;
                }

                if (parsed->header.isResponse())
                {
                    // 客户端收到响应场景
                    lastResponse_ = std::move(parsed);
                }
                else
                {
                    // 服务端收到查询场景
                    lastQuery_ = *parsed;
                    if (responder_)
                    {
                        if (auto reply = responder_(*parsed); reply.has_value())
                        {
                            sendDnsResponse(*reply);
                        }
                    }
                }

                requestConsume(2 + msgLen);
            }
        }

        /**
         * @brief 主动推送一个 DNS 响应报文（带 2 字节长度前缀）
         */
        bool sendDnsResponse(const DnsMessage &msg)
        {
            auto bytes = msg.encode();
            if (bytes.size() > 65535)
            {
                return false;
            }

            std::vector<uint8_t> frame;
            frame.reserve(2 + bytes.size());
            frame.push_back(static_cast<uint8_t>(bytes.size() >> 8));
            frame.push_back(static_cast<uint8_t>(bytes.size() & 0xFF));
            frame.insert(frame.end(), bytes.begin(), bytes.end());

            auto res = pushResponse(std::string_view(reinterpret_cast<const char *>(frame.data()), frame.size()));
            return res.has_value();
        }
    };

    /**
     * @brief UDP DNS 数据报入站处理器
     *
     * 满足 DatagramConstraint 静态约束，直连 UDP 53 端口。
     */
    class HandlerInboundDatagramDns : public HandlerInboundDatagram
    {
    public:
        using QueryResponder = std::function<std::optional<DnsMessage>(const DnsMessage &)>;

    private:
        QueryResponder responder_{nullptr};

    public:
        HandlerInboundDatagramDns() noexcept = default;
        ~HandlerInboundDatagramDns() noexcept override = default;

        void setResponder(QueryResponder responder) noexcept
        {
            responder_ = std::move(responder);
        }

        void reset() noexcept override
        {
            HandlerInboundDatagram::reset();
        }

        /**
         * @brief 数据报入站事件
         */
        void onDatagram(const sockaddr_in &peer, const char *data, size_t n) noexcept override
        {
            if (data == nullptr || n == 0)
            {
                return;
            }
            std::span<const uint8_t> payload(reinterpret_cast<const uint8_t *>(data), n);
            auto parsed = DnsMessage::decode(payload);
            if (!parsed.has_value())
            {
                return;
            }

            if (!parsed->header.isResponse() && responder_)
            {
                if (auto reply = responder_(*parsed); reply.has_value())
                {
                    auto bytes = reply->encode();
                    std::string respData(reinterpret_cast<const char *>(bytes.data()), bytes.size());
                    sendTo(peer, std::move(respData));
                }
            }
        }
    };

    /**
     * @brief 客户端出站 DNS 处理器 (HandlerOutboundConnectionDns)
     *
     * 负责向上游 DNS 服务器发起标准 TCP DNS 递归查询。
     */
    class HandlerOutboundConnectionDns : public HandlerOutboundConnection
    {
    private:
        std::string queryDomain_{};
        uint16_t queryType_{kTypeA};
        uint16_t txid_{0x5678};
        bool querySent_{false};
        std::optional<DnsMessage> responseMessage_{std::nullopt};

    public:
        HandlerOutboundConnectionDns() noexcept = default;
        HandlerOutboundConnectionDns(std::string domain, uint16_t qtype = kTypeA, uint16_t txid = 0x5678)
            : queryDomain_(std::move(domain)),
              queryType_(qtype),
              txid_(txid)
        {
        }

        void setQuery(std::string domain, uint16_t qtype = kTypeA, uint16_t txid = 0x5678)
        {
            queryDomain_ = std::move(domain);
            queryType_ = qtype;
            txid_ = txid;
            querySent_ = false;
            responseMessage_.reset();
        }

        [[nodiscard]] const std::optional<DnsMessage> &response() const noexcept { return responseMessage_; }

        void reset() noexcept override
        {
            HandlerOutboundConnection::reset();
            querySent_ = false;
            responseMessage_.reset();
        }

        void process() override
        {
            if (!querySent_ && !queryDomain_.empty())
            {
                auto queryBytes = encodeQuery(queryDomain_, queryType_, txid_);
                std::vector<uint8_t> frame;
                frame.reserve(2 + queryBytes.size());
                frame.push_back(static_cast<uint8_t>(queryBytes.size() >> 8));
                frame.push_back(static_cast<uint8_t>(queryBytes.size() & 0xFF));
                frame.insert(frame.end(), queryBytes.begin(), queryBytes.end());

                [[maybe_unused]] auto _ = pushResponse(
                    std::string_view(reinterpret_cast<const char *>(frame.data()), frame.size()));
                querySent_ = true;
                stage_ = OutboundStage::CONNECTING;
            }

            if (stage_ == OutboundStage::CONNECTING && requestBytes() >= 2)
            {
                const auto *raw = reinterpret_cast<const uint8_t *>(requestBegin());
                const uint16_t msgLen = (static_cast<uint16_t>(raw[0]) << 8) | raw[1];

                if (requestBytes() >= static_cast<size_t>(2 + msgLen))
                {
                    std::span<const uint8_t> payload(raw + 2, msgLen);
                    auto resp = DnsMessage::decode(payload);
                    if (resp.has_value() && resp->header.id == txid_)
                    {
                        responseMessage_ = std::move(resp);
                        requestConsume(2 + msgLen);
                        stage_ = OutboundStage::STREAMING;
                    }
                    else
                    {
                        onParseError("HandlerOutboundConnectionDns: TxID mismatch or malformed packet");
                    }
                }
            }
        }
    };

    /**
     * @brief UDP DNS 数据报客户端出站处理器
     */
    class HandlerOutboundDatagramDns : public HandlerOutboundDatagram
    {
    private:
        std::string queryDomain_{};
        uint16_t queryType_{kTypeA};
        uint16_t txid_{0x1234};
        std::optional<DnsMessage> responseMessage_{std::nullopt};

    public:
        HandlerOutboundDatagramDns() noexcept = default;
        HandlerOutboundDatagramDns(const sockaddr_in &server, std::string domain, uint16_t qtype = kTypeA,
                                   uint16_t txid = 0x1234)
            : HandlerOutboundDatagram(server),
              queryDomain_(std::move(domain)),
              queryType_(qtype),
              txid_(txid)
        {
        }

        [[nodiscard]] const std::optional<DnsMessage> &response() const noexcept { return responseMessage_; }

        void reset() noexcept override
        {
            HandlerOutboundDatagram::reset();
            responseMessage_.reset();
        }

        void sendQuery()
        {
            if (!queryDomain_.empty() && remotePeer_.sin_port != 0)
            {
                auto queryBytes = encodeQuery(queryDomain_, queryType_, txid_);
                sendTo(remotePeer_, reinterpret_cast<const char *>(queryBytes.data()), queryBytes.size());
            }
        }

        void onDatagram(const sockaddr_in &peer, const char *data, size_t n) noexcept override
        {
            (void)peer;
            if (data == nullptr || n == 0)
            {
                return;
            }
            std::span<const uint8_t> payload(reinterpret_cast<const uint8_t *>(data), n);
            auto resp = DnsMessage::decode(payload);
            if (resp.has_value() && resp->header.id == txid_)
            {
                responseMessage_ = std::move(resp);
            }
        }
    };

} // namespace mynet::handler::dns

namespace mynet::handler
{
    using dns::HandlerInboundConnectionDns;
    using dns::HandlerInboundDatagramDns;
    using dns::HandlerOutboundConnectionDns;
    using dns::HandlerOutboundDatagramDns;
} // namespace mynet::handler
