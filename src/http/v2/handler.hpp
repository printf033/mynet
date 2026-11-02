#pragma once

/**
 * @file http/v2/handler.hpp
 * @brief HTTP/2 协议处理器：分帧、流表与基于信用的流多路复用。
 *
 * 本文件是 HTTP/2 的唯一实现入口，包含 mux 协议常量、STREAM_ERROR 与
 * HandlerHttp2，并把公开名字转发到 http::v2 命名空间，与 http::v1::HandlerHttp、
 * http::v3::HandlerHttp3 的用法保持一致。
 */

#include "../../connection.hpp"
#include "frame.hpp"
#include "hpack.hpp"
#include "log_config.hpp"
#include "objectPool.hpp"
#include "requestBuffer.hpp"
#include "streamTable.hpp"
#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace mynet
{

    /**
     * @namespace mux
     * @brief 流多路复用的协议常量与设置项标识符。
     */
    /**
     * @brief HTTP/2 SETTINGS 帧参数标识符枚举 (RFC 7540 Section 6.5.2)
     */
    enum class SETTINGS_ID : uint16_t
    {
        HEADER_TABLE_SIZE = 0x1,
        ENABLE_PUSH = 0x2,
        MAX_CONCURRENT_STREAMS = 0x3,
        INITIAL_WINDOW_SIZE = 0x4,
        MAX_FRAME_SIZE = 0x5,
        MAX_HEADER_LIST_SIZE = 0x6
    };

    namespace mux
    {
        inline constexpr uint32_t kInitialWindowSize = (64 << 10) - 1;
        inline constexpr uint32_t kDefaultMaxStreams = 128;
        inline constexpr uint16_t kSettingMaxConcurrentStreams =
            std::to_underlying(SETTINGS_ID::MAX_CONCURRENT_STREAMS);
        inline constexpr uint16_t kSettingInitialWindowSize = std::to_underlying(SETTINGS_ID::INITIAL_WINDOW_SIZE);
        inline constexpr uint16_t kSettingMaxFrameSize = std::to_underlying(SETTINGS_ID::MAX_FRAME_SIZE);
        inline constexpr uint16_t kSettingMaxHeaderListSize = std::to_underlying(SETTINGS_ID::MAX_HEADER_LIST_SIZE);
    } // namespace mux

    /**
     * @enum STREAM_ERROR
     * @brief 多路复用流或连接提前终止的错误原因枚举。
     */
    enum class STREAM_ERROR : uint8_t
    {
        NO_ERROR = 0x0,
        PROTOCOL_ERROR = 0x1,
        INTERNAL_ERROR = 0x2,
        FLOW_CONTROL_ERROR = 0x3,
        STREAM_CLOSED = 0x5,
        FRAME_SIZE_ERROR = 0x6,
        REFUSED_STREAM = 0x7,
        CANCEL = 0x8,
        COMPRESSION_ERROR = 0x9,
        ENHANCE_YOUR_CALM = 0xb
    };

    /**
     * @class HandlerHttp2
     * @brief HTTP/2 协议处理器：将单一字节流解复用为多个独立逻辑交互流。
     *
     * 实现 HandlerConnection 契约概念，可直接作为 Connection<HandlerHttp2<H>> 的协议处理器。
     * 负责分帧解码、流控窗口管理、流生命周期跟踪与响应数据序列化。
     *
     * 与 HandlerHttp（HTTP/1.x）、HandlerHttp3（HTTP/3）命名对齐。
     *
     * @tparam StreamHandler 每条独立流所实例化的协议处理器类型。
     */
    template <typename StreamHandler = HandlerConnection>
        requires MandatoryMethodConnection<StreamHandler>
    class HandlerHttp2 : public HandlerConnection
    {
    public:
        using Stream = StreamHandler;

        /// @brief RFC 9113 Section 3.4 客户端连接前言（连接的第一段 24 字节）
        static constexpr std::string_view kClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

        HandlerHttp2() noexcept = default;
        ~HandlerHttp2() noexcept override = default;
        HandlerHttp2(const HandlerHttp2 &) =
            delete ("an http2 handler owns the stream table and the frames bound to it");
        HandlerHttp2 &
        operator=(const HandlerHttp2 &) = delete ("an http2 handler owns the stream table and the frames bound to it");
        HandlerHttp2(HandlerHttp2 &&) = delete ("an http2 handler owns the stream table and the frames bound to it");
        HandlerHttp2 &
        operator=(HandlerHttp2 &&) = delete ("an http2 handler owns the stream table and the frames bound to it");

        /**
         * @brief 设置允许的最大并发活跃流数量。
         * @param n 最大并发流数量。
         */
        inline void setMaxConcurrentStreams(size_t n)
        {
            maxStreams_ = n == 0 ? 1 : n;
            if (streams_.size() == 0)
            {
                if (auto poolRes = streamPool_.init(maxStreams_); !poolRes) [[unlikely]]
                {
                    // 池不可用时 ensureStreamPool/acquire 侧自然降级，不影响已建立的流
                    LOG_ERROR("HandlerHttp2::setMaxConcurrentStreams: initialising stream pool ({} slots) failed",
                              maxStreams_);
                }
                if (auto tableRes = streams_.init(maxStreams_); !tableRes) [[unlikely]]
                {
                    LOG_ERROR("HandlerHttp2::setMaxConcurrentStreams: initialising stream table ({} slots) failed",
                              maxStreams_);
                }
            }
        }

        [[nodiscard]] inline size_t maxConcurrentStreams() const noexcept { return maxStreams_; }

        [[nodiscard]] inline size_t openStreams() const noexcept { return streams_.size(); }

        /**
         * @brief 设置连接级与活跃流的请求解析缓冲上限
         * @param n 缓冲上限字节数
         */
        inline void setMaxRequestBytes(size_t n) noexcept
        {
            HandlerConnection::setMaxRequestBytes(n);
            if (!streams_.ready())
            {
                return;
            }
            for (size_t i = 0; i < streams_.capacity(); ++i)
            {
                if (streams_.keyAt(i) != 0)
                {
                    const StreamSlot *slot = streams_.slotAt(i);
                    if (slot != nullptr && slot->handler != nullptr)
                    {
                        slot->handler->setMaxRequestBytes(n);
                    }
                }
            }
        }

        /**
         * @brief 取得当前所有活跃流上未消费的请求数据量总和（字节）
         */
        [[nodiscard]] inline size_t aggregateStreamRequestBytes() const noexcept
        {
            if (!streams_.ready())
            {
                return 0;
            }
            size_t total = 0;
            for (size_t i = 0; i < streams_.capacity(); ++i)
            {
                if (streams_.keyAt(i) != 0)
                {
                    const StreamSlot *slot = streams_.slotAt(i);
                    if (slot != nullptr && slot->handler != nullptr)
                    {
                        total += slot->handler->requestBytes();
                    }
                }
            }
            return total;
        }

        /**
         * @brief 是否还有因出站背压而未解码的字节
         *
         * 只有"上一轮确实是被背压截断"才为 true；单纯的不完整帧不算，否则连接层
         * 会在同一份数据上空转。
         */
        [[nodiscard]] inline bool needsProcess() const noexcept
        {
            // 三种情况都要再驱动一次：还有未推出的出站帧（flushOut 曾因队列满失败，
            // 例如收尾的 END_STREAM 帧）、有流因队列满而停在半路、或还有因背压而
            // 未解码的入站帧。漏掉第二种会让剩余响应体永久滞留：入站已解完、出站
            // 队列已空，却再没有人去泵那条流。
            return !outScratch_.empty() || pumpStalled_ || (pendingDecode_ && requestBuffer_.readableBytes() > 0);
        }

        [[nodiscard]] inline size_t streamPoolCapacity() const noexcept { return streamPool_.capacity(); }

        [[nodiscard]] inline uint32_t lastPeerStreamId() const noexcept { return lastPeerStreamId_; }

        [[nodiscard]] inline uint32_t connectionSendWindow() const noexcept
        {
            return connSendWindow_ < 0 ? 0u : static_cast<uint32_t>(connSendWindow_);
        }

        [[nodiscard]] inline bool goawayReceived() const noexcept { return goawayReceived_; }

        /**
         * @brief 重置多路复用器状态，回收对象池中的所有流。
         */
        void reset() noexcept override
        {
            HandlerConnection::reset();
            streams_.clear(
                [this]([[maybe_unused]] const uint32_t id, StreamSlot &slot)
                {
                    if (slot.handler != nullptr)
                    {
                        streamPool_.release(slot.handler);
                    }
                });
            ensureStreamPool();
            // 发送窗口是对端给我们的额度：connection 级窗口在 RFC 9113 里只受
            // WINDOW_UPDATE 影响，SETTINGS_INITIAL_WINDOW_SIZE 只作用于 stream 级。
            // 因此这里必须回到协议默认值，绝不能用本端接收窗口配置。
            connSendWindow_ = static_cast<int64_t>(mux::kInitialWindowSize);
            connRecvWindow_ = connRecvLimit_;
            // 流级发送窗口的基准同样属于对端状态：连接对象来自对象池，会跨连接复用，
            // 漏复位会把上一条连接对端宣告的 INITIAL_WINDOW_SIZE 带到新连接上。
            initialSendWindow_ = mux::kInitialWindowSize;
            lastPeerStreamId_ = 0;
            consecutiveResets_ = 0;
            unackedPings_ = 0;
            unackedSettings_ = 0;
            consecutiveEmptyFrames_ = 0;
            consecutiveWindowUpdates_ = 0;
            consecutivePriorityFrames_ = 0;
            settingsSent_ = false;
            goawayReceived_ = false;
            prefaceConsumed_ = false;
            pendingDecode_ = false;
            pumpStalled_ = false;
            pumpedBytes_ = 0;
            awaitingContinuation_ = false;
            headerBlockStreamId_ = 0;
            std::string().swap(headerBlock_);
            contEndStream_ = false;
            contFrameCount_ = 0;
            contEmptyFrames_ = 0;
            peerMaxHeaderListBytes_ = std::numeric_limits<size_t>::max();
            recvMaxFrameSize_ = frame::kDefaultMaxFrameSize;
            sendMaxFrameSize_ = frame::kDefaultMaxFrameSize;
            decoder_.setMaxFrameSize(recvMaxFrameSize_);
            hpackDecoder_.reset();
            hpackEncoder_.reset();
            outScratch_.clear();
        }

        void onConnect(int fd) noexcept override
        {
            HandlerConnection::onConnect(fd);
            applyMultiplexerConfig();
        }

        /**
         * @brief 从 multiplexer 与 connection 配置段刷新本连接的流并发、窗口与请求缓冲上限。
         *
         * 必须在每个新连接上调用（而不是只在构造时读一次），这样 reloadConfig()
         * 之后建立的新连接立刻采用新值——这正是 multiplexer 与 connection 段被归类为"热"的依据。
         */
        inline void applyMultiplexerConfig() noexcept
        {
            const MultiplexerConfig &cfg = getMultiplexerConfig();
            setMaxConcurrentStreams(cfg.maxConcurrentStreams);
            setMaxRequestBytes(getConnectionConfig().maxRequestBytes);
            // SETTINGS_MAX_FRAME_SIZE 只约束本端愿意接收的帧（对端据此分片），
            // 协议下限是 16384，配置值低于它会让合规对端被误判为超长帧。
            recvMaxFrameSize_ = std::clamp(static_cast<uint32_t>(cfg.maxFrameSize), frame::kDefaultMaxFrameSize,
                                           static_cast<uint32_t>(0x00ffffffu));
            decoder_.setMaxFrameSize(recvMaxFrameSize_);
            initialWindow_ = cfg.initialWindowSize;
            // 连接级接收窗口的下限是协议默认 65535：SETTINGS 只能改 stream 级，
            // 而连接级窗口无法被"缩小"——对端始终按 65535 起算。若本端记账值比
            // 65535 小，就会出现"我们以为对端只能发这么多"的假象，也让回补阈值
            // 算错。真正限制并发注入量的是 stream 级窗口（由 SETTINGS 宣告）。
            connRecvLimit_ = std::max<uint32_t>(mux::kInitialWindowSize, static_cast<uint32_t>(initialWindow_));
            // stream 级同理：SETTINGS_INITIAL_WINDOW_SIZE 允许调小，但只在对端
            // **收到并处理我们的 SETTINGS 之后**生效。在此之前对端仍按协议默认
            // 65535 发送，所以本地记账下限也必须是 65535，否则会把合规对端
            // 判成 FLOW_CONTROL_ERROR。
            streamRecvLimit_ = connRecvLimit_;
            // 对端实际可注入的额度是 SETTINGS 宣告值（可以小于 65535）。回补判据必须
            // 按它计算：若仍用 streamRecvLimit_/2，宣告 16 KiB 时对端发满 16 KiB 后
            // 本端 recvWindow 仍高于阈值、永不回补，上传就此永久挂住。
            streamCreditUnit_ = std::max<uint32_t>(1u, static_cast<uint32_t>(initialWindow_));
            connSendWindow_ = static_cast<int64_t>(mux::kInitialWindowSize);
            connRecvWindow_ = connRecvLimit_;
        }

        /**
         * @brief 适配 Connection::echo 契约：遍历当前活跃流表，驱动每条流上的处理器执行 echo() 并泵送响应
         */
        inline void echo() noexcept
        {
            if (streams_.ready())
            {
                for (size_t i = 0; i < streams_.capacity(); ++i)
                {
                    const uint32_t id = streams_.keyAt(i);
                    if (id != 0)
                    {
                        StreamSlot *slot = streams_.find(id);
                        if (slot != nullptr && slot->handler != nullptr)
                        {
                            slot->handler->echo();
                            pumpStream(id, *slot);
                        }
                    }
                }
            }
            (void)flushOut();
        }

        /**
         * @brief 向指定流发送 DATA 数据（复用流处理器的响应队列与连接层写通道）
         *
         * @param streamId 目标流 ID
         * @param data 数据载荷
         * @param endStream 是否在数据发完后关闭流的输出端
         * @return 是否成功推入流响应队列
         */
        inline bool sendData(uint32_t streamId, std::string_view data, bool endStream = false)
        {
            StreamSlot *slot = streams_.find(streamId);
            if (slot == nullptr || slot->handler == nullptr) [[unlikely]]
            {
                return false;
            }
            if (!slot->handler->pushResponse(data)) [[unlikely]]
            {
                return false;
            }
            if (endStream)
            {
                // remoteEnded 专指"对端已结束发送"。本端结束发送是 half-closed(local)，
                // 两者混用会让 pumpStream 在响应排空时立刻关闭流，随后对端迟到的
                // END_STREAM 又会回调到已回收的流槽位上。
                slot->localEnded = true;
            }
            pumpStream(streamId, *slot);
            return true;
        }

        /**
         * @brief 向指定流发送 HEADERS 帧（直接复用 Connection 的响应队列与帧通道）
         *
         * @param streamId 目标流 ID
         * @param headerBlock 编码后的首部块载荷
         * @param endStream 是否同时终结当前流
         * @return 是否成功构造并推入帧
         */
        inline bool sendHeaders(uint32_t streamId, std::string_view headerBlock, bool endStream = false)
        {
            if (stream(streamId) == nullptr) [[unlikely]]
            {
                return false;
            }
            appendHeaderBlock(streamId, headerBlock, endStream);
            (void)flushOut();
            return true;
        }

        /**
         * @brief 向指定流发送完整的 HTTP/2 响应（首部与载荷，复用连接层设施）
         *
         * @param streamId 目标流 ID
         * @param headerBlock 编码后的首部块载荷
         * @param body 数据体
         * @return 是否成功发送
         */
        inline bool sendResponse(uint32_t streamId, std::string_view headerBlock, std::string_view body)
        {
            if (!sendHeaders(streamId, headerBlock, body.empty()))
            {
                return false;
            }
            if (!body.empty())
            {
                return sendData(streamId, body, true);
            }
            return true;
        }

        /**
         * @brief 以 HPACK 编码的响应首部 + 数据体发送一次完整响应
         *
         * 这是与标准客户端（curl/nghttp2、浏览器）互通所需的入口：:status 与
         * 附加首部由本方法编码，调用方不再手写首部块。响应 DATA 仍由流控与
         * 分片路径（pumpStream）驱动。
         *
         * @param streamId 目标流 ID
         * @param status HTTP 状态码
         * @param body 响应体（可为空）
         * @param extra 附加响应首部
         * @return 流不存在或响应队列拒收时返回 false
         */
        inline bool sendResponse(uint32_t streamId, uint32_t status, std::string_view body,
                                 std::span<const http::v2::Header> extra = {})
        {
            StreamSlot *slot = stream(streamId);
            if (slot == nullptr || slot->handler == nullptr) [[unlikely]]
            {
                return false;
            }
            std::vector<http::v2::Header> headers;
            headers.reserve(2 + extra.size());
            headers.push_back({":status", std::to_string(status)});
            if (!body.empty())
            {
                headers.push_back({"content-length", std::to_string(body.size())});
            }
            for (const auto &header : extra)
            {
                headers.push_back(header);
            }
            size_t listBytes = 0;
            for (const auto &header : headers)
            {
                listBytes += header.name.size() + header.value.size() + http::v2::hpack::kEntryOverhead;
            }
            if (listBytes > peerMaxHeaderListBytes_) [[unlikely]]
            {
                // 超出对端宣告的上限。绝不能静默跳过：流的对端已经 END_STREAM，
                // 若这里直接返回，pumpStream 会补一个"没有 HEADERS 的 END_STREAM"，
                // 对端只能按连接级协议错误处理。显式重置该流才是可恢复的结果。
                LOG_WARN("HandlerHttp2: response header list for stream {} ({} bytes) exceeds the peer limit {}",
                         streamId, listBytes, peerMaxHeaderListBytes_);
                sendResetStream(streamId, STREAM_ERROR::ENHANCE_YOUR_CALM);
                closeStream(streamId);
                return false;
            }
            // 先把数据体放进流响应队列，再发 HEADERS：否则 pumpStream 会在
            // 首部发出后立刻判定"无待发响应"并结束流，数据体将永远发不出去。
            if (!body.empty() && !slot->handler->pushResponse(body)) [[unlikely]]
            {
                return false;
            }
            appendHeaderBlock(streamId, http::v2::HpackEncoder::encode(headers), false);
            (void)flushOut();
            pumpStream(streamId, *slot);
            return true;
        }

        // ---- 协议前端可重写的钩子函数 ----

        /**
         * @brief 新流开启时调用的钩子。
         * @param id 流标识符。
         */
        virtual void onStreamOpen([[maybe_unused]] uint32_t id) noexcept {}

        /**
         * @brief 流的首部到达时调用的钩子。
         * @param id 流标识符。
         * @param block 未解析的首部载荷块。
         */
        virtual void onStreamHeaders([[maybe_unused]] uint32_t id, [[maybe_unused]] std::string_view block) noexcept {}

        /**
         * @brief 流的首部被 HPACK 解码后调用的钩子。
         * @param id 流标识符。
         * @param headers 解码后的首部字段（含 :method / :path 等伪首部）。
         */
        virtual void onStreamHeadersDecoded([[maybe_unused]] uint32_t id,
                                            [[maybe_unused]] const std::vector<http::v2::Header> &headers) noexcept
        {
        }

        /**
         * @brief 流的 trailers 到达时调用的钩子（尾部首部，必然伴随 END_STREAM）。
         * @param id 流标识符。
         * @param headers 解码后的尾部首部字段。
         */
        virtual void onStreamTrailers([[maybe_unused]] uint32_t id,
                                      [[maybe_unused]] const std::vector<http::v2::Header> &headers) noexcept
        {
        }

        /**
         * @brief 对端在本流上发送 END_STREAM 时调用的钩子（请求体已完整到达）。
         * @param id 流标识符。
         */
        virtual void onStreamEnd([[maybe_unused]] uint32_t id) noexcept {}

        /**
         * @brief 流的 DATA 载荷到达时调用的钩子。
         * @param id 流标识符。
         * @param bytes 载荷数据切片。
         */
        virtual void onStreamData([[maybe_unused]] uint32_t id, [[maybe_unused]] std::string_view bytes) noexcept {}

        /**
         * @brief 流终止或关闭时调用的钩子。
         * @param id 流标识符。
         */
        virtual void onStreamClose([[maybe_unused]] uint32_t id) noexcept {}

        /**
         * @brief 发生不可恢复的协议错误时调用的钩子。
         * @param code 协议错误码。
         * @param why 错误原因描述。
         */
        virtual void onProtocolError([[maybe_unused]] STREAM_ERROR code, [[maybe_unused]] std::string_view why) noexcept
        {
        }

        /**
         * @brief 逐帧解析到达的请求字节流并进行分发。
         */
        void process()
        {
            ensureStreamPool();
            if (!settingsSent_) [[unlikely]]
            {
                sendSettings();
            }
            // 客户端连接前言是连接上的第一段字节：不消费它，帧解码器会把 "PRI "
            // 读成 5 MiB 的载荷长度并直接判 FRAME_TOO_LARGE，任何真实客户端都连不上。
            if (!prefaceConsumed_) [[unlikely]]
            {
                if (!consumePreface())
                {
                    return;
                }
            }
            while (true)
            {
                if (closeAfterResponse_) [[unlikely]]
                {
                    // 已判定终止：残余字节不再驱动协议状态，但 GOAWAY 若曾因响应
                    // 队列满而滞留在 outScratch_ 中，仍要尽力推出。
                    (void)flushOut();
                    return;
                }
                // 出站背压：连接层的 collectResponses() 只在 process() 返回后搬运一次，
                // 所以这里必须在响应队列压满前停下，剩余帧留在 requestBuffer_ 中由下一轮
                // 继续解码。否则一轮里解出的 WINDOW_UPDATE 会被放大成数倍 DATA 帧，
                // 把队列压爆——而 mux 帧是不可丢弃的。
                if (!outScratch_.empty() && !flushOut()) [[unlikely]]
                {
                    pendingDecode_ = true;
                    return;
                }
                // 上一轮因响应队列压满而停泵的流：队列已被连接层搬空，继续发。
                if (pumpStalled_) [[unlikely]]
                {
                    pumpStalled_ = false;
                    pumpAll();
                }
                if (responseCount() >= responseCapacity()) [[unlikely]]
                {
                    pendingDecode_ = true;
                    return;
                }

                std::expected<std::optional<Frame>, FRAME_ERROR> parsed = decoder_.next(requestBuffer_);
                if (!parsed) [[unlikely]]
                {
                    protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, toString(parsed.error()));
                    return;
                }
                if (!parsed->has_value())
                {
                    pendingDecode_ = false;
                    return; // 帧不完整，等待后续更多网络数据到达
                }
                handleFrame(std::move(parsed->value()));
                if (closeAfterResponse_) [[unlikely]]
                {
                    return;
                }
            }
        }

    protected:
        /**
         * @brief 消费并校验客户端连接前言
         *
         * @return true 表示前言已完整消费（或此前已消费）；false 表示数据不足，需等待更多字节。
         *         前言内容不匹配时触发连接级 PROTOCOL_ERROR 并返回 false。
         */
        [[nodiscard]] inline bool consumePreface()
        {
            const size_t available = requestBuffer_.readableBytes();
            const size_t compare = std::min(available, kClientPreface.size());
            if (compare > 0 && std::string_view(requestBuffer_.readableBegin(), compare) !=
                                   kClientPreface.substr(0, compare)) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "invalid HTTP/2 client connection preface");
                return false;
            }
            if (available < kClientPreface.size())
            {
                return false; // 前言尚未收齐，等待后续字节
            }
            requestBuffer_.retrieve(kClientPreface.size());
            prefaceConsumed_ = true;
            return true;
        }

        inline void ensureStreamPool()
        {
            if (streamPool_.capacity() == 0 || !streams_.ready()) [[unlikely]]
            {
                if (streamPool_.capacity() == 0)
                {
                    if (auto poolRes = streamPool_.init(maxStreams_); !poolRes) [[unlikely]]
                    {
                        // noexcept 链上不能抛：池保持不可用，acquire() 返回 nullptr 自然降级
                        LOG_ERROR("HandlerHttp2::ensureStreamPool: initialising stream pool ({} slots) failed",
                                  maxStreams_);
                    }
                }
                if (!streams_.ready())
                {
                    if (auto tableRes = streams_.init(maxStreams_); !tableRes) [[unlikely]]
                    {
                        // 表不可用时 open() 返回 nullptr，openStream 侧以 REFUSED_STREAM 自然降级
                        LOG_ERROR("HandlerHttp2::ensureStreamPool: initialising stream table ({} slots) failed",
                                  maxStreams_);
                    }
                }
            }
        }

        struct StreamSlot
        {
            StreamHandler *handler = nullptr;
            int64_t sendWindow = mux::kInitialWindowSize;
            uint32_t recvWindow = mux::kInitialWindowSize;
            uint32_t pendingOffset = 0;   ///< 在途 chunk 已发出的字节数（partial 发送游标）
            bool headersReceived = false; ///< 本流已收到请求首部（后续 HEADERS 只可能是 trailers）
            bool remoteEnded = false;
            bool localEnded = false; ///< 本端已声明 END_STREAM（half-closed local）
            bool finalSent = false;
            bool readPaused = false; ///< 出站响应未排空：暂缓恢复本流接收窗口，阻断慢读对端继续注入
            std::string pending{};   ///< 在途响应块（collectResponses 阶段只保留一个，发送不完驻留）
        };

        // ---- 帧分发处理 ----

        inline void handleFrame(Frame frame)
        {
            LOG_DEBUG("HandlerHttp2: frame type {} flags {} on stream {} ({} payload byte(s))",
                      std::to_underlying(frame.type), frame.flags, frame.streamId, frame.payload.size());
            // RFC 9113 §6.2：首部块一旦开始分片，只能由同一流的 CONTINUATION 续接，
            // 期间连接上不得出现任何其他帧。这条规则同时是 CVE-2024-27983 的防线：
            // 攻击者无法用廉价帧打断/重置首部累积状态。
            if (awaitingContinuation_) [[unlikely]]
            {
                if (frame.type != FRAME_TYPE::CONTINUATION || frame.streamId != headerBlockStreamId_)
                {
                    protocolFailure(STREAM_ERROR::PROTOCOL_ERROR,
                                    "a frame arrived in the middle of a fragmented header block");
                    return;
                }
                handleContinuation(frame);
                return;
            }
            switch (frame.type)
            {
            case FRAME_TYPE::HEADERS:
                handleHeaders(frame);
                break;
            case FRAME_TYPE::DATA:
                handleData(frame);
                break;
            case FRAME_TYPE::SETTINGS:
                handleSettings(frame);
                break;
            case FRAME_TYPE::PING:
                handlePing(frame);
                break;
            case FRAME_TYPE::WINDOW_UPDATE:
                handleWindowUpdate(frame);
                break;
            case FRAME_TYPE::RESET:
                handleReset(frame);
                break;
            case FRAME_TYPE::GOAWAY:
                handleGoaway(frame);
                break;
            case FRAME_TYPE::PRIORITY:
                if (frame.streamId == 0) [[unlikely]]
                {
                    protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "PRIORITY on the connection stream");
                    break;
                }
                if (frame.payload.size() != 5) [[unlikely]]
                {
                    sendResetStream(frame.streamId, STREAM_ERROR::FRAME_SIZE_ERROR);
                    break;
                }
                // CVE-2019-9513 Priority Flood 防御
                ++consecutivePriorityFrames_;
                if (consecutivePriorityFrames_ > kMaxConsecutivePriorityFrames) [[unlikely]]
                {
                    protocolFailure(STREAM_ERROR::ENHANCE_YOUR_CALM, "excessive PRIORITY frames (priority flood)");
                    break;
                }
                break;
            case FRAME_TYPE::PUSH_PROMISE:
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "PUSH_PROMISE arrived on a server-side connection");
                break;
            case FRAME_TYPE::CONTINUATION:
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "unexpected CONTINUATION frame");
                break;
            }
        }

        inline void handleHeaders(Frame &frame)
        {
            // 流标识合法性必须在进入分片等待之前判定：否则一条必然被拒的连接可以
            // 先堆满重组缓冲（甚至让 stream 0 的 CONTINUATION 被接受），才拿到错误。
            if (frame.streamId == 0 || (frame.streamId % 2) == 0) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "HEADERS on a stream the peer may not open");
                return;
            }
            std::string_view block;
            if (!unframePayload(frame, block)) [[unlikely]]
            {
                return;
            }
            if (frame.hasFlag(FrameFlags::kPriority))
            {
                if (block.size() < 5) [[unlikely]]
                {
                    protocolFailure(STREAM_ERROR::PROTOCOL_ERROR,
                                    "HEADERS carries a priority field that is not 5 bytes");
                    return;
                }
                block.remove_prefix(5);
            }

            const bool endStream = frame.hasFlag(FrameFlags::kEndStream);
            if (frame.hasFlag(FrameFlags::kEndHeaders)) [[likely]]
            {
                completeHeaderBlock(frame.streamId, block, endStream);
                return;
            }

            // 首部块跨帧：**无条件**进入等待状态，即使这条流随后会被拒绝。
            // 少记一步就会把紧随其后的同流 CONTINUATION 判成连接级错误，
            // 在并发流打满时把同一连接上的其他在途流一起拖死。
            if (block.size() > kMaxHeaderBlockBytes) [[unlikely]]
            {
                // 首部块本身已超出可安全重组的规模：此时既无法保持解码器同步，
                // 也无法吞完后续分片，只能终止连接。
                protocolFailure(STREAM_ERROR::COMPRESSION_ERROR, "header block exceeds the reassembly limit");
                return;
            }
            headerBlockStreamId_ = frame.streamId;
            contEndStream_ = endStream;
            contFrameCount_ = 0;
            contEmptyFrames_ = 0;
            awaitingContinuation_ = true;
            headerBlock_.assign(block);
        }

        /**
         * @brief 处理分片首部块中的 CONTINUATION 帧
         *
         * 累积期间只接受同一流的 CONTINUATION（由 handleFrame 保证）。整块收齐后
         * 统一交给 completeHeaderBlock() 解码——无论该流是否会被接纳，都必须执行
         * 解码以保持连接级 HPACK 动态表与对端同步。
         */
        inline void handleContinuation(Frame &frame)
        {
            if ((frame.flags & ~FrameFlags::kEndHeaders) != 0) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "CONTINUATION carries undefined flags");
                return;
            }
            // 字节上限约束内存，帧数上限只防"零长 CONTINUATION"这类不占字节却
            // 消耗解析轮次的洪水；合规客户端用极小分片发送不会因此被误杀。
            if (++contFrameCount_ > kMaxContinuationFrames) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::ENHANCE_YOUR_CALM, "excessive CONTINUATION frames (continuation flood)");
                return;
            }
            if (frame.payload.empty())
            {
                ++contEmptyFrames_;
                if (contEmptyFrames_ > kMaxEmptyContinuationFrames) [[unlikely]]
                {
                    protocolFailure(STREAM_ERROR::ENHANCE_YOUR_CALM,
                                    "excessive empty CONTINUATION frames (continuation flood)");
                    return;
                }
            }
            else
            {
                contEmptyFrames_ = 0;
            }

            if (headerBlock_.size() + frame.payload.size() > kMaxHeaderBlockBytes) [[unlikely]]
            {
                // 无法在不越界的前提下重组：继续吞分片也无法恢复解码器同步，
                // 只能按压缩错误终止连接（此时后续帧本就不再处理）。
                protocolFailure(STREAM_ERROR::COMPRESSION_ERROR, "header block exceeds the reassembly limit");
                return;
            }
            headerBlock_.append(frame.payload);

            if (!frame.hasFlag(FrameFlags::kEndHeaders))
            {
                return;
            }

            const uint32_t id = headerBlockStreamId_;
            const bool endStream = contEndStream_;
            std::string block = std::move(headerBlock_);
            awaitingContinuation_ = false;
            headerBlockStreamId_ = 0;
            std::string().swap(headerBlock_); // 归还重组缓冲，避免长连接常驻大块
            contEndStream_ = false;
            contFrameCount_ = 0;
            contEmptyFrames_ = 0;
            completeHeaderBlock(id, block, endStream);
        }

        /**
         * @brief 首部块完整到达后的统一收尾：HPACK 解码 + 流准入 + 通知应用 + END_STREAM
         *
         * 解码**先于**流准入判定：动态表是连接级状态，跳过任意一个首部块（哪怕它的
         * 流被拒绝）都会让本端索引空间与对端整体错位，后续请求会被静默解出错误的首部。
         */
        inline void completeHeaderBlock(uint32_t id, std::string_view block, bool endStream)
        {
            // 与压缩状态无关的两项准入判定放在解码之前：不递增的流标识是协议违约，
            // 先报错可以避免为一个非法请求维护解码器状态。
            StreamSlot *slot = stream(id);
            if (slot == nullptr && id <= lastPeerStreamId_) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "a stream identifier that does not increase");
                return;
            }

            auto decoded = hpackDecoder_.decode(block);
            if (!decoded) [[unlikely]]
            {
                if (decoded.error() == http::v2::HPACK_ERROR::HEADER_LIST_TOO_LARGE)
                {
                    // 块已完整解析，动态表仍然同步：首部规模超限只是这条流的问题。
                    // 仍要推进已见流标识，否则对端在途的 DATA / RST_STREAM 会被判成
                    // idle-stream 连接错误。
                    lastPeerStreamId_ = std::max(lastPeerStreamId_, id);
                    sendResetStream(id, STREAM_ERROR::ENHANCE_YOUR_CALM);
                    closeStream(id);
                    return;
                }
                // RFC 7541 Section 4.3：压缩状态一旦失步，整条连接无法继续
                protocolFailure(STREAM_ERROR::COMPRESSION_ERROR, http::v2::toString(decoded.error()));
                return;
            }

            // 解码成功后再碰准入逻辑：**即使随后拒绝这条流**，也必须推进已见流标识，
            // 否则紧随其后的同流帧会被判成 idle-stream，一次超限请求就拖垮整条连接。
            lastPeerStreamId_ = std::max(lastPeerStreamId_, id);

            if (slot == nullptr)
            {
                if (goawayReceived_) [[unlikely]]
                {
                    LOG_WARN("HandlerHttp2: refusing a new stream after GOAWAY from the peer");
                    sendResetStream(id, STREAM_ERROR::REFUSED_STREAM);
                    return;
                }
                slot = openStream(id);
                if (slot == nullptr) [[unlikely]]
                {
                    // 表已同步，仅拒绝这一条流：并发打满不再牵连整条连接
                    sendResetStream(id, STREAM_ERROR::REFUSED_STREAM);
                    return;
                }
            }
            else if (slot->remoteEnded) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "HEADERS after END_STREAM on the same stream");
                return;
            }

            if (slot->headersReceived) [[unlikely]]
            {
                // RFC 9113 §8.1：同一流上第二次 HEADERS 只能是 tailers，且必须终结
                // 请求（带 END_STREAM）。把它当普通首部再通知一次，应用会看到两份
                // "请求头"，进而把 trailers 误当成新的请求。
                if (!endStream) [[unlikely]]
                {
                    protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "a second HEADERS frame without END_STREAM");
                    return;
                }
                onStreamHeaders(id, block);
                onStreamTrailers(id, *decoded);
                if (StreamSlot *again = stream(id); again != nullptr)
                {
                    endRemoteSide(id, *again);
                }
                return;
            }

            slot->headersReceived = true;
            onStreamHeaders(id, block);
            onStreamHeadersDecoded(id, *decoded);
            if (endStream)
            {
                // 钩子可以在此直接回一条完整响应并关闭本流（早响应）：slot 引用可能
                // 已随 closeStream 失效，必须重新查表而不是继续用旧引用。
                if (StreamSlot *again = stream(id); again != nullptr)
                {
                    endRemoteSide(id, *again);
                }
            }
        }

        inline void handleData(Frame &frame)
        {
            if (frame.streamId == 0) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "DATA on the connection stream");
                return;
            }
            StreamSlot *slot = stream(frame.streamId);
            if (slot == nullptr) [[unlikely]]
            {
                if (frame.streamId > lastPeerStreamId_)
                {
                    protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "DATA on a stream that was never opened");
                }
                else
                {
                    sendResetStream(frame.streamId, STREAM_ERROR::STREAM_CLOSED);
                }
                return;
            }
            if (slot->remoteEnded) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "DATA after END_STREAM on the same stream");
                return;
            }

            std::string_view bytes;
            if (!unframePayload(frame, bytes)) [[unlikely]]
            {
                return;
            }
            if (bytes.empty() && !frame.hasFlag(FrameFlags::kEndStream))
            {
                // CVE-2019-9518 Empty Frame Flood 防御：连续空 DATA 帧攻击
                ++consecutiveEmptyFrames_;
                if (consecutiveEmptyFrames_ > kMaxConsecutiveEmptyFrames) [[unlikely]]
                {
                    protocolFailure(STREAM_ERROR::ENHANCE_YOUR_CALM,
                                    "excessive empty non-terminal frames (empty frame flood)");
                    return;
                }
            }
            else
            {
                consecutiveEmptyFrames_ = 0;
                consecutiveResets_ = 0;
                unackedPings_ = 0;
                unackedSettings_ = 0;
                consecutiveWindowUpdates_ = 0;
                consecutivePriorityFrames_ = 0;
            }

            // RFC 7540 Section 6.1: 无论是否包含填充，整个 DATA 帧载荷长度（含 pad length 与 padding）
            // 均计入连接级与流级流量控制窗口扣减
            const size_t flowControlBytes = frame.payload.size();
            if (flowControlBytes > connRecvWindow_ || flowControlBytes > slot->recvWindow) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::FLOW_CONTROL_ERROR,
                                "a DATA frame larger than the receive window it counts against");
                return;
            }
            connRecvWindow_ -= static_cast<uint32_t>(flowControlBytes);
            slot->recvWindow -= static_cast<uint32_t>(flowControlBytes);

            // 每流请求缓冲必须自己受限：connection.maxRequestBytes 只作用在连接级
            // handler 上，而 HTTP/2 的请求体驻留在 per-stream 处理器里。像"缓冲到
            // END_STREAM 再回响应"这种实现，若不在这里拦截，单个上传即可吃满内存。
            if (bytes.size() > slot->handler->readCredit()) [[unlikely]]
            {
                LOG_WARN("HandlerHttp2: stream {} exceeded the per-stream request buffer limit", frame.streamId);
                // 本帧已从连接级窗口扣减：拒绝该流时把额度还回去，否则每次超限
                // 都会永久吃掉一段连接级信用（窗口只有 64 KiB，几次就降额）。
                creditConnectionWindow();
                sendResetStream(frame.streamId, STREAM_ERROR::ENHANCE_YOUR_CALM);
                closeStream(frame.streamId);
                return;
            }

            // 连接级聚合上限：所有活跃流未消费的请求体总和不得超过 connection.maxRequestBytes。
            // 否则 128 条流并发时各自可达单流上限，导致单连接驻留数百 MiB 内存引发 OOM。
            const size_t maxConn = this->maxRequestBytes_;
            const size_t currentAggregate = aggregateStreamRequestBytes();
            const size_t connCredit = currentAggregate >= maxConn ? 0 : maxConn - currentAggregate;
            if (bytes.size() > connCredit) [[unlikely]]
            {
                LOG_WARN("HandlerHttp2: stream {} exceeded the connection aggregate request buffer limit ({} bytes)",
                         frame.streamId, maxConn);
                creditConnectionWindow();
                sendResetStream(frame.streamId, STREAM_ERROR::ENHANCE_YOUR_CALM);
                closeStream(frame.streamId);
                return;
            }

            onStreamData(frame.streamId, bytes);
            if (auto res = slot->handler->appendRequest(bytes.data(), static_cast<ssize_t>(bytes.size())); !res)
                [[unlikely]]
            {
                LOG_ERROR("HandlerHttp2: stream {} appendRequest failed: {}", frame.streamId, toString(res.error()));
                creditConnectionWindow();
                sendResetStream(frame.streamId, STREAM_ERROR::INTERNAL_ERROR);
                closeStream(frame.streamId);
                return;
            }
            if constexpr (requires { slot->handler->process(); })
            {
                slot->handler->process();
            }
            else
            {
                slot->handler->echo();
            }
            collectResponses(frame.streamId, *slot);

            if (frame.hasFlag(FrameFlags::kEndStream))
            {
                endRemoteSide(frame.streamId, *slot);
                return;
            }
            // collectResponses 可能已随出站排空关闭本流，旧引用不再可用
            if (StreamSlot *again = stream(frame.streamId); again != nullptr)
            {
                creditReceiveWindow(frame.streamId, *again);
            }
        }

        inline void handleSettings(Frame &frame)
        {
            if (frame.streamId != 0) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "SETTINGS on a stream other than zero");
                return;
            }
            if (frame.hasFlag(FrameFlags::kAck))
            {
                if (!frame.payload.empty()) [[unlikely]]
                {
                    protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "SETTINGS ACK with a payload");
                }
                if (unackedSettings_ > 0)
                {
                    --unackedSettings_;
                }
                return;
            }
            // CVE-2019-9515 Settings Flood 防御：限制对端连续未确认 SETTINGS 激增
            ++unackedSettings_;
            if (unackedSettings_ > kMaxUnackedSettings) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::ENHANCE_YOUR_CALM,
                                "excessive SETTINGS frames without peer activity (settings flood)");
                return;
            }
            if (frame.payload.size() % 6 != 0) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR,
                                "SETTINGS payload is not a whole number of 6 byte entries");
                return;
            }
            for (size_t off = 0; off + 6 <= frame.payload.size(); off += 6)
            {
                uint16_t idRaw = 0;
                std::memcpy(&idRaw, frame.payload.data() + off, sizeof(idRaw));
                const uint16_t id = std::byteswap(idRaw);
                const uint32_t value = frame::readBigEndian32(frame.payload.data() + off + 2);
                switch (id)
                {
                case mux::kSettingMaxHeaderListSize:
                    // 对端宣告的是它愿意接收的首部列表上限，只约束本端出站编码。
                    // 0 就是"不接受任何首部"（RFC 9113 未给 0 开特例），不做通配处理。
                    peerMaxHeaderListBytes_ = static_cast<size_t>(value);
                    break;
                case mux::kSettingMaxFrameSize:
                    if (value < frame::kDefaultMaxFrameSize || value > 0x00ffffffu) [[unlikely]]
                    {
                        protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "invalid SETTINGS_MAX_FRAME_SIZE value");
                        return;
                    }
                    // 对端宣告的是它愿意接收的上限，只能约束本端出站分片；
                    // 本端解码上限由我们自己的 SETTINGS 决定。
                    sendMaxFrameSize_ = value;
                    break;
                case mux::kSettingInitialWindowSize:
                {
                    if (value > frame::kStreamIdMask) [[unlikely]]
                    {
                        protocolFailure(STREAM_ERROR::FLOW_CONTROL_ERROR, "initial window size exceeds 2^31 - 1");
                        return;
                    }
                    const int64_t delta = static_cast<int64_t>(value) - static_cast<int64_t>(initialSendWindow_);
                    if (!applyDeltaToAllStreams(delta)) [[unlikely]]
                    {
                        protocolFailure(STREAM_ERROR::FLOW_CONTROL_ERROR, "stream send window overflow from SETTINGS");
                        return;
                    }
                    initialSendWindow_ = value;
                    pumpAll();
                    break;
                }
                default:
                    break;
                }
            }
            sendSettingsAck();
        }

        inline void handlePing(Frame &frame)
        {
            if (frame.streamId != 0) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "PING on a stream other than zero");
                return;
            }
            if (frame.payload.size() != 8) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "PING payload is not 8 bytes");
                return;
            }
            if (frame.hasFlag(FrameFlags::kAck))
            {
                if (unackedPings_ > 0)
                {
                    --unackedPings_;
                }
                return;
            }
            // CVE-2019-9512 Ping Flood 防御：单连接连续未排空 PING 突发上限
            ++unackedPings_;
            if (unackedPings_ > kMaxUnackedPings) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::ENHANCE_YOUR_CALM,
                                "excessive PING frames without peer activity (ping flood)");
                return;
            }
            Frame ack;
            ack.type = FRAME_TYPE::PING;
            ack.flags = FrameFlags::kAck;
            ack.payload = frame.payload;
            appendFrame(outScratch_, ack);
            flushOut();
        }

        inline void handleWindowUpdate(Frame &frame)
        {
            if (frame.payload.size() != 4) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "WINDOW_UPDATE payload is not 4 bytes");
                return;
            }
            // CVE-2019-9511 / CVE-2019-9513 Window Update Flood 防御：
            // 检测连续快速 WINDOW_UPDATE 风暴，防止频繁重排与迭代开销。
            // 判据是"连续无进展"：真实的大响应下载每来一帧都会推进出站发送，
            // 这类帧在末尾按进展清零；只有窗口在涨、数据发不出去的泛洪才会累积。
            const uint64_t pumpedBefore = pumpedBytes_;
            ++consecutiveWindowUpdates_;
            if (consecutiveWindowUpdates_ > kMaxConsecutiveWindowUpdates) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::ENHANCE_YOUR_CALM,
                                "excessive WINDOW_UPDATE frames (window update flood)");
                return;
            }
            const uint32_t increment = frame::readBigEndian32(frame.payload.data()) & frame::kStreamIdMask;
            if (increment == 0) [[unlikely]]
            {
                if (frame.streamId == 0)
                {
                    protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "a zero connection WINDOW_UPDATE");
                }
                else
                {
                    sendResetStream(frame.streamId, STREAM_ERROR::PROTOCOL_ERROR);
                    if (stream(frame.streamId) != nullptr)
                    {
                        closeStream(frame.streamId);
                    }
                }
                return;
            }
            if (frame.streamId == 0)
            {
                if (connSendWindow_ + static_cast<int64_t>(increment) > static_cast<int64_t>(frame::kStreamIdMask))
                    [[unlikely]]
                {
                    protocolFailure(STREAM_ERROR::FLOW_CONTROL_ERROR, "connection flow-control window overflow");
                    return;
                }
                connSendWindow_ += increment;
                pumpAll();
                if (pumpedBytes_ > pumpedBefore)
                {
                    consecutiveWindowUpdates_ = 0;
                }
                return;
            }
            StreamSlot *slot = stream(frame.streamId);
            if (slot == nullptr)
            {
                if (frame.streamId > lastPeerStreamId_) [[unlikely]]
                {
                    protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "WINDOW_UPDATE on an idle stream");
                }
                return;
            }
            if (slot->sendWindow + static_cast<int64_t>(increment) > static_cast<int64_t>(frame::kStreamIdMask))
                [[unlikely]]
            {
                sendResetStream(frame.streamId, STREAM_ERROR::FLOW_CONTROL_ERROR);
                closeStream(frame.streamId);
                return;
            }
            slot->sendWindow += increment;
            pumpStream(frame.streamId, *slot);
            if (pumpedBytes_ > pumpedBefore)
            {
                consecutiveWindowUpdates_ = 0;
            }
        }

        inline void handleReset(Frame &frame)
        {
            if (frame.payload.size() != 4) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "RST_STREAM payload is not 4 bytes");
                return;
            }
            if (frame.streamId == 0) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "RST_STREAM on the connection stream");
                return;
            }
            if (frame.streamId > lastPeerStreamId_) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "RST_STREAM on an idle stream");
                return;
            }
            // CVE-2023-44487 Rapid Reset 防御：
            // 检测连续快速重置风暴（客户端开流后立即发 RST_STREAM），防止 CPU 与对象池耗尽
            ++consecutiveResets_;
            if (consecutiveResets_ > kMaxConsecutiveResets) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::ENHANCE_YOUR_CALM, "excessive RST_STREAM frames (rapid reset attack)");
                return;
            }
            closeStream(frame.streamId);
        }

        inline void handleGoaway(Frame &frame)
        {
            if (frame.streamId != 0) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "GOAWAY on a stream other than zero");
                return;
            }
            if (frame.payload.size() < 8) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "GOAWAY payload is shorter than its 8 byte prefix");
                return;
            }
            goawayReceived_ = true;
            const uint32_t lastId = frame::readBigEndian32(frame.payload.data()) & frame::kStreamIdMask;
            const auto code = static_cast<STREAM_ERROR>(frame::readBigEndian32(frame.payload.data() + 4));
            LOG_INFO("HandlerHttp2: peer sent GOAWAY (last stream {}, code {})", lastId, std::to_underlying(code));

            // RFC 7540 Section 6.8:
            // 收到 GOAWAY 后，任何 streamId > lastId 的活跃流均视为未被对端处理，
            // 按照 REFUSED_STREAM 语义关闭并回收流槽位。
            if (streams_.ready())
            {
                std::vector<uint32_t> toClose;
                for (size_t i = 0; i < streams_.capacity(); ++i)
                {
                    const uint32_t id = streams_.keyAt(i);
                    if (id != 0 && id > lastId)
                    {
                        toClose.push_back(id);
                    }
                }
                for (uint32_t id : toClose)
                {
                    closeStream(id);
                }
            }
        }

        inline StreamSlot *openStream(uint32_t id)
        {
            StreamHandler *handler = streamPool_.acquire();
            if (handler == nullptr) [[unlikely]]
            {
                LOG_WARN("HandlerHttp2: the stream pool is exhausted at {} streams, refusing stream {}", maxStreams_,
                         id);
                lastPeerStreamId_ = id;
                return nullptr;
            }
            handler->reset();
            handler->setMaxRequestBytes(this->maxRequestBytes_);
            lastPeerStreamId_ = id;
            StreamSlot *slot = streams_.open(id);
            if (slot == nullptr) [[unlikely]]
            {
                // 表不可用或装填因子超限：回滚池租约，按 REFUSED_STREAM 降级
                streamPool_.release(handler);
                LOG_WARN("HandlerHttp2::openStream: stream table is full at {} active streams, refusing stream {}",
                         streams_.size(), id);
                return nullptr;
            }
            slot->handler = handler;
            slot->sendWindow = static_cast<int64_t>(initialSendWindow_);
            slot->recvWindow = streamRecvLimit_;
            slot->pendingOffset = 0;
            slot->headersReceived = false;
            slot->remoteEnded = false; // 墓碑复用槽位继承旧流标志：全部状态字段显式复位
            slot->localEnded = false;
            slot->finalSent = false;
            slot->pending.clear();
            onStreamOpen(id);
            return slot;
        }

        inline void endRemoteSide(uint32_t id, StreamSlot &slot)
        {
            slot.remoteEnded = true;
            creditReceiveWindow(id, slot);
            onStreamEnd(id);
            // 应用层可能在 onStreamEnd 中完成响应并关闭本流：此时 slot 引用已失效，
            // 必须重新查表，绝不能继续使用旧引用。
            if (StreamSlot *again = stream(id); again != nullptr)
            {
                if (again->finalSent)
                {
                    closeStream(id); // 双方都已 END_STREAM，流在此闭合
                    return;
                }
                collectResponses(id, *again);
            }
        }

        inline void closeStream(uint32_t id)
        {
            StreamSlot *slot = streams_.find(id);
            if (slot == nullptr)
            {
                return;
            }
            if (slot->handler != nullptr)
            {
                streamPool_.release(slot->handler);
            }
            streams_.erase(id);
            onStreamClose(id);
        }

        // ---- 响应发送路径 ----

        inline void collectResponses(uint32_t id, StreamSlot &slot) { pumpStream(id, slot); }

        inline void pumpStream(uint32_t id, StreamSlot &slot)
        {
            while (true)
            {
                if (slot.pendingOffset >= slot.pending.size())
                {
                    if (slot.handler != nullptr && slot.handler->hasResponse())
                    {
                        slot.pending = slot.handler->takeResponse();
                        slot.pendingOffset = 0;
                    }
                    else
                    {
                        break;
                    }
                }

                std::string &chunk = slot.pending;
                const size_t chunkRemaining = chunk.size() - slot.pendingOffset;
                const char *chunkData = chunk.data() + slot.pendingOffset;

                if (slot.sendWindow <= 0 || connSendWindow_ <= 0)
                {
                    return;
                }
                const size_t allowed =
                    std::min({chunkRemaining, static_cast<size_t>(slot.sendWindow),
                              static_cast<size_t>(connSendWindow_), static_cast<size_t>(sendMaxFrameSize_)});
                if (allowed == 0)
                {
                    return;
                }
                Frame frame;
                frame.streamId = id;
                frame.type = FRAME_TYPE::DATA;
                frame.payload.assign(chunkData, allowed);
                appendFrame(outScratch_, frame);
                if (!flushOut()) [[unlikely]]
                {
                    // 队列满：本帧已计入 pendingOffset，字节留在 outScratch_ 中，
                    // 由下一轮 flush 推出；本轮停止泵送以免把队列压得更深。
                    slot.sendWindow -= static_cast<int64_t>(allowed);
                    connSendWindow_ -= static_cast<int64_t>(allowed);
                    slot.pendingOffset += static_cast<uint32_t>(allowed);
                    pumpedBytes_ += allowed;
                    pumpStalled_ = true;
                    return;
                }
                slot.sendWindow -= static_cast<int64_t>(allowed);
                connSendWindow_ -= static_cast<int64_t>(allowed);
                slot.pendingOffset += static_cast<uint32_t>(allowed);
                pumpedBytes_ += allowed;
            }
            // 在途块已发尽：若无更多响应块则维持游标等待后续 WINDOW_UPDATE 推进
            if (slot.pendingOffset < slot.pending.size() || (slot.handler != nullptr && slot.handler->hasResponse()))
            {
                return;
            }
            // 出站已排空：若此前因慢读背压暂停了本流接收窗口，在此补发信用恢复。
            // 对端窗口已被本轮注入扣减至低位，需要一次完整增量才能继续发送。
            if (slot.readPaused)
            {
                slot.readPaused = false;
                if (streamCreditNeeded(slot))
                {
                    const uint32_t increment = streamRecvLimit_ - slot.recvWindow;
                    slot.recvWindow += increment;
                    sendWindowUpdate(id, increment);
                }
            }
            if ((!slot.remoteEnded && !slot.localEnded) || slot.finalSent)
            {
                return;
            }
            Frame last;
            last.streamId = id;
            last.type = FRAME_TYPE::DATA;
            last.flags = FrameFlags::kEndStream;
            appendFrame(outScratch_, last);
            (void)flushOut();
            slot.finalSent = true;
            // 只有对端也已结束发送，流才真正闭合；否则停在 half-closed(local)，
            // 等对端的 END_STREAM（或 RST_STREAM）来收尾。
            if (slot.remoteEnded)
            {
                closeStream(id);
            }
        }

        inline void pumpAll()
        {
            if (!streams_.ready())
            {
                return;
            }
            std::vector<uint32_t> ids;
            ids.reserve(streams_.size());
            for (size_t i = 0; i < streams_.capacity(); ++i)
            {
                const uint32_t id = streams_.keyAt(i);
                if (id != 0)
                {
                    ids.push_back(id);
                }
            }
            std::sort(ids.begin(), ids.end());
            for (uint32_t id : ids)
            {
                if (StreamSlot *slot = streams_.find(id); slot != nullptr)
                {
                    pumpStream(id, *slot);
                }
            }
        }

        /**
         * @brief 流级接收信用是否需要回补
         *
         * 以"对端已消耗的额度"为准：对端可用额度是我们 SETTINGS 宣告的窗口
         * （streamCreditUnit_），消耗过半即回补，与本地记账基准 streamRecvLimit_
         * （不低于 65535，用于容纳 SETTINGS 生效前的协议默认发送）无关。
         */
        [[nodiscard]] inline bool streamCreditNeeded(const StreamSlot &slot) const noexcept
        {
            return streamRecvLimit_ - slot.recvWindow >= streamCreditUnit_ / 2;
        }

        /**
         * @brief 按阈值回补连接级接收窗口（与具体流无关）
         */
        inline void creditConnectionWindow()
        {
            if (connRecvWindow_ < connRecvLimit_ / 2)
            {
                const uint32_t increment = connRecvLimit_ - connRecvWindow_;
                connRecvWindow_ += increment;
                sendWindowUpdate(0, increment);
            }
        }

        inline void creditReceiveWindow(uint32_t id, StreamSlot &slot)
        {
            // 慢读背压（对齐 connection.hpp v1/v2 修复模式）：
            // 若该流的出站响应尚未排空（pending 或 handler 队列仍有数据），
            // 暂缓恢复流级接收窗口 —— 对端因窗口耗尽无法继续注入 DATA，
            // 阻止 "零窗口读 + 无限注入" 的响应驻留放大（每流可达
            // responseCapacity × maxRequestBytes，128 流叠加可 OOM）。
            // 连接级窗口始终照常恢复：阻塞它会影响其他健康流。
            // 恢复点在 pumpStream：出站排空后补发 WINDOW_UPDATE。
            if (!slot.readPaused)
            {
                if (streamCreditNeeded(slot))
                {
                    const uint32_t increment = streamRecvLimit_ - slot.recvWindow;
                    slot.recvWindow += increment;
                    sendWindowUpdate(id, increment);
                }
                if (slot.pendingOffset < slot.pending.size() ||
                    (slot.handler != nullptr && slot.handler->hasResponse()))
                {
                    slot.readPaused = true; // 本轮恢复后立刻又积压了出站：下一轮起暂停信用恢复
                }
            }
            if (connRecvWindow_ < connRecvLimit_ / 2)
            {
                const uint32_t increment = connRecvLimit_ - connRecvWindow_;
                connRecvWindow_ += increment;
                sendWindowUpdate(0, increment);
            }
        }

        // ---- 出站帧构建与发送 ----

        inline void sendSettings()
        {
            Frame frame;
            frame.type = FRAME_TYPE::SETTINGS;
            appendSetting(frame.payload, mux::kSettingMaxConcurrentStreams, static_cast<uint32_t>(maxStreams_));
            appendSetting(frame.payload, mux::kSettingInitialWindowSize, static_cast<uint32_t>(initialWindow_));
            appendSetting(frame.payload, mux::kSettingMaxFrameSize, recvMaxFrameSize_);
            // 宣告我们能接受的首部列表上限：既是给对端的配额提示，也让"超限"
            // 成为可预期的流级错误，而不是让对方在解到一半时才失败。
            appendSetting(frame.payload, mux::kSettingMaxHeaderListSize,
                          static_cast<uint32_t>(http::v2::hpack::kMaxHeaderListBytes));
            appendFrame(outScratch_, frame);

            // SETTINGS_INITIAL_WINDOW_SIZE 只改变 **stream 级**接收窗口；connection 级
            // 窗口只能靠 WINDOW_UPDATE 提升（RFC 9113 §6.9.2）。配置值大于协议默认
            // 65535 时，必须显式补一条 stream 0 的增量，否则 connRecvWindow_ 与对端
            // 的实际可用额度不一致，声称的大窗口根本不存在。
            if (connRecvLimit_ > mux::kInitialWindowSize)
            {
                Frame update;
                update.type = FRAME_TYPE::WINDOW_UPDATE;
                update.streamId = 0;
                const uint32_t increment = static_cast<uint32_t>(connRecvLimit_ - mux::kInitialWindowSize);
                frame::appendBigEndian32(update.payload, increment & frame::kStreamIdMask);
                appendFrame(outScratch_, update);
            }
            (void)flushOut();
            settingsSent_ = true;
        }

        inline void sendSettingsAck()
        {
            Frame frame;
            frame.type = FRAME_TYPE::SETTINGS;
            frame.flags = FrameFlags::kAck;
            appendFrame(outScratch_, frame);
            (void)flushOut();
        }

        /**
         * @brief 写入一个首部块，按对端 SETTINGS_MAX_FRAME_SIZE 用 CONTINUATION 分片
         *
         * HEADERS 帧的载荷同样受帧上限约束：超过对端宣告值的首部块必须拆成
         * HEADERS + CONTINUATION（END_HEADERS 落在最后一片）。CONTINUATION 必须
         * 紧跟同一流的首部帧，因此本函数一次性把整组帧写入 outScratch_。
         */
        inline void appendHeaderBlock(uint32_t id, std::string_view block, bool endStream)
        {
            const size_t limit = std::max<size_t>(1, sendMaxFrameSize_);
            size_t offset = 0;
            do
            {
                const size_t chunk = std::min(limit, block.size() - offset);
                const bool last = offset + chunk == block.size();
                Frame frame;
                frame.streamId = id;
                frame.type = offset == 0 ? FRAME_TYPE::HEADERS : FRAME_TYPE::CONTINUATION;
                frame.flags = last ? FrameFlags::kEndHeaders : 0;
                if (offset == 0 && endStream)
                {
                    frame.flags |= FrameFlags::kEndStream;
                }
                frame.payload.assign(block.substr(offset, chunk));
                appendFrame(outScratch_, frame);
                offset += chunk;
            } while (offset < block.size());
        }

        inline void sendWindowUpdate(uint32_t id, uint32_t increment)
        {
            Frame frame;
            frame.type = FRAME_TYPE::WINDOW_UPDATE;
            frame.streamId = id;
            frame::appendBigEndian32(frame.payload, increment & frame::kStreamIdMask);
            appendFrame(outScratch_, frame);
            (void)flushOut();
        }

        inline void sendResetStream(uint32_t id, STREAM_ERROR code)
        {
            Frame frame;
            frame.type = FRAME_TYPE::RESET;
            frame.streamId = id;
            frame::appendBigEndian32(frame.payload, std::to_underlying(code));
            appendFrame(outScratch_, frame);
            (void)flushOut();
        }

        inline void protocolFailure(STREAM_ERROR code, std::string_view why)
        {
            if (closeAfterResponse_) [[unlikely]]
            {
                return;
            }
            LOG_ERROR("HandlerHttp2: protocol error on stream {}: {}", lastPeerStreamId_, why);
            Frame frame;
            frame.type = FRAME_TYPE::GOAWAY;
            frame::appendBigEndian32(frame.payload, lastPeerStreamId_ & frame::kStreamIdMask);
            frame::appendBigEndian32(frame.payload, std::to_underlying(code));
            frame.payload.append(why);
            appendFrame(outScratch_, frame);
            (void)flushOut();
            closeAfterResponse_ = true;
            onProtocolError(code, why);
        }

        /**
         * @brief 把累积的出站帧推入连接响应队列
         *
         * @return false 表示响应队列已满、字节**保留在 outScratch_ 中**待下一轮重试。
         *         绝不能丢弃：丢一个 DATA 帧就毁掉整条流（对端拿到错误长度或超时），
         *         丢一个控制帧则直接失步。
         */
        [[nodiscard]] inline bool flushOut()
        {
            if (outScratch_.empty()) [[unlikely]]
            {
                return true;
            }
            if (!pushResponse(std::move(outScratch_))) [[unlikely]]
            {
                return false; // push 失败不移动实参，outScratch_ 内容完整保留
            }
            outScratch_.clear();
            return true;
        }

        static inline void appendSetting(std::string &out, uint16_t id, uint32_t value)
        {
            const uint16_t beId = std::byteswap(id);
            out.append(reinterpret_cast<const char *>(&beId), sizeof(beId));
            frame::appendBigEndian32(out, value);
        }

        inline bool unframePayload(Frame &frame, std::string_view &out)
        {
            std::string_view body(frame.payload);
            if (frame.hasFlag(FrameFlags::kPadded))
            {
                if (body.empty()) [[unlikely]]
                {
                    protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "PADDED with an empty payload");
                    return false;
                }
                const size_t pad = static_cast<unsigned char>(body.front());
                body.remove_prefix(1);
                if (pad > body.size()) [[unlikely]]
                {
                    protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "padding longer than the payload it is padding");
                    return false;
                }
                body.remove_suffix(pad);
            }
            out = body;
            return true;
        }

        [[nodiscard]] inline StreamSlot *stream(uint32_t id) { return streams_.find(id); }

        /**
         * @brief 取得指定流的上层处理器（供派生协议前端读取该流的已收字节）
         */
        [[nodiscard]] inline StreamHandler *streamHandler(uint32_t id) noexcept
        {
            StreamSlot *slot = stream(id);
            return slot == nullptr ? nullptr : slot->handler;
        }

        /**
         * @brief SETTINGS initial-window 变更的流级窗口平移（两遍：先验证后提交）。
         * @return false 表示存在流会溢出，调用方以 FLOW_CONTROL_ERROR 整体失败。
         */
        inline bool applyDeltaToAllStreams(int64_t delta)
        {
            if (!streams_.ready())
            {
                return true; // 无表即无流，无需平移
            }
            for (size_t i = 0; i < streams_.capacity(); ++i)
            {
                const uint32_t id = streams_.keyAt(i);
                if (id != 0)
                {
                    const StreamSlot *slot = streams_.slotAt(i);
                    if (slot->sendWindow + delta > static_cast<int64_t>(frame::kStreamIdMask)) [[unlikely]]
                    {
                        return false;
                    }
                }
            }
            for (size_t i = 0; i < streams_.capacity(); ++i)
            {
                const uint32_t id = streams_.keyAt(i);
                if (id != 0)
                {
                    streams_.slotAt(i)->sendWindow += delta;
                }
            }
            return true;
        }

        static constexpr size_t kMaxConsecutiveResets = 100;
        static constexpr size_t kMaxUnackedPings = 64;
        static constexpr size_t kMaxUnackedSettings = 16;
        static constexpr size_t kMaxConsecutiveEmptyFrames = 32;
        static constexpr size_t kMaxConsecutiveWindowUpdates = 100;
        static constexpr size_t kMaxConsecutivePriorityFrames = 64;
        /// @brief 单个首部块（HEADERS + CONTINUATION 累积）的压缩字节上限
        ///
        /// 必须显著高于 SETTINGS 宣告的**解压后**列表上限：Huffman 最坏情况是
        /// 30 位/字节（码长 28~30 的符号），即膨胀 3.75 倍，加上每字段的索引开销
        /// 后，一个刚好卡在列表上限的合规块仍可能接近 246 KiB。留 4 倍余量
        /// （256 KiB）后，真正过大的列表由解码器按流级错误裁决，而不是在重组
        /// 阶段就被误判。此倍数不得下调。
        static constexpr size_t kMaxHeaderBlockBytes = 4 * http::v2::hpack::kMaxHeaderListBytes;
        /// @brief 单个首部块允许的分片帧数上限（防零长帧洪水，内存由字节上限兜底）
        static constexpr size_t kMaxContinuationFrames = 4096;
        /// @brief 连续零长 CONTINUATION 帧上限
        static constexpr size_t kMaxEmptyContinuationFrames = 32;

        ObjectPool<StreamHandler> streamPool_{};
        mux::StreamTable<StreamSlot> streams_{};
        FrameDecoder decoder_{};
        http::v2::HpackDecoder hpackDecoder_{};
        http::v2::HpackEncoder hpackEncoder_{};
        std::string outScratch_{};
        /// 本端宣告的接收帧上限（SETTINGS_MAX_FRAME_SIZE），只约束入站解码。
        uint32_t recvMaxFrameSize_ = frame::kDefaultMaxFrameSize;
        /// 对端宣告的接收帧上限，只约束出站分片（默认协议值，收到 SETTINGS 后更新）。
        uint32_t sendMaxFrameSize_ = frame::kDefaultMaxFrameSize;
        bool prefaceConsumed_ = false;
        /// 上一轮 process() 因出站背压提前返回（剩余字节仍在请求缓冲里）
        bool pendingDecode_ = false;
        /// 有流因响应队列压满而停在发送半路（队列腾空后必须再泵一次）
        bool pumpStalled_ = false;
        /// 正在等待 CONTINUATION 收尾的首部块状态（连接级：同一时刻只能有一个）
        bool awaitingContinuation_ = false;
        uint32_t headerBlockStreamId_ = 0;
        std::string headerBlock_{};
        bool contEndStream_ = false;
        size_t contFrameCount_ = 0;
        size_t contEmptyFrames_ = 0;
        /// 对端 SETTINGS_MAX_HEADER_LIST_SIZE，约束本端出站首部。
        /// 0 表示对端不接受任何首部（RFC 9113 未给 0 开特例），不是"无限制"。
        size_t peerMaxHeaderListBytes_ = std::numeric_limits<size_t>::max();
        size_t maxStreams_ = mux::kDefaultMaxStreams;
        size_t initialWindow_ = mux::kInitialWindowSize;
        /// 连接级接收窗口的真值：至少协议默认 65535，可被配置抬高，不可降低。
        uint32_t connRecvLimit_ = mux::kInitialWindowSize;
        /// 流级接收窗口的真值：同样不低于协议默认 65535，理由见 applyMultiplexerConfig。
        uint32_t streamRecvLimit_ = mux::kInitialWindowSize;
        /// 本端 SETTINGS 宣告的流级窗口：对端实际可注入的额度，也是回补判据的基准。
        uint32_t streamCreditUnit_ = mux::kInitialWindowSize;
        int64_t connSendWindow_ = mux::kInitialWindowSize;
        uint32_t connRecvWindow_ = mux::kInitialWindowSize;
        uint32_t initialSendWindow_ = mux::kInitialWindowSize;
        uint32_t lastPeerStreamId_ = 0;
        /// 累计已从流响应队列搬运到线上的 DATA 字节数，用于判定 WINDOW_UPDATE 是否带来进展。
        uint64_t pumpedBytes_ = 0;
        size_t consecutiveResets_ = 0;
        size_t unackedPings_ = 0;
        size_t unackedSettings_ = 0;
        size_t consecutiveEmptyFrames_ = 0;
        size_t consecutiveWindowUpdates_ = 0;
        size_t consecutivePriorityFrames_ = 0;
        bool settingsSent_ = false;
        bool goawayReceived_ = false;
    };

    namespace http::v2
    {
        using ::mynet::Frame;
        using ::mynet::FRAME_ERROR;
        using ::mynet::FRAME_TYPE;
        using ::mynet::FrameDecoder;
        using ::mynet::STREAM_ERROR;
        namespace FrameFlags = ::mynet::FrameFlags;

        // HandlerHttp2 定义在本文件的 ::mynet 命名空间内；此处将名字引入 http::v2，
        // 使 http::v2::HandlerHttp2 与 http::v1::HandlerHttp、http::v3::HandlerHttp3 用法一致。
        using ::mynet::HandlerHttp2;
    } // namespace http::v2

} // namespace mynet
