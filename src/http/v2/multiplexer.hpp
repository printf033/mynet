#pragma once

/**
 * @file multiplexer.hpp
 * @brief HTTP/2 分帧多路复用器，用于在单条物理连接上承载多个独立的逻辑流交互。
 */

#include "../../handler.hpp"
#include "buffer.hpp"
#include "concepts.hpp"
#include "frame.hpp"
#include "log.hpp"
#include "objectPool.hpp"
#include "streamTable.hpp"
#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <optional>
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
    namespace mux
    {
        inline constexpr uint32_t kInitialWindowSize = (64 << 10) - 1;
        inline constexpr uint32_t kWindowUpdateThreshold = kInitialWindowSize / 2;
        inline constexpr uint32_t kDefaultMaxStreams = 128;
        inline constexpr uint16_t kSettingMaxConcurrentStreams = 0x3;
        inline constexpr uint16_t kSettingInitialWindowSize = 0x4;
        inline constexpr uint16_t kSettingMaxFrameSize = 0x5;
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
        ENHANCE_YOUR_CALM = 0xb
    };

    /**
     * @class Multiplexer
     * @brief 将单一字节流解复用为多个独立逻辑交互流的多路复用器。
     *
     * 实现 HandlerBase 契约概念，可直接作为 Connection<Multiplexer<H>> 的协议处理器。
     * 负责分帧解码、流控窗口管理、流生命周期跟踪与响应数据序列化。
     *
     * @tparam StreamHandler 每条独立流所实例化的协议处理器类型。
     */
    template <typename StreamHandler>
        requires ProtocolHandler<StreamHandler>
    class Multiplexer : public HandlerBase
    {
    public:
        using Stream = StreamHandler;

        Multiplexer() noexcept = default;
        ~Multiplexer() noexcept override = default;
        Multiplexer(const Multiplexer &) = delete("a multiplexer owns the stream table and the frames bound to it");
        Multiplexer &
        operator=(const Multiplexer &) = delete("a multiplexer owns the stream table and the frames bound to it");
        Multiplexer(Multiplexer &&) = delete("a multiplexer owns the stream table and the frames bound to it");
        Multiplexer &
        operator=(Multiplexer &&) = delete("a multiplexer owns the stream table and the frames bound to it");

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
                    LOG_ERROR("Multiplexer::setMaxConcurrentStreams: initialising stream pool ({} slots) failed",
                              maxStreams_);
                }
                if (auto tableRes = streams_.init(maxStreams_); !tableRes) [[unlikely]]
                {
                    LOG_ERROR("Multiplexer::setMaxConcurrentStreams: initialising stream table ({} slots) failed",
                              maxStreams_);
                }
            }
        }

        [[nodiscard]] inline size_t maxConcurrentStreams() const noexcept { return maxStreams_; }

        [[nodiscard]] inline size_t openStreams() const noexcept { return streams_.size(); }

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
            HandlerBase::reset();
            streams_.clear(
                [this]([[maybe_unused]] const uint32_t id, StreamSlot &slot)
                {
                    if (slot.handler != nullptr)
                    {
                        streamPool_.release(slot.handler);
                    }
                });
            ensureStreamPool();
            connSendWindow_ = mux::kInitialWindowSize;
            connRecvWindow_ = mux::kInitialWindowSize;
            lastPeerStreamId_ = 0;
            consecutiveResets_ = 0;
            unackedPings_ = 0;
            unackedSettings_ = 0;
            consecutiveEmptyFrames_ = 0;
            consecutiveWindowUpdates_ = 0;
            consecutivePriorityFrames_ = 0;
            settingsSent_ = false;
            goawayReceived_ = false;
            outScratch_.clear();
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
            while (true)
            {
                std::expected<std::optional<Frame>, FRAME_ERROR> parsed = decoder_.next(requestBuffer_);
                if (!parsed) [[unlikely]]
                {
                    protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, toString(parsed.error()));
                    return;
                }
                if (!parsed->has_value())
                {
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
        inline void ensureStreamPool()
        {
            if (streamPool_.capacity() == 0 || !streams_.ready()) [[unlikely]]
            {
                if (streamPool_.capacity() == 0)
                {
                    if (auto poolRes = streamPool_.init(maxStreams_); !poolRes) [[unlikely]]
                    {
                        // noexcept 链上不能抛：池保持不可用，acquire() 返回 nullptr 自然降级
                        LOG_ERROR("Multiplexer::ensureStreamPool: initialising stream pool ({} slots) failed",
                                  maxStreams_);
                    }
                }
                if (!streams_.ready())
                {
                    if (auto tableRes = streams_.init(maxStreams_); !tableRes) [[unlikely]]
                    {
                        // 表不可用时 open() 返回 nullptr，openStream 侧以 REFUSED_STREAM 自然降级
                        LOG_ERROR("Multiplexer::ensureStreamPool: initialising stream table ({} slots) failed",
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
            uint32_t pendingOffset = 0; ///< 在途 chunk 已发出的字节数（partial 发送游标）
            bool remoteEnded = false;
            bool finalSent = false;
            std::string pending{}; ///< 在途响应块（collectResponses 阶段只保留一个，发送不完驻留）
        };

        // ---- 帧分发处理 ----

        inline void handleFrame(Frame frame)
        {
            LOG_DEBUG("Multiplexer: frame type {} flags {} on stream {} ({} payload byte(s))",
                      std::to_underlying(frame.type), frame.flags, frame.streamId, frame.payload.size());
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
            if (!canOpenStream(frame.streamId, "HEADERS")) [[unlikely]]
            {
                return;
            }
            // CVE-2024-27983 Continuation Flood 防御：
            // 在不支持多帧首部分片的轻量多路复用器中，首部必须在单帧内完整终结 (END_HEADERS)
            if (!frame.hasFlag(FrameFlags::kEndHeaders)) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "HEADERS frame missing END_HEADERS flag");
                return;
            }
            StreamSlot *slot = stream(frame.streamId);
            if (slot == nullptr)
            {
                slot = openStream(frame.streamId);
                if (slot == nullptr) [[unlikely]]
                {
                    sendResetStream(frame.streamId, STREAM_ERROR::REFUSED_STREAM);
                    return;
                }
            }
            else if (slot->remoteEnded) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "HEADERS after END_STREAM on the same stream");
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
            onStreamHeaders(frame.streamId, block);
            if (frame.hasFlag(FrameFlags::kEndStream))
            {
                endRemoteSide(frame.streamId, *slot);
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

            onStreamData(frame.streamId, bytes);
            if (auto res = slot->handler->appendRequest(bytes.data(), static_cast<ssize_t>(bytes.size())); !res)
                [[unlikely]]
            {
                LOG_ERROR("Multiplexer: stream {} appendRequest failed: {}", frame.streamId, toString(res.error()));
                sendResetStream(frame.streamId, STREAM_ERROR::INTERNAL_ERROR);
                closeStream(frame.streamId);
                return;
            }
            slot->handler->process();
            collectResponses(frame.streamId, *slot);

            if (frame.hasFlag(FrameFlags::kEndStream))
            {
                endRemoteSide(frame.streamId, *slot);
                return;
            }
            creditReceiveWindow(frame.streamId, *slot);
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
                case mux::kSettingMaxFrameSize:
                    if (value < frame::kDefaultMaxFrameSize || value > 0x00ffffffu) [[unlikely]]
                    {
                        protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "invalid SETTINGS_MAX_FRAME_SIZE value");
                        return;
                    }
                    decoder_.setMaxFrameSize(value);
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
            // 检测连续快速 WINDOW_UPDATE 风暴，防止频繁重排与迭代开销
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
                return;
            }
            slot->sendWindow += increment;
            pumpStream(frame.streamId, *slot);
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
            LOG_INFO("Multiplexer: peer sent GOAWAY (last stream {}, code {})", lastId, std::to_underlying(code));

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

        // ---- 流生命周期管理 ----

        inline bool canOpenStream(uint32_t id, const char *what)
        {
            if (id == 0 || (id % 2) == 0) [[unlikely]]
            {
                std::string why = what;
                why += " on a stream the peer may not open";
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, why);
                return false;
            }
            if (goawayReceived_) [[unlikely]]
            {
                LOG_WARN("Multiplexer: refusing a new stream after GOAWAY from the peer");
                sendResetStream(id, STREAM_ERROR::REFUSED_STREAM);
                return false;
            }
            if (stream(id) != nullptr)
            {
                return true;
            }
            if (id <= lastPeerStreamId_) [[unlikely]]
            {
                protocolFailure(STREAM_ERROR::PROTOCOL_ERROR, "a stream identifier that does not increase");
                return false;
            }
            return true;
        }

        inline StreamSlot *openStream(uint32_t id)
        {
            StreamHandler *handler = streamPool_.acquire();
            if (handler == nullptr) [[unlikely]]
            {
                LOG_WARN("Multiplexer: the stream pool is exhausted at {} streams, refusing stream {}", maxStreams_,
                         id);
                lastPeerStreamId_ = id;
                return nullptr;
            }
            handler->reset();
            lastPeerStreamId_ = id;
            StreamSlot *slot = streams_.open(id);
            if (slot == nullptr) [[unlikely]]
            {
                // 表不可用或装填因子超限：回滚池租约，按 REFUSED_STREAM 降级
                streamPool_.release(handler);
                LOG_WARN("Multiplexer::openStream: stream table is full at {} active streams, refusing stream {}",
                         streams_.size(), id);
                return nullptr;
            }
            slot->handler = handler;
            slot->sendWindow = static_cast<int64_t>(initialSendWindow_);
            slot->recvWindow = mux::kInitialWindowSize;
            slot->pendingOffset = 0;
            slot->remoteEnded = false; // 墓碑复用槽位继承旧流标志：全部状态字段显式复位
            slot->finalSent = false;
            slot->pending.clear();
            onStreamOpen(id);
            return slot;
        }

        inline void endRemoteSide(uint32_t id, StreamSlot &slot)
        {
            slot.remoteEnded = true;
            creditReceiveWindow(id, slot);
            collectResponses(id, slot);
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
                              static_cast<size_t>(connSendWindow_), static_cast<size_t>(decoder_.maxFrameSize())});
                if (allowed == 0)
                {
                    return;
                }
                Frame frame;
                frame.streamId = id;
                frame.type = FRAME_TYPE::DATA;
                frame.payload.assign(chunkData, allowed);
                appendFrame(outScratch_, frame);
                flushOut();
                slot.sendWindow -= static_cast<int64_t>(allowed);
                connSendWindow_ -= static_cast<int64_t>(allowed);
                slot.pendingOffset += static_cast<uint32_t>(allowed);
            }
            // 在途块已发尽：若无更多响应块则维持游标等待后续 WINDOW_UPDATE 推进
            if (slot.pendingOffset < slot.pending.size() || (slot.handler != nullptr && slot.handler->hasResponse()))
            {
                return;
            }
            if (!slot.remoteEnded || slot.finalSent)
            {
                return;
            }
            Frame last;
            last.streamId = id;
            last.type = FRAME_TYPE::DATA;
            last.flags = FrameFlags::kEndStream;
            appendFrame(outScratch_, last);
            flushOut();
            slot.finalSent = true;
            closeStream(id);
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

        inline void creditReceiveWindow(uint32_t id, StreamSlot &slot)
        {
            if (slot.recvWindow < mux::kWindowUpdateThreshold)
            {
                const uint32_t increment = mux::kInitialWindowSize - slot.recvWindow;
                slot.recvWindow += increment;
                sendWindowUpdate(id, increment);
            }
            if (connRecvWindow_ < mux::kWindowUpdateThreshold)
            {
                const uint32_t increment = mux::kInitialWindowSize - connRecvWindow_;
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
            appendSetting(frame.payload, mux::kSettingInitialWindowSize, mux::kInitialWindowSize);
            appendSetting(frame.payload, mux::kSettingMaxFrameSize, decoder_.maxFrameSize());
            appendFrame(outScratch_, frame);
            flushOut();
            settingsSent_ = true;
        }

        inline void sendSettingsAck()
        {
            Frame frame;
            frame.type = FRAME_TYPE::SETTINGS;
            frame.flags = FrameFlags::kAck;
            appendFrame(outScratch_, frame);
            flushOut();
        }

        inline void sendWindowUpdate(uint32_t id, uint32_t increment)
        {
            Frame frame;
            frame.type = FRAME_TYPE::WINDOW_UPDATE;
            frame.streamId = id;
            frame::appendBigEndian32(frame.payload, increment & frame::kStreamIdMask);
            appendFrame(outScratch_, frame);
            flushOut();
        }

        inline void sendResetStream(uint32_t id, STREAM_ERROR code)
        {
            Frame frame;
            frame.type = FRAME_TYPE::RESET;
            frame.streamId = id;
            frame::appendBigEndian32(frame.payload, std::to_underlying(code));
            appendFrame(outScratch_, frame);
            flushOut();
        }

        inline void protocolFailure(STREAM_ERROR code, std::string_view why)
        {
            if (closeAfterResponse_) [[unlikely]]
            {
                return;
            }
            LOG_ERROR("Multiplexer: protocol error on stream {}: {}", lastPeerStreamId_, why);
            Frame frame;
            frame.type = FRAME_TYPE::GOAWAY;
            frame::appendBigEndian32(frame.payload, lastPeerStreamId_ & frame::kStreamIdMask);
            frame::appendBigEndian32(frame.payload, std::to_underlying(code));
            frame.payload.append(why);
            appendFrame(outScratch_, frame);
            flushOut();
            closeAfterResponse_ = true;
            onProtocolError(code, why);
        }

        inline void flushOut()
        {
            if (outScratch_.empty()) [[unlikely]]
            {
                return;
            }
            if (!pushResponse(std::move(outScratch_))) [[unlikely]]
            {
                // 响应队列满：MUX 帧是不可丢弃的控制数据，丢弃并记录；
                // 实际背压由 writeHighWaterMark 在连接层先行拦截，此路径仅防御性
                LOG_ERROR("Multiplexer::flushOut: response queue full, mux output dropped ({} bytes)",
                          outScratch_.size());
            }
            outScratch_.clear();
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
                    StreamSlot *slot = streams_.slotAt(i);
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

        ObjectPool<StreamHandler> streamPool_{};
        mux::StreamTable<StreamSlot> streams_{};
        FrameDecoder decoder_{};
        std::string outScratch_{};
        size_t maxStreams_ = mux::kDefaultMaxStreams;
        int64_t connSendWindow_ = mux::kInitialWindowSize;
        uint32_t connRecvWindow_ = mux::kInitialWindowSize;
        uint32_t initialSendWindow_ = mux::kInitialWindowSize;
        uint32_t lastPeerStreamId_ = 0;
        size_t consecutiveResets_ = 0;
        size_t unackedPings_ = 0;
        size_t unackedSettings_ = 0;
        size_t consecutiveEmptyFrames_ = 0;
        size_t consecutiveWindowUpdates_ = 0;
        size_t consecutivePriorityFrames_ = 0;
        bool settingsSent_ = false;
        bool goawayReceived_ = false;
    };

} // namespace mynet
