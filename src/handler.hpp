#pragma once

/**
 * @file handler.hpp
 * @brief 统一纯业务协议处理器基类 (Handler / HandlerInbound / HandlerOutbound / MuxInboundHandler)
 *
 * 与底层传输端点 (Connection / Datagram) 解耦，供流式连接与无连接数据报会话同等持有与复用。
 */

#include "address.hpp"
#include "config/log.hpp"
#include "configHolder.hpp"
#include "constraints.hpp"
#include "error.hpp"
#include "requestBuffer.hpp"
#include "responseQueue.hpp"
#include "transport.hpp"
#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <expected>
#include <functional>
#include <memory>
#include <netinet/in.h>
#include <new>
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace mynet
{
    class Connection;

    namespace handler
    {
        enum class InboundStage : uint8_t
        {
            HANDSHAKE, ///< 正在接收并解析入站握手报文/鉴权/提取目标地址
            STREAMING, ///< 握手完成，进入数据流式透传/内核零拷贝转发阶段
            ERROR      ///< 鉴权失败或协议格式畸变
        };

        enum class OutboundStage : uint8_t
        {
            INITIAL,    ///< 初始未握手状态
            CONNECTING, ///< 正在发送出站协议头部或等待对端认证回执
            STREAMING,  ///< 握手完成，进入流式数据透传/内核零拷贝转发
            ERROR       ///< 出站协议握手失败或对端报错
        };
    } // namespace handler

    using DatagramQueue = ResponseQueueBase<Packet>;

    /**
     * @brief 统一纯业务协议处理器基类 (Handler)
     *
     * 架构核心支柱：
     * 1. 彻底与传输层无关：不包含任何底层 socket/fd/网络传输状态；
     * 2. 彻底合并流式与数据报：统一收敛单一根基类，无分化、无二义性，同时提供流式帧解析与数据报发送缓冲；
     * 3. 在连接之上、之内：挂载于 Connection 或会话对象中，通过 connection_ 回溯宿主连接；
     * 4. 纯业务状态机：包含 stages、targetAddress、command、回调以及业务生命周期钩子。
     */
    class Handler
    {
    public:
        [[nodiscard]] virtual bool isPassthrough() const noexcept
        {
            return wireState_ == nullptr || (wireState_->transport.empty() && !wireState_->codecMode);
        }
        [[nodiscard]] virtual bool canSplice() const noexcept { return isPassthrough(); }
        using RequestCallback = std::function<void(uint8_t cmd, const Address &target)>;
        using DatagramCallback = std::function<void(const sockaddr_in &peer, const Address &target,
                                                    const char *data, size_t n)>;

    protected:
        // 按需分配的冷路径扩展状态：避免每个纯 TCP 连接平白携带传输管线、双解码缓冲与 1024 槽数据报队列
        struct WireCodecState
        {
            transport::TransportPipeline transport{};
            RequestBuffer wireRxBuffer{};
            RequestBuffer codecRxBuffer{};
            ResponseQueue pendingAppTx{};
            bool codecMode{false};
            bool pendingAppTxInit{false};

            explicit WireCodecState(size_t readHighWaterMark) noexcept
            {
                wireRxBuffer.setHighWaterMark(readHighWaterMark);
            }
        };

        struct DatagramState
        {
            DatagramCallback datagramCallback{nullptr};
            sockaddr_in remotePeer{};
            size_t maxDatagramBytes{1 << 16};
            size_t maxPendingOutgoing{1 << 10};
            DatagramQueue outgoing{};
            size_t droppedOutgoing{0};
        };

        // 连接关联与套接字描述符
        Connection *connection_{nullptr};
        int fd_{-1};

        // 业务状态机
        handler::InboundStage inboundStage_{handler::InboundStage::HANDSHAKE};
        handler::OutboundStage outboundStage_{handler::OutboundStage::INITIAL};
        std::optional<Address> targetAddress_{std::nullopt};
        uint8_t command_{0};
        RequestCallback requestCallback_{nullptr};

        // 业务层高频核心缓冲与队列
        RequestBuffer requestBuffer_{};
        ResponseQueue responseQueue_{};
        std::string spare_{};
        size_t maxRequestBytes_{getConnectionConfig().maxRequestBytes};
        size_t readHighWaterMark_{getConnectionConfig().readHighWaterMark};
        bool closeAfterResponse_{false};

        struct ExternalDataPlaneState
        {
            std::function<void()> onData{};
            std::function<int(uint32_t)> onReactorIo{};
            std::function<bool()> suppressConnRecv{};
            uint64_t nextDetachToken{1};
            std::vector<std::pair<uint64_t, std::function<void()>>> detachHooks{};
        };

        // 按需延迟初始化的传输/编解码状态、数据报状态与外部数据面钩子
        std::unique_ptr<WireCodecState> wireState_{nullptr};
        std::unique_ptr<DatagramState> dgramState_{nullptr};
        std::unique_ptr<ExternalDataPlaneState> extDataPlane_{nullptr};

        [[nodiscard]] inline WireCodecState *ensureWireState() noexcept
        {
            if (wireState_ == nullptr) [[unlikely]]
            {
                wireState_.reset(new (std::nothrow) WireCodecState(readHighWaterMark_));
            }
            return wireState_.get();
        }

        [[nodiscard]] inline DatagramState *ensureDatagramState() noexcept
        {
            if (dgramState_ == nullptr) [[unlikely]]
            {
                auto *st = new (std::nothrow) DatagramState();
                if (st != nullptr)
                {
                    const auto &cfg = getDatagramConfig();
                    st->maxDatagramBytes = cfg.maxDatagramBytes;
                    st->maxPendingOutgoing = cfg.maxPendingOutgoing;
                    dgramState_.reset(st);
                }
            }
            return dgramState_.get();
        }

        inline void ensureOutgoingInit() noexcept
        {
            if (auto *ds = ensureDatagramState(); ds != nullptr && ds->outgoing.capacity() == 0) [[unlikely]]
            {
                [[maybe_unused]] auto _ = ds->outgoing.init(ds->maxPendingOutgoing);
            }
        }

        [[nodiscard]] static inline const transport::TransportPipeline &emptyPipeline() noexcept
        {
            static const transport::TransportPipeline kEmpty{};
            return kEmpty;
        }

        [[nodiscard]] inline Result<> flushPendingAppTx() noexcept
        {
            if (wireState_ == nullptr || !wireState_->pendingAppTxInit || wireState_->pendingAppTx.empty() ||
                !wireState_->transport.isReady())
            {
                return {};
            }
            while (!wireState_->pendingAppTx.empty())
            {
                auto pkt = std::move(wireState_->pendingAppTx.front());
                wireState_->pendingAppTx.pop();
                if (!pkt.bytes.empty())
                {
                    std::span<const uint8_t> sp(reinterpret_cast<const uint8_t *>(pkt.bytes.data()),
                                                pkt.bytes.size());
                    if (auto r = wireState_->transport.processOutbound(sp, responseQueue_); !r)
                    {
                        return r;
                    }
                }
            }
            return {};
        }

        [[nodiscard]] inline Result<> emitEncodedToWire(std::string_view sv) noexcept
        {
            if (sv.data() == nullptr || sv.empty())
            {
                return {};
            }
            if (wireState_ == nullptr || wireState_->transport.empty())
            {
                return responseQueue_.emplace(sv);
            }
            if (wireState_->transport.isReady())
            {
                if (auto r = flushPendingAppTx(); !r)
                {
                    return r;
                }
                std::span<const uint8_t> sp(reinterpret_cast<const uint8_t *>(sv.data()), sv.size());
                return wireState_->transport.processOutbound(sp, responseQueue_);
            }
            if (!wireState_->pendingAppTxInit)
            {
                if (auto r = wireState_->pendingAppTx.init(64); !r)
                {
                    return r;
                }
                wireState_->pendingAppTxInit = true;
            }
            return wireState_->pendingAppTx.emplace(sv);
        }

    public:
        Handler() noexcept
            : Handler(getConnectionConfig())
        {
        }

        explicit Handler(size_t responseCapacity) noexcept
        {
            [[maybe_unused]] auto _ = responseQueue_.init(responseCapacity);
        }

        explicit Handler(const ConnectionConfig &config) noexcept
            : maxRequestBytes_(config.maxRequestBytes),
              readHighWaterMark_(config.readHighWaterMark)
        {
            requestBuffer_.setHighWaterMark(readHighWaterMark_);
            [[maybe_unused]] auto _ = responseQueue_.init(config.responseCapacity);
        }

        explicit Handler(const DatagramConfig &config) noexcept
        {
            requestBuffer_.setHighWaterMark(readHighWaterMark_);
            [[maybe_unused]] auto _ = responseQueue_.init(getConnectionConfig().responseCapacity);
            if (auto *ds = ensureDatagramState(); ds != nullptr)
            {
                ds->maxDatagramBytes = config.maxDatagramBytes;
                ds->maxPendingOutgoing = config.maxPendingOutgoing;
                [[maybe_unused]] auto _2 = ds->outgoing.init(ds->maxPendingOutgoing);
            }
        }

        explicit Handler(const Address &target) noexcept
            : Handler()
        {
            targetAddress_ = target;
        }

        explicit Handler(const sockaddr_in &peer) noexcept
            : Handler()
        {
            if (auto *ds = ensureDatagramState(); ds != nullptr)
            {
                ds->remotePeer = peer;
            }
        }

        virtual ~Handler() noexcept { notifyExternalClosed(); }

        Handler(const Handler &) = delete;
        Handler &operator=(const Handler &) = delete;
        Handler(Handler &&) = delete;
        Handler &operator=(Handler &&) = delete;

        // ---- 连接关联与挂钩 (Connection Linkage) ----
        inline void setConnection(Connection *c) noexcept { connection_ = c; }
        [[nodiscard]] inline Connection *connection() const noexcept { return connection_; }
        [[nodiscard]] inline int fd() const noexcept;

        // ---- 传输管道与流式编解码器扩展接口 ----
        inline void setCodecMode(bool enabled) noexcept
        {
            if (enabled)
            {
                if (auto *ws = ensureWireState(); ws != nullptr)
                {
                    ws->codecMode = true;
                }
            }
            else if (wireState_ != nullptr)
            {
                wireState_->codecMode = false;
            }
        }
        [[nodiscard]] inline bool codecMode() const noexcept
        {
            return wireState_ != nullptr && wireState_->codecMode;
        }
        [[nodiscard]] inline bool usesWireBuffer() const noexcept
        {
            return wireState_ != nullptr && (!wireState_->transport.empty() || wireState_->codecMode);
        }

        inline void addTransportLayer(std::unique_ptr<transport::ITransport> layer)
        {
            if (auto *ws = ensureWireState(); ws != nullptr)
            {
                ws->transport.addLayer(std::move(layer));
            }
        }

        [[nodiscard]] inline transport::TransportPipeline &transportPipeline() noexcept
        {
            if (auto *ws = ensureWireState(); ws != nullptr)
            {
                return ws->transport;
            }
            static transport::TransportPipeline s_fallbackPipeline{};
            return s_fallbackPipeline;
        }
        [[nodiscard]] inline const transport::TransportPipeline &transportPipeline() const noexcept
        {
            return wireState_ != nullptr ? wireState_->transport : emptyPipeline();
        }
        [[nodiscard]] inline bool isTransportReady() const noexcept
        {
            return wireState_ == nullptr || wireState_->transport.isReady();
        }

        [[nodiscard]] inline Result<> startTransportHandshake() noexcept
        {
            if (wireState_ == nullptr)
            {
                return {};
            }
            return wireState_->transport.startHandshake(responseQueue_);
        }

        /**
         * @brief 当协议使用双缓冲/编解码模式时的线侧原始接收缓冲（供协议 Codec 解码读取）
         */
        [[nodiscard]] inline RequestBuffer &wireRxBuffer() noexcept
        {
            if (auto *ws = ensureWireState(); ws != nullptr)
            {
                return !ws->transport.empty() ? ws->codecRxBuffer : ws->wireRxBuffer;
            }
            return requestBuffer_;
        }

        /**
         * @brief 子类编解码钩子：将线侧密文/分帧数据（wireRxBuffer()）解码并追加明文至 appOut（requestBuffer_）
         */
        [[nodiscard]] virtual Result<> onWireDecode(RequestBuffer &wireIn, RequestBuffer &appOut) noexcept
        {
            if (wireIn.readableBytes() > 0)
            {
                auto r = appOut.append(wireIn.readableBegin(), wireIn.readableBytes());
                wireIn.retrieve(wireIn.readableBytes());
                return r;
            }
            return {};
        }

        /**
         * @brief 子类编解码钩子：将即将发送给对端的明文应用数据编码（如 Shadowsocks AEAD 分块加密），
         * 编码结果推入 encodedOut；默认直通模式直接写入 encodedOut。
         */
        [[nodiscard]] virtual Result<> onEncodePayload(std::string_view plain, ResponseQueue &encodedOut) noexcept
        {
            if (plain.data() == nullptr || plain.empty())
            {
                return {};
            }
            return encodedOut.emplace(plain);
        }

        /**
         * @brief 推进传输层与编解码管线，产出纯净的应用明文入 requestBuffer_ 并将待发字节送入 responseQueue_
         */
        [[nodiscard]] inline Result<> processWireToApp() noexcept
        {
            if (wireState_ == nullptr)
            {
                return {};
            }
            if (!wireState_->transport.empty() && wireState_->wireRxBuffer.readableBytes() > 0)
            {
                RequestBuffer &dst = wireState_->codecMode ? wireState_->codecRxBuffer : requestBuffer_;
                if (auto r = wireState_->transport.processInbound(wireState_->wireRxBuffer, dst, responseQueue_); !r)
                {
                    onParseError("Handler: transport layer inbound processing failed");
                    return r;
                }
            }

            if (wireState_->transport.isReady())
            {
                if (auto r = flushPendingAppTx(); !r)
                {
                    return r;
                }
            }

            if (wireState_->codecMode)
            {
                RequestBuffer &codecIn =
                    !wireState_->transport.empty() ? wireState_->codecRxBuffer : wireState_->wireRxBuffer;
                if (codecIn.readableBytes() > 0)
                {
                    if (auto r = onWireDecode(codecIn, requestBuffer_); !r)
                    {
                        return r;
                    }
                }
            }
            return {};
        }

        /**
         * @brief 协议无关统一驱动入口：先推进传输栈与流编解码器，再执行协议自身状态机 handle()
         */
        inline void drive()
        {
            if (usesWireBuffer())
            {
                [[maybe_unused]] auto _ = processWireToApp();
            }
            if (wireState_ == nullptr || wireState_->transport.empty() || wireState_->transport.isReady() ||
                requestBytes() > 0)
            {
                handle();
            }
        }

        /**
         * @brief 业务数据报/流载荷外发统一入口（经由 onEncodePayload 编码再经 TransportPipeline 封装入网）
         */
        [[nodiscard]] virtual Result<> sendPayload(std::string_view plain) noexcept
        {
            if (plain.data() == nullptr || plain.empty())
            {
                return {};
            }
            if (!codecMode())
            {
                return emitEncodedToWire(plain);
            }
            ResponseQueue encoded;
            if (auto r = encoded.init(64); !r)
            {
                return r;
            }
            if (auto r = onEncodePayload(plain, encoded); !r)
            {
                return r;
            }
            while (!encoded.empty())
            {
                auto pkt = std::move(encoded.front());
                encoded.pop();
                if (!pkt.bytes.empty())
                {
                    if (auto r = emitEncodedToWire(pkt.bytes); !r)
                    {
                        return r;
                    }
                }
            }
            return {};
        }

        // ---- 业务生命周期与钩子 ----
        virtual void handle() {}
        virtual void onConnect(int fd) noexcept { fd_ = fd; }
        virtual void onUpgrade() noexcept {}
        virtual void onMessageComplete() noexcept {}
        virtual void onParseError([[maybe_unused]] const char *reason) noexcept
        {
            inboundStage_ = handler::InboundStage::ERROR;
            outboundStage_ = handler::OutboundStage::ERROR;
        }
        virtual void onDatagram([[maybe_unused]] const sockaddr_in &peer, [[maybe_unused]] const char *data,
                                [[maybe_unused]] size_t n) noexcept
        {
        }

        virtual void reset() noexcept
        {
            fd_ = -1;
            connection_ = nullptr;
            inboundStage_ = handler::InboundStage::HANDSHAKE;
            outboundStage_ = handler::OutboundStage::INITIAL;
            targetAddress_.reset();
            command_ = 0;
            requestCallback_ = nullptr;

            const auto &connCfg = getConnectionConfig();
            maxRequestBytes_ = connCfg.maxRequestBytes;
            readHighWaterMark_ = connCfg.readHighWaterMark;

            requestBuffer_.reset();
            requestBuffer_.setHighWaterMark(readHighWaterMark_);
            if (wireState_ != nullptr)
            {
                wireState_->wireRxBuffer.reset();
                wireState_->wireRxBuffer.setHighWaterMark(readHighWaterMark_);
                wireState_->codecRxBuffer.reset();
                if (wireState_->pendingAppTxInit)
                {
                    wireState_->pendingAppTx.reset();
                }
                wireState_->transport.reset();
            }
            responseQueue_.reset();
            spare_.clear();
            closeAfterResponse_ = false;
            clearExternalDataPlane();

            if (dgramState_ != nullptr)
            {
                const auto &cfg = getDatagramConfig();
                dgramState_->datagramCallback = nullptr;
                dgramState_->remotePeer = {};
                dgramState_->maxDatagramBytes = cfg.maxDatagramBytes;
                dgramState_->maxPendingOutgoing = cfg.maxPendingOutgoing;
                if (dgramState_->outgoing.capacity() != 0)
                {
                    if (dgramState_->outgoing.capacity() != cfg.maxPendingOutgoing) [[unlikely]]
                    {
                        [[maybe_unused]] auto _ = dgramState_->outgoing.init(cfg.maxPendingOutgoing);
                    }
                    else
                    {
                        dgramState_->outgoing.reset();
                    }
                }
                dgramState_->droppedOutgoing = 0;
            }
        }

        // ---- 代理业务状态机 ----
        void setOnRequest(RequestCallback cb) noexcept { requestCallback_ = std::move(cb); }
        void setOnDatagram(DatagramCallback cb) noexcept
        {
            if (auto *ds = ensureDatagramState(); ds != nullptr)
            {
                ds->datagramCallback = std::move(cb);
            }
        }
        void setRemotePeer(const sockaddr_in &peer) noexcept
        {
            if (auto *ds = ensureDatagramState(); ds != nullptr)
            {
                ds->remotePeer = peer;
            }
        }
        [[nodiscard]] const sockaddr_in &remotePeer() const noexcept
        {
            static constexpr sockaddr_in kEmptyPeer{};
            return dgramState_ != nullptr ? dgramState_->remotePeer : kEmptyPeer;
        }
        void setTarget(const Address &target) noexcept { targetAddress_ = target; }
        void setCommand(uint8_t cmd) noexcept { command_ = cmd; }
        void setStage(handler::InboundStage st) noexcept { inboundStage_ = st; }
        void setStage(handler::OutboundStage st) noexcept { outboundStage_ = st; }

        [[nodiscard]] inline handler::InboundStage inboundStage() const noexcept { return inboundStage_; }
        [[nodiscard]] inline handler::OutboundStage outboundStage() const noexcept { return outboundStage_; }
        [[nodiscard]] inline handler::InboundStage stage() const noexcept { return inboundStage_; }
        [[nodiscard]] virtual bool isEstablished() const noexcept
        {
            return inboundStage_ == handler::InboundStage::STREAMING ||
                   outboundStage_ == handler::OutboundStage::STREAMING;
        }
        [[nodiscard]] inline uint8_t command() const noexcept { return command_; }
        [[nodiscard]] inline const std::optional<Address> &targetAddress() const noexcept
        {
            return targetAddress_;
        }
        [[nodiscard]] inline const Address &target() const noexcept
        {
            static const Address kEmptyTarget{};
            return targetAddress_.has_value() ? *targetAddress_ : kEmptyTarget;
        }

        // ---- 业务缓冲区与响应队列操作 ----
        [[nodiscard]] inline Result<> appendRequest(const char *buf, ssize_t rn) noexcept
        {
            if (buf != nullptr && rn > 0) [[likely]]
            {
                if (usesWireBuffer())
                {
                    if (auto r = wireState_->wireRxBuffer.append(buf, static_cast<size_t>(rn)); !r)
                    {
                        return r;
                    }
                    return processWireToApp();
                }
                return requestBuffer_.append(buf, static_cast<size_t>(rn));
            }
            return {};
        }
        [[nodiscard]] inline Result<> appendRequest(std::string_view sv) noexcept
        {
            return appendRequest(sv.data(), static_cast<ssize_t>(sv.size()));
        }
        [[nodiscard]] inline std::expected<char *, ERR>
        prepareRequestWritable(size_t minBytes = getConnectionConfig().readChunkSize) noexcept
        {
            RequestBuffer &rx = usesWireBuffer() ? wireState_->wireRxBuffer : requestBuffer_;
            if (auto res = rx.ensureWritable(minBytes); !res) [[unlikely]]
            {
                return std::unexpected(res.error());
            }
            return rx.writableBegin();
        }
        [[nodiscard]] inline char *requestWritableBegin() noexcept
        {
            return usesWireBuffer() ? wireState_->wireRxBuffer.writableBegin() : requestBuffer_.writableBegin();
        }
        [[nodiscard]] inline size_t requestWritableBytes() const noexcept
        {
            return usesWireBuffer() ? wireState_->wireRxBuffer.writableBytes() : requestBuffer_.writableBytes();
        }
        inline void commitRequest(size_t n) noexcept
        {
            if (usesWireBuffer())
            {
                wireState_->wireRxBuffer.commitWritten(n);
            }
            else
            {
                requestBuffer_.commitWritten(n);
            }
        }
        [[nodiscard]] inline bool requestOverLimit() const noexcept
        {
            const size_t wireBytes =
                wireState_ != nullptr
                    ? (wireState_->wireRxBuffer.readableBytes() + wireState_->codecRxBuffer.readableBytes())
                    : 0;
            return (requestBuffer_.readableBytes() + wireBytes) > maxRequestBytes_;
        }
        [[nodiscard]] inline size_t requestBytes() const noexcept { return requestBuffer_.readableBytes(); }
        [[nodiscard]] inline const char *requestBegin() const noexcept { return requestBuffer_.readableBegin(); }
        inline void requestConsume(size_t n) noexcept { requestBuffer_.retrieve(n); }
        inline void requestClear() noexcept { requestBuffer_.reset(); }
        [[nodiscard]] inline size_t readCredit() const noexcept
        {
            const size_t wireBytes =
                wireState_ != nullptr
                    ? (wireState_->wireRxBuffer.readableBytes() + wireState_->codecRxBuffer.readableBytes())
                    : 0;
            const size_t used = requestBuffer_.readableBytes() + wireBytes;
            return used >= maxRequestBytes_ ? 0 : maxRequestBytes_ - used;
        }
        inline void setMaxRequestBytes(size_t n) noexcept { maxRequestBytes_ = n; }
        [[nodiscard]] inline size_t maxRequestBytes() const noexcept { return maxRequestBytes_; }

        [[nodiscard]] inline bool hasResponse() const noexcept { return !responseQueue_.empty(); }
        [[nodiscard]] inline size_t responseCount() const noexcept { return responseQueue_.size(); }
        [[nodiscard]] inline size_t responseCapacity() const noexcept { return responseQueue_.capacity(); }
        [[nodiscard]] inline size_t responseBytes() const noexcept
        {
            size_t total = 0;
            for (size_t i = 0; i < responseQueue_.size(); ++i)
            {
                total += responseQueue_[i].bytes.size();
            }
            return total;
        }
        [[nodiscard]] inline std::string takeResponse()
        {
            if (responseQueue_.empty()) [[unlikely]]
            {
                return {};
            }
            std::string out = std::move(responseQueue_.front().bytes);
            if (spare_.capacity() > 0)
            {
                responseQueue_.front().bytes = std::move(spare_);
            }
            responseQueue_.pop();
            return out;
        }
        inline void recycleSpare(std::string &&s) noexcept
        {
            if (s.capacity() > spare_.capacity())
            {
                s.clear();
                spare_ = std::move(s);
            }
        }
        [[nodiscard]] inline Result<> pushResponse(std::string &&s) noexcept
        {
            if (wireState_ != nullptr && !wireState_->transport.empty())
            {
                return emitEncodedToWire(s);
            }
            return responseQueue_.push(std::move(s));
        }
        [[nodiscard]] inline Result<> pushResponse(const std::string &s) noexcept
        {
            return pushResponse(std::string_view(s));
        }
        [[nodiscard]] inline Result<> pushResponse(std::string_view sv) noexcept
        {
            if (sv.data() == nullptr || sv.empty())
            {
                return {};
            }
            return emitEncodedToWire(sv);
        }
        [[nodiscard]] inline Result<> pushResponse(const char *s) noexcept
        {
            if (s == nullptr) [[unlikely]]
            {
                return {};
            }
            return pushResponse(std::string_view(s));
        }
        [[nodiscard]] inline Result<> reserveResponses(size_t capacity) noexcept
        {
            return responseQueue_.init(capacity);
        }
        [[nodiscard]] inline bool closeAfterResponse() const noexcept { return closeAfterResponse_; }
        inline void setCloseAfterResponse(bool v) noexcept { closeAfterResponse_ = v; }
        [[nodiscard]] inline ResponseQueue &responseQueue() noexcept { return responseQueue_; }
        [[nodiscard]] inline const ResponseQueue &responseQueue() const noexcept { return responseQueue_; }
        inline void clearResponses() noexcept { responseQueue_.reset(); }

        // ---- 外部数据面联动钩子 (Forwarder / EventLoop) ----
        inline void setExternalDataPlane(std::function<void()> onData,
                                         std::function<int(uint32_t)> onReactorIo = {},
                                         std::function<bool()> suppressConnRecv = {})
        {
            if (extDataPlane_ == nullptr)
            {
                extDataPlane_ = std::make_unique<ExternalDataPlaneState>();
            }
            extDataPlane_->onData = std::move(onData);
            extDataPlane_->onReactorIo = std::move(onReactorIo);
            extDataPlane_->suppressConnRecv = std::move(suppressConnRecv);
        }

        [[nodiscard]] inline uint64_t addExternalDetachHook(std::function<void()> onDetach)
        {
            if (!onDetach)
            {
                return 0;
            }
            if (extDataPlane_ == nullptr)
            {
                extDataPlane_ = std::make_unique<ExternalDataPlaneState>();
            }
            const uint64_t tok = extDataPlane_->nextDetachToken++;
            extDataPlane_->detachHooks.emplace_back(tok, std::move(onDetach));
            return tok;
        }

        inline void removeExternalDetachHook(uint64_t token) noexcept
        {
            if (token == 0 || extDataPlane_ == nullptr)
            {
                return;
            }
            std::erase_if(extDataPlane_->detachHooks, [token](const auto &kv) { return kv.first == token; });
        }

        inline void clearExternalDataPlane() noexcept
        {
            if (extDataPlane_ != nullptr)
            {
                extDataPlane_->onData = nullptr;
                extDataPlane_->onReactorIo = nullptr;
                extDataPlane_->suppressConnRecv = nullptr;
            }
        }

        inline void notifyExternalClosed() noexcept
        {
            if (extDataPlane_ != nullptr)
            {
                auto hooks = std::move(extDataPlane_->detachHooks);
                extDataPlane_->detachHooks.clear();
                clearExternalDataPlane();
                for (auto &kv : hooks)
                {
                    if (kv.second)
                    {
                        kv.second();
                    }
                }
            }
        }

        [[nodiscard]] virtual inline bool hasExternalDataPlane() const noexcept
        {
            return extDataPlane_ != nullptr &&
                   (static_cast<bool>(extDataPlane_->onData) || static_cast<bool>(extDataPlane_->onReactorIo) ||
                    static_cast<bool>(extDataPlane_->suppressConnRecv));
        }

        [[nodiscard]] virtual inline bool shouldSuppressConnRecv() const noexcept
        {
            return extDataPlane_ != nullptr && extDataPlane_->suppressConnRecv && extDataPlane_->suppressConnRecv();
        }

        virtual inline void notifyExternalData()
        {
            if (extDataPlane_ != nullptr && extDataPlane_->onData)
            {
                extDataPlane_->onData();
            }
        }

        [[nodiscard]] virtual inline int handleExternalReactorIo(uint32_t events)
        {
            if (extDataPlane_ != nullptr && extDataPlane_->onReactorIo)
            {
                return extDataPlane_->onReactorIo(events);
            }
            return -1;
        }

        // ---- 数据报发送操作 ----
        inline void sendTo(const sockaddr_in &target, const char *buf, size_t n)
        {
            contract_assert(buf != nullptr);
            ensureOutgoingInit();
            if (dgramState_ != nullptr && !dgramState_->outgoing.emplace(target, buf, n)) [[unlikely]]
            {
                ++dgramState_->droppedOutgoing;
                LOG_WARN("Handler: outgoing queue full ({} pending), dropping a {} byte packet for {}",
                         dgramState_->outgoing.size(), n, datagramPeerText(target));
            }
        }

        inline void sendTo(const sockaddr_in &target, std::string bytes)
        {
            ensureOutgoingInit();
            const size_t sz = bytes.size();
            if (dgramState_ != nullptr && !dgramState_->outgoing.emplace(target, std::move(bytes))) [[unlikely]]
            {
                ++dgramState_->droppedOutgoing;
                LOG_WARN("Handler: outgoing queue full ({} pending), dropping a {} byte packet for {}",
                         dgramState_->outgoing.size(), sz, datagramPeerText(target));
            }
        }

        inline void forwardTo(const sockaddr_in &upstream, const char *data, size_t n) { sendTo(upstream, data, n); }

        inline void broadcastTo(const std::vector<sockaddr_in> &targets, const char *buf, size_t n)
        {
            for (const auto &t : targets)
            {
                sendTo(t, buf, n);
            }
        }

        [[nodiscard]] inline bool hasOutgoing() const noexcept
        {
            return dgramState_ != nullptr && !dgramState_->outgoing.empty();
        }
        [[nodiscard]] inline size_t outgoingCount() const noexcept
        {
            return dgramState_ != nullptr ? dgramState_->outgoing.size() : 0;
        }
        [[nodiscard]] inline const Packet &peekOutgoing() const noexcept
        {
            static const Packet kEmptyPacket{};
            return (dgramState_ != nullptr && !dgramState_->outgoing.empty()) ? dgramState_->outgoing.front()
                                                                              : kEmptyPacket;
        }

        [[nodiscard]] inline Packet takeOutgoing()
        {
            if (dgramState_ == nullptr || dgramState_->outgoing.empty()) [[unlikely]]
            {
                return {};
            }
            Packet out = std::move(dgramState_->outgoing.front());
            dgramState_->outgoing.pop();
            return out;
        }

        [[nodiscard]] inline std::vector<Packet> takeAllOutgoing()
        {
            std::vector<Packet> out;
            if (dgramState_ == nullptr || dgramState_->outgoing.empty()) [[unlikely]]
            {
                return out;
            }
            out.reserve(dgramState_->outgoing.size());
            while (!dgramState_->outgoing.empty())
            {
                out.push_back(std::move(dgramState_->outgoing.front()));
                dgramState_->outgoing.pop();
            }
            return out;
        }

        inline void setMaxDatagramBytes(size_t n) noexcept
        {
            if (auto *ds = ensureDatagramState(); ds != nullptr)
            {
                ds->maxDatagramBytes = n;
            }
        }
        inline void setMaxPendingOutgoing(size_t n) noexcept
        {
            contract_assert(n > 0);
            if (auto *ds = ensureDatagramState(); ds != nullptr)
            {
                ds->maxPendingOutgoing = n;
                [[maybe_unused]] auto _ = ds->outgoing.init(n);
            }
        }
        [[nodiscard]] inline size_t maxPendingOutgoing() const noexcept
        {
            return dgramState_ != nullptr ? dgramState_->maxPendingOutgoing : getDatagramConfig().maxPendingOutgoing;
        }

        [[nodiscard]] inline DatagramQueue &outgoing() noexcept
        {
            ensureOutgoingInit();
            if (dgramState_ != nullptr)
            {
                return dgramState_->outgoing;
            }
            static DatagramQueue s_fallbackOutgoing{};
            return s_fallbackOutgoing;
        }
        [[nodiscard]] inline const DatagramQueue &outgoing() const noexcept
        {
            static const DatagramQueue kEmptyOutgoing{};
            return dgramState_ != nullptr ? dgramState_->outgoing : kEmptyOutgoing;
        }
        [[nodiscard]] inline size_t maxDatagramBytes() const noexcept
        {
            return dgramState_ != nullptr ? dgramState_->maxDatagramBytes : getDatagramConfig().maxDatagramBytes;
        }
        [[nodiscard]] inline size_t droppedOutgoing() const noexcept
        {
            return dgramState_ != nullptr ? dgramState_->droppedOutgoing : 0;
        }
    };


    template <typename H>
    concept DerivedFromHandler = std::derived_from<H, Handler>;

    template <typename H>
    concept DerivedFromHandlerBase = DerivedFromHandler<H>;

    template <typename H>
    concept DerivedFromHandlerConnection = DerivedFromHandler<H>;

    template <typename D>
    concept DerivedFromHandlerDatagram = DerivedFromHandler<D>;


    /**
     * @brief 通用多协议嗅探分发器基类 (MuxInboundHandlerBase)
     *
     * 采用 std::variant 按需延迟实例化唯一命中的子协议处理器（消除同实例内多份 ~64KiB 空缓冲冗余），
     * 并统一封装子状态机与宿主缓冲/响应/Splice 同步逻辑，取代散落于 SOCKS / Mixed / KernelProxyHandler
     * 的三处重复 syncToChild/syncFromChild 样板代码。
     */
    template <typename... ChildHandlers>
    class MuxInboundHandler : public Handler
    {
    protected:
        std::variant<std::monostate, ChildHandlers...> activeVariant_{std::monostate{}};
        bool requestNotified_{false};

        template <typename ChildT, typename... Args>
        inline ChildT &emplaceChild(Args &&...args)
        {
            return activeVariant_.template emplace<ChildT>(std::forward<Args>(args)...);
        }

        [[nodiscard]] inline Handler *activeChild() noexcept
        {
            return std::visit(
                [](auto &v) noexcept -> Handler *
                {
                    if constexpr (std::is_same_v<std::decay_t<decltype(v)>, std::monostate>)
                    {
                        return nullptr;
                    }
                    else
                    {
                        return &v;
                    }
                },
                activeVariant_);
        }

        [[nodiscard]] inline const Handler *activeChild() const noexcept
        {
            return std::visit(
                [](const auto &v) noexcept -> const Handler *
                {
                    if constexpr (std::is_same_v<std::decay_t<decltype(v)>, std::monostate>)
                    {
                        return nullptr;
                    }
                    else
                    {
                        return &v;
                    }
                },
                activeVariant_);
        }

        inline void syncToChild(Handler &child)
        {
            if (child.connection() != connection())
            {
                child.setConnection(connection());
            }
            if (child.fd() != fd() && fd() >= 0)
            {
                child.onConnect(fd());
            }
            const size_t avail = requestBytes();
            if (avail > child.requestBytes())
            {
                const size_t diff = avail - child.requestBytes();
                const char *p = requestBegin() + child.requestBytes();
                [[maybe_unused]] auto _ = child.appendRequest(p, static_cast<ssize_t>(diff));
            }
        }

        inline void syncFromChild(Handler &child)
        {
            const size_t childAvail = child.requestBytes();
            if (requestBytes() > childAvail)
            {
                requestConsume(requestBytes() - childAvail);
            }

            while (child.hasResponse())
            {
                std::string resp = child.takeResponse();
                [[maybe_unused]] auto _ = pushResponse(std::move(resp));
            }

            if (child.closeAfterResponse())
            {
                setCloseAfterResponse(true);
            }

        }

        inline bool driveChild(Handler &child)
        {
            if (isEstablished() && child.isPassthrough())
            {
                return true;
            }
            syncToChild(child);
            child.drive();
            syncFromChild(child);
            if (child.isEstablished())
            {
                setStage(handler::InboundStage::STREAMING);
                targetAddress_ = child.targetAddress();
                command_ = child.command();
                if (!requestNotified_)
                {
                    requestNotified_ = true;
                    if (requestCallback_ && targetAddress_.has_value())
                    {
                        requestCallback_(command_, *targetAddress_);
                    }
                }
                return true;
            }
            return false;
        }

    public:
        using Handler::Handler;
        ~MuxInboundHandler() noexcept override = default;

        [[nodiscard]] bool isPassthrough() const noexcept override
        {
            if (!Handler::isPassthrough())
            {
                return false;
            }
            if (const auto *child = activeChild(); child != nullptr)
            {
                return child->isPassthrough();
            }
            return true;
        }

        [[nodiscard]] bool canSplice() const noexcept override
        {
            if (!Handler::canSplice())
            {
                return false;
            }
            if (const auto *child = activeChild(); child != nullptr)
            {
                return child->canSplice();
            }
            return true;
        }

        [[nodiscard]] bool hasExternalDataPlane() const noexcept override
        {
            if (Handler::hasExternalDataPlane())
            {
                return true;
            }
            if (const auto *child = activeChild(); child != nullptr)
            {
                return child->hasExternalDataPlane();
            }
            return false;
        }

        [[nodiscard]] bool shouldSuppressConnRecv() const noexcept override
        {
            if (Handler::shouldSuppressConnRecv())
            {
                return true;
            }
            if (const auto *child = activeChild(); child != nullptr)
            {
                return child->shouldSuppressConnRecv();
            }
            return false;
        }

        void notifyExternalData() override
        {
            Handler::notifyExternalData();
            if (auto *child = activeChild(); child != nullptr)
            {
                child->notifyExternalData();
            }
        }

        [[nodiscard]] int handleExternalReactorIo(uint32_t events) override
        {
            if (const int r = Handler::handleExternalReactorIo(events); r >= 0)
            {
                return r;
            }
            if (auto *child = activeChild(); child != nullptr)
            {
                return child->handleExternalReactorIo(events);
            }
            return -1;
        }

        [[nodiscard]] bool isEstablished() const noexcept override
        {
            if (const auto *child = activeChild(); child != nullptr)
            {
                return child->isEstablished();
            }
            return Handler::isEstablished();
        }

        void reset() noexcept override
        {
            Handler::reset();
            requestNotified_ = false;
            activeVariant_.template emplace<std::monostate>();
        }
    };

    /**
     * @brief 流式会话处理器的必需方法集合
     *
     * 名字直指含义：这是 ConnectionBase 及流式处理架构下对派生处理器的全量契约清单，
     * 逐项校验所有成员函数的签名与 noexcept 规范，防止派生类用 = delete 或不兼容签名破坏契约。
     */
    template <typename H>
    concept MandatoryMethodConnection =
        DerivedFromHandlerConnection<H> && Resettable<H> &&
        requires(H &h, const char *buf, ssize_t rn, size_t n, std::string_view sv, const std::string &str,
                 std::string &&s, bool b, int fd) {
            // ---- 读取侧控制 (Read Side) ----
            { h.appendRequest(buf, rn) } noexcept -> std::same_as<Result<>>;
            { h.appendRequest(sv) } noexcept -> std::same_as<Result<>>;
            { h.prepareRequestWritable(n) } noexcept -> std::same_as<std::expected<char *, ERR>>;
            { h.requestWritableBegin() } noexcept -> std::same_as<char *>;
            { h.requestWritableBytes() } noexcept -> std::same_as<size_t>;
            { h.commitRequest(n) } noexcept;
            { h.requestOverLimit() } noexcept -> std::same_as<bool>;
            { h.requestBytes() } noexcept -> std::same_as<size_t>;
            { h.requestBegin() } noexcept -> std::same_as<const char *>;
            { h.requestConsume(n) } noexcept;
            { h.requestClear() } noexcept;
            { h.readCredit() } noexcept -> std::same_as<size_t>;
            { h.setMaxRequestBytes(n) } noexcept;

            // ---- 发送响应侧控制 (Write Side) ----
            { h.hasResponse() } noexcept -> std::same_as<bool>;
            { h.responseCount() } noexcept -> std::same_as<size_t>;
            { h.takeResponse() } -> std::same_as<std::string>;
            { h.recycleSpare(std::move(s)) } noexcept;
            { h.pushResponse(std::move(s)) } noexcept -> std::same_as<Result<>>;
            { h.pushResponse(str) } noexcept -> std::same_as<Result<>>;
            { h.pushResponse(sv) } noexcept -> std::same_as<Result<>>;
            { h.pushResponse(buf) } noexcept -> std::same_as<Result<>>;
            { h.reserveResponses(n) } noexcept -> std::same_as<Result<>>;

            // ---- 生命周期管理 (Lifecycle) ----
            { h.closeAfterResponse() } noexcept -> std::same_as<bool>;
            { h.setCloseAfterResponse(b) } noexcept;

            // ---- 协议钩子与连接状态 (Hooks & Connection State) ----
            { h.onConnect(fd) } noexcept;
            { h.onUpgrade() } noexcept;
            { h.onMessageComplete() } noexcept;
            { h.onParseError(buf) } noexcept;
            { h.fd() } noexcept -> std::same_as<int>;
            { h.handle() };
        };

    /**
     * @brief 统一连接抽象基类别名
     *
     * 保持与传输中立代码的兼容性。特定协议的连接派生类应在各个协议目录下自行实现
     * （如 ConnectionHttp、ConnectionSocks、ConnectionDirect 等）。
     */
    // using Connection = ConnectionBase; (Connection is now the base class)

    template <typename D>
    concept MandatoryMethodDatagram = DerivedFromHandlerDatagram<D> && Resettable<D> &&
                                      requires(D &d, const sockaddr_in &peer, const char *buf, size_t n,
                                               std::string bytes, const std::vector<sockaddr_in> &targets) {
                                          { d.onDatagram(peer, buf, n) } noexcept;
                                          { d.onMessageComplete() } noexcept;
                                          { d.onParseError(buf) } noexcept;

                                          d.sendTo(peer, buf, n);
                                          d.sendTo(peer, std::move(bytes));
                                          d.forwardTo(peer, buf, n);
                                          d.broadcastTo(targets, buf, n);
                                          { d.hasOutgoing() } noexcept -> std::same_as<bool>;
                                          { d.outgoingCount() } noexcept -> std::same_as<size_t>;
                                          { d.peekOutgoing() } noexcept -> std::same_as<const Packet &>;
                                          { d.takeOutgoing() } -> std::same_as<Packet>;
                                          { d.droppedOutgoing() } noexcept -> std::same_as<size_t>;

                                          { d.setMaxDatagramBytes(n) } noexcept;
                                          { d.maxDatagramBytes() } noexcept -> std::same_as<size_t>;
                                          { d.setMaxPendingOutgoing(n) } noexcept;
                                          { d.maxPendingOutgoing() } noexcept -> std::same_as<size_t>;
                                      };

} // namespace mynet

namespace mynet::handler
{
    /**
     * @brief 入站协议处理器适配层（轻量无状态转译，单一根基类 Handler）
     */
    class HandlerInbound : public mynet::Handler
    {
    public:
        using Handler::Handler;
        [[nodiscard]] inline InboundStage stage() const noexcept { return inboundStage(); }
    };

    /**
     * @brief 出站协议处理器适配层（轻量无状态转译，单一根基类 Handler）
     */
    class HandlerOutbound : public mynet::Handler
    {
    public:
        using Handler::Handler;
        [[nodiscard]] inline OutboundStage stage() const noexcept { return outboundStage(); }
    };

} // namespace mynet::handler

namespace mynet
{
    using HandlerInbound = handler::HandlerInbound;
    using HandlerOutbound = handler::HandlerOutbound;

} // namespace mynet
