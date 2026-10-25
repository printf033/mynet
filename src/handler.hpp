#pragma once

#include "buffer.hpp"
#include "concepts.hpp"
#include "datagram.hpp"
#include "log.hpp"
#include "ringQueue.hpp"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace mynet
{

    /**
     * @brief 业务协议处理器基类
     *
     * 架构分层职责：
     * - 处理器（Handler）专精于协议流解析（Parsing）与应答生成（Response Production）；
     * - 传输层（Connection）掌管套接字收发进度、Keep-Alive 超时与底层 TLS 加密。
     * 这种解耦使得单次网络数据读取能够连续生成多条管道化应答，同时通过 readCredit() 提供自然的流控背压。
     */
    class HandlerBase
    {
    public:
        /**
         * @brief 构造时一次性定容响应队列
         *
         * 默认 64 槽对齐流水线深度：开箱即可用，后续连接层可在建连时调用
         * reserveResponses() 按协议需求重新定容（init 幂等）。
         */
        explicit HandlerBase(size_t responseCapacity = 64) noexcept
        {
            [[maybe_unused]] auto _ =
                responseQueue_.init(responseCapacity); // 槽位分配失败降级为容量 0 拒收，不折损零异常构造
        }

        virtual ~HandlerBase() noexcept = default;

        HandlerBase(const HandlerBase &) = delete("a handler holds parser state bound to one connection");
        HandlerBase &operator=(const HandlerBase &) = delete("a handler holds parser state bound to one connection");
        HandlerBase(HandlerBase &&) = delete("a handler holds parser state bound to one connection");
        HandlerBase &operator=(HandlerBase &&) = delete("a handler holds parser state bound to one connection");

        /**
         * @brief 重置处理器状态（虚函数，以便派生类重置专属解析器）
         */
        virtual void reset() noexcept
        {
            requestBuffer_.reset();
            responseQueue_.clear();
            closeAfterResponse_ = false;
        }

        // ---- 读取侧控制 (Read Side) ----

        /**
         * @brief 追加一段对端请求字节到解析缓冲（零异常，失败显式错误码）
         *
         * Buffer::append() 为 nothrow 接口：堆扩容失败以 ERR::BUF_ALLOC_FAILED
         * 交付，缓冲区保持原样，调用方据此可安全丢弃本次读到的字节（对端重传
         * 或连接关闭兜底）。
         *
         * @param buf 对端字节首地址（允许为 nullptr，此时为无操作）
         * @param rn 本次读取的字节数（须非负）
         * @return 成功 {}；解析缓冲扩容失败 std::unexpected(ERR::BUF_ALLOC_FAILED)
         */
        [[nodiscard]] inline Result<> appendRequest(const char *buf, ssize_t rn) noexcept
        {
            if (buf != nullptr && rn > 0) [[likely]]
            {
                return requestBuffer_.append(buf, static_cast<size_t>(rn));
            }
            return {};
        }

        [[nodiscard]] inline bool requestOverLimit() const noexcept
        {
            return requestBuffer_.readableBytes() > maxRequestBytes_;
        }

        [[nodiscard]] inline size_t requestBytes() const noexcept { return requestBuffer_.readableBytes(); }

        [[nodiscard]] inline const char *requestBegin() const noexcept { return requestBuffer_.readableBegin(); }

        inline void requestConsume(size_t n) noexcept { requestBuffer_.retrieve(n); }

        inline void requestClear() noexcept { requestBuffer_.retrieveAll(); }

        /**
         * @brief 剩余信用窗口（为 0 时事件循环将暂停接收读取，实施背压保护）
         */
        [[nodiscard]] inline size_t readCredit() const noexcept
        {
            const size_t used = requestBuffer_.readableBytes();
            return used >= maxRequestBytes_ ? 0 : maxRequestBytes_ - used;
        }

        inline void setMaxRequestBytes(size_t n) noexcept { maxRequestBytes_ = n; }

        // ---- 发送响应侧控制 (Write Side) ----

        [[nodiscard]] inline bool hasResponse() const noexcept { return !responseQueue_.empty(); }

        [[nodiscard]] inline size_t responseCount() const noexcept { return responseQueue_.size(); }

        [[nodiscard]] inline std::string takeResponse()
        {
            if (responseQueue_.empty()) [[unlikely]]
            {
                return std::string();
            }
            std::string out = std::move(responseQueue_.front());
            responseQueue_.pop();
            return out;
        }

        /**
         * @brief 推入一条完整响应（定容队列，满队显式拒绝）
         */
        [[nodiscard]] inline Result<> pushResponse(std::string s) noexcept { return responseQueue_.push(std::move(s)); }

        /**
         * @brief 推入一段视图响应（零拷贝适配 string_view 与连续字节）
         */
        [[nodiscard]] inline Result<> pushResponse(std::string_view sv) noexcept
        {
            if (sv.data() == nullptr || sv.empty())
            {
                return {};
            }
            return responseQueue_.emplace(sv);
        }

        /**
         * @brief 推入以空终止的字符串字面量（重载消歧义，内部转为 string_view）
         */
        [[nodiscard]] inline Result<> pushResponse(const char *s) noexcept
        {
            if (s == nullptr) [[unlikely]]
            {
                return {};
            }
            return pushResponse(std::string_view(s));
        }

        /**
         * @brief 预分配响应队列槽位（连接建立时调用一次）
         *
         * @param capacity 槽位数量（允许流水线化的最大响应条数）
         * @return 成功 {}；槽位分配失败 std::unexpected(ERR::POOL_ALLOC_FAILED)
         */
        [[nodiscard]] inline Result<> reserveResponses(size_t capacity) noexcept
        {
            return responseQueue_.init(capacity);
        }

        // ---- 生命周期管理 (Lifecycle) ----

        [[nodiscard]] inline bool closeAfterResponse() const noexcept { return closeAfterResponse_; }

        inline void setCloseAfterResponse(bool v) noexcept { closeAfterResponse_ = v; }

        // ---- 业务扩展虚钩子 (Business Hooks) ----

        virtual void onMessageComplete() noexcept {}
        virtual void onParseError([[maybe_unused]] const char *reason) noexcept {}
        virtual void onUpgrade() noexcept {}

        /**
         * @brief 默认执行逻辑：标准 Echo 协议回显
         */
        void process()
        {
            if (requestBuffer_.empty()) [[unlikely]]
            {
                return;
            }
            if (!pushResponse(requestBuffer_.readableView())) [[unlikely]]
            {
                LOG_WARN("Handler::process: response queue full, echoing dropped");
            }
            requestBuffer_.retrieveAll();
        }

    protected:
        Buffer requestBuffer_;
        RingQueue responseQueue_;
        size_t maxRequestBytes_ = 4 << 20;
        bool closeAfterResponse_ = false;
    };

    /**
     * @class HandlerDatagramEcho
     * @brief UDP 数据报标准回显协议处理器
     *
     * 具备 HandlerBase（满足 EventSocket / Proactor 容器生命周期契约）与
     * DatagramHandler（提供无连接数据报发送与接收管理）双重特性，
     * 收到对端数据报后原样回显给发送端。
     */
    class HandlerDatagramEcho : public HandlerBase, public DatagramHandler
    {
    public:
        HandlerDatagramEcho() noexcept = default;
        ~HandlerDatagramEcho() noexcept override = default;

        HandlerDatagramEcho(const HandlerDatagramEcho &) = delete("a datagram echo handler owns socket reply state");
        HandlerDatagramEcho &
        operator=(const HandlerDatagramEcho &) = delete("a datagram echo handler owns socket reply state");
        HandlerDatagramEcho(HandlerDatagramEcho &&) = delete("a datagram echo handler owns socket reply state");
        HandlerDatagramEcho &
        operator=(HandlerDatagramEcho &&) = delete("a datagram echo handler owns socket reply state");

        // 此套接字上无流式数据，无需流式解析
        void process() noexcept {}

        void reset() noexcept override
        {
            HandlerBase::reset();
            DatagramHandler::reset();
        }

        void onDatagram(const sockaddr_in &peer, const char *data, size_t n) noexcept override
        {
            LOG_INFO("HandlerDatagramEcho: {} sent {} byte(s)", datagramPeerText(peer), n);
            pushReply(peer, data, n);
        }
    };

} // namespace mynet
