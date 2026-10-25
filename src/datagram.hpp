#pragma once

#include "error.hpp"
#include "log.hpp"
#include <arpa/inet.h>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <utility>

namespace mynet
{

    /**
     * @brief UDP 数据报回复上下文元信息封装
     *
     * 关联对端地址元数据与待发送二进制报文载荷。
     */
    struct DatagramReply
    {
        sockaddr_in peer{};
        std::string bytes{};
    };

    /**
     * @brief 格式化 IPv4 对端套接字地址文本 ("192.0.2.7:5353")
     *
     * @param peer 对端 sockaddr_in 地址结构
     * @return std::string 人类可读地址字符串
     */
    [[nodiscard]] inline std::string datagramPeerText(const sockaddr_in &peer)
    {
        char host[INET_ADDRSTRLEN] = {};
        if (::inet_ntop(AF_INET, &peer.sin_addr, host, sizeof host) == nullptr) [[unlikely]]
        {
            return std::string("<unnamed>:") + std::to_string(::ntohs(peer.sin_port));
        }
        std::string out;
        out.reserve(22);
        out.append(host);
        out.push_back(':');
        out.append(std::to_string(::ntohs(peer.sin_port)));
        return out;
    }

    /**
     * @brief UDP 数据报无连接协议处理器基类
     *
     * 解决无连接套接字上对端报文交织问题，具备完整的待回包队列管理与溢出丢包计数防护。
     */
    class DatagramHandler
    {
    public:
        DatagramHandler() noexcept = default;
        virtual ~DatagramHandler() noexcept = default;

        DatagramHandler(const DatagramHandler &) = delete("a datagram handler owns the reply queue for one socket");
        DatagramHandler &
        operator=(const DatagramHandler &) = delete("a datagram handler owns the reply queue for one socket");
        DatagramHandler(DatagramHandler &&) = delete("a datagram handler owns the reply queue for one socket");
        DatagramHandler &
        operator=(DatagramHandler &&) = delete("a datagram handler owns the reply queue for one socket");

        /**
         * @brief 单个完整数据报到达回调
         *
         * @param peer 发送方网络地址
         * @param data 报文载荷首地址
         * @param n 报文有效字节长度
         */
        virtual void onDatagram(const sockaddr_in &peer, const char *data, size_t n) noexcept = 0;

        /**
         * @brief 重置处理器状态与队列计数
         */
        virtual void reset() noexcept
        {
            replies_.clear();
            droppedReplies_ = 0;
        }

        // ---- 回复队列管理 (Reply Side) ----

        inline void pushReply(const sockaddr_in &peer, const char *buf, size_t n)
        {
            contract_assert(buf != nullptr);
            if (replies_.size() >= maxPendingReplies_) [[unlikely]]
            {
                ++droppedReplies_;
                LOG_WARN("DatagramHandler: reply queue full ({} pending), dropping a {} byte reply for {}",
                         replies_.size(), n, datagramPeerText(peer));
                return;
            }
            replies_.push_back(DatagramReply{peer, (n > 0) ? std::string(buf, n) : std::string()});
        }

        inline void pushReply(const sockaddr_in &peer, std::string bytes)
        {
            if (replies_.size() >= maxPendingReplies_) [[unlikely]]
            {
                ++droppedReplies_;
                LOG_WARN("DatagramHandler: reply queue full ({} pending), dropping a {} byte reply for {}",
                         replies_.size(), bytes.size(), datagramPeerText(peer));
                return;
            }
            replies_.push_back(DatagramReply{peer, std::move(bytes)});
        }

        [[nodiscard]] inline bool hasReply() const noexcept { return !replies_.empty(); }
        [[nodiscard]] inline size_t replyCount() const noexcept { return replies_.size(); }
        [[nodiscard]] inline const DatagramReply &peekReply() const noexcept { return replies_.front(); }

        [[nodiscard]] inline DatagramReply takeReply()
        {
            if (replies_.empty()) [[unlikely]]
            {
                return {};
            }
            DatagramReply out = std::move(replies_.front());
            replies_.pop_front();
            return out;
        }

        [[nodiscard]] inline size_t droppedReplies() const noexcept { return droppedReplies_; }

        inline void setMaxDatagramBytes(size_t n) noexcept { maxDatagramBytes_ = n; }
        [[nodiscard]] inline size_t maxDatagramBytes() const noexcept { return maxDatagramBytes_; }

        inline void setMaxPendingReplies(size_t n) noexcept
        {
            contract_assert(n > 0);
            maxPendingReplies_ = n;
        }
        [[nodiscard]] inline size_t maxPendingReplies() const noexcept { return maxPendingReplies_; }

    protected:
        size_t maxDatagramBytes_ = (64 << 10) - 1;
        size_t maxPendingReplies_ = 1 << 10;
        size_t droppedReplies_ = 0;
        std::deque<DatagramReply> replies_{};
    };

} // namespace mynet
