#pragma once

/**
 * @file http/v3/streamTable.hpp
 * @brief RFC 9114 HTTP/3 流类型判定、生命周期跟踪与流表管理器。
 */

#include "buffer.hpp"
#include "frame.hpp"
#include "qpack.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace mynet
{
    namespace http::v3
    {
        /**
         * @brief RFC 9114 Section 6.2 单向流类型标识符
         */
        namespace stream_type
        {
            inline constexpr uint64_t kControl = 0x00;
            inline constexpr uint64_t kPush = 0x01;
            inline constexpr uint64_t kQpackEncoder = 0x02;
            inline constexpr uint64_t kQpackDecoder = 0x03;
        } // namespace stream_type

        /**
         * @brief 流生命周期状态枚举
         */
        enum class STREAM_STATE : uint8_t
        {
            IDLE = 0,
            OPEN = 1,
            HALF_CLOSED_REMOTE = 2,
            HALF_CLOSED_LOCAL = 3,
            CLOSED = 4
        };

        /**
         * @brief 判断流是否为单向流 (RFC 9000: 流 ID 第 2 位为 1 表示单向流)
         */
        [[nodiscard]] constexpr bool isUnidirectionalStream(uint64_t streamId) noexcept
        {
            return (streamId & 0x02u) != 0;
        }

        /**
         * @brief 判断流是否为客户端发起的双向请求流 (streamId % 4 == 0)
         */
        [[nodiscard]] constexpr bool isClientBidirectionalStream(uint64_t streamId) noexcept
        {
            return (streamId & 0x03u) == 0;
        }

        /**
         * @brief HTTP/3 单条逻辑流上下文槽位
         */
        struct StreamSlot
        {
            uint64_t streamId = 0;
            STREAM_STATE state = STREAM_STATE::IDLE;
            bool isUnidirectional = false;
            bool uniTypeIdentified = false;
            uint64_t uniType = 0;
            Buffer inBuffer{};
            bool finReceived = false;
            bool headersComplete = false;
            std::vector<Header> requestHeaders{};
            std::string requestBody{};

            StreamSlot() noexcept = default;
            StreamSlot(const StreamSlot &) = delete;
            StreamSlot &operator=(const StreamSlot &) = delete;
            StreamSlot(StreamSlot &&) noexcept = default;
            StreamSlot &operator=(StreamSlot &&) noexcept = default;

            void reset() noexcept
            {
                streamId = 0;
                state = STREAM_STATE::IDLE;
                isUnidirectional = false;
                uniTypeIdentified = false;
                uniType = 0;
                inBuffer.retrieveAll();
                finReceived = false;
                headersComplete = false;
                requestHeaders.clear();
                requestBody.clear();
            }
        };

        /**
         * @brief HTTP/3 流上下文哈希表管理器
         */
        class StreamTable
        {
        public:
            explicit StreamTable(size_t maxStreams = 128) noexcept
                : maxStreams_(maxStreams)
            {
            }

            ~StreamTable() noexcept = default;
            StreamTable(const StreamTable &) = delete;
            StreamTable &operator=(const StreamTable &) = delete;
            StreamTable(StreamTable &&) noexcept = default;
            StreamTable &operator=(StreamTable &&) noexcept = default;

            void setMaxStreams(size_t maxStreams) noexcept { maxStreams_ = maxStreams; }
            [[nodiscard]] size_t maxStreams() const noexcept { return maxStreams_; }
            [[nodiscard]] size_t size() const noexcept { return streams_.size(); }
            [[nodiscard]] bool empty() const noexcept { return streams_.empty(); }

            void reset() noexcept { streams_.clear(); }

            /**
             * @brief 查找或创建流槽位
             */
            [[nodiscard]] StreamSlot *getOrCreate(uint64_t streamId)
            {
                auto it = streams_.find(streamId);
                if (it != streams_.end())
                {
                    return &it->second;
                }
                if (streams_.size() >= maxStreams_) [[unlikely]]
                {
                    return nullptr;
                }
                auto [newIt, _] = streams_.emplace(streamId, StreamSlot{});
                StreamSlot &slot = newIt->second;
                slot.streamId = streamId;
                slot.state = STREAM_STATE::OPEN;
                slot.isUnidirectional = isUnidirectionalStream(streamId);
                return &slot;
            }

            /**
             * @brief 查找指定流 ID 槽位
             */
            [[nodiscard]] StreamSlot *find(uint64_t streamId) noexcept
            {
                auto it = streams_.find(streamId);
                return (it != streams_.end()) ? &it->second : nullptr;
            }

            /**
             * @brief 关闭并擦除指定流
             */
            void close(uint64_t streamId) noexcept { streams_.erase(streamId); }

        private:
            size_t maxStreams_ = 128;
            std::unordered_map<uint64_t, StreamSlot> streams_{};
        };

    } // namespace http::v3
} // namespace mynet
