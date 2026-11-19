#pragma once

/**
 * @file handler/http/v3/streamTable.hpp
 * @brief RFC 9114 HTTP/3 流类型判定、生命周期跟踪与流表管理器。
 */

#include "../v2/streamTable.hpp"
#include "frame.hpp"
#include "qpack.hpp"
#include "requestBuffer.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace mynet
{
    class HandlerConnection;

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
        template <typename StreamHandler = HandlerConnection>
        struct StreamSlot
        {
            StreamHandler *handler = nullptr;
            uint64_t streamId = 0;
            STREAM_STATE state = STREAM_STATE::IDLE;
            bool isUnidirectional = false;
            bool uniTypeIdentified = false;
            uint64_t uniType = 0;
            RequestBuffer inBuffer{};
            bool finReceived = false;
            bool headersComplete = false;
            bool headersReceived = false;
            bool localEnded = false;
            std::vector<Header> requestHeaders{};
            std::string requestBody{};
            std::string pendingResponse{};
            uint32_t pendingOffset = 0;

            StreamSlot() noexcept = default;
            StreamSlot(const StreamSlot &) = delete;
            StreamSlot &operator=(const StreamSlot &) = delete;
            StreamSlot(StreamSlot &&) noexcept = default;
            StreamSlot &operator=(StreamSlot &&) noexcept = default;

            void reset() noexcept
            {
                handler = nullptr;
                streamId = 0;
                state = STREAM_STATE::IDLE;
                isUnidirectional = false;
                uniTypeIdentified = false;
                uniType = 0;
                inBuffer.reset();
                finReceived = false;
                headersComplete = false;
                headersReceived = false;
                localEnded = false;
                requestHeaders.clear();
                requestBody.clear();
                pendingResponse.clear();
                pendingOffset = 0;
            }
        };

        /**
         * @brief HTTP/3 流上下文定容平坦哈希表管理器（基于公共 mux::StreamTable 算法）
         */
        template <typename Slot = StreamSlot<HandlerConnection>>
        class StreamTable
        {
        public:
            static constexpr uint64_t kNilStreamId = std::numeric_limits<uint64_t>::max();

            explicit StreamTable(size_t maxStreams = 128) noexcept
                : maxStreams_(maxStreams == 0 ? 1 : maxStreams)
            {
                [[maybe_unused]] auto _ = streams_.init(maxStreams_);
            }

            ~StreamTable() noexcept = default;
            StreamTable(const StreamTable &) = delete; // a stream table owns its slots and stream states
            StreamTable &
            operator=(const StreamTable &) = delete; // a stream table owns its slots and stream states
            StreamTable(StreamTable &&) noexcept = default;
            StreamTable &operator=(StreamTable &&) noexcept = default;

            void setMaxStreams(size_t maxStreams) noexcept
            {
                maxStreams_ = maxStreams == 0 ? 1 : maxStreams;
                if (!streams_.ready() || streams_.size() == 0)
                {
                    [[maybe_unused]] auto _ = streams_.init(maxStreams_);
                }
            }

            [[nodiscard]] size_t maxStreams() const noexcept { return maxStreams_; }
            [[nodiscard]] size_t size() const noexcept { return streams_.size(); }
            [[nodiscard]] size_t capacity() const noexcept { return streams_.capacity(); }
            [[nodiscard]] bool empty() const noexcept { return streams_.size() == 0; }
            [[nodiscard]] bool ready() const noexcept { return streams_.ready(); }

            template <typename F>
            void clear(F &&fn) noexcept
            {
                streams_.clear(std::forward<F>(fn));
            }

            void reset() noexcept
            {
                streams_.clear([]([[maybe_unused]] uint64_t id, Slot &slot) { slot.reset(); });
            }

            /**
             * @brief 查找或创建流槽位（开放寻址零动态分配）
             */
            [[nodiscard]] Slot *getOrCreate(uint64_t streamId)
            {
                if (!streams_.ready()) [[unlikely]]
                {
                    if (auto res = streams_.init(maxStreams_); !res) [[unlikely]]
                    {
                        return nullptr;
                    }
                }
                Slot *slot = streams_.find(streamId);
                if (slot != nullptr)
                {
                    return slot;
                }
                if (streams_.size() >= maxStreams_) [[unlikely]]
                {
                    return nullptr;
                }
                slot = streams_.open(streamId);
                if (slot != nullptr)
                {
                    slot->streamId = streamId;
                    slot->state = STREAM_STATE::OPEN;
                    slot->isUnidirectional = isUnidirectionalStream(streamId);
                }
                return slot;
            }

            /**
             * @brief 查找指定流 ID 槽位
             */
            [[nodiscard]] Slot *find(uint64_t streamId) noexcept { return streams_.find(streamId); }
            [[nodiscard]] const Slot *find(uint64_t streamId) const noexcept
            {
                return const_cast<StreamTable *>(this)->find(streamId);
            }

            /**
             * @brief 关闭并擦除指定流
             */
            void close(uint64_t streamId) noexcept { streams_.erase(streamId); }

            [[nodiscard]] const uint64_t &keyAt(size_t i) const noexcept { return streams_.keyAt(i); }
            [[nodiscard]] Slot *slotAt(size_t i) noexcept { return streams_.slotAt(i); }
            [[nodiscard]] const Slot *slotAt(size_t i) const noexcept { return streams_.slotAt(i); }

        private:
            size_t maxStreams_ = 128;
            mux::StreamTable<Slot, uint64_t, kNilStreamId> streams_{};
        };

    } // namespace http::v3
} // namespace mynet
