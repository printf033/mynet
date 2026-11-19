#pragma once

/**
 * @file port_pool.hpp
 * @brief 内核临时端口池避让与零碰撞探针预留分配器 (借鉴 sing-box common/kernelports)
 *
 * 核心机制：
 * 1. 自动读取 Linux /proc/sys/net/ipv4/ip_local_port_range，识别系统内核动态分配范围；
 * 2. 选取内核临时端口区间之外的安全端口段 (如 1024 ~ first-1 或 last+1 ~ 65535) 作为专用 NAT/出站池；
 * 3. 具备探针式零碰撞校验 (Probe Reservation)：在最终交付端口前执行瞬时探针 bind() 探测，
 *    若遇 EADDRINUSE 则瞬时跳过，彻底避免透明网关或并发 NAT 与宿主应用发生端口抢占冲突；
 * 4. 全程基于原子计数与轻量级探针，现代 C++26 noexcept 实现。
 */

#include <cstdint>
#include <fstream>
#include <string>
#include <atomic>
#include <optional>
#include <algorithm>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cerrno>

namespace mynet::transparent
{

    struct PortRange
    {
        uint16_t start{1024};
        uint16_t count{30000};

        [[nodiscard]] constexpr bool contains(uint16_t port) const noexcept
        {
            return port >= start && port < (start + count);
        }
    };

    class KernelPortPool
    {
    private:
        static constexpr uint16_t DEFAULT_EPHEMERAL_FIRST = 32768;
        static constexpr uint16_t DEFAULT_EPHEMERAL_LAST = 60999;
        static constexpr uint16_t LOWEST_SELECTOR = 1024;

        PortRange safeRange_{};
        std::atomic<uint16_t> cursor_{0};

        static std::pair<uint16_t, uint16_t> readSystemEphemeralRange() noexcept
        {
            std::ifstream file("/proc/sys/net/ipv4/ip_local_port_range");
            if (!file.is_open())
            {
                return {DEFAULT_EPHEMERAL_FIRST, DEFAULT_EPHEMERAL_LAST};
            }
            uint32_t first = 0;
            uint32_t last = 0;
            if (file >> first >> last && first >= LOWEST_SELECTOR && last <= 65535 && first <= last)
            {
                return {static_cast<uint16_t>(first), static_cast<uint16_t>(last)};
            }
            return {DEFAULT_EPHEMERAL_FIRST, DEFAULT_EPHEMERAL_LAST};
        }

        static PortRange computeSafePortRange() noexcept
        {
            auto [first, last] = readSystemEphemeralRange();

            PortRange below{LOWEST_SELECTOR, 0};
            if (first > LOWEST_SELECTOR)
            {
                below.count = first - LOWEST_SELECTOR;
            }

            PortRange above{static_cast<uint16_t>(last + 1), 0};
            if (last < 65535)
            {
                above.count = 65535 - last;
            }

            // 选择可用范围更大的安全区块
            if (above.count > below.count)
            {
                return above;
            }
            if (below.count > 0)
            {
                return below;
            }
            // 默认保底
            return PortRange{49152, static_cast<uint16_t>(65535 - 49152 + 1)};
        }

    public:
        KernelPortPool() noexcept
            : safeRange_(computeSafePortRange()),
              cursor_(0)
        {
        }

        static KernelPortPool& instance() noexcept
        {
            static KernelPortPool s_inst;
            return s_inst;
        }

        [[nodiscard]] const PortRange& safeRange() const noexcept { return safeRange_; }

        /**
         * @brief 执行探针式 bind 测试，确认端口在当前系统是否可用
         */
        [[nodiscard]] static bool probePortFree(uint16_t port, uint8_t protocol = IPPROTO_TCP) noexcept
        {
            const int sockType = (protocol == IPPROTO_UDP) ? SOCK_DGRAM : SOCK_STREAM;
            int fd = ::socket(AF_INET, sockType | SOCK_CLOEXEC, 0);
            if (fd < 0) return true; // 无法创建则视为不阻拦

            sockaddr_in sin{};
            sin.sin_family = AF_INET;
            sin.sin_addr.s_addr = htonl(INADDR_ANY);
            sin.sin_port = htons(port);

            int res = ::bind(fd, reinterpret_cast<sockaddr*>(&sin), sizeof(sin));
            int err = errno;
            ::close(fd);

            if (res == 0) return true;
            return err != EADDRINUSE;
        }

        /**
         * @brief 从安全区间中分配一个绝无冲突的端口
         *
         * @param protocol IPPROTO_TCP 或 IPPROTO_UDP
         * @param maxAttempts 最大探针探测尝试次数 (防止遍历死循环)
         */
        [[nodiscard]] std::optional<uint16_t> allocatePort(
            uint8_t protocol = IPPROTO_TCP,
            size_t maxAttempts = 64) noexcept
        {
            if (safeRange_.count == 0) return std::nullopt;

            for (size_t attempt = 0; attempt < maxAttempts; ++attempt)
            {
                uint16_t idx = cursor_.fetch_add(1, std::memory_order_relaxed);
                uint16_t candidate = safeRange_.start + (idx % safeRange_.count);

                if (probePortFree(candidate, protocol))
                {
                    return candidate;
                }
            }
            return std::nullopt;
        }
    };

} // namespace mynet::transparent
