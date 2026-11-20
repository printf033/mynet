#pragma once

/**
 * @file ebpf.hpp
 * @brief 基于 Linux eBPF 的高性能透明代理、内核套接字流卸载与 cgroupv2 进程感知引擎 (Production-Grade Real eBPF
 * Engine)。
 *
 * 深度实现并对齐 dae 内核级流量拦截与旁路调度架构：
 * 1. 真实内核数据路径挂载 (TC / TCX Datapath Hook Attachment)：
 *    通过 libbpf 在网卡驱动层挂载真实 BPF ELF 字节码。对于现代 Linux 内核 (>= 6.6) 优先采用
 *    bpf_program__attach_tcx 挂载，旧版本平滑回退至经典 clsact TC filter (bpf_tc_attach)；
 *    直连流量在 TC 层直接 TC_ACT_OK 放行，彻底消除 100% 用户态切换与内核管道拷贝；
 * 2. 真实套接字内核流卸载 (SockMap / SOCKHASH Stream Verdict Offload)：
 *    采用 5 元组 (TuplesKey: saddr, daddr, sport, dport, proto) 映射对端套接字，挂载
 *    sk_skb/stream_verdict 判决程序，调用 bpf_sk_redirect_hash 在内核底层无锁直推套接字字节流；
 * 3. cgroupv2 实时进程感知 (cgroup Socket Cookie -> Process Perception)：
 *    挂载 cgroup/connect4、cgroup/connect6、cgroup/sock_create、cgroup/sock_release 钩子，
 *    在连接发起微秒内将 socket cookie 与 PID / 进程名写入 BPF 哈希表；用户态通过 SO_COOKIE
 *    瞬间提取进程名，彻底消灭高开销的 /proc 遍历扫描；
 * 4. 全场景双模自愈架构：
 *    特权生产环境下加载内核驱动并执行物理网卡线速旁路；在非特权容器、沙箱或单元测试中无缝降级为
 *    用户态 LPM Trie 前缀树 + Flow Cache 流缓存 + Linux splice(2) 管道零拷贝引擎，保证 100% 稳定性。
 */

#include "address.hpp"
#include "config/log.hpp"
#include "configHolder.hpp"
#include "connection.hpp"
#include "error.hpp"
#include "geo.hpp"
#include "router.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <functional>
#include <mutex>
#include <netinet/in.h>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#if defined(__linux__)
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/magic.h>
#include <linux/pkt_cls.h>
#include <net/if.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/vfs.h>

#if defined(MYNET_HAVE_LIBBPF)
#include "ebpf/kern/mynet_kernel_bpf_embedded.hpp"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#endif

#ifndef BPF_FS_MAGIC
#define BPF_FS_MAGIC 0xcafe4a11
#endif
#ifndef SO_COOKIE
#define SO_COOKIE 57
#endif
#ifndef PR_SET_THP_DISABLE
#define PR_SET_THP_DISABLE 41
#endif
#endif

namespace mynet::ebpf
{

    /**
     * @brief eBPF 数据包处置动作 (对齐 Linux TC 操作码与 dae 行为)
     */
    enum class Action : uint32_t
    {
        DIRECT = 0, ///< 内核级直接放行 (TC_ACT_OK, 0 用户态切换)
        PROXY = 1,  ///< 打标并重定向到 TProxy 代理入站 (Fwmark)
        BLOCK = 2   ///< 内核驱动层丢弃 (TC_ACT_SHOT)
    };

    /**
     * @brief eBPF 统计指标
     */
    struct EbpfStats
    {
        uint64_t directBypassedPackets{0};
        uint64_t proxiedPackets{0};
        uint64_t blockedPackets{0};
        uint64_t totalBytesEvaluated{0};
    };

    /**
     * @brief 内核直连流量只读观测指标 (借鉴 dae direct_stats)
     *
     * 解决传统用户态代理无法观测被内核 TC 直接放行 (DIRECT / TC_ACT_OK) 的直连流量吞吐问题：
     * 从内核 conn_state_map 实时累加直连流的包数与字节数。
     */
    struct DirectTrafficStats
    {
        uint64_t directPackets{0};
        uint64_t directBytes{0};
    };

    /**
     * @brief Linux 网络协议栈内核参数与网关防重定向管理器 (借鉴 dae SysctlManager)
     *
     * 针对 Linux 旁路由 / 透明网关场景自动调优内核参数：
     * 1. 自动开启 IP 转发 (net.ipv4.ip_forward = 1) 与本机环回路由 (net.ipv4.conf.all.route_localnet = 1)；
     * 2. 彻底禁用 ICMP 重定向 (send_redirects = 0)：
     *    Linux 内核使用 OR 逻辑判断是否发送 ICMP 重定向：
     *    conf.all.send_redirects || conf.<ifname>.send_redirects
     *    因此必须同时将 all 与目标网卡接口设为 0，否则同网段客户端将被路由器通告直连旁路而绕过代理。
     */
    class SysctlManager
    {
    public:
        static constexpr std::string_view kProcSysNet = "/proc/sys/net";

        /**
         * @brief 写入指定 sysctl 节点数值
         */
        static bool setSysctl(std::string_view path, std::string_view value) noexcept
        {
            if (path.empty())
                return false;
            int fd = ::open(std::string(path).c_str(), O_WRONLY | O_CLOEXEC);
            if (fd < 0)
                return false;
            ssize_t n = ::write(fd, value.data(), value.size());
            ::close(fd);
            return n == static_cast<ssize_t>(value.size());
        }

        /**
         * @brief 读取指定 sysctl 节点数值
         */
        static std::optional<std::string> getSysctl(std::string_view path) noexcept
        {
            if (path.empty())
                return std::nullopt;
            int fd = ::open(std::string(path).c_str(), O_RDONLY | O_CLOEXEC);
            if (fd < 0)
                return std::nullopt;
            char buf[64] = {};
            ssize_t n = ::read(fd, buf, sizeof(buf) - 1);
            ::close(fd);
            if (n <= 0)
                return std::nullopt;
            std::string s(buf, static_cast<size_t>(n));
            while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' '))
            {
                s.pop_back();
            }
            return s;
        }

        /**
         * @brief 同时获取决定指定网卡 ICMP 重定向的全部 sysctl 节点路径 (conf.all 与 conf.<ifname>)
         */
        static std::vector<std::string> sendRedirectsSysctls(std::string_view ifname) noexcept
        {
            std::vector<std::string> paths;
            paths.reserve(2);
            paths.push_back(std::string(kProcSysNet) + "/ipv4/conf/all/send_redirects");
            if (!ifname.empty() && ifname != "all")
            {
                paths.push_back(std::string(kProcSysNet) + "/ipv4/conf/" + std::string(ifname) + "/send_redirects");
            }
            return paths;
        }

        /**
         * @brief 彻底禁用 ICMP 重定向 (conf.all 与 conf.<ifname> 均设为 0)
         */
        static bool setSendRedirects(std::string_view ifname, bool enable = false) noexcept
        {
            const std::string_view val = enable ? "1\n" : "0\n";
            bool ok = true;
            for (const auto &p : sendRedirectsSysctls(ifname))
            {
                if (!setSysctl(p, val))
                {
                    ok = false;
                }
            }
            return ok;
        }

        /**
         * @brief 检查指定接口上的 send_redirects 是否已完全处于关闭状态 (all 与 ifname 均必须为 0)
         */
        static bool isSendRedirectsDisabled(std::string_view ifname) noexcept
        {
            for (const auto &p : sendRedirectsSysctls(ifname))
            {
                auto val = getSysctl(p);
                if (!val.has_value() || *val != "0")
                {
                    return false;
                }
            }
            return true;
        }

        /**
         * @brief 为透明代理/旁路由模式一键调优核心内核参数
         */
        static bool tuneTransparentGateway(std::string_view lanIf, std::string_view wanIf) noexcept
        {
            bool ok = true;
            if (!setSysctl("/proc/sys/net/ipv4/ip_forward", "1\n"))
                ok = false;
            if (!setSysctl("/proc/sys/net/ipv4/conf/all/route_localnet", "1\n"))
                ok = false;
            if (!setSendRedirects("all", false))
                ok = false;
            if (!lanIf.empty() && !setSendRedirects(lanIf, false))
                ok = false;
            if (!wanIf.empty() && !setSendRedirects(wanIf, false))
                ok = false;
            return ok;
        }
    };

    /// 局域网 ICMP 重定向内核参数安全控制器别名 (机制 77)
    using SendRedirectsController = SysctlManager;

    /**
     * @brief 判定是否为短生命周期 UDP 流量 (如 DNS 53 端口查询) (机制 65: is_short_lived_udp_traffic)
     *
     * 避免随机高频端口的 DNS 查询频繁插入 conn_state_map 导致 65536 映射表满载颠簸与 Map Churn
     */
    [[nodiscard]] constexpr bool isShortLivedUdp(uint16_t sport, uint16_t dport) noexcept
    {
        return sport == 53 || dport == 53;
    }

    /**
     * @brief 自适应 BPF 连接跟踪回收步调控制器 (借鉴 dae conn_state_janitor, 机制 87)
     *
     * 稳态步调 5s；当 map 利用率超过 70% 时进入压力模式加速为 1s；
     * 连续 3 轮低于 50% 时退出压力模式；并在系统平静时退避至 30s。
     * 同时通过 DELETE_RETAIN_MAX = 8192 上限回收暂存空间，避免突发内存常驻。
     */
    class JanitorCadenceController
    {
    public:
        static constexpr std::chrono::seconds STEADY_INTERVAL{5};
        static constexpr std::chrono::seconds PRESSURE_INTERVAL{1};
        static constexpr std::chrono::seconds MAX_INTERVAL{30};
        static constexpr uint32_t PRESSURE_ENTER_USAGE_PCT{70};
        static constexpr uint32_t PRESSURE_EXIT_USAGE_PCT{50};
        static constexpr uint32_t PRESSURE_EXIT_ROUNDS{3};
        static constexpr size_t DELETE_RETAIN_MAX{8192};

    private:
        bool inPressureMode_{false};
        uint32_t consecutiveCalmRounds_{0};

    public:
        [[nodiscard]] std::chrono::seconds step(uint32_t currentEntries, uint32_t maxEntries) noexcept
        {
            if (maxEntries == 0)
                return STEADY_INTERVAL;
            uint32_t usagePct = (currentEntries * 100) / maxEntries;

            if (!inPressureMode_)
            {
                if (usagePct >= PRESSURE_ENTER_USAGE_PCT)
                {
                    inPressureMode_ = true;
                    consecutiveCalmRounds_ = 0;
                    return PRESSURE_INTERVAL;
                }
                return (usagePct == 0) ? MAX_INTERVAL : STEADY_INTERVAL;
            }
            else
            {
                if (usagePct < PRESSURE_EXIT_USAGE_PCT)
                {
                    consecutiveCalmRounds_++;
                    if (consecutiveCalmRounds_ >= PRESSURE_EXIT_ROUNDS)
                    {
                        inPressureMode_ = false;
                        consecutiveCalmRounds_ = 0;
                        return STEADY_INTERVAL;
                    }
                }
                else
                {
                    consecutiveCalmRounds_ = 0;
                }
                return PRESSURE_INTERVAL;
            }
        }

        [[nodiscard]] bool inPressureMode() const noexcept { return inPressureMode_; }
        void reset() noexcept
        {
            inPressureMode_ = false;
            consecutiveCalmRounds_ = 0;
        }
    };

    /**
     * @brief 内核异步事件通知结构 (对齐 mynet_kernel.bpf.c mynet_event)
     */
    enum class BpfEventType : uint32_t
    {
        BLOCKED = 1,
        BLOCKED_ALIVE = 2,
        UDP_OVERFLOW = 3,
        TCP_OVERFLOW = 4,
    };

    struct alignas(8) MynetEvent
    {
        uint64_t timestampNs{0};
        uint32_t type{0};
        uint32_t pid{0};
        uint16_t sport{0};
        uint16_t dport{0};
        uint8_t protocol{0};
        uint8_t pad[3]{0, 0, 0};
        uint32_t saddr{0};
        uint32_t daddr{0};
    };

    /**
     * @brief 数据平面增量区间健康与压力监控器 (借鉴 dae control/datapath_overflow_report.go)
     *
     * 解决长周期常驻代理进程因累计计数导致虚假永久告警的痛点：
     * 1. 采用滑动监控窗口（如 30 秒周期），仅计算相邻报告区间之间的增量 delta；
     * 2. 当任一区间内的连接溢出数、黑洞限速丢弃数或 RingBuffer 丢弃数激增时，分级裁决为 WARNING 或 CRITICAL；
     * 3. 在指标恢复平稳（delta == 0）后自动静默，避免日志常态刷屏。
     */
    class DatapathOverflowMonitor
    {
    public:
        enum class PressureLevel : uint8_t
        {
            NORMAL,  ///< 正常平稳运行
            WARNING, ///< 资源轻度承压或偶尔瞬态丢包
            CRITICAL ///< 表项打满，持续高频拒绝新连接
        };

        struct Snapshot
        {
            uint64_t udpConnOverflow{0};
            uint64_t tcpConnOverflow{0};
            uint64_t blockRateDrops{0};
            uint64_t eventDrops{0};
        };

        struct IntervalReport
        {
            PressureLevel level{PressureLevel::NORMAL};
            bool moved{false};
            uint64_t deltaUdpOverflow{0};
            uint64_t deltaTcpOverflow{0};
            uint64_t deltaBlockDrops{0};
            uint64_t deltaEventDrops{0};
        };

    private:
        bool primed_{false};
        Snapshot baseline_{};
        uint64_t heavyThreshold_{100}; ///< 单区间突增超过 100 判定为 CRITICAL

    public:
        explicit DatapathOverflowMonitor(uint64_t heavyThreshold = 100) noexcept
            : heavyThreshold_(heavyThreshold)
        {
        }

        /**
         * @brief 记录并评估当前周期的快照指标增量
         */
        IntervalReport evaluate(const Snapshot &current) noexcept
        {
            if (!primed_)
            {
                baseline_ = current;
                primed_ = true;
                return IntervalReport{.level = PressureLevel::NORMAL, .moved = false};
            }

            IntervalReport report{};
            auto computeDelta = [](uint64_t curr, uint64_t &base) -> uint64_t
            {
                if (curr < base)
                {
                    base = curr; // 计数器复位或重新挂载
                    return 0;
                }
                uint64_t d = curr - base;
                base = curr;
                return d;
            };

            report.deltaUdpOverflow = computeDelta(current.udpConnOverflow, baseline_.udpConnOverflow);
            report.deltaTcpOverflow = computeDelta(current.tcpConnOverflow, baseline_.tcpConnOverflow);
            report.deltaBlockDrops = computeDelta(current.blockRateDrops, baseline_.blockRateDrops);
            report.deltaEventDrops = computeDelta(current.eventDrops, baseline_.eventDrops);

            uint64_t totalDelta =
                report.deltaUdpOverflow + report.deltaTcpOverflow + report.deltaBlockDrops + report.deltaEventDrops;

            if (totalDelta == 0)
            {
                report.moved = false;
                report.level = PressureLevel::NORMAL;
                return report;
            }

            report.moved = true;
            if (report.deltaUdpOverflow >= heavyThreshold_ || report.deltaTcpOverflow >= heavyThreshold_)
            {
                report.level = PressureLevel::CRITICAL;
            }
            else
            {
                report.level = PressureLevel::WARNING;
            }

            return report;
        }

        void reset() noexcept
        {
            primed_ = false;
            baseline_ = {};
        }
    };

    /**
     * @brief 报文元数据 (用于流表决断与仿真)
     */
    struct PacketMetadata
    {
        in_addr srcIp{};
        in_addr dstIp{};
        in6_addr srcIp6{};
        in6_addr dstIp6{};
        bool isIpv6{false};
        uint16_t srcPort{0};
        uint16_t dstPort{0};
        uint8_t protocol{IPPROTO_TCP};
        uint32_t mark{0};
        size_t length{0};
    };

    /**
     * @brief BPF_MAP_TYPE_LPM_TRIE IPv4 节点结构 (对齐 Linux 内核 struct bpf_lpm_trie_key)
     */
    struct alignas(4) BpfLpmKeyIpv4
    {
        uint32_t prefixlen{32};
        uint32_t ip{0}; ///< 大端网络字节序 IP
    };

    /**
     * @brief BPF_MAP_TYPE_LPM_TRIE IPv6 节点结构 (对齐 Linux 内核 struct bpf_lpm_trie_key)
     */
    struct alignas(4) BpfLpmKeyIpv6
    {
        uint32_t prefixlen{128};
        uint8_t ip[16]{};
    };

    /**
     * @brief 5元组键结构，用于 fast_sock (SOCKHASH) 套接字直推与 UDP 连接状态追踪
     */
    struct alignas(4) TuplesKey
    {
        uint32_t saddr{0};
        uint32_t daddr{0};
        uint16_t sport{0};
        uint16_t dport{0};
        uint8_t proto{IPPROTO_TCP};
        uint8_t pad[3]{0, 0, 0};

        constexpr bool operator==(const TuplesKey &other) const noexcept
        {
            return saddr == other.saddr && daddr == other.daddr && sport == other.sport && dport == other.dport &&
                   proto == other.proto;
        }
    };

    struct TuplesKeyHash
    {
        size_t operator()(const TuplesKey &k) const noexcept
        {
            size_t h = static_cast<size_t>(k.saddr) ^ (static_cast<size_t>(k.daddr) << 1);
            h ^= (static_cast<size_t>(k.sport) << 16) | static_cast<size_t>(k.dport);
            h ^= static_cast<size_t>(k.proto) << 24;
            return h;
        }
    };

    /**
     * @brief UDP & TCP 连接状态追踪表项 (对齐内核 struct conn_state_entry)
     */
    struct alignas(8) ConnStateEntry
    {
        uint32_t action{0};
        uint32_t fwmark{0};
        uint64_t lastSeenNs{0};
        uint64_t packets{0};
        uint64_t bytes{0};
        uint8_t dscp{0};
        uint8_t pad[7]{0};
    };

    /**
     * @brief 获取单调递增纳秒时间戳 (对齐内核 bpf_ktime_get_ns)
     */
    [[nodiscard]] inline uint64_t getMonotonicTimeNs() noexcept
    {
        struct timespec ts{};
        ::clock_gettime(CLOCK_MONOTONIC, &ts);
        return static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL + static_cast<uint64_t>(ts.tv_nsec);
    }

    /**
     * @brief 进程信息映射结构 (与内核 BPF 映射对齐)
     */
    struct PidPname
    {
        uint32_t pid{0};
        char pname[16]{};
        uint64_t last_seen_ns{0};
    };

    /**
     * @brief 本地进程识别特征
     */
    struct ProcessInfo
    {
        uint32_t pid{0};
        std::string name{};
    };

    /**
     * @brief eBPF 状态配置数组值 (对齐内核 struct mynet_bpf_config)
     */
    struct alignas(4) BpfConfigVal
    {
        uint16_t tproxyPort{0};
        uint16_t pad{0};
        uint32_t fwmark{0};
        uint8_t directBypassEnabled{1};
        uint8_t dropQuic{0};
        uint16_t wanIfIndex{0};
        uint8_t activeEpoch{0};
        uint8_t asymmetricGateway{0};
        uint8_t gatewayMac[6]{0};
        uint8_t wanMac[6]{0};
        uint8_t enableSkAssign{0};
        uint8_t redirectIfindex{0};
        uint16_t rateLimitWindowMs{1000};
        uint8_t tproxyPortProtect{0};
        uint8_t pad3{0};
    };
    static_assert(sizeof(BpfConfigVal) == 32, "BpfConfigVal must be exactly 32 bytes matching kernel struct");

    /**
     * @brief DNS 域名规则位图内核投影数据 (借鉴 dae domain_routing_map)
     */
    struct DomainRoutingKey
    {
        uint32_t ip{0};
        uint8_t slot{0};
        uint8_t pad[3]{0, 0, 0};
        bool operator==(const DomainRoutingKey &o) const noexcept { return ip == o.ip && slot == o.slot; }
    };

    struct DomainRoutingVal
    {
        std::array<uint32_t, 4> ruleBitmap{0, 0, 0, 0};
    };

    /**
     * @brief 内核向用户态零拷贝路由交接条目 (借鉴 dae routing_handoff_map)
     */
    struct RoutingHandoffEntry
    {
        uint64_t lastSeenNs{0};
        uint32_t mark{0};
        uint16_t outbound{0};
        uint8_t dscp{0};
        uint8_t must{0};
        uint8_t mac[6]{0, 0, 0, 0, 0, 0};
        uint8_t epochSlot{0};
        uint8_t pad{0};
    };

    /**
     * @brief 代理回包定向直通路由表条目 (借鉴 dae redirect_track)
     */
    struct RedirectTrackEntry
    {
        uint32_t ifindex{0};
        uint8_t fromWan{0};
        uint8_t smac[6]{0, 0, 0, 0, 0, 0};
        uint8_t dmac[6]{0, 0, 0, 0, 0, 0};
        uint64_t lastSeenNs{0};
    };

    /**
     * @brief dae eBPF 核心透明代理与流卸载引擎 (dae-style eBPF Engine)
     */
    class EbpfEngine
    {
    public:
        struct LpmEntry
        {
            uint32_t net;
            uint32_t mask;
            uint32_t prefixlen;
            Action action;

            [[nodiscard]] constexpr bool matches(uint32_t hIp) const noexcept { return (hIp & mask) == net; }
        };

        struct LpmEntryIpv6
        {
            uint8_t net[16];
            uint8_t mask[16];
            uint32_t prefixlen;
            Action action;

            [[nodiscard]] bool matches(const uint8_t *ip) const noexcept
            {
                for (size_t i = 0; i < 16; ++i)
                {
                    if ((ip[i] & mask[i]) != net[i])
                        return false;
                }
                return true;
            }
        };

    private:
        mutable std::mutex mutex_{};
        EbpfConfig config_{};
        bool kernelBpfActive_{false};
        bool tcFilterAttached_{false};
        bool verdictAttached_{false};
        bool cgroupAttached_{false};
        int wanIfIndex_{0};
        int virtualIfIndex_{0};

#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
        struct bpf_object *bpfObj_{nullptr};
        struct bpf_link *tcLink_{nullptr};
        struct bpf_tc_hook tcHook_{};
        bool tcHookClassic_{false};

        struct bpf_link *cgConn4Link_{nullptr};
        struct bpf_link *cgConn6Link_{nullptr};
        struct bpf_link *cgSend4Link_{nullptr};
        struct bpf_link *cgSend6Link_{nullptr};
        struct bpf_link *cgCreateLink_{nullptr};
        struct bpf_link *cgReleaseLink_{nullptr};
        int cgroupFd_{-1};
#endif

        struct SlaveTcAttachment
        {
            std::string ifName{};
            int ifindex{0};
#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
            struct bpf_link *link{nullptr};
            struct bpf_tc_hook hook{};
            bool isClassic{false};
#endif
        };
        std::vector<SlaveTcAttachment> slaveTcAttachments_{};
        std::vector<std::string> attachedInterfaces_{};

        int lpmMapFd_[2]{-1, -1};
        int lpmMapIpv6Fd_[2]{-1, -1};
        int directMapFd_{-1};
        int directStatsMapFd_{-1};
        int configMapFd_{-1};
        int sockMapFd_{-1};
        int cookieMapFd_{-1};
        int connStateMapFd_{-1};
        int listenSockMapFd_{-1};
        int blockRateMapFd_{-1};
        int tcpOffloadPauseMapFd_{-1};
        int outboundConnectivityMapFd_{-1};
        int eventRingbufFd_{-1};
        int bpfStatsMapFd_{-1};
        int domainRoutingMapFd_{-1};
        int routingHandoffMapFd_{-1};
        int redirectTrackMapFd_{-1};

        // 用户态备用/仿真数据结构 (全环境 100% 兼容)
        std::atomic<uint8_t> activeEpoch_{0};
        std::vector<LpmEntry> lpmEntries_[2]{};
        std::vector<LpmEntryIpv6> lpmEntriesIpv6_[2]{};
        std::unordered_set<uint32_t> directIps_{};
        std::unordered_map<uint64_t, Action> flowCache_{};
        std::unordered_map<TuplesKey, ConnStateEntry, TuplesKeyHash> connStateMap_{};
        int listenSockets_[3]{-1, -1, -1};
        std::unordered_map<uint64_t, ProcessInfo> socketProcessMap_{};
        std::unordered_map<uint32_t, uint64_t> blockRateMap_{};
        std::unordered_set<TuplesKey, TuplesKeyHash> pausedOffloads_{};
        std::unordered_map<uint32_t, bool> outboundConnectivity_{};
        std::unordered_map<uint32_t, uint64_t> bpfStatsMap_{};
        std::unordered_map<uint64_t, std::array<uint32_t, 4>> domainRoutingMap_{};
        std::unordered_map<TuplesKey, RoutingHandoffEntry, TuplesKeyHash> routingHandoffMap_{};
        std::unordered_map<TuplesKey, RedirectTrackEntry, TuplesKeyHash> redirectTrackMap_{};
        uint64_t redirectRebindStaleNs_{5'000'000'000ULL};
        std::atomic<uint64_t> statRedirectRebindRejected_{0};

        std::atomic<uint64_t> directBypassedPackets_{0};
        std::atomic<uint64_t> proxiedPackets_{0};
        std::atomic<uint64_t> blockedPackets_{0};
        std::atomic<uint64_t> totalBytesEvaluated_{0};

    public:
        EbpfEngine() noexcept = default;

        explicit EbpfEngine(const EbpfConfig &cfg) { init(cfg); }

        ~EbpfEngine() { cleanup(); }

        EbpfEngine(const EbpfEngine &) = delete;
        EbpfEngine &operator=(const EbpfEngine &) = delete;
        EbpfEngine(EbpfEngine &&) = delete;
        EbpfEngine &operator=(EbpfEngine &&) = delete;

        [[nodiscard]] inline bool isKernelBpfActive() const noexcept { return kernelBpfActive_; }
        [[nodiscard]] inline bool isTcFilterAttached() const noexcept { return tcFilterAttached_; }
        [[nodiscard]] inline bool isVerdictAttached() const noexcept { return verdictAttached_; }
        [[nodiscard]] inline bool isCgroupAttached() const noexcept { return cgroupAttached_; }
        [[nodiscard]] inline const EbpfConfig &config() const noexcept { return config_; }
        [[nodiscard]] inline int sockMapFd() const noexcept { return sockMapFd_; }
        [[nodiscard]] inline int cookieMapFd() const noexcept { return cookieMapFd_; }
        [[nodiscard]] inline int connStateMapFd() const noexcept { return connStateMapFd_; }
        [[nodiscard]] inline int listenSockMapFd() const noexcept { return listenSockMapFd_; }
        [[nodiscard]] inline int blockRateMapFd() const noexcept { return blockRateMapFd_; }
        [[nodiscard]] inline int tcpOffloadPauseMapFd() const noexcept { return tcpOffloadPauseMapFd_; }
        [[nodiscard]] inline int outboundConnectivityMapFd() const noexcept { return outboundConnectivityMapFd_; }
        [[nodiscard]] inline int virtualIfIndex() const noexcept { return virtualIfIndex_; }
        [[nodiscard]] inline uint8_t activeEpoch() const noexcept
        {
            return activeEpoch_.load(std::memory_order_relaxed);
        }

        /**
         * @brief 初始化 dae eBPF 运行时与驱动映射结构
         */
        bool init(const EbpfConfig &cfg)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            cleanup();
            config_ = cfg;

            // 1. 尝试通过 libbpf 加载真实内核 eBPF 驱动程序
            kernelBpfActive_ = tryLoadKernelBpf();

            if (kernelBpfActive_)
            {
                LOG_INFO("eBPF: Successfully loaded real Linux kernel BPF bytecode (TC, Sockmap, cgroupv2)");
                syncConfigToKernel();

                // 2. 尝试挂载网卡 TC / TCX 驱动过滤器
                if (!config_.wanInterface.empty())
                {
                    attachTcFilterLocked(config_.wanInterface, true);
                }

                // 3. 尝试挂载 cgroupv2 实时进程感知钩子
                attachCgroupLocked("/sys/fs/cgroup");
            }
            else
            {
                // 回退模式：若允许系统调用，探测创建基础 maps，否则进入完全仿真
                tryCreateKernelMaps();
                LOG_INFO("eBPF: Running in robust user-space emulation mode (unprivileged/sandbox container)");
            }

            // 默认加载私网地址为 DIRECT 直连旁路 (初始化 dual slots)
            loadDefaultPrivateCidrs(0);
            loadDefaultPrivateCidrs(1);
            return true;
        }

        /**
         * @brief 挂载网卡 TC / TCX 驱动过滤器
         */
        bool attachTcFilter(std::string_view ifName, bool ingress = true)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            attachedInterfaces_.clear();
            if (!ifName.empty())
            {
                attachedInterfaces_.push_back(std::string(ifName));
                auto slaves = discoverBridgeSlaves(ifName);
                for (const auto &s : slaves)
                {
                    attachedInterfaces_.push_back(s);
                }
            }
            return attachTcFilterLocked(ifName, ingress);
        }

        /**
         * @brief 获取当前挂载了 TC 过滤器的所有接口（包含 bridge master 与从属 slaves）
         */
        [[nodiscard]] std::vector<std::string> getAttachedInterfaces() const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return attachedInterfaces_;
        }

        /**
         * @brief 自动发现 Linux Bridge 网桥接口下的全部从属成员物理设备 (借鉴 dae bridge_members)
         *
         * 在旁路由/局域网交换机网桥环境下，从属物理设备之间转发的流量不会走 bridge master 的 ingress，
         * 因此必须发现并挂载所有从属 member 端口。
         */
        [[nodiscard]] static std::vector<std::string> discoverBridgeSlaves(std::string_view bridgeIf) noexcept
        {
            std::vector<std::string> slaves;
            if (bridgeIf.empty())
            {
                return slaves;
            }

            std::string brifPath = "/sys/class/net/" + std::string(bridgeIf) + "/brif";
            std::error_code ec;
            if (!std::filesystem::exists(brifPath, ec) || !std::filesystem::is_directory(brifPath, ec))
            {
                return slaves;
            }

            for (const auto &entry : std::filesystem::directory_iterator(brifPath, ec))
            {
                if (ec)
                    break;
                slaves.push_back(entry.path().filename().string());
            }
            std::sort(slaves.begin(), slaves.end());
            return slaves;
        }

        /**
         * @brief 一键为旁路由/透明代理配置内核网络栈参数 (ip_forward=1, route_localnet=1, send_redirects=0)
         */
        bool tuneGatewaySysctls() noexcept
        {
            return SysctlManager::tuneTransparentGateway(config_.lanInterface, config_.wanInterface);
        }

        /**
         * @brief 读取内核直连流量统计指标 (借鉴 dae direct_stats)
         */
        [[nodiscard]] DirectTrafficStats getDirectTrafficStats() const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            DirectTrafficStats stats{};
            stats.directPackets = directBypassedPackets_.load(std::memory_order_relaxed);

#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
            if (kernelBpfActive_ && connStateMapFd_ >= 0)
            {
                TuplesKey key{};
                TuplesKey nextKey{};
                while (::bpf_map_get_next_key(connStateMapFd_, &key, &nextKey) == 0)
                {
                    ConnStateEntry val{};
                    if (::bpf_map_lookup_elem(connStateMapFd_, &nextKey, &val) == 0)
                    {
                        if (val.action == 0) // TC_ACT_OK (DIRECT)
                        {
                            stats.directPackets += val.packets;
                            stats.directBytes += val.bytes;
                        }
                    }
                    key = nextKey;
                }
            }
#endif
            for (const auto &[k, v] : connStateMap_)
            {
                if (v.action == 0)
                {
                    stats.directPackets += v.packets;
                    stats.directBytes += v.bytes;
                }
            }
            return stats;
        }

        /**
         * @brief 判定是否处于单网卡双角色 (Dual-role) 模式
         */
        [[nodiscard]] bool isDualRole() const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return !config_.wanInterface.empty() && config_.wanInterface == config_.lanInterface;
        }

        /**
         * @brief 读取内核 BPF 运行时内部诊断度量统计 (借鉴 dae bpf_stats_map)
         */
        [[nodiscard]] std::unordered_map<uint32_t, uint64_t> getBpfInternalStats() const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            std::unordered_map<uint32_t, uint64_t> stats;
#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
            if (kernelBpfActive_ && bpfStatsMapFd_ >= 0)
            {
                for (uint32_t k = 0; k < 8; ++k)
                {
                    uint64_t v = 0;
                    if (::bpf_map_lookup_elem(bpfStatsMapFd_, &k, &v) == 0)
                    {
                        stats[k] = v;
                    }
                }
            }
#endif
            for (const auto &[k, v] : bpfStatsMap_)
            {
                stats[k] += v;
            }
            return stats;
        }

        /**
         * @brief 记录/仿真内核 BPF 诊断统计项
         */
        void recordBpfStat(uint32_t key, uint64_t delta = 1) noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            bpfStatsMap_[key] += delta;
#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
            if (kernelBpfActive_ && bpfStatsMapFd_ >= 0)
            {
                uint64_t curr = 0;
                ::bpf_map_lookup_elem(bpfStatsMapFd_, &key, &curr);
                curr += delta;
                ::bpf_map_update_elem(bpfStatsMapFd_, &key, &curr, BPF_ANY);
            }
#endif
        }

        /**
         * @brief DNS 域名规则位图内核投影写入 (借鉴 dae domain_routing_map)
         */
        bool updateDomainRouting(uint32_t ip, uint8_t slot, const std::array<uint32_t, 4> &bitmap) noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            uint64_t mapKey = (static_cast<uint64_t>(slot) << 32) | ip;
            domainRoutingMap_[mapKey] = bitmap;
#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
            if (kernelBpfActive_ && domainRoutingMapFd_ >= 0)
            {
                DomainRoutingKey k{.ip = ip, .slot = slot};
                DomainRoutingVal v{.ruleBitmap = bitmap};
                return ::bpf_map_update_elem(domainRoutingMapFd_, &k, &v, BPF_ANY) == 0;
            }
#endif
            return true;
        }

        /**
         * @brief DNS 域名规则位图内核投影删除
         */
        bool deleteDomainRouting(uint32_t ip, uint8_t slot) noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            uint64_t mapKey = (static_cast<uint64_t>(slot) << 32) | ip;
            domainRoutingMap_.erase(mapKey);
#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
            if (kernelBpfActive_ && domainRoutingMapFd_ >= 0)
            {
                DomainRoutingKey k{.ip = ip, .slot = slot};
                return ::bpf_map_delete_elem(domainRoutingMapFd_, &k) == 0;
            }
#endif
            return true;
        }

        /**
         * @brief DNS 域名规则位图内核投影查询
         */
        [[nodiscard]] std::optional<std::array<uint32_t, 4>> lookupDomainRouting(uint32_t ip,
                                                                                 uint8_t slot) const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
            if (kernelBpfActive_ && domainRoutingMapFd_ >= 0)
            {
                DomainRoutingKey k{.ip = ip, .slot = slot};
                DomainRoutingVal v{};
                if (::bpf_map_lookup_elem(domainRoutingMapFd_, &k, &v) == 0)
                {
                    return v.ruleBitmap;
                }
            }
#endif
            uint64_t mapKey = (static_cast<uint64_t>(slot) << 32) | ip;
            auto it = domainRoutingMap_.find(mapKey);
            if (it != domainRoutingMap_.end())
            {
                return it->second;
            }
            return std::nullopt;
        }

        /**
         * @brief 发布内核向用户态零拷贝路由交接结果 (借鉴 dae routing_handoff_map)
         */
        bool publishRoutingHandoff(const TuplesKey &key, const RoutingHandoffEntry &entry) noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            routingHandoffMap_[key] = entry;
#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
            if (kernelBpfActive_ && routingHandoffMapFd_ >= 0)
            {
                return ::bpf_map_update_elem(routingHandoffMapFd_, &key, &entry, BPF_ANY) == 0;
            }
#endif
            return true;
        }

        /**
         * @brief 消费内核向用户态零拷贝路由交接结果 (读取后立即删除)
         */
        std::optional<RoutingHandoffEntry> consumeRoutingHandoff(const TuplesKey &key) noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
            if (kernelBpfActive_ && routingHandoffMapFd_ >= 0)
            {
                RoutingHandoffEntry entry{};
                if (::bpf_map_lookup_elem(routingHandoffMapFd_, &key, &entry) == 0)
                {
                    ::bpf_map_delete_elem(routingHandoffMapFd_, &key);
                    return entry;
                }
            }
#endif
            auto it = routingHandoffMap_.find(key);
            if (it != routingHandoffMap_.end())
            {
                auto entry = it->second;
                routingHandoffMap_.erase(it);
                return entry;
            }
            return std::nullopt;
        }

        /**
         * @brief 更新代理回包定向直通路由表 (借鉴 dae redirect_track 单写者防伪造保护机制)
         */
        bool updateRedirectTrack(const TuplesKey &key, const RedirectTrackEntry &entry) noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = redirectTrackMap_.find(key);
            if (it != redirectTrackMap_.end())
            {
                const auto &existing = it->second;
                bool samePub = (existing.ifindex == entry.ifindex && existing.fromWan == entry.fromWan &&
                                std::memcmp(existing.smac, entry.smac, 6) == 0);
                if (!samePub)
                {
                    if (entry.lastSeenNs >= existing.lastSeenNs &&
                        (entry.lastSeenNs - existing.lastSeenNs) < redirectRebindStaleNs_)
                    {
                        statRedirectRebindRejected_.fetch_add(1, std::memory_order_relaxed);
                        return false;
                    }
                }
            }
            redirectTrackMap_[key] = entry;
#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
            if (kernelBpfActive_ && redirectTrackMapFd_ >= 0)
            {
                return ::bpf_map_update_elem(redirectTrackMapFd_, &key, &entry, BPF_ANY) == 0;
            }
#endif
            return true;
        }

        [[nodiscard]] uint64_t redirectRebindRejectedCount() const noexcept
        {
            return statRedirectRebindRejected_.load(std::memory_order_relaxed);
        }

        void setRedirectRebindStaleNs(uint64_t ns) noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            redirectRebindStaleNs_ = ns;
        }

        [[nodiscard]] uint64_t redirectRebindStaleNs() const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return redirectRebindStaleNs_;
        }

        /**
         * @brief 查询代理回包定向直通路由表
         */
        [[nodiscard]] std::optional<RedirectTrackEntry> lookupRedirectTrack(const TuplesKey &key) const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
            if (kernelBpfActive_ && redirectTrackMapFd_ >= 0)
            {
                RedirectTrackEntry entry{};
                if (::bpf_map_lookup_elem(redirectTrackMapFd_, &key, &entry) == 0)
                {
                    return entry;
                }
            }
#endif
            auto it = redirectTrackMap_.find(key);
            if (it != redirectTrackMap_.end())
            {
                return it->second;
            }
            return std::nullopt;
        }

        /**
         * @brief 动态配置 TProxy 端口未授权入站硬防护开关 (借鉴 dae tproxy_port_protect)
         */
        void setTproxyPortProtect(bool protect) noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            config_.tproxyPortProtect = protect;
#if defined(__linux__)
            if (kernelBpfActive_ && configMapFd_ >= 0)
            {
                uint32_t key = 0;
                BpfConfigVal val{};
                if (::bpf_map_lookup_elem(configMapFd_, &key, &val) == 0)
                {
                    val.tproxyPortProtect = protect ? 1 : 0;
                    ::bpf_map_update_elem(configMapFd_, &key, &val, BPF_ANY);
                }
            }
#endif
        }

        [[nodiscard]] bool isTproxyPortProtected() const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return config_.tproxyPortProtect;
        }

        /**
         * @brief 透明大页 (THP) 内存防膨胀消减 (借鉴 dae disable_thp via prctl)
         */
        static bool disableTransparentHugePages() noexcept
        {
#if defined(__linux__) && defined(PR_SET_THP_DISABLE)
            return ::prctl(PR_SET_THP_DISABLE, 1, 0, 0, 0) == 0;
#else
            return false;
#endif
        }

        /**
         * @brief Linux 6.7+ Netkit 下一代虚拟网卡自适应协商创建 (借鉴 dae netkit_linux)
         */
        static bool detectAndCreateNetkitDevice(const std::string &name, const std::string &peerName,
                                                bool scrubNone = true) noexcept
        {
            if (name.empty() || peerName.empty())
                return false;
#if defined(__linux__)
            std::string cmd = "ip link add " + name + " type netkit mode l2";
            if (scrubNone)
            {
                cmd += " scrub none peer scrub none " + peerName;
            }
            else
            {
                cmd += " peer " + peerName;
            }
            int ret = ::system((cmd + " 2>/dev/null").c_str());
            if (ret == 0)
                return true;
            // 回落至经典 veth pair
            std::string fallbackCmd = "ip link add " + name + " type veth peer name " + peerName;
            return ::system((fallbackCmd + " 2>/dev/null").c_str()) == 0;
#else
            return false;
#endif
        }

        /**
         * @brief 卸载网卡 TC 过滤器
         */
        void detachTcFilter()
        {
            std::lock_guard<std::mutex> lock(mutex_);
            detachTcFilterLocked();
        }

        /**
         * @brief 挂载 cgroupv2 进程感知钩子
         */
        bool attachCgroup(const std::string &cgroupPath = "/sys/fs/cgroup")
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return attachCgroupLocked(cgroupPath);
        }

        /**
         * @brief 卸载 cgroup 钩子
         */
        void detachCgroup()
        {
            std::lock_guard<std::mutex> lock(mutex_);
            detachCgroupLocked();
        }

        /**
         * @brief 向 eBPF LPM Trie 注入一条 IPv4 CIDR 路由规则
         */
        /**
         * @brief 向 eBPF LPM Trie 注入一条 IPv4 CIDR 路由规则 (支持双 Epoch 槽位注入)
         */
        bool addLpmCidr(std::string_view cidrStr, Action action, int epochSlot = -1)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return addLpmCidrLocked(cidrStr, action, epochSlot);
        }

        bool addLpmCidr(uint32_t netBe, uint8_t prefix, Action action, int epochSlot = -1)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return addLpmCidrLocked(netBe, prefix, action, epochSlot);
        }

        bool addLpmCidrLocked(uint32_t netBe, uint8_t prefix, Action action, int epochSlot = -1)
        {
            if (prefix > 32)
                return false;

            const uint8_t curEpoch = activeEpoch_.load(std::memory_order_relaxed);
            const uint8_t slot = (epochSlot >= 0 && epochSlot <= 1) ? static_cast<uint8_t>(epochSlot) : curEpoch;

            uint32_t hIp = ntohl(netBe);
            uint32_t mask = (prefix == 0) ? 0 : (~0U << (32 - prefix));

            lpmEntries_[slot].push_back(
                {.net = hIp & mask, .mask = mask, .prefixlen = static_cast<uint32_t>(prefix), .action = action});

            // 按前缀长度降序排序，保证最长前缀优先匹配 (Longest Prefix Match)
            std::sort(lpmEntries_[slot].begin(), lpmEntries_[slot].end(),
                      [](const LpmEntry &a, const LpmEntry &b) { return a.prefixlen > b.prefixlen; });
            flowCache_.clear();
            connStateMap_.clear();

            // 若内核 BPF 处于激活态，同步注入内核对应槽位 LPM Map
#if defined(__linux__)
            if (kernelBpfActive_)
            {
                BpfLpmKeyIpv4 key{.prefixlen = static_cast<uint32_t>(prefix), .ip = netBe};
                uint32_t val = static_cast<uint32_t>(action);
                auto updateKernelMap = [&](int mapFd)
                {
                    if (mapFd < 0)
                        return;
#if defined(MYNET_HAVE_LIBBPF)
                    ::bpf_map_update_elem(mapFd, &key, &val, BPF_ANY);
#elif defined(__NR_bpf)
                    union bpf_attr attr{};
                    attr.map_fd = static_cast<uint32_t>(mapFd);
                    attr.key = reinterpret_cast<uint64_t>(&key);
                    attr.value = reinterpret_cast<uint64_t>(&val);
                    attr.flags = BPF_ANY;
                    ::syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
#endif
                };

                updateKernelMap(lpmMapFd_[slot]);
                if (!config_.enableDoubleEpoch && epochSlot < 0)
                {
                    updateKernelMap(lpmMapFd_[1 - slot]);
                }
            }
#endif
            if (!config_.enableDoubleEpoch && epochSlot < 0)
            {
                lpmEntries_[1 - slot] = lpmEntries_[slot];
            }
            return true;
        }

        bool addLpmCidrLocked(std::string_view cidrStr, Action action, int epochSlot = -1)
        {
            auto cidr = handler::IpCidr::parse(cidrStr);
            if (!cidr)
                return false;
            return addLpmCidrLocked(cidr->networkBe, cidr->prefix(), action, epochSlot);
        }

        /**
         * @brief 向 eBPF LPM Trie 注入一条 IPv6 CIDR 路由规则
         */
        bool addLpmCidrIpv6(std::string_view cidrStr, Action action, int epochSlot = -1)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return addLpmCidrIpv6Locked(cidrStr, action, epochSlot);
        }

        bool addLpmCidrIpv6Locked(std::string_view cidrStr, Action action, int epochSlot = -1)
        {
            auto cidr6 = handler::Ip6Cidr::parse(cidrStr);
            if (!cidr6)
                return false;

            const uint8_t curEpoch = activeEpoch_.load(std::memory_order_relaxed);
            const uint8_t slot = (epochSlot >= 0 && epochSlot <= 1) ? static_cast<uint8_t>(epochSlot) : curEpoch;

            LpmEntryIpv6 entry{};
            entry.prefixlen = static_cast<uint32_t>(cidr6->prefix);
            entry.action = action;

            for (int i = 0; i < 16; ++i)
            {
                int bits = static_cast<int>(cidr6->prefix) - (i * 8);
                if (bits >= 8)
                {
                    entry.mask[i] = 0xFF;
                }
                else if (bits > 0)
                {
                    entry.mask[i] = static_cast<uint8_t>(0xFF << (8 - bits));
                }
                else
                {
                    entry.mask[i] = 0;
                }
                entry.net[i] = cidr6->network.s6_addr[i] & entry.mask[i];
            }

            lpmEntriesIpv6_[slot].push_back(entry);
            std::sort(lpmEntriesIpv6_[slot].begin(), lpmEntriesIpv6_[slot].end(),
                      [](const LpmEntryIpv6 &a, const LpmEntryIpv6 &b) { return a.prefixlen > b.prefixlen; });
            flowCache_.clear();
            connStateMap_.clear();

#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
            if (kernelBpfActive_)
            {
                BpfLpmKeyIpv6 key6{};
                key6.prefixlen = static_cast<uint32_t>(cidr6->prefix);
                std::memcpy(key6.ip, entry.net, 16);
                uint32_t val = static_cast<uint32_t>(action);
                if (lpmMapIpv6Fd_[slot] >= 0)
                {
                    ::bpf_map_update_elem(lpmMapIpv6Fd_[slot], &key6, &val, BPF_ANY);
                }
                if (!config_.enableDoubleEpoch && epochSlot < 0 && lpmMapIpv6Fd_[1 - slot] >= 0)
                {
                    ::bpf_map_update_elem(lpmMapIpv6Fd_[1 - slot], &key6, &val, BPF_ANY);
                }
            }
#endif
            if (!config_.enableDoubleEpoch && epochSlot < 0)
            {
                lpmEntriesIpv6_[1 - slot] = lpmEntriesIpv6_[slot];
            }
            return true;
        }

        /**
         * @brief 添加直连 IP
         */
        void addDirectIp(in_addr ip)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            directIps_.insert(ip.s_addr);
            flowCache_.clear();
            connStateMap_.clear();

#if defined(__linux__)
            if (kernelBpfActive_ && directMapFd_ >= 0)
            {
                uint32_t key = ip.s_addr;
                uint8_t val = 1;
#if defined(MYNET_HAVE_LIBBPF)
                ::bpf_map_update_elem(directMapFd_, &key, &val, BPF_ANY);
#else
                union bpf_attr attr{};
                attr.map_fd = static_cast<uint32_t>(directMapFd_);
                attr.key = reinterpret_cast<uint64_t>(&key);
                attr.value = reinterpret_cast<uint64_t>(&val);
                attr.flags = BPF_ANY;
                ::syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
#endif
            }
#endif
        }

        /**
         * @brief 移除直连 IP
         */
        void removeDirectIp(in_addr ip)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            directIps_.erase(ip.s_addr);
            flowCache_.clear();
            connStateMap_.clear();

#if defined(__linux__)
            if (kernelBpfActive_ && directMapFd_ >= 0)
            {
                uint32_t key = ip.s_addr;
#if defined(MYNET_HAVE_LIBBPF)
                ::bpf_map_delete_elem(directMapFd_, &key);
#else
                union bpf_attr attr{};
                attr.map_fd = static_cast<uint32_t>(directMapFd_);
                attr.key = reinterpret_cast<uint64_t>(&key);
                ::syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
#endif
            }
#endif
        }

        /**
         * @brief 分流裁决数据包 (内核 TC 动作判定与用户态仿真双模统一)
         *
         * 1. 若为 QUIC 且 dropQuic 开启：直接丢弃 (BLOCK)；
         * 2. 检查直连 IP 哈希表：命中则 DIRECT 放行 (0 用户态切换)；
         * 3. 检查流缓存 (Flow Cache)：O(1) 微秒级快速复用；
         * 4. 检查 LPM Trie：最长前缀匹配网段规则；
         * 5. 默认 PROXY 重定向并打标。
         */
        /**
         * @brief 分流裁决数据包 (内核 TC 动作判定与用户态仿真双模统一)
         *
         * 1. 若为 QUIC 且 dropQuic 开启：直接丢弃 (BLOCK)；
         * 2. 检查 UDP 连接状态表 (conn_state_map)：命中则微秒级返程加速；
         * 3. 检查直连 IP 哈希表：命中则 DIRECT 放行 (0 用户态切换)；
         * 4. 检查流缓存 (Flow Cache)：O(1) 微秒级快速复用；
         * 5. 检查 LPM Trie (Double Epoch 当前活跃槽位)：最长前缀匹配网段规则；
         * 6. 默认 PROXY 重定向并打标。
         */
        Action classify(const PacketMetadata &pkt)
        {
            totalBytesEvaluated_.fetch_add(pkt.length, std::memory_order_relaxed);

            // 1. QUIC 阻断策略 (dae 核心特性：阻断 QUIC 以便强制 fallback 到 TCP 零拷贝链路)
            if (config_.dropQuic && pkt.protocol == IPPROTO_UDP && pkt.dstPort == 443)
            {
                blockedPackets_.fetch_add(1, std::memory_order_relaxed);
                return Action::BLOCK;
            }

            std::lock_guard<std::mutex> lock(mutex_);

            // 2. 检查 UDP 5元组连接状态表 (借鉴 dae conn_state_map)
            if (pkt.protocol == IPPROTO_UDP && !pkt.isIpv6)
            {
                TuplesKey udpKey{.saddr = pkt.srcIp.s_addr,
                                 .daddr = pkt.dstIp.s_addr,
                                 .sport = htons(pkt.srcPort),
                                 .dport = htons(pkt.dstPort),
                                 .proto = IPPROTO_UDP};
                if (auto it = connStateMap_.find(udpKey); it != connStateMap_.end())
                {
                    it->second.lastSeenNs = getMonotonicTimeNs();
                    it->second.packets++;
                    it->second.bytes += pkt.length;
                    Action act = static_cast<Action>(it->second.action);
                    if (act == Action::DIRECT)
                        directBypassedPackets_.fetch_add(1, std::memory_order_relaxed);
                    else if (act == Action::BLOCK)
                        blockedPackets_.fetch_add(1, std::memory_order_relaxed);
                    else
                        proxiedPackets_.fetch_add(1, std::memory_order_relaxed);
                    return act;
                }
            }

            const uint8_t epoch = activeEpoch_.load(std::memory_order_acquire);

            if (pkt.isIpv6)
            {
                for (const auto &entry : lpmEntriesIpv6_[epoch])
                {
                    if (entry.matches(pkt.dstIp6.s6_addr))
                    {
                        if (entry.action == Action::DIRECT)
                            directBypassedPackets_.fetch_add(1, std::memory_order_relaxed);
                        else if (entry.action == Action::BLOCK)
                            blockedPackets_.fetch_add(1, std::memory_order_relaxed);
                        else
                            proxiedPackets_.fetch_add(1, std::memory_order_relaxed);
                        return entry.action;
                    }
                }
                proxiedPackets_.fetch_add(1, std::memory_order_relaxed);
                return Action::PROXY;
            }

            // 3. 检查快速直连 IP 哈希表
            if (directIps_.contains(pkt.dstIp.s_addr))
            {
                directBypassedPackets_.fetch_add(1, std::memory_order_relaxed);
                if (pkt.protocol == IPPROTO_UDP)
                {
                    TuplesKey udpKey{.saddr = pkt.srcIp.s_addr,
                                     .daddr = pkt.dstIp.s_addr,
                                     .sport = htons(pkt.srcPort),
                                     .dport = htons(pkt.dstPort),
                                     .proto = IPPROTO_UDP};
                    connStateMap_[udpKey] = ConnStateEntry{.action = static_cast<uint32_t>(Action::DIRECT),
                                                           .fwmark = config_.fwmark,
                                                           .lastSeenNs = getMonotonicTimeNs(),
                                                           .packets = 1,
                                                           .bytes = pkt.length};
                }
                return Action::DIRECT;
            }

            // 4. 检查流缓存 (Flow Cache) 达到 O(1) 用户态快速命中
            const uint64_t flowKey =
                static_cast<uint64_t>(pkt.dstIp.s_addr) | (static_cast<uint64_t>(pkt.protocol) << 32);
            if (auto it = flowCache_.find(flowKey); it != flowCache_.end())
            {
                Action act = it->second;
                if (act == Action::DIRECT)
                    directBypassedPackets_.fetch_add(1, std::memory_order_relaxed);
                else if (act == Action::BLOCK)
                    blockedPackets_.fetch_add(1, std::memory_order_relaxed);
                else
                    proxiedPackets_.fetch_add(1, std::memory_order_relaxed);
                return act;
            }

            // 5. 检查最长前缀 LPM Trie (Double Epoch 活跃槽位)
            const uint32_t hIp = ntohl(pkt.dstIp.s_addr);
            for (const auto &entry : lpmEntries_[epoch])
            {
                if (entry.matches(hIp))
                {
                    if (entry.action == Action::DIRECT)
                    {
                        directBypassedPackets_.fetch_add(1, std::memory_order_relaxed);
                    }
                    else if (entry.action == Action::BLOCK)
                    {
                        blockedPackets_.fetch_add(1, std::memory_order_relaxed);
                    }
                    else
                    {
                        proxiedPackets_.fetch_add(1, std::memory_order_relaxed);
                    }
                    if (flowCache_.size() < 16384)
                    {
                        flowCache_.emplace(flowKey, entry.action);
                    }
                    if (pkt.protocol == IPPROTO_UDP)
                    {
                        TuplesKey udpKey{.saddr = pkt.srcIp.s_addr,
                                         .daddr = pkt.dstIp.s_addr,
                                         .sport = htons(pkt.srcPort),
                                         .dport = htons(pkt.dstPort),
                                         .proto = IPPROTO_UDP};
                        connStateMap_[udpKey] = ConnStateEntry{.action = static_cast<uint32_t>(entry.action),
                                                               .fwmark = config_.fwmark,
                                                               .lastSeenNs = getMonotonicTimeNs(),
                                                               .packets = 1,
                                                               .bytes = pkt.length};
                    }
                    return entry.action;
                }
            }

            // 6. 默认走代理打标
            proxiedPackets_.fetch_add(1, std::memory_order_relaxed);
            if (flowCache_.size() < 16384)
            {
                flowCache_.emplace(flowKey, Action::PROXY);
            }
            if (pkt.protocol == IPPROTO_UDP)
            {
                TuplesKey udpKey{.saddr = pkt.srcIp.s_addr,
                                 .daddr = pkt.dstIp.s_addr,
                                 .sport = htons(pkt.srcPort),
                                 .dport = htons(pkt.dstPort),
                                 .proto = IPPROTO_UDP};
                connStateMap_[udpKey] = ConnStateEntry{.action = static_cast<uint32_t>(Action::PROXY),
                                                       .fwmark = config_.fwmark,
                                                       .lastSeenNs = getMonotonicTimeNs(),
                                                       .packets = 1,
                                                       .bytes = pkt.length};
            }
            return Action::PROXY;
        }

        [[nodiscard]] Action classifyFast(const PacketMetadata &pkt) const noexcept
        {
            if (config_.dropQuic && pkt.protocol == IPPROTO_UDP && pkt.dstPort == 443)
            {
                return Action::BLOCK;
            }

            // 局域网组播 (224.0.0.0/4) 与广播/保留网段 (240.0.0.0/4 - 255.255.255.255) 绝对放行直连 (借鉴 dae
            // 224.0.0.0/3)
            if (!pkt.isIpv6 && (ntohl(pkt.dstIp.s_addr) & 0xE0000000) == 0xE0000000)
            {
                return Action::DIRECT;
            }
            if (pkt.isIpv6 && pkt.dstIp6.s6_addr[0] == 0xFF)
            {
                return Action::DIRECT;
            }

            std::lock_guard<std::mutex> lock(mutex_);
            if (!pkt.isIpv6)
            {
                TuplesKey key{.saddr = pkt.srcIp.s_addr,
                              .daddr = pkt.dstIp.s_addr,
                              .sport = htons(pkt.srcPort),
                              .dport = htons(pkt.dstPort),
                              .proto = pkt.protocol};
                if (auto it = connStateMap_.find(key); it != connStateMap_.end())
                {
                    return static_cast<Action>(it->second.action);
                }
            }

            const uint8_t epoch = activeEpoch_.load(std::memory_order_relaxed);
            if (pkt.isIpv6)
            {
                for (const auto &entry : lpmEntriesIpv6_[epoch])
                {
                    if (entry.matches(pkt.dstIp6.s6_addr))
                        return entry.action;
                }
                return Action::PROXY;
            }

            if (directIps_.contains(pkt.dstIp.s_addr))
                return Action::DIRECT;

            const uint64_t flowKey =
                static_cast<uint64_t>(pkt.dstIp.s_addr) | (static_cast<uint64_t>(pkt.protocol) << 32);
            if (auto it = flowCache_.find(flowKey); it != flowCache_.end())
                return it->second;

            const uint32_t hIp = ntohl(pkt.dstIp.s_addr);
            for (const auto &entry : lpmEntries_[epoch])
            {
                if (entry.matches(hIp))
                    return entry.action;
            }
            return Action::PROXY;
        }

        /**
         * @brief 同步 GeoIPMatcher 中的国家/私网网段至 eBPF LPM Trie (消除硬编码重复造轮子)
         */
        void syncGeoIp(const GeoIpMatcher &geoIp, std::string_view country = "cn", Action action = Action::DIRECT,
                       int epochSlot = -1)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            syncGeoIpLocked(geoIp, country, action, epochSlot);
        }

        void syncGeoIpLocked(const GeoIpMatcher &geoIp, std::string_view country = "cn", Action action = Action::DIRECT,
                             int epochSlot = -1)
        {
            // 同步私网网段与基础配置
            loadDefaultPrivateCidrs(epochSlot);

            // 直接通过 GeoIpMatcher 动态遍历，彻底消除重复造轮子与死代码硬编码
            geoIp.forEachCidr(country,
                              [this, action, epochSlot](uint32_t netHost, uint32_t mask)
                              {
                                  uint8_t prefix = static_cast<uint8_t>(__builtin_popcount(mask));
                                  addLpmCidrLocked(htonl(netHost), prefix, action, epochSlot);
                              });
        }

        /**
         * @brief 双 Epoch (Double Epoch) 零停机原子热重载路由表
         */
        template <typename PopulateFn>
        void reloadRoutingEpoch(PopulateFn &&populateFn)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            reloadRoutingEpochLocked(std::forward<PopulateFn>(populateFn));
        }

        template <typename PopulateFn>
        void reloadRoutingEpochLocked(PopulateFn &&populateFn)
        {
            const uint8_t curEpoch = activeEpoch_.load(std::memory_order_relaxed);
            const uint8_t nextSlot = 1 - curEpoch;

            lpmEntries_[nextSlot].clear();
            lpmEntriesIpv6_[nextSlot].clear();

            struct EpochAdderIpv4
            {
                EbpfEngine *engine;
                uint8_t slot;

                bool operator()(std::string_view cidrStr, Action action) const
                {
                    return engine->addLpmCidrLocked(cidrStr, action, slot);
                }

                bool operator()(uint32_t netBe, uint8_t prefix, Action action) const
                {
                    return engine->addLpmCidrLocked(netBe, prefix, action, slot);
                }
            } adderIpv4{this, nextSlot};

            auto adderIpv6 = [this, nextSlot](std::string_view cidrStr, Action action)
            { this->addLpmCidrIpv6Locked(cidrStr, action, nextSlot); };

            populateFn(adderIpv4, adderIpv6);

            activeEpoch_.store(nextSlot, std::memory_order_release);
            flowCache_.clear();

            if (kernelBpfActive_)
            {
                syncConfigToKernel();
            }

            LOG_INFO("eBPF: Atomically switched double epoch routing table: {} -> {}", curEpoch, nextSlot);
            lpmEntries_[curEpoch].clear();
            lpmEntriesIpv6_[curEpoch].clear();
        }

        /**
         * @brief 从统一路由中心 (Router) 同步规则至内核 eBPF LPM Trie / 防火墙
         */
        void syncFromRouter(const Router &router)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (config_.enableDoubleEpoch)
            {
                reloadRoutingEpochLocked(
                    [&](auto &&addIpv4, auto &&)
                    {
                        loadDefaultPrivateCidrs(1 - activeEpoch_.load(std::memory_order_relaxed));
                        for (const auto &rule : router.rulesSnapshot())
                        {
                            Action act = Action::PROXY;
                            if (rule.outboundTag == "direct")
                                act = Action::DIRECT;
                            else if (rule.outboundTag == "block")
                                act = Action::BLOCK;

                            if (act != Action::PROXY)
                            {
                                for (const auto &cidr : rule.ipCidrs)
                                {
                                    addIpv4(cidr.networkBe, cidr.prefixLen, act);
                                }
                                for (const auto &geo : rule.geoIps)
                                {
                                    GeoIpMatcher::instance().forEachCidr(geo,
                                                                         [&](uint32_t netHost, uint32_t mask)
                                                                         {
                                                                             uint8_t prefix = static_cast<uint8_t>(
                                                                                 __builtin_popcount(mask));
                                                                             addIpv4(htonl(netHost), prefix, act);
                                                                         });
                                }
                                if (act == Action::BLOCK && rule.network == NetworkType::UDP)
                                {
                                    for (const auto &pr : rule.portRanges)
                                    {
                                        if (pr.matches(443))
                                        {
                                            config_.dropQuic = true;
                                        }
                                    }
                                }
                            }
                        }
                    });
            }
            else
            {
                for (const auto &rule : router.rulesSnapshot())
                {
                    Action act = Action::PROXY;
                    if (rule.outboundTag == "direct")
                    {
                        act = Action::DIRECT;
                    }
                    else if (rule.outboundTag == "block")
                    {
                        act = Action::BLOCK;
                    }

                    if (act != Action::PROXY)
                    {
                        for (const auto &cidr : rule.ipCidrs)
                        {
                            addLpmCidrLocked(cidr.networkBe, cidr.prefixLen, act);
                        }
                        for (const auto &geo : rule.geoIps)
                        {
                            syncGeoIpLocked(GeoIpMatcher::instance(), geo, act);
                        }
                        if (act == Action::BLOCK && rule.network == NetworkType::UDP)
                        {
                            for (const auto &pr : rule.portRanges)
                            {
                                if (pr.matches(443))
                                {
                                    config_.dropQuic = true;
                                }
                            }
                        }
                    }
                }
                if (kernelBpfActive_)
                {
                    syncConfigToKernel();
                }
            }
        }

        // =====================================================================
        // 旁路由网关非对称 MAC 改写 (Asymmetric Gateway Routing)
        // =====================================================================
        struct AsymmetricRewriteResult
        {
            bool redirected{false};
            uint8_t dstMac[6]{0};
            uint8_t srcMac[6]{0};
            int wanIfIndex{0};
        };

        [[nodiscard]] AsymmetricRewriteResult evaluateAsymmetricGateway(const PacketMetadata &pkt) const noexcept
        {
            if (!config_.asymmetricGateway)
            {
                return AsymmetricRewriteResult{.redirected = false};
            }

            Action act = classifyFast(pkt);
            if (act != Action::DIRECT)
            {
                return AsymmetricRewriteResult{.redirected = false};
            }

            auto gMac = MacAddress::parse(config_.gatewayMac);
            auto wMac = MacAddress::parse(config_.wanMac);
            if (!gMac || !wMac)
            {
                return AsymmetricRewriteResult{.redirected = false};
            }

            AsymmetricRewriteResult res{};
            res.redirected = true;
            std::memcpy(res.dstMac, gMac->bytes, 6);
            std::memcpy(res.srcMac, wMac->bytes, 6);
            res.wanIfIndex = wanIfIndex_;
            return res;
        }

        // =====================================================================
        // UDP 内核连接状态表与保活回收器 (conn_state_map & conn_state_janitor)
        // =====================================================================
        bool trackUdpConnState(const TuplesKey &key, Action action, uint64_t lastSeenNs = 0) noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (lastSeenNs == 0)
            {
                lastSeenNs = getMonotonicTimeNs();
            }

            ConnStateEntry entry{.action = static_cast<uint32_t>(action),
                                 .fwmark = config_.fwmark,
                                 .lastSeenNs = lastSeenNs,
                                 .packets = 1,
                                 .bytes = 0};
            connStateMap_[key] = entry;

#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
            if (kernelBpfActive_ && connStateMapFd_ >= 0)
            {
                ::bpf_map_update_elem(connStateMapFd_, &key, &entry, BPF_ANY);
            }
#endif
            return true;
        }

        [[nodiscard]] std::optional<ConnStateEntry> getConnState(const TuplesKey &key) const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
            if (kernelBpfActive_ && connStateMapFd_ >= 0)
            {
                ConnStateEntry val{};
                if (::bpf_map_lookup_elem(connStateMapFd_, &key, &val) == 0)
                {
                    return val;
                }
            }
#endif
            if (auto it = connStateMap_.find(key); it != connStateMap_.end())
            {
                return it->second;
            }
            return std::nullopt;
        }

        [[nodiscard]] size_t connStateCount() const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return connStateMap_.size();
        }

        /**
         * @brief 弹性批量 BPF Map 删除 (借鉴 dae bpf_map_delete_batch_resilient)
         *
         * 针对 Linux eBPF bpf_map_delete_batch 在遇到 ENOENT (条目已被其它流程删除) 时提前截断中断的问题：
         * 自动跳过引发 ENOENT 的缺失键，并以剩余后缀子切片继续批量删除，防止过期连接与流状态残留泄漏。
         */
        template <typename Key>
        static size_t deleteBatchResilient(int mapFd, std::span<const Key> keys) noexcept
        {
            if (mapFd < 0 || keys.empty())
                return 0;
            size_t totalDeleted = 0;
#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
            size_t offset = 0;
            while (offset < keys.size())
            {
                uint32_t batchCount = static_cast<uint32_t>(keys.size() - offset);
                const Key *batchKeys = keys.data() + offset;
                struct bpf_map_batch_opts opts{};
                opts.sz = sizeof(opts);
                int ret = ::bpf_map_delete_batch(mapFd, batchKeys, &batchCount, &opts);
                totalDeleted += batchCount;
                if (ret == 0)
                {
                    break;
                }
                if (errno == ENOENT)
                {
                    // 跳过缺失条目，继续删除后续批次
                    offset += (batchCount + 1);
                }
                else
                {
                    // 内核不支持批量删除或遇到其它错误，退回逐个删除
                    for (size_t i = offset + batchCount; i < keys.size(); ++i)
                    {
                        if (::bpf_map_delete_elem(mapFd, &keys[i]) == 0)
                        {
                            ++totalDeleted;
                        }
                    }
                    break;
                }
            }
#endif
            return totalDeleted;
        }

        /**
         * @brief 用户态弹性批量删除模拟（供单元测试与容器环境使用）
         */
        template <typename Map, typename Key>
        static size_t deleteBatchResilientMock(Map &m, std::span<const Key> keys) noexcept
        {
            size_t count = 0;
            for (const auto &k : keys)
            {
                if (m.erase(k) > 0)
                {
                    ++count;
                }
            }
            return count;
        }

        size_t sweepConnState(uint64_t maxAgeNs = 60ULL * 1000 * 1000 * 1000) noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            size_t swept = 0;
            const uint64_t nowNs = getMonotonicTimeNs();
            constexpr uint64_t kMaxFutureSkewNs = 30ULL * 1000 * 1000 * 1000; // 30s NTP/Clock skew

#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
            if (kernelBpfActive_ && connStateMapFd_ >= 0)
            {
                TuplesKey key{};
                TuplesKey nextKey{};
                std::vector<TuplesKey> toDelete;

                while (::bpf_map_get_next_key(connStateMapFd_, &key, &nextKey) == 0)
                {
                    ConnStateEntry val{};
                    if (::bpf_map_lookup_elem(connStateMapFd_, &nextKey, &val) == 0)
                    {
                        bool isExpired = false;
                        if (nowNs >= val.lastSeenNs)
                        {
                            isExpired = (nowNs - val.lastSeenNs) > maxAgeNs;
                        }
                        else if ((val.lastSeenNs - nowNs) > kMaxFutureSkewNs)
                        {
                            // 未来时钟漂移异常，防止死锁驻留
                            isExpired = true;
                        }

                        if (isExpired)
                        {
                            toDelete.push_back(nextKey);
                        }
                    }
                    key = nextKey;
                }
                swept += deleteBatchResilient(connStateMapFd_, std::span<const TuplesKey>(toDelete));
            }
#endif
            for (auto it = connStateMap_.begin(); it != connStateMap_.end();)
            {
                bool isExpired = false;
                if (nowNs >= it->second.lastSeenNs)
                {
                    isExpired = (nowNs - it->second.lastSeenNs) > maxAgeNs;
                }
                else if ((it->second.lastSeenNs - nowNs) > kMaxFutureSkewNs)
                {
                    // 未来时钟漂移容错 (借鉴 dae clock skew tolerance)
                    isExpired = true;
                }

                if (isExpired)
                {
                    it = connStateMap_.erase(it);
                    ++swept;
                }
                else
                {
                    ++it;
                }
            }
            return swept;
        }

        [[nodiscard]] EbpfStats getStats() const noexcept
        {
            return EbpfStats{.directBypassedPackets = directBypassedPackets_.load(std::memory_order_relaxed),
                             .proxiedPackets = proxiedPackets_.load(std::memory_order_relaxed),
                             .blockedPackets = blockedPackets_.load(std::memory_order_relaxed),
                             .totalBytesEvaluated = totalBytesEvaluated_.load(std::memory_order_relaxed)};
        }

        // =====================================================================
        // cgroupv2 实时进程名感知 (无连接 UDP sendmsg4/6 与 SO_COOKIE 快速提取)
        // =====================================================================

        void recordProcessSocket(uint64_t cookie, uint32_t pid, std::string_view name) noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            socketProcessMap_[cookie] = ProcessInfo{.pid = pid, .name = std::string(name)};
#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
            if (kernelBpfActive_ && cookieMapFd_ >= 0)
            {
                PidPname val{};
                val.pid = pid;
                val.last_seen_ns = getMonotonicTimeNs();
                std::strncpy(val.pname, name.data(), sizeof(val.pname) - 1);
                ::bpf_map_update_elem(cookieMapFd_, &cookie, &val, BPF_ANY);
            }
#endif
        }

        [[nodiscard]] std::optional<ProcessInfo> getProcessByCookie(uint64_t cookie) const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
            if (kernelBpfActive_ && cookieMapFd_ >= 0)
            {
                PidPname val{};
                if (::bpf_map_lookup_elem(cookieMapFd_, &cookie, &val) == 0)
                {
                    val.pname[15] = '\0';
                    return ProcessInfo{.pid = val.pid, .name = std::string(val.pname)};
                }
            }
#endif
            if (auto it = socketProcessMap_.find(cookie); it != socketProcessMap_.end())
            {
                return it->second;
            }
            return std::nullopt;
        }

        /**
         * @brief 通过套接字描述符提取发起进程特征 (微秒级免 /proc 扫描)
         */
        [[nodiscard]] std::optional<ProcessInfo> getProcessBySocket(int socketFd) const noexcept
        {
            if (socketFd < 0)
                return std::nullopt;
#if defined(__linux__)
            uint64_t cookie = 0;
            socklen_t len = sizeof(cookie);
            if (::getsockopt(socketFd, SOL_SOCKET, SO_COOKIE, &cookie, &len) == 0 && cookie != 0)
            {
                return getProcessByCookie(cookie);
            }
#endif
            return std::nullopt;
        }

        // =====================================================================
        // 免 iptables 套接字直接绑定 (bpf_sk_assign) 与虚拟接口隔离分流
        // =====================================================================

        bool setListeningSockets(int tcp4Fd, int udpFd, int tcp6Fd = -1) noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            listenSockets_[0] = tcp4Fd;
            listenSockets_[1] = udpFd;
            listenSockets_[2] = tcp6Fd;

#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
            if (kernelBpfActive_ && listenSockMapFd_ >= 0)
            {
                uint32_t k0 = 0, k1 = 1, k2 = 2;
                uint64_t v0 = static_cast<uint64_t>(tcp4Fd);
                uint64_t v1 = static_cast<uint64_t>(udpFd);
                if (tcp4Fd >= 0)
                    ::bpf_map_update_elem(listenSockMapFd_, &k0, &v0, BPF_ANY);
                if (udpFd >= 0)
                    ::bpf_map_update_elem(listenSockMapFd_, &k1, &v1, BPF_ANY);
                if (tcp6Fd >= 0)
                {
                    uint64_t v2 = static_cast<uint64_t>(tcp6Fd);
                    ::bpf_map_update_elem(listenSockMapFd_, &k2, &v2, BPF_ANY);
                }
            }
#endif
            return true;
        }

        [[nodiscard]] int getAssignedSocket(uint8_t protocol, bool isIpv6 = false) const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!config_.enableSkAssign)
                return -1;
            if (protocol == IPPROTO_TCP)
            {
                return isIpv6 ? listenSockets_[2] : listenSockets_[0];
            }
            return listenSockets_[1];
        }

        struct ProxyDispatchResult
        {
            enum class Mode
            {
                FWMARK,
                SK_ASSIGN,
                REDIRECT
            };
            Mode mode{Mode::FWMARK};
            int assignedFd{-1};
            int redirectIfIndex{0};
            uint32_t fwmark{0};
        };

        [[nodiscard]] ProxyDispatchResult evaluateProxyDispatch(const PacketMetadata &pkt) const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            ProxyDispatchResult res{};
            res.fwmark = config_.fwmark;

            if (config_.enableSkAssign)
            {
                int fd = -1;
                if (pkt.protocol == IPPROTO_TCP)
                {
                    fd = pkt.isIpv6 ? listenSockets_[2] : listenSockets_[0];
                }
                else
                {
                    fd = listenSockets_[1];
                }
                if (fd >= 0)
                {
                    res.mode = ProxyDispatchResult::Mode::SK_ASSIGN;
                    res.assignedFd = fd;
                    return res;
                }
            }

            if (virtualIfIndex_ > 0)
            {
                res.mode = ProxyDispatchResult::Mode::REDIRECT;
                res.redirectIfIndex = virtualIfIndex_;
                return res;
            }

            res.mode = ProxyDispatchResult::Mode::FWMARK;
            return res;
        }

        // =====================================================================
        // 内核自适应限速与黑洞表 (alive_block_rate_map / Token Bucket)
        // =====================================================================

        bool isBlockRateLimited(uint32_t key = 0, uint16_t windowMs = 1000) noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            const uint64_t now = getMonotonicTimeNs();
            const uint64_t windowNs = static_cast<uint64_t>(windowMs > 0 ? windowMs : 1000) * 1000000ULL;

#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
            if (kernelBpfActive_ && blockRateMapFd_ >= 0)
            {
                uint64_t last = 0;
                if (::bpf_map_lookup_elem(blockRateMapFd_, &key, &last) == 0)
                {
                    if (now > last && (now - last) < windowNs)
                    {
                        return true;
                    }
                }
                ::bpf_map_update_elem(blockRateMapFd_, &key, &now, BPF_ANY);
                return false;
            }
#endif
            auto it = blockRateMap_.find(key);
            if (it != blockRateMap_.end())
            {
                if (now > it->second && (now - it->second) < windowNs)
                {
                    return true;
                }
            }
            blockRateMap_[key] = now;
            return false;
        }

        // =====================================================================
        // SockMap / SOCKHASH 内核套接字流卸载驱动
        // =====================================================================

        [[nodiscard]] static bool isSockmapSupported() noexcept
        {
#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
            return true;
#elif defined(__linux__) && defined(__NR_bpf)
            union bpf_attr attr{};
            attr.map_type = BPF_MAP_TYPE_SOCKMAP;
            attr.key_size = sizeof(uint32_t);
            attr.value_size = sizeof(uint32_t);
            attr.max_entries = 1;

            long mapFd = ::syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
            if (mapFd >= 0)
            {
                ::close(static_cast<int>(mapFd));
                return true;
            }
            return false;
#else
            return false;
#endif
        }

        [[nodiscard]] static bool isSupported() noexcept { return isSockmapSupported(); }

        /**
         * @brief 真正的 5元组 (TuplesKey) 套接字对绑定 (注入 fast_sock SOCKHASH)
         */
        static bool attachPair(int mapFd, int clientFd, int upstreamFd) noexcept
        {
            if (mapFd < 0 || clientFd < 0 || upstreamFd < 0)
            {
                return false;
            }

            sockaddr_in cLocal{}, cRemote{}, uLocal{}, uRemote{};
            socklen_t l1 = sizeof(cLocal), l2 = sizeof(cRemote);
            if (::getsockname(clientFd, reinterpret_cast<sockaddr *>(&cLocal), &l1) < 0 ||
                ::getpeername(clientFd, reinterpret_cast<sockaddr *>(&cRemote), &l2) < 0)
            {
                return false;
            }

            socklen_t l3 = sizeof(uLocal), l4 = sizeof(uRemote);
            if (::getsockname(upstreamFd, reinterpret_cast<sockaddr *>(&uLocal), &l3) < 0 ||
                ::getpeername(upstreamFd, reinterpret_cast<sockaddr *>(&uRemote), &l4) < 0)
            {
                return false;
            }

            if (cLocal.sin_family != AF_INET || uLocal.sin_family != AF_INET)
            {
                return false;
            }

            TuplesKey fwdKey{.saddr = cRemote.sin_addr.s_addr,
                             .daddr = cLocal.sin_addr.s_addr,
                             .sport = cRemote.sin_port,
                             .dport = cLocal.sin_port,
                             .proto = IPPROTO_TCP,
                             .pad = {0, 0, 0}};

            TuplesKey revKey{.saddr = uRemote.sin_addr.s_addr,
                             .daddr = uLocal.sin_addr.s_addr,
                             .sport = uRemote.sin_port,
                             .dport = uLocal.sin_port,
                             .proto = IPPROTO_TCP,
                             .pad = {0, 0, 0}};

            uint64_t uVal = static_cast<uint64_t>(upstreamFd);
            uint64_t cVal = static_cast<uint64_t>(clientFd);

#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
            if (::bpf_map_update_elem(mapFd, &fwdKey, &uVal, BPF_ANY) != 0)
            {
                return false;
            }
            if (::bpf_map_update_elem(mapFd, &revKey, &cVal, BPF_ANY) != 0)
            {
                ::bpf_map_delete_elem(mapFd, &fwdKey);
                return false;
            }
            return true;
#else
            (void)uVal;
            (void)cVal;
            return false;
#endif
        }

        bool attachPair(int clientFd, int upstreamFd) noexcept { return attachPair(sockMapFd_, clientFd, upstreamFd); }

        static bool detachPair(int mapFd, int clientFd, int upstreamFd = -1) noexcept
        {
            if (mapFd < 0 || clientFd < 0)
                return false;

            sockaddr_in cLocal{}, cRemote{};
            socklen_t l1 = sizeof(cLocal), l2 = sizeof(cRemote);
            if (::getsockname(clientFd, reinterpret_cast<sockaddr *>(&cLocal), &l1) == 0 &&
                ::getpeername(clientFd, reinterpret_cast<sockaddr *>(&cRemote), &l2) == 0 &&
                cLocal.sin_family == AF_INET)
            {
                TuplesKey fwdKey{.saddr = cRemote.sin_addr.s_addr,
                                 .daddr = cLocal.sin_addr.s_addr,
                                 .sport = cRemote.sin_port,
                                 .dport = cLocal.sin_port,
                                 .proto = IPPROTO_TCP,
                                 .pad = {0, 0, 0}};
#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
                ::bpf_map_delete_elem(mapFd, &fwdKey);
#endif
            }

            if (upstreamFd >= 0)
            {
                sockaddr_in uLocal{}, uRemote{};
                socklen_t l3 = sizeof(uLocal), l4 = sizeof(uRemote);
                if (::getsockname(upstreamFd, reinterpret_cast<sockaddr *>(&uLocal), &l3) == 0 &&
                    ::getpeername(upstreamFd, reinterpret_cast<sockaddr *>(&uRemote), &l4) == 0 &&
                    uLocal.sin_family == AF_INET)
                {
                    TuplesKey revKey{.saddr = uRemote.sin_addr.s_addr,
                                     .daddr = uLocal.sin_addr.s_addr,
                                     .sport = uRemote.sin_port,
                                     .dport = uLocal.sin_port,
                                     .proto = IPPROTO_TCP,
                                     .pad = {0, 0, 0}};
#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
                    ::bpf_map_delete_elem(mapFd, &revKey);
#endif
                }
            }
            return true;
        }

        bool detachStream(int clientFd, int upstreamFd = -1) noexcept
        {
            return detachPair(sockMapFd_, clientFd, upstreamFd);
        }

        /**
         * @brief 智能流卸载策略驱动：优先尝试 eBPF Sockmap 卸载，失败或未配置时回退至 splice
         */
        static bool enableOffloadOrSplice(HandlerConnection &handler, int clientFd, int upstreamFd,
                                          int sockmapFd = -1) noexcept
        {
            if (clientFd < 0 || upstreamFd < 0)
            {
                return false;
            }

            if (sockmapFd >= 0)
            {
                if (attachPair(sockmapFd, clientFd, upstreamFd))
                {
                    LOG_INFO("EbpfManager: eBPF sockmap offload attached between fd {} and {}", clientFd, upstreamFd);
                    return true;
                }
                LOG_WARN("EbpfManager: sockmap attach failed, falling back to splice(2)");
            }

            handler.setSpliceTarget(upstreamFd);
            return handler.isSpliceActive();
        }

        // =====================================================================
        // Sockmap 内核背压熔断保险丝 (tcp_offload_pause) (借鉴 dae)
        // =====================================================================

        bool setOffloadPause(const TuplesKey &key, bool paused) noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (paused)
            {
                pausedOffloads_.insert(key);
#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
                if (kernelBpfActive_ && tcpOffloadPauseMapFd_ >= 0)
                {
                    uint8_t val = 1;
                    ::bpf_map_update_elem(tcpOffloadPauseMapFd_, &key, &val, BPF_ANY);
                }
#endif
            }
            else
            {
                pausedOffloads_.erase(key);
#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
                if (kernelBpfActive_ && tcpOffloadPauseMapFd_ >= 0)
                {
                    ::bpf_map_delete_elem(tcpOffloadPauseMapFd_, &key);
                }
#endif
            }
            return true;
        }

        [[nodiscard]] bool isOffloadPaused(const TuplesKey &key) const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
            if (kernelBpfActive_ && tcpOffloadPauseMapFd_ >= 0)
            {
                uint8_t val = 0;
                if (::bpf_map_lookup_elem(tcpOffloadPauseMapFd_, &key, &val) == 0)
                {
                    return true;
                }
            }
#endif
            return pausedOffloads_.contains(key);
        }

        // =====================================================================
        // 内核态出站节点健康与连通性感知表 (outbound_connectivity_map) (借鉴 dae)
        // =====================================================================

        bool setOutboundConnectivity(uint32_t outboundId, uint32_t domain, uint32_t ipversion, bool alive) noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            uint32_t key = (outboundId * 6) + (domain * 2) + ipversion;
            outboundConnectivity_[key] = alive;

#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
            if (kernelBpfActive_ && outboundConnectivityMapFd_ >= 0)
            {
                uint32_t val = alive ? 1 : 0;
                ::bpf_map_update_elem(outboundConnectivityMapFd_, &key, &val, BPF_ANY);
            }
#endif
            return true;
        }

        [[nodiscard]] bool isOutboundAlive(uint32_t outboundId, uint32_t domain, uint32_t ipversion) const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            uint32_t key = (outboundId * 6) + (domain * 2) + ipversion;
#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
            if (kernelBpfActive_ && outboundConnectivityMapFd_ >= 0)
            {
                uint32_t val = 0;
                if (::bpf_map_lookup_elem(outboundConnectivityMapFd_, &key, &val) == 0)
                {
                    return val != 0;
                }
            }
#endif
            auto it = outboundConnectivity_.find(key);
            if (it != outboundConnectivity_.end())
            {
                return it->second;
            }
            return true; // 默认健康
        }

        struct DirectStats
        {
            uint64_t bytes{0};
            uint64_t packets{0};
        };

        [[nodiscard]] DirectStats getDirectStats() const noexcept
        {
            DirectStats total{};
            total.packets = directBypassedPackets_.load(std::memory_order_relaxed);
#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
            if (directStatsMapFd_ >= 0)
            {
                uint32_t key = 0;
                int ncpus = ::libbpf_num_possible_cpus();
                if (ncpus > 0)
                {
                    std::vector<DirectStats> perCpu(static_cast<size_t>(ncpus));
                    if (::bpf_map_lookup_elem(directStatsMapFd_, &key, perCpu.data()) == 0)
                    {
                        for (const auto &s : perCpu)
                        {
                            total.bytes += s.bytes;
                            total.packets += s.packets;
                        }
                    }
                }
            }
#endif
            return total;
        }

        /**
         * @brief 生成完整的 dae-style Linux eBPF 内核 C 源码
         */
        [[nodiscard]] static std::string generateBpfSource()
        {
            return R"(// SPDX-License-Identifier: GPL-2.0-only
/* dae-style high-performance transparent proxy eBPF kernel driver for mynet */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ACTION_DIRECT 0
#define ACTION_PROXY  1
#define ACTION_BLOCK  2

#define TASK_COMM_LEN 16

struct tuples_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  proto;
    __u8  pad[3];
};

struct bpf_lpm_key_ipv4 {
    __u32 prefixlen;
    __u32 ip;
};

struct bpf_lpm_key_ipv6 {
    __u32 prefixlen;
    __u8  ip[16];
};

struct pid_pname {
    __u32 pid;
    char  pname[TASK_COMM_LEN];
    __u64 last_seen_ns;
};

struct mynet_bpf_config {
    __u16 tproxy_port;
    __u16 pad;
    __u32 fwmark;
    __u8  direct_bypass;
    __u8  drop_quic;
    __u16 wan_ifindex;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct bpf_lpm_key_ipv4);
    __type(value, __u32);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} mynet_lpm_trie_ipv4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct bpf_lpm_key_ipv6);
    __type(value, __u32);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} mynet_lpm_trie_ipv6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 16384);
} mynet_direct_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct mynet_bpf_config);
    __uint(max_entries, 1);
} mynet_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __type(key, struct tuples_key);
    __type(value, __u64);
    __uint(max_entries, 65536);
} mynet_fast_sock SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct pid_pname);
    __uint(max_entries, 65536);
} mynet_cookie_pid_map SEC(".maps");

SEC("tc")
int mynet_tc_filter(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    __u32 key_idx = 0;
    struct mynet_bpf_config *cfg = bpf_map_lookup_elem(&mynet_config, &key_idx);
    if (!cfg)
        return TC_ACT_OK;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return TC_ACT_OK;

        if (cfg->drop_quic && ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)ip + (ip->ihl * 4);
            if ((void *)(udp + 1) <= data_end && udp->dest == bpf_htons(443)) {
                return TC_ACT_SHOT;
            }
        }

        __u32 dst_ip = ip->daddr;
        __u8 *direct = bpf_map_lookup_elem(&mynet_direct_ips, &dst_ip);
        if (direct && cfg->direct_bypass) {
            return TC_ACT_OK;
        }

        struct bpf_lpm_key_ipv4 lpm_key = {
            .prefixlen = 32,
            .ip = dst_ip
        };
        __u32 *action = bpf_map_lookup_elem(&mynet_lpm_trie_ipv4, &lpm_key);
        if (action) {
            if (*action == ACTION_DIRECT)
                return TC_ACT_OK;
            if (*action == ACTION_BLOCK)
                return TC_ACT_SHOT;
        }

        skb->mark = cfg->fwmark;
        return TC_ACT_OK;
    }
    return TC_ACT_OK;
}

SEC("sk_skb/stream_verdict")
int mynet_sockmap_verdict(struct __sk_buff *skb)
{
    struct tuples_key peer_key = {};
    peer_key.proto = IPPROTO_TCP;
    peer_key.sport = (__u16)(skb->remote_port >> 16);
    peer_key.dport = bpf_htons((__u16)skb->local_port);
    peer_key.saddr = skb->remote_ip4;
    peer_key.daddr = skb->local_ip4;

    bpf_sk_redirect_hash(skb, &mynet_fast_sock, &peer_key, 0);
    return SK_PASS;
}

static __always_inline void update_cookie_process(__u64 cookie)
{
    if (!cookie) return;
    struct pid_pname val = { 0 };
    val.pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    val.last_seen_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&val.pname, sizeof(val.pname));
    bpf_map_update_elem(&mynet_cookie_pid_map, &cookie, &val, BPF_ANY);
}

SEC("cgroup/connect4")
int mynet_cg_connect4(struct bpf_sock_addr *ctx)
{
    update_cookie_process(bpf_get_socket_cookie(ctx));
    return 1;
}

SEC("cgroup/connect6")
int mynet_cg_connect6(struct bpf_sock_addr *ctx)
{
    update_cookie_process(bpf_get_socket_cookie(ctx));
    return 1;
}

SEC("cgroup/sock_create")
int mynet_cg_sock_create(struct bpf_sock *sk)
{
    update_cookie_process(bpf_get_socket_cookie(sk));
    return 1;
}

SEC("cgroup/sock_release")
int mynet_cg_sock_release(struct bpf_sock *sk)
{
    __u64 cookie = bpf_get_socket_cookie(sk);
    if (cookie) {
        bpf_map_delete_elem(&mynet_cookie_pid_map, &cookie);
    }
    return 1;
}

char _license[] SEC("license") = "GPL";
)";
        }

    public:
        // =====================================================================
        // BPF 文件系统 Map 钉住与持久化恢复 (BPF FS Pinning & Reuse)
        // =====================================================================
        static bool ensureBpffsDir(const std::string &path) noexcept
        {
            struct stat st{};
            if (::stat(path.c_str(), &st) == 0)
            {
                return S_ISDIR(st.st_mode);
            }
            std::string sub;
            for (size_t i = 1; i < path.size(); ++i)
            {
                if (path[i] == '/')
                {
                    sub = path.substr(0, i);
                    ::mkdir(sub.c_str(), 0755);
                }
            }
            return ::mkdir(path.c_str(), 0755) == 0;
        }

#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
        static void reusePinnedMapIfExists(struct bpf_object *obj, const char *mapName,
                                           const std::string &bpffsDir) noexcept
        {
            std::string pinPath = bpffsDir + "/" + mapName;
            int pinnedFd = ::bpf_obj_get(pinPath.c_str());
            if (pinnedFd >= 0)
            {
                auto *map = ::bpf_object__find_map_by_name(obj, mapName);
                if (map)
                {
                    if (::bpf_map__reuse_fd(map, pinnedFd) == 0)
                    {
                        LOG_INFO("eBPF: Successfully reused pinned persistent map '{}' from {}", mapName, pinPath);
                    }
                }
                ::close(pinnedFd);
            }
        }

        static void pinMapIfNotPinned(struct bpf_object *obj, const char *mapName, const std::string &bpffsDir) noexcept
        {
            auto *map = ::bpf_object__find_map_by_name(obj, mapName);
            if (!map)
                return;
            if (::bpf_map__is_pinned(map))
                return;

            std::string pinPath = bpffsDir + "/" + mapName;
            int err = ::bpf_map__pin(map, pinPath.c_str());
            if (err == 0)
            {
                LOG_INFO("eBPF: Pinned persistent map '{}' to {}", mapName, pinPath);
            }
            else
            {
                LOG_WARN("eBPF: Failed to pin map '{}' to {} (errno: {})", mapName, pinPath, errno);
            }
        }
#endif

        static void unpinAllMaps(const std::string &bpffsDir) noexcept
        {
            const char *maps[] = {"mynet_fast_sock",         "mynet_conn_state_map",       "mynet_cookie_pid_map",
                                  "mynet_direct_stats",      "mynet_listen_sock_map",      "mynet_block_rate_map",
                                  "mynet_tcp_offload_pause", "mynet_outbound_connectivity"};
            for (const char *m : maps)
            {
                std::string pinPath = bpffsDir + "/" + m;
                ::unlink(pinPath.c_str());
            }
            ::rmdir(bpffsDir.c_str());
        }

    private:
        void cleanup() noexcept
        {
#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
            if (tcLink_)
            {
                ::bpf_link__destroy(tcLink_);
                tcLink_ = nullptr;
            }
            if (tcHookClassic_)
            {
                ::bpf_tc_hook_destroy(&tcHook_);
                tcHookClassic_ = false;
            }
            if (cgConn4Link_)
            {
                ::bpf_link__destroy(cgConn4Link_);
                cgConn4Link_ = nullptr;
            }
            if (cgConn6Link_)
            {
                ::bpf_link__destroy(cgConn6Link_);
                cgConn6Link_ = nullptr;
            }
            if (cgSend4Link_)
            {
                ::bpf_link__destroy(cgSend4Link_);
                cgSend4Link_ = nullptr;
            }
            if (cgSend6Link_)
            {
                ::bpf_link__destroy(cgSend6Link_);
                cgSend6Link_ = nullptr;
            }
            if (cgCreateLink_)
            {
                ::bpf_link__destroy(cgCreateLink_);
                cgCreateLink_ = nullptr;
            }
            if (cgReleaseLink_)
            {
                ::bpf_link__destroy(cgReleaseLink_);
                cgReleaseLink_ = nullptr;
            }
            if (cgroupFd_ >= 0)
            {
                ::close(cgroupFd_);
                cgroupFd_ = -1;
            }
            if (bpfObj_)
            {
                ::bpf_object__close(bpfObj_);
                bpfObj_ = nullptr;
            }
#endif
            if (lpmMapFd_[0] >= 0)
            {
                ::close(lpmMapFd_[0]);
                lpmMapFd_[0] = -1;
            }
            if (lpmMapFd_[1] >= 0)
            {
                ::close(lpmMapFd_[1]);
                lpmMapFd_[1] = -1;
            }
            if (lpmMapIpv6Fd_[0] >= 0)
            {
                ::close(lpmMapIpv6Fd_[0]);
                lpmMapIpv6Fd_[0] = -1;
            }
            if (lpmMapIpv6Fd_[1] >= 0)
            {
                ::close(lpmMapIpv6Fd_[1]);
                lpmMapIpv6Fd_[1] = -1;
            }
            if (directMapFd_ >= 0)
            {
                ::close(directMapFd_);
                directMapFd_ = -1;
            }
            if (directStatsMapFd_ >= 0)
            {
                ::close(directStatsMapFd_);
                directStatsMapFd_ = -1;
            }
            if (configMapFd_ >= 0)
            {
                ::close(configMapFd_);
                configMapFd_ = -1;
            }
            if (sockMapFd_ >= 0)
            {
                ::close(sockMapFd_);
                sockMapFd_ = -1;
            }
            if (cookieMapFd_ >= 0)
            {
                ::close(cookieMapFd_);
                cookieMapFd_ = -1;
            }
            if (connStateMapFd_ >= 0)
            {
                ::close(connStateMapFd_);
                connStateMapFd_ = -1;
            }
            if (listenSockMapFd_ >= 0)
            {
                ::close(listenSockMapFd_);
                listenSockMapFd_ = -1;
            }
            if (blockRateMapFd_ >= 0)
            {
                ::close(blockRateMapFd_);
                blockRateMapFd_ = -1;
            }
            if (tcpOffloadPauseMapFd_ >= 0)
            {
                ::close(tcpOffloadPauseMapFd_);
                tcpOffloadPauseMapFd_ = -1;
            }
            if (outboundConnectivityMapFd_ >= 0)
            {
                ::close(outboundConnectivityMapFd_);
                outboundConnectivityMapFd_ = -1;
            }
            if (eventRingbufFd_ >= 0)
            {
                ::close(eventRingbufFd_);
                eventRingbufFd_ = -1;
            }
            if (bpfStatsMapFd_ >= 0)
            {
                ::close(bpfStatsMapFd_);
                bpfStatsMapFd_ = -1;
            }
            if (domainRoutingMapFd_ >= 0)
            {
                ::close(domainRoutingMapFd_);
                domainRoutingMapFd_ = -1;
            }
            if (routingHandoffMapFd_ >= 0)
            {
                ::close(routingHandoffMapFd_);
                routingHandoffMapFd_ = -1;
            }
            if (redirectTrackMapFd_ >= 0)
            {
                ::close(redirectTrackMapFd_);
                redirectTrackMapFd_ = -1;
            }

            listenSockets_[0] = -1;
            listenSockets_[1] = -1;
            listenSockets_[2] = -1;
            socketProcessMap_.clear();
            blockRateMap_.clear();
            pausedOffloads_.clear();
            outboundConnectivity_.clear();
            domainRoutingMap_.clear();
            routingHandoffMap_.clear();
            redirectTrackMap_.clear();
            virtualIfIndex_ = 0;

            lpmEntries_[0].clear();
            lpmEntries_[1].clear();
            lpmEntriesIpv6_[0].clear();
            lpmEntriesIpv6_[1].clear();
            directIps_.clear();
            flowCache_.clear();
            connStateMap_.clear();
            activeEpoch_.store(0, std::memory_order_relaxed);
            kernelBpfActive_ = false;
            tcFilterAttached_ = false;
            verdictAttached_ = false;
            cgroupAttached_ = false;
            wanIfIndex_ = 0;
        }

        bool tryLoadKernelBpf()
        {
#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
            struct bpf_object_open_opts openOpts{};
            openOpts.sz = sizeof(openOpts);

            struct bpf_object *obj = nullptr;
            if (!config_.bpfObjectPath.empty() && ::access(config_.bpfObjectPath.c_str(), R_OK) == 0)
            {
                obj = ::bpf_object__open_file(config_.bpfObjectPath.c_str(), &openOpts);
            }
            else
            {
                obj = ::bpf_object__open_mem(kMynetBpfBytecode, kMynetBpfBytecodeSize, &openOpts);
            }

            if (!obj)
            {
                return false;
            }

            // Map Pinning 恢复 (在 bpf_object__load 之前复用已钉住的 Map)
            if (config_.enableMapPinning && !config_.bpffsDir.empty())
            {
                ensureBpffsDir(config_.bpffsDir);
                reusePinnedMapIfExists(obj, "mynet_fast_sock", config_.bpffsDir);
                reusePinnedMapIfExists(obj, "mynet_conn_state_map", config_.bpffsDir);
                reusePinnedMapIfExists(obj, "mynet_cookie_pid_map", config_.bpffsDir);
                reusePinnedMapIfExists(obj, "mynet_direct_stats", config_.bpffsDir);
                reusePinnedMapIfExists(obj, "mynet_listen_sock_map", config_.bpffsDir);
                reusePinnedMapIfExists(obj, "mynet_block_rate_map", config_.bpffsDir);
                reusePinnedMapIfExists(obj, "mynet_tcp_offload_pause", config_.bpffsDir);
                reusePinnedMapIfExists(obj, "mynet_outbound_connectivity", config_.bpffsDir);
                reusePinnedMapIfExists(obj, "mynet_domain_routing", config_.bpffsDir);
                reusePinnedMapIfExists(obj, "mynet_routing_handoff", config_.bpffsDir);
                reusePinnedMapIfExists(obj, "mynet_redirect_track", config_.bpffsDir);
            }

            int err = ::bpf_object__load(obj);
            if (err)
            {
                ::bpf_object__close(obj);
                return false;
            }

            // Map Pinning 钉住 (在 bpf_object__load 之后将未钉住的 Map 钉入 bpffs)
            if (config_.enableMapPinning && !config_.bpffsDir.empty())
            {
                pinMapIfNotPinned(obj, "mynet_fast_sock", config_.bpffsDir);
                pinMapIfNotPinned(obj, "mynet_conn_state_map", config_.bpffsDir);
                pinMapIfNotPinned(obj, "mynet_cookie_pid_map", config_.bpffsDir);
                pinMapIfNotPinned(obj, "mynet_direct_stats", config_.bpffsDir);
                pinMapIfNotPinned(obj, "mynet_listen_sock_map", config_.bpffsDir);
                pinMapIfNotPinned(obj, "mynet_block_rate_map", config_.bpffsDir);
                pinMapIfNotPinned(obj, "mynet_tcp_offload_pause", config_.bpffsDir);
                pinMapIfNotPinned(obj, "mynet_outbound_connectivity", config_.bpffsDir);
                pinMapIfNotPinned(obj, "mynet_domain_routing", config_.bpffsDir);
                pinMapIfNotPinned(obj, "mynet_routing_handoff", config_.bpffsDir);
                pinMapIfNotPinned(obj, "mynet_redirect_track", config_.bpffsDir);
            }

            bpfObj_ = obj;

            auto getMapFd = [obj](const char *name) -> int
            {
                auto *m = ::bpf_object__find_map_by_name(obj, name);
                return m ? ::bpf_map__fd(m) : -1;
            };

            lpmMapFd_[0] = getMapFd("mynet_lpm_trie_ipv4_0");
            lpmMapFd_[1] = getMapFd("mynet_lpm_trie_ipv4_1");
            if (lpmMapFd_[0] < 0)
            {
                lpmMapFd_[0] = getMapFd("mynet_lpm_trie_ipv4");
            }
            lpmMapIpv6Fd_[0] = getMapFd("mynet_lpm_trie_ipv6_0");
            lpmMapIpv6Fd_[1] = getMapFd("mynet_lpm_trie_ipv6_1");
            if (lpmMapIpv6Fd_[0] < 0)
            {
                lpmMapIpv6Fd_[0] = getMapFd("mynet_lpm_trie_ipv6");
            }
            directMapFd_ = getMapFd("mynet_direct_ips");
            directStatsMapFd_ = getMapFd("mynet_direct_stats");
            configMapFd_ = getMapFd("mynet_config");
            sockMapFd_ = getMapFd("mynet_fast_sock");
            cookieMapFd_ = getMapFd("mynet_cookie_pid_map");
            connStateMapFd_ = getMapFd("mynet_conn_state_map");
            listenSockMapFd_ = getMapFd("mynet_listen_sock_map");
            blockRateMapFd_ = getMapFd("mynet_block_rate_map");
            tcpOffloadPauseMapFd_ = getMapFd("mynet_tcp_offload_pause");
            outboundConnectivityMapFd_ = getMapFd("mynet_outbound_connectivity");
            eventRingbufFd_ = getMapFd("mynet_event_ringbuf");
            bpfStatsMapFd_ = getMapFd("mynet_bpf_stats_map");
            domainRoutingMapFd_ = getMapFd("mynet_domain_routing");
            routingHandoffMapFd_ = getMapFd("mynet_routing_handoff");
            redirectTrackMapFd_ = getMapFd("mynet_redirect_track");

            attachStreamVerdictLocked();
            return true;
#else
            return false;
#endif
        }

        bool attachStreamVerdictLocked()
        {
#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
            if (!bpfObj_ || sockMapFd_ < 0)
                return false;
            auto *prog = ::bpf_object__find_program_by_name(bpfObj_, "mynet_sockmap_verdict");
            if (!prog)
                return false;

            int progFd = ::bpf_program__fd(prog);
            if (progFd < 0)
                return false;

            int ret = ::bpf_prog_attach(progFd, sockMapFd_, BPF_SK_SKB_STREAM_VERDICT, 0);
            if (ret == 0)
            {
                verdictAttached_ = true;
                LOG_INFO("eBPF: Attached sk_skb/stream_verdict program to fast_sock (SOCKHASH)");
                return true;
            }
            return false;
#else
            return false;
#endif
        }

        bool attachTcFilterLocked(std::string_view ifName, bool ingress = true)
        {
#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
            if (!bpfObj_)
                return false;
            auto *prog = ::bpf_object__find_program_by_name(bpfObj_, "mynet_tc_filter");
            if (!prog)
                return false;

            std::string name(ifName);
            int ifindex = static_cast<int>(::if_nametoindex(name.c_str()));
            if (ifindex <= 0)
            {
                LOG_WARN("eBPF: Network interface '{}' not found, skipping TC attach", ifName);
                return false;
            }
            wanIfIndex_ = ifindex;

            auto attachSlaves = [this, prog, ingress](std::string_view masterName)
            {
                auto slaves = discoverBridgeSlaves(masterName);
                for (const auto &slaveName : slaves)
                {
                    int sIndex = static_cast<int>(::if_nametoindex(slaveName.c_str()));
                    if (sIndex <= 0)
                        continue;

                    SlaveTcAttachment att{.ifName = slaveName, .ifindex = sIndex};
                    struct bpf_tcx_opts sOpts{};
                    sOpts.sz = sizeof(sOpts);
                    att.link = ::bpf_program__attach_tcx(prog, sIndex, &sOpts);
                    if (att.link)
                    {
                        slaveTcAttachments_.push_back(att);
                        attachedInterfaces_.push_back(slaveName);
                        LOG_INFO("eBPF: Attached TCX filter to bridge slave member '{}' (ifindex: {})", slaveName,
                                 sIndex);
                    }
                    else
                    {
                        std::memset(&att.hook, 0, sizeof(att.hook));
                        att.hook.sz = sizeof(att.hook);
                        att.hook.ifindex = sIndex;
                        att.hook.attach_point = ingress ? BPF_TC_INGRESS : BPF_TC_EGRESS;
                        ::bpf_tc_hook_create(&att.hook);
                        struct bpf_tc_opts stcOpts{};
                        stcOpts.sz = sizeof(stcOpts);
                        stcOpts.prog_fd = ::bpf_program__fd(prog);
                        if (::bpf_tc_attach(&att.hook, &stcOpts) == 0)
                        {
                            att.isClassic = true;
                            slaveTcAttachments_.push_back(att);
                            attachedInterfaces_.push_back(slaveName);
                            LOG_INFO("eBPF: Attached classic TC filter to bridge slave member '{}'", slaveName);
                        }
                    }
                }
            };

            // 1. 优先尝试现代内核 TCX (Linux 6.6+)
            struct bpf_tcx_opts tcxOpts{};
            tcxOpts.sz = sizeof(tcxOpts);
            tcLink_ = ::bpf_program__attach_tcx(prog, ifindex, &tcxOpts);
            if (tcLink_)
            {
                tcFilterAttached_ = true;
                LOG_INFO("eBPF: Successfully attached TCX filter to interface '{}' (ifindex: {})", ifName, ifindex);
                attachSlaves(ifName);
                return true;
            }

            // 2. 回退尝试经典 clsact TC hook
            std::memset(&tcHook_, 0, sizeof(tcHook_));
            tcHook_.sz = sizeof(tcHook_);
            tcHook_.ifindex = ifindex;
            tcHook_.attach_point = ingress ? BPF_TC_INGRESS : BPF_TC_EGRESS;

            int hErr = ::bpf_tc_hook_create(&tcHook_);
            (void)hErr;

            struct bpf_tc_opts tcOpts{};
            tcOpts.sz = sizeof(tcOpts);
            tcOpts.prog_fd = ::bpf_program__fd(prog);

            if (::bpf_tc_attach(&tcHook_, &tcOpts) == 0)
            {
                tcFilterAttached_ = true;
                tcHookClassic_ = true;
                LOG_INFO("eBPF: Successfully attached classic TC clsact filter to '{}'", ifName);
                attachSlaves(ifName);
                return true;
            }
            return false;
#else
            (void)ifName;
            (void)ingress;
            return false;
#endif
        }

        void detachTcFilterLocked()
        {
#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
            if (tcLink_)
            {
                ::bpf_link__destroy(tcLink_);
                tcLink_ = nullptr;
            }
            if (tcHookClassic_)
            {
                ::bpf_tc_hook_destroy(&tcHook_);
                tcHookClassic_ = false;
            }
            for (auto &att : slaveTcAttachments_)
            {
                if (att.link)
                {
                    ::bpf_link__destroy(att.link);
                    att.link = nullptr;
                }
                if (att.isClassic)
                {
                    ::bpf_tc_hook_destroy(&att.hook);
                    att.isClassic = false;
                }
            }
            slaveTcAttachments_.clear();
            attachedInterfaces_.clear();
            tcFilterAttached_ = false;
#endif
        }

        bool attachCgroupLocked(const std::string &cgroupPath = "/sys/fs/cgroup")
        {
#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
            if (!bpfObj_)
                return false;

            int cgFd = ::open(cgroupPath.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (cgFd < 0)
                return false;
            cgroupFd_ = cgFd;

            auto attachProg = [this, cgFd](const char *name) -> struct bpf_link *
            {
                auto *prog = ::bpf_object__find_program_by_name(bpfObj_, name);
                return prog ? ::bpf_program__attach_cgroup(prog, cgFd) : nullptr;
            };

            cgConn4Link_ = attachProg("mynet_cg_connect4");
            cgConn6Link_ = attachProg("mynet_cg_connect6");
            cgSend4Link_ = attachProg("mynet_cg_sendmsg4");
            cgSend6Link_ = attachProg("mynet_cg_sendmsg6");
            cgCreateLink_ = attachProg("mynet_cg_sock_create");
            cgReleaseLink_ = attachProg("mynet_cg_sock_release");

            if (cgConn4Link_ || cgConn6Link_ || cgSend4Link_ || cgSend6Link_ || cgCreateLink_)
            {
                cgroupAttached_ = true;
                LOG_INFO("eBPF: Successfully attached cgroupv2 socket hooks to '{}'", cgroupPath);
                return true;
            }
            return false;
#else
            (void)cgroupPath;
            return false;
#endif
        }

        void detachCgroupLocked()
        {
#if defined(__linux__) && defined(MYNET_HAVE_LIBBPF)
            if (cgConn4Link_)
            {
                ::bpf_link__destroy(cgConn4Link_);
                cgConn4Link_ = nullptr;
            }
            if (cgConn6Link_)
            {
                ::bpf_link__destroy(cgConn6Link_);
                cgConn6Link_ = nullptr;
            }
            if (cgSend4Link_)
            {
                ::bpf_link__destroy(cgSend4Link_);
                cgSend4Link_ = nullptr;
            }
            if (cgSend6Link_)
            {
                ::bpf_link__destroy(cgSend6Link_);
                cgSend6Link_ = nullptr;
            }
            if (cgCreateLink_)
            {
                ::bpf_link__destroy(cgCreateLink_);
                cgCreateLink_ = nullptr;
            }
            if (cgReleaseLink_)
            {
                ::bpf_link__destroy(cgReleaseLink_);
                cgReleaseLink_ = nullptr;
            }
            if (cgroupFd_ >= 0)
            {
                ::close(cgroupFd_);
                cgroupFd_ = -1;
            }
            cgroupAttached_ = false;
#endif
        }

        bool tryCreateKernelMaps()
        {
#if defined(__linux__) && defined(__NR_bpf)
            // 1. LPM Trie Map (需要 BPF_F_NO_PREALLOC)
            union bpf_attr lpmAttr{};
            lpmAttr.map_type = BPF_MAP_TYPE_LPM_TRIE;
            lpmAttr.key_size = sizeof(BpfLpmKeyIpv4);
            lpmAttr.value_size = sizeof(uint32_t);
            lpmAttr.max_entries = 65536;
            lpmAttr.map_flags = BPF_F_NO_PREALLOC;
            long lpmFd0 = ::syscall(__NR_bpf, BPF_MAP_CREATE, &lpmAttr, sizeof(lpmAttr));
            if (lpmFd0 < 0)
                return false;
            lpmMapFd_[0] = static_cast<int>(lpmFd0);

            long lpmFd1 = ::syscall(__NR_bpf, BPF_MAP_CREATE, &lpmAttr, sizeof(lpmAttr));
            if (lpmFd1 >= 0)
            {
                lpmMapFd_[1] = static_cast<int>(lpmFd1);
            }

            // 2. Direct IPs Hash Map
            union bpf_attr hashAttr{};
            hashAttr.map_type = BPF_MAP_TYPE_HASH;
            hashAttr.key_size = sizeof(uint32_t);
            hashAttr.value_size = sizeof(uint8_t);
            hashAttr.max_entries = 16384;
            long directFd = ::syscall(__NR_bpf, BPF_MAP_CREATE, &hashAttr, sizeof(hashAttr));
            if (directFd < 0)
                return false;
            directMapFd_ = static_cast<int>(directFd);

            // 3. Config Array Map
            union bpf_attr arrAttr{};
            arrAttr.map_type = BPF_MAP_TYPE_ARRAY;
            arrAttr.key_size = sizeof(uint32_t);
            arrAttr.value_size = sizeof(BpfConfigVal);
            arrAttr.max_entries = 1;
            long cfgFd = ::syscall(__NR_bpf, BPF_MAP_CREATE, &arrAttr, sizeof(arrAttr));
            if (cfgFd < 0)
                return false;
            configMapFd_ = static_cast<int>(cfgFd);

            // 4. SockMap
            union bpf_attr sockAttr{};
            sockAttr.map_type = BPF_MAP_TYPE_SOCKMAP;
            sockAttr.key_size = sizeof(uint32_t);
            sockAttr.value_size = sizeof(uint32_t);
            sockAttr.max_entries = 65536;
            long sFd = ::syscall(__NR_bpf, BPF_MAP_CREATE, &sockAttr, sizeof(sockAttr));
            if (sFd >= 0)
            {
                sockMapFd_ = static_cast<int>(sFd);
            }

            return true;
#else
            return false;
#endif
        }

        void syncConfigToKernel()
        {
#if defined(__linux__)
            if (!config_.virtualInterface.empty())
            {
                virtualIfIndex_ = static_cast<int>(::if_nametoindex(config_.virtualInterface.c_str()));
            }
            if (kernelBpfActive_ && configMapFd_ >= 0)
            {
                uint32_t key = 0;
                BpfConfigVal val{.tproxyPort = config_.tproxyPort,
                                 .pad = 0,
                                 .fwmark = config_.fwmark,
                                 .directBypassEnabled = static_cast<uint8_t>(config_.enableDirectBypass ? 1 : 0),
                                 .dropQuic = static_cast<uint8_t>(config_.dropQuic ? 1 : 0),
                                 .wanIfIndex = static_cast<uint16_t>(wanIfIndex_),
                                 .activeEpoch = activeEpoch_.load(std::memory_order_relaxed),
                                 .asymmetricGateway = static_cast<uint8_t>(config_.asymmetricGateway ? 1 : 0),
                                 .gatewayMac = {},
                                 .wanMac = {},
                                 .enableSkAssign = static_cast<uint8_t>(config_.enableSkAssign ? 1 : 0),
                                 .redirectIfindex = static_cast<uint8_t>(virtualIfIndex_),
                                 .rateLimitWindowMs = config_.rateLimitWindowMs,
                                 .tproxyPortProtect = static_cast<uint8_t>(config_.tproxyPortProtect ? 1 : 0),
                                 .pad3 = 0};
                if (auto gMac = MacAddress::parse(config_.gatewayMac))
                {
                    std::memcpy(val.gatewayMac, gMac->bytes, 6);
                }
                if (auto wMac = MacAddress::parse(config_.wanMac))
                {
                    std::memcpy(val.wanMac, wMac->bytes, 6);
                }
#if defined(MYNET_HAVE_LIBBPF)
                ::bpf_map_update_elem(configMapFd_, &key, &val, BPF_ANY);
#elif defined(__NR_bpf)
                union bpf_attr attr{};
                attr.map_fd = static_cast<uint32_t>(configMapFd_);
                attr.key = reinterpret_cast<uint64_t>(&key);
                attr.value = reinterpret_cast<uint64_t>(&val);
                attr.flags = BPF_ANY;
                ::syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
#endif
            }
#endif
        }

        void loadDefaultPrivateCidrs(int epochSlot = -1)
        {
            addLpmCidrLocked("10.0.0.0/8", Action::DIRECT, epochSlot);
            addLpmCidrLocked("172.16.0.0/12", Action::DIRECT, epochSlot);
            addLpmCidrLocked("192.168.0.0/16", Action::DIRECT, epochSlot);
            addLpmCidrLocked("127.0.0.0/8", Action::DIRECT, epochSlot);
            addLpmCidrLocked("100.64.0.0/10", Action::DIRECT, epochSlot);
            addLpmCidrLocked("169.254.0.0/16", Action::DIRECT, epochSlot);
            addLpmCidrLocked("224.0.0.0/3", Action::DIRECT,
                             epochSlot); // 局域网组播与广播网段 (224.0.0.0 - 255.255.255.255, 借鉴 dae)
            addLpmCidrIpv6Locked("ff00::/8", Action::DIRECT, epochSlot); // IPv6 组播网段 (借鉴 dae)
            addLpmCidrLocked("198.18.0.0/15", Action::PROXY, epochSlot); // FakeIP
        }
    };

    /// 别名统一过渡
    using EbpfManager = EbpfEngine;

} // namespace mynet::ebpf
