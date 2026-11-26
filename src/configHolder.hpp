#pragma once

#include "compat.hpp"
#include "transport.hpp"
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace mynet
{

    /**
     * @brief 线程安全配置容器（发布者）
     *
     * 采用版本代次（Generation Counter）与 RCU 智能指针生命周期闭环机制。
     * 配置写入（发布）由互斥锁保护，原子替换内部 std::shared_ptr<const T> 指针，并通过 release 内存序递增代次；
     * 配合 ConfigSnapshot 与 Connection 会话生命周期绑定，存量连接自然持有旧代配置共享指针，
     * 当存量会话全部结束退出后，引用计数归零，旧配置自动触发优雅排空与安全析构，实现真正的零锁、零拷贝与 RCU 安全退役。
     *
     * @tparam T 配置对象类型
     */
    template <typename T>
    class ConfigHolder
    {
        mutable std::mutex mtx_;
        std::shared_ptr<const T> ptr_{std::make_shared<const T>()};
        std::atomic<uint32_t> generation_{1};

    public:
        ConfigHolder() = default;
        explicit ConfigHolder(T initial)
            : ptr_(std::make_shared<const T>(std::move(initial)))
        {
        }
        explicit ConfigHolder(std::shared_ptr<const T> initial)
            : ptr_(initial ? std::move(initial) : std::make_shared<const T>())
        {
        }
        ConfigHolder(const ConfigHolder &) = delete;
        ConfigHolder &operator=(const ConfigHolder &) = delete;

        /**
         * @brief 发布新配置并递增版本代次 (RCU 安全原子发布)
         *
         * 在互斥锁保护下原子替换内部共享配置指针，并通过 release 内存序递增代次。
         * 旧配置资源不会被立即就地销毁，而是由已持有该代配置的存量会话/快照安全持有；
         * 随着存量会话全部退出，引用计数归零后自动触发优雅排空与安全析构。
         *
         * @param value 新的配置实例（通过移动语义传入以避免冗余拷贝）
         */
        void publish(T value) { publish(std::make_shared<const T>(std::move(value))); }

        /**
         * @brief 发布新的配置共享指针
         */
        void publish(std::shared_ptr<const T> newPtr)
        {
            if (!newPtr)
            {
                newPtr = std::make_shared<const T>();
            }
            {
                std::lock_guard<std::mutex> lock(mtx_);
                ptr_ = std::move(newPtr);
            }
            generation_.fetch_add(1, std::memory_order_release);
        }

        /**
         * @brief 获取当前配置的 RCU 共享只读指针 (O(1) 零深拷贝，生命周期自动维系)
         */
        [[nodiscard]] std::shared_ptr<const T> currentConfig() const noexcept
        {
            std::lock_guard<std::mutex> lock(mtx_);
            return ptr_;
        }

        /**
         * @brief 复制当前配置实例 (向前兼容)
         *
         * 在互斥锁保护下读取当前配置对象的完整副本，供快照同步或外部查询使用。
         *
         * @return T 当前配置对象的完整副本
         */
        [[nodiscard]] T duplicate() const
        {
            std::lock_guard<std::mutex> lock(mtx_);
            return ptr_ ? *ptr_ : T{};
        }

        /**
         * @brief 获取当前配置的版本代次
         *
         * 使用 acquire 内存序读取原子代次计数器，用于无锁快速判断配置是否已被修改。
         *
         * @return uint32_t 当前配置版本代次号
         */
        [[nodiscard]] uint32_t getGeneration() const noexcept { return generation_.load(std::memory_order_acquire); }

        /**
         * @brief 获取当前代际配置的活跃引用总数 (含 ConfigHolder 自身 + 所有活跃会话/快照)
         */
        [[nodiscard]] long currentActiveReferences() const noexcept
        {
            std::lock_guard<std::mutex> lock(mtx_);
            return ptr_ ? ptr_.use_count() : 0;
        }
    };

    /**
     * @brief 线程局部配置快照（订阅者，RCU 零拷贝）
     *
     * 绑定至指定的 ConfigHolder，通常作为 thread_local 变量使用。
     * 每次访问时仅需一次原子 acquire 读校验代次；若代次未变则直接返回线程私有智能指针引用的只读配置，
     * 做到热路径完全零锁、零内存拷贝与零缓存行争用；
     * 若代次发生递增，仅原子复制一次 shared_ptr 句柄（O(1)，零内存分配与深拷贝），
     * 旧代配置指针释放后，若无活跃会话引用则自然被回收。
     *
     * @tparam T 配置对象类型
     */
    template <typename T>
    class ConfigSnapshot
    {
        const ConfigHolder<T> &holder_;
        std::shared_ptr<const T> localPtr_{};
        uint32_t generation_ = 0;

    public:
        /**
         * @brief 构造配置快照并绑定目标容器
         *
         * @param holder 目标配置容器的常量引用，生命周期须覆盖此快照
         */
        explicit ConfigSnapshot(const ConfigHolder<T> &holder)
            : holder_(holder)
        {
        }
        ConfigSnapshot(const ConfigSnapshot &) = delete;
        ConfigSnapshot &operator=(const ConfigSnapshot &) = delete;

        /**
         * @brief 获取最新配置的常量引用 (RCU 零深拷贝)
         *
         * 快速检查容器版本代次。若版本发生递增，拉取最新共享指针至本线程私有缓存，
         * 并同步代次号；若未更新则直接返回本线程缓存的配置引用。
         *
         * @return const T& 当前生效配置的常量引用
         */
        inline const T &refConfig() noexcept
        {
            const uint32_t gen = holder_.getGeneration();
            if (gen != generation_ || !localPtr_)
            {
                localPtr_ = holder_.currentConfig();
                generation_ = gen;
            }
            return *localPtr_;
        }

        /**
         * @brief 便捷别名接口
         */
        inline const T &get() noexcept { return refConfig(); }

        /**
         * @brief 获取当前快照持有的 RCU 共享指针句柄
         */
        [[nodiscard]] inline std::shared_ptr<const T> getShared() noexcept
        {
            refConfig();
            return localPtr_;
        }

        /**
         * @brief 获取快照当前绑定的代次
         */
        [[nodiscard]] inline uint32_t generation() const noexcept { return generation_; }
    };

    /**
     * @brief 配置项的生效时机
     */
    enum class ReloadMode : uint8_t
    {
        Hot,    ///< 运行中 reloadConfig() 后立即生效：每个新连接或每次 I/O 都会重新读取
        Startup ///< 仅在引擎/监听器启动时读取一次；reload 后必须重启该服务才生效
    };

    /**
     * @brief 单个配置字段的生效时机登记项
     */
    struct ConfigFieldReload
    {
        std::string_view path; ///< 形如 "server.backlog" 的点分路径
        ReloadMode mode;
    };

    /**
     * @brief 服务端基础连接与网络配置
     */
    struct ServerConfig
    {
        std::string host = "0.0.0.0";
        uint16_t port = 8888;
        int backlog = 128;
        /// 连接上限，同时也是引擎的池容量（唯一真源）：
        /// Reactor 用它做连接池槽位数，Proactor 用它做会话池槽位数。
        ///
        /// 注意这是**启动时预分配**的槽位数量，不是按需增长的上限：每个槽位连同
        /// 其请求/响应缓冲区实测约 3 KiB，因此 65536 会一次性占掉约 190 MiB RSS。
        /// 默认取 8192（约 24 MiB），按实际并发量调整。
        size_t maxConnections = 8192;
        int idleTimeoutSecs = 0;
        bool tcpNoDelay = true;
        bool tcpQuickAck = false;
        bool enableSplice = true;
        bool reuseAddr = true;          ///< 是否开启 SO_REUSEADDR 允许快速复用处于 TIME_WAIT 状态的端口
        bool reusePort = true;          ///< 是否开启 SO_REUSEPORT 允许多线程/多进程监听同一端口负载均衡
        std::string engine = "reactor"; ///< 运行引擎底层实现类型 ("reactor" 或 "proactor") [启动]
    };

    /**
     * @brief epoll Reactor 引擎专用配置
     */
    struct ReactorConfig
    {
        int maxEvents = 1 << 10;        ///< 单次 epoll_wait 最大返回事件数 (个)
        int idleSweepIntervalMs = 1000; ///< 空闲连接扫描节拍 (毫秒)
    };

    /**
     * @brief io_uring Proactor 引擎专用配置
     */
    struct ProactorConfig
    {
        size_t sqEntries = 2048;           ///< io_uring 提交队列深度 (SQE)
        size_t cqEntries = 2048;           ///< io_uring 完成队列深度 (CQE，须 >= sqEntries)
        size_t maxAcceptEvents = 256;      ///< 在途 multishot accept 并发上限 (个)
        size_t bufEntries = 1024;          ///< 内核 Buffer Ring 槽位数量 (个)
        size_t bufSize = 4096;             ///< Buffer Ring 单槽字节数 (字节)
        size_t udpBufSize = 64 << 10;      ///< UDP 接收窗口下限 (字节)
        size_t bufRingAlignment = 4 << 10; ///< Buffer Ring 底层内存对齐粒度；posix_memalign 要求 2 的幂
        int cqeWaitMs = 1000;              ///< 等待完成事件的超时上限 (毫秒)，超时后扫描空闲会话并重提交
    };

    /**
     * @brief 流式连接与请求响应管道配置
     */
    struct ConnectionConfig
    {
        size_t responseCapacity = 64;        ///< 默认响应队列初始槽位容量 (条)
        size_t readChunkSize = 4 << 10;      ///< 单次直写请求接收读取分块大小 (4 KiB)
        size_t maxRequestBytes = 4 << 20;    ///< 单连接请求解析缓冲上限 (4 MiB)
        size_t writeHighWaterMark = 4 << 20; ///< 单连接发送队列高水位线 (4 MiB)
        size_t writeHardCapFactor = 2;       ///< 发送积压硬顶倍数（>= factor * writeHighWaterMark 时发完即关）
        size_t spliceChunkSize = 64 << 10;   ///< Linux splice(2) 单次移动分块大小 (64 KiB)
        size_t maxWriteIov = 16;             ///< 向量化 I/O (writev) 单次聚合发送分片上限 (1~64)
        size_t readHighWaterMark = 64 << 10; ///< 单连接请求缓冲区滑动窗口高水位线 (64 KiB)
        size_t maxDrainRounds = 64;          ///< 单次事件循环发送队列最大轮询清空轮次 (次)
    };

    /**
     * @brief UDP 数据报会话与外发队列配置
     */
    struct DatagramConfig
    {
        size_t maxDatagramBytes = (64 << 10) - 1; ///< 单个 UDP 数据报载荷上限 (65535 字节)
        size_t maxPendingOutgoing = 1024;         ///< 待发送外发队列槽位上限 (条)
    };

    /**
     * @brief TLS 安全传输与 ALPN 协商配置
     */
    struct SecurityConfig
    {
        /// 服务端证书路径；runSsl(ip, port) 无路径重载从这里取。
        std::string certFile{};
        /// 服务端私钥路径；同上。
        std::string keyFile{};
        /// CA 根证书路径（双向认证时使用）；空表示不加载自定义 CA。
        std::string caFile{};
        /// TLS 1.2 及以下密码套件列表。默认留空 = 不调用 SSL_CTX_set_cipher_list，
        /// 从而保留 libssl 从 openssl.cnf 读取的 system_default 策略。
        /// 写 "DEFAULT" 会被归一为同样的"不调用"。
        std::string ciphers{};
        /// TLS 1.3 密码套件列表（如 TLS_AES_256_GCM_SHA384 等）
        std::string tls13CipherSuites{};
        /// ALPN 协议列表（逗号分隔）。默认空 = 不协商 ALPN，与引擎引入配置驱动前一致：
        /// 服务端只有在确实实现某协议时才应宣告它，否则会对客户端撒谎。
        std::string alpnProtocols{};
        /// 最低 TLS 版本（默认 0x0303 即 TLS 1.2，RFC 5246；0x0304 为 TLS 1.3）
        int minVersion = 0x0303;
        /// 最高 TLS 版本（默认 0 表示 OpenSSL 自动协商上限）
        int maxVersion = 0;
        /// 服务端 TLS 会话缓存超时时间（秒），默认 3600 秒（1 小时）
        long sessionTimeout = 3600;
        /// 是否启用 TLS 会话凭证（Session Tickets，用于加速重连与会话恢复）
        bool enableSessionTickets = true;
        /// TLS 1.3 握手后发送的会话票据数量（OpenSSL 默认 2）
        size_t numTickets = 2;
        /// TLS 会话缓存标识上下文（默认 "mynet"）
        std::string sessionIdContext = "mynet";
    };

    /**
     * @brief HTTP/1.x 协议解析边界与安全限额配置
     */
    struct Http1Config
    {
        size_t maxUrlLength = 8192;              ///< URL 最大允许长度 (字节)
        size_t maxHeadersCount = 100;            ///< 请求/响应允许包含的最大首部行数
        size_t maxHeaderFieldLength = 4096;      ///< 单个首部字段名长度上限 (字节)
        size_t maxHeaderValueLength = 16384;     ///< 单个首部字段值长度上限 (字节)
        size_t maxTotalHeadersLength = 65536;    ///< 全部首部累计大小上限 (64 KiB)
        size_t maxBodyLength = 16 * 1024 * 1024; ///< 请求/响应 Body 允许的最大长度 (16 MiB)
    };

    /**
     * @brief HTTP/2 协议流并发、初始窗口与帧大小限额配置
     */
    struct Http2Config
    {
        size_t maxConcurrentStreams = 100;   ///< 单连接最大并发活跃流数量
        size_t initialWindowSize = 65535;    ///< 连接级与流级初始流控窗口 (字节)
        size_t maxFrameSize = 16384;         ///< 本端接受的单帧 Payload 上限 (字节)
        size_t maxHeaderListSize = 64 << 10; ///< 本端接受的最大首部列表大小 (字节，默认 64 KiB)
        size_t headerTableSize = 4096;       ///< HPACK 动态表初始容量上限 (字节，默认 4096)
    };

    /**
     * @brief HTTP/3 (QUIC) 传输层与协议层安全限额配置
     */
    struct Http3Config
    {
        size_t maxRequestBodyBytes = 16 << 20;  ///< HTTP/3 请求 Body 上限 (16 MiB)
        size_t maxStreamBufferBytes = 16 << 20; ///< HTTP/3 单流缓冲接收上限 (16 MiB)
        size_t maxHeaderBlockBytes = 64 << 10;  ///< QPACK 编码首部块上限 (64 KiB)
        size_t maxHeaderEntries = 256;          ///< QPACK 允许包含的最大首部条目数
        uint16_t port = 4433;                   ///< HTTP/3 UDP 默认监听端口
    };

    /**
     * @brief SOCKS5 代理处理器配置选项
     */
    struct ProxyConfig
    {
        bool autoReplyConnectSuccess = true; ///< CONNECT 成功时自动向客户端回发 0x00 响应
    };

    /**
     * @brief 双向流式与数据报中继转发引擎配置
     */
    struct ForwarderConfig
    {
        bool enableSplice = true;          ///< 是否启用 Linux splice(2) 内核零拷贝
        bool propagateClose = true;        ///< 单向关闭是否自动级联至对端
        size_t spliceChunkSize = 64 << 10; ///< Linux splice(2) 单次移动分块大小 (64 KiB)
        size_t bufferChunkSize = 16 << 10; ///< 用户态缓冲回退双向泵送分块大小 (16 KiB)
        int sessionIdleTimeoutSecs = 300;  ///< 流式转发会话空闲超时 (秒)
        int udpSessionTimeoutSecs = 60;    ///< 数据报转发会话空闲超时 (秒)
    };

    /**
     * @brief 策略路由单条规则配置
     */
    struct RouteRuleConfig
    {
        std::string outbound = "direct";           ///< 命中的目标出站标签 (如 "direct", "block", "proxy-out")
        std::vector<std::string> domains{};        ///< 完整域名精确匹配列表
        std::vector<std::string> domainSuffixes{}; ///< 域名后缀匹配列表 (如 "google.com")
        std::vector<std::string> domainKeywords{}; ///< 域名关键字匹配列表 (如 "adserver")
        std::vector<std::string> ipCidrs{};        ///< IP CIDR 子网列表 (如 "192.168.0.0/16")
        std::vector<std::string> portRanges{};     ///< 端口/范围列表 (如 "80", "8000-8080")
        std::vector<std::string> protocols{};      ///< 嗅探协议名称列表 (如 "tls", "http", "quic")
        std::string network = "any";               ///< 传输层网络协议 ("any", "tcp", "udp")
        std::vector<std::string> inboundTags{};    ///< 入站来源标签列表 (如 "mixed-in")
        bool invert = false;                       ///< 是否反转匹配条件 (NOT)
        std::vector<std::string> geoIps{};         ///< GeoIP 国家/私网代码 (如 "cn", "private")
        std::vector<std::string> geoSites{};       ///< GeoSite 域名资产分类 (如 "cn", "category-ads-all")
        std::string processName{};                 ///< 客户端发起进程名 (如 "curl", "chrome")
    };

    /**
     * @brief 策略路由全局引擎配置
     */
    struct RouterConfig
    {
        std::string defaultOutbound = "direct"; ///< 规则未命中时的默认出站节点标签
        std::vector<RouteRuleConfig> rules{};   ///< 策略路由规则列表
    };

    /**
     * @brief DNS 解析与高速缓存配置
     */
    struct DnsConfig
    {
        std::vector<std::string> servers = {"8.8.8.8", "1.1.1.1"}; ///< 上游 DNS 服务器列表
        uint16_t port = 53;                                        ///< 默认 DNS 端口
        uint32_t ttlSecs = 300;                                    ///< 默认 DNS 记录缓存存活期 (秒)
        bool enableCache = true;                                   ///< 是否启用 DNS 查询结果内存缓存
    };

    /**
     * @brief 入站监听节点配置规范
     */
    struct InboundConfig
    {
        std::string tag = "mixed-in";      ///< 入站标签名称 (供分流规则匹配)
        std::string protocol = "mixed";    ///< 入站协议类型 ("mixed", "socks5", "http", "trojan", "direct", "tproxy",
                                           ///< "vless", "hysteria2", "shadowsocks", "tun")
        std::string host = "0.0.0.0";      ///< 监听绑定地址
        uint16_t port = 1080;              ///< 监听端口
        std::string username{};            ///< 鉴权用户名 (可选)
        std::string password{};            ///< 鉴权密码或密钥 (可选)
        bool enableSniffing = true;        ///< 是否启用首包域名与协议嗅探
        std::string uuid{};                ///< VLESS 用户 UUID (可选)
        std::string ifName = "tun0";       ///< TUN 设备名称 (TUN 专用)
        std::string inetIp = "172.19.0.1"; ///< TUN 本地 IPv4 (TUN 专用)
        std::string inetMask = "255.255.255.0"; ///< TUN 掩码 (TUN 专用)
        uint32_t mtu = 1500;                    ///< TUN MTU (TUN 专用)
        transport::TransportConfig transport{}; ///< 可叠加传输层配置 (TLS / WebSocket / gRPC)
    };

    /**
     * @brief 出站落地节点配置规范
     */
    struct OutboundConfig
    {
        std::string tag = "direct";  ///< 出站标签名称
        std::string type = "direct"; ///< 节点类型 ("direct", "block", "socks5", "trojan", "selector", "vless",
                                     ///< "hysteria2", "urltest", "fallback")
        std::string host{};          ///< 远端服务器地址或域名 (代理节点使用)
        uint16_t port = 0;           ///< 远端服务器端口
        std::string username{};      ///< 鉴权用户名 (SOCKS5 等可选)
        std::string password{};      ///< 鉴权密码或密钥 (Trojan / SOCKS5 等可选)
        std::string method{}; ///< 加密方式 (Shadowsocks 专用，如 "aes-128-gcm", "aes-256-gcm", "chacha20-poly1305")
        std::vector<std::string> outbounds{}; ///< 选择器子出站节点标签列表 (Selector / UrlTest / Fallback 专用)
        std::string defaultTag{};             ///< 选择器默认活动节点 (Selector 专用)
        std::string uuid{};                   ///< VLESS / VMess 用户 UUID
        std::string security = "auto";        ///< VMess 加密方式 (VMess 专用)
        std::string url = "http://cp.cloudflare.com/generate_204"; ///< 测速 URL (UrlTest 专用)
        uint32_t intervalSecs = 300;                               ///< 测速周期 (秒, UrlTest 专用)
        uint32_t toleranceMs = 50;                                 ///< 延迟抖动容差 (毫秒, UrlTest 专用)
        transport::TransportConfig transport{};                    ///< 可叠加传输层配置 (TLS / WebSocket / gRPC)
    };

    /**
     * @brief Linux TC eBPF 透明代理与内核级直连旁路引擎配置
     */
    struct EbpfConfig
    {
        bool enabled = false;                       ///< 是否启用 eBPF 透明代理与旁路加速
        std::string wanInterface = "eth0";          ///< 外网流量拦截网卡 (WAN)
        std::string lanInterface = "lo";            ///< 内网回环网卡 (LAN)
        uint16_t tproxyPort = 12345;                ///< 本地 TProxy 代理监听端口 (Fwmark 重定向目标)
        uint32_t fwmark = 0x1;                      ///< 代理报文标记防火墙 Mark 值
        bool enableDirectBypass = true;             ///< 是否开启内核级直连旁路 (TC_ACT_OK 放行)
        bool enableLpmGeoIp = true;                 ///< 是否在内核挂载 LPM Trie GeoIP 规则
        bool dropQuic = false;                      ///< 是否在内核 TC 层拦截 QUIC (UDP 443) 迫使其降级至 TCP
        std::string bpfObjectPath{};                ///< 外部预编译 eBPF 目标文件路径 (可选，留空则使用嵌入式字节码)
        std::string cgroupPath = "/sys/fs/cgroup";  ///< cgroupv2 挂载路径
        bool enableDoubleEpoch = true;              ///< 是否开启双 Epoch 双缓冲路由表零停机原子热重载
        bool enableMapPinning = false;              ///< 是否在 bpffs 持久化钉住 BPF Map 保证热重启连接不中断
        std::string bpffsDir = "/sys/fs/bpf/mynet"; ///< BPF 文件系统钉住挂载目录
        bool asymmetricGateway = false;             ///< 是否开启旁路由非对称 MAC 改写线速直连
        std::string gatewayMac{};                   ///< 上级主路由 MAC 地址 (例如 00:11:22:33:44:55)
        std::string wanMac{};                       ///< 本机 WAN 网卡 MAC 地址
        bool enableConnStateJanitor = true;         ///< 是否开启 UDP 内核连接状态表与保活回收器
        bool enableSkAssign = false; ///< 是否启用 bpf_sk_assign 内核直接套接字绑定（免 iptables/nftables）
        bool enableUnconnectedUdpAttribution = true; ///< 是否通过 cgroup/sendmsg4/6 捕获无连接 UDP 进程属主
        std::string virtualInterface{};              ///< 隔离转发虚拟接口名 (如 mynet0/veth/netkit)，留空则走标准路由
        uint16_t rateLimitWindowMs = 1000;           ///< 阻断与恶意扫描在内核的令牌桶限速窗口 (毫秒)
        bool tproxyPortProtect = false;              ///< 是否在内核 TC 层丢弃未经 eBPF 授权直连 tproxy 端口的外来报文
    };

    /**
     * @brief FakeIP 虚拟地址池与域名反解配置
     */
    struct FakeIPConfig
    {
        bool enabled = true;                     ///< 是否启用 FakeIP 虚拟地址池分流
        std::string inetRange = "198.18.0.0/15"; ///< FakeIP 保留虚拟地址段 (RFC 6333)
        size_t maxCapacity = 65534;              ///< FakeIP 内存池容量与 LRU 缓存上限
    };

    /**
     * @brief GeoIP 国家网段与 GeoSite 域名资产规则配置
     */
    struct GeoConfig
    {
        std::string geoIpPath{};   ///< 外部 GeoIP 规则文件路径 (如 "geoip.dat")
        std::string geoSitePath{}; ///< 外部 GeoSite 资产文件路径 (如 "geosite.dat")
        bool autoReload = false;   ///< 文件变更时是否自动重新加载
    };

    /**
     * @brief Clash / sing-box 兼容 RESTful 控制平面 API 配置
     */
    struct ControllerConfig
    {
        bool enabled = false;           ///< 是否启用 RESTful 控制 API 监听
        std::string host = "127.0.0.1"; ///< API 绑定监听地址
        uint16_t port = 9090;           ///< API 绑定监听端口
        std::string secret{};           ///< API Bearer Token 访问密钥 (可选)
    };

    /**
     * @brief mynet 全局综合网络配置
     */
    struct MynetConfig
    {
        ServerConfig server{};
        ReactorConfig reactor{};
        ProactorConfig proactor{};
        ConnectionConfig connection{};
        DatagramConfig datagram{};
        SecurityConfig security{};
        Http1Config http1{};
        Http2Config http2{};
        Http3Config http3{};
        ProxyConfig proxy{};
        ForwarderConfig forwarder{};
        RouterConfig router{};
        DnsConfig dns{};
        EbpfConfig ebpf{};
        FakeIPConfig fakeip{};
        GeoConfig geo{};
        ControllerConfig controller{};
        std::vector<InboundConfig> inbounds{};
        std::vector<OutboundConfig> outbounds{};
    };

    /**
     * @brief 全部配置字段的生效时机登记表
     *
     * 这张表是"热配置 / 启动配置"的唯一真源：README 的分类、测试的断言都从这里读。
     * 新增字段时必须同步登记，tests/test_config_lua.cpp 会逐字段核对，漏登记即失败。
     */
    inline constexpr ConfigFieldReload kConfigReloadMap[] = {
        // ---- server ----
        {"server.host", ReloadMode::Startup},
        {"server.port", ReloadMode::Startup},
        {"server.backlog", ReloadMode::Startup},
        {"server.maxConnections", ReloadMode::Startup},
        {"server.idleTimeoutSecs", ReloadMode::Startup},
        {"server.tcpNoDelay", ReloadMode::Hot},
        {"server.tcpQuickAck", ReloadMode::Hot},
        {"server.enableSplice", ReloadMode::Hot},
        {"server.reuseAddr", ReloadMode::Startup},
        {"server.reusePort", ReloadMode::Startup},
        {"server.engine", ReloadMode::Startup},
        // ---- reactor ----
        {"reactor.maxEvents", ReloadMode::Startup},
        {"reactor.idleSweepIntervalMs", ReloadMode::Startup},
        // ---- proactor ----
        {"proactor.sqEntries", ReloadMode::Startup},
        {"proactor.cqEntries", ReloadMode::Startup},
        {"proactor.maxAcceptEvents", ReloadMode::Startup},
        {"proactor.bufEntries", ReloadMode::Startup},
        {"proactor.bufSize", ReloadMode::Startup},
        {"proactor.udpBufSize", ReloadMode::Startup},
        {"proactor.bufRingAlignment", ReloadMode::Startup},
        {"proactor.cqeWaitMs", ReloadMode::Startup},
        // ---- connection ----
        {"connection.responseCapacity", ReloadMode::Hot},
        {"connection.readChunkSize", ReloadMode::Hot},
        {"connection.maxRequestBytes", ReloadMode::Hot},
        {"connection.writeHighWaterMark", ReloadMode::Hot},
        {"connection.writeHardCapFactor", ReloadMode::Hot},
        {"connection.spliceChunkSize", ReloadMode::Hot},
        {"connection.maxWriteIov", ReloadMode::Hot},
        {"connection.readHighWaterMark", ReloadMode::Hot},
        {"connection.maxDrainRounds", ReloadMode::Hot},
        // ---- datagram ----
        {"datagram.maxDatagramBytes", ReloadMode::Hot},
        {"datagram.maxPendingOutgoing", ReloadMode::Hot},
        // ---- security ----
        {"security.certFile", ReloadMode::Startup},
        {"security.keyFile", ReloadMode::Startup},
        {"security.caFile", ReloadMode::Startup},
        {"security.ciphers", ReloadMode::Startup},
        {"security.tls13CipherSuites", ReloadMode::Startup},
        {"security.alpnProtocols", ReloadMode::Startup},
        {"security.minVersion", ReloadMode::Startup},
        {"security.maxVersion", ReloadMode::Startup},
        {"security.sessionTimeout", ReloadMode::Startup},
        {"security.enableSessionTickets", ReloadMode::Startup},
        {"security.numTickets", ReloadMode::Startup},
        {"security.sessionIdContext", ReloadMode::Startup},
        // ---- http1 ----
        {"http1.maxUrlLength", ReloadMode::Hot},
        {"http1.maxHeadersCount", ReloadMode::Hot},
        {"http1.maxHeaderFieldLength", ReloadMode::Hot},
        {"http1.maxHeaderValueLength", ReloadMode::Hot},
        {"http1.maxTotalHeadersLength", ReloadMode::Hot},
        {"http1.maxBodyLength", ReloadMode::Hot},
        // ---- http2 ----
        {"http2.maxConcurrentStreams", ReloadMode::Hot},
        {"http2.initialWindowSize", ReloadMode::Hot},
        {"http2.maxFrameSize", ReloadMode::Hot},
        {"http2.maxHeaderListSize", ReloadMode::Hot},
        {"http2.headerTableSize", ReloadMode::Hot},
        // ---- http3 ----
        {"http3.maxRequestBodyBytes", ReloadMode::Hot},
        {"http3.maxStreamBufferBytes", ReloadMode::Hot},
        {"http3.maxHeaderBlockBytes", ReloadMode::Hot},
        {"http3.maxHeaderEntries", ReloadMode::Hot},
        {"http3.port", ReloadMode::Startup},
        // ---- proxy ----
        {"proxy.autoReplyConnectSuccess", ReloadMode::Hot},
        // ---- forwarder ----
        {"forwarder.enableSplice", ReloadMode::Hot},
        {"forwarder.propagateClose", ReloadMode::Hot},
        {"forwarder.spliceChunkSize", ReloadMode::Hot},
        {"forwarder.bufferChunkSize", ReloadMode::Hot},
        {"forwarder.sessionIdleTimeoutSecs", ReloadMode::Hot},
        {"forwarder.udpSessionTimeoutSecs", ReloadMode::Hot},
        // ---- router ----
        {"router.defaultOutbound", ReloadMode::Hot},
        {"router.rules", ReloadMode::Hot},
        // ---- dns ----
        {"dns.servers", ReloadMode::Hot},
        {"dns.port", ReloadMode::Startup},
        {"dns.ttlSecs", ReloadMode::Hot},
        {"dns.enableCache", ReloadMode::Hot},
        // ---- ebpf ----
        {"ebpf.enabled", ReloadMode::Startup},
        {"ebpf.wanInterface", ReloadMode::Startup},
        {"ebpf.lanInterface", ReloadMode::Startup},
        {"ebpf.tproxyPort", ReloadMode::Startup},
        {"ebpf.fwmark", ReloadMode::Hot},
        {"ebpf.enableDirectBypass", ReloadMode::Hot},
        {"ebpf.enableLpmGeoIp", ReloadMode::Hot},
        {"ebpf.dropQuic", ReloadMode::Hot},
        {"ebpf.bpfObjectPath", ReloadMode::Startup},
        {"ebpf.cgroupPath", ReloadMode::Startup},
        {"ebpf.enableDoubleEpoch", ReloadMode::Hot},
        {"ebpf.enableMapPinning", ReloadMode::Startup},
        {"ebpf.bpffsDir", ReloadMode::Startup},
        {"ebpf.asymmetricGateway", ReloadMode::Hot},
        {"ebpf.gatewayMac", ReloadMode::Hot},
        {"ebpf.wanMac", ReloadMode::Hot},
        {"ebpf.enableConnStateJanitor", ReloadMode::Hot},
        {"ebpf.enableSkAssign", ReloadMode::Hot},
        {"ebpf.enableUnconnectedUdpAttribution", ReloadMode::Startup},
        {"ebpf.virtualInterface", ReloadMode::Startup},
        {"ebpf.rateLimitWindowMs", ReloadMode::Hot},
        {"ebpf.tproxyPortProtect", ReloadMode::Hot},
        // ---- fakeip ----
        {"fakeip.enabled", ReloadMode::Startup},
        {"fakeip.inetRange", ReloadMode::Startup},
        {"fakeip.maxCapacity", ReloadMode::Startup},
        // ---- geo ----
        {"geo.geoIpPath", ReloadMode::Startup},
        {"geo.geoSitePath", ReloadMode::Startup},
        {"geo.autoReload", ReloadMode::Startup},
        // ---- controller ----
        {"controller.enabled", ReloadMode::Startup},
        {"controller.host", ReloadMode::Startup},
        {"controller.port", ReloadMode::Startup},
        {"controller.secret", ReloadMode::Startup},
    };

    /**
     * @brief 查询某个配置字段的生效时机
     * @param path 形如 "server.backlog" 的点分路径
     * @return 登记表里的时机；未登记时返回 Startup（最保守：不承诺热生效）
     */
    [[nodiscard]] constexpr ReloadMode reloadModeOf(std::string_view path) noexcept
    {
        for (const ConfigFieldReload &entry : kConfigReloadMap)
        {
            if (entry.path == path)
            {
                return entry.mode;
            }
        }
        return ReloadMode::Startup;
    }

    // =========================================================================
    // 校验函数（Validation Predicates）
    // 按分层逻辑严格对齐：
    // 1. 服务端与底层引擎 (Server, Reactor, Proactor)
    // 2. 传输层会话与队列 (Connection, Datagram)
    // 3. 传输安全 (Security)
    // 4. 应用层协议与代理 (Http1, Http2, Http3, Proxy)
    // =========================================================================

    /**
     * @brief 校验服务端基础网络配置是否处于可运行区间
     */
    [[nodiscard]] constexpr bool validServerConfig(const ServerConfig &cfg) noexcept
    {
        return cfg.backlog >= 1 && cfg.maxConnections >= 1 && cfg.idleTimeoutSecs >= 0 &&
               (cfg.engine == "reactor" || cfg.engine == "proactor");
    }

    /**
     * @brief 校验 Reactor 引擎配置是否处于可运行区间
     *
     * 引擎入口以此为契约前置条件：配置只允许来自 configHolder/config.lua，
     * 默认值与钳位规则集中在 config/lua.hpp 的 loadReactorSection 里，引擎侧不再
     * 另设兜底默认值。
     */
    [[nodiscard]] constexpr bool validReactorConfig(const ReactorConfig &cfg) noexcept
    {
        // 这里只回答"能不能跑起来"，不回答"是否推荐"。
        // maxEvents = 1 技术上合法（epoll_wait 接受任何 >0 的 maxevents），
        // 只是每轮只收一个事件、效率差；lua_config 里的 [16, 65536] 是配置允许区间。
        return cfg.maxEvents >= 1 && cfg.idleSweepIntervalMs >= 1;
    }

    /**
     * @brief 校验 Proactor 引擎配置是否处于可运行区间
     */
    [[nodiscard]] constexpr bool validProactorConfig(const ProactorConfig &cfg) noexcept
    {
        // cqEntries >= sqEntries 是内核对 IORING_SETUP_CQSIZE 的硬性要求，
        // 违反时 io_uring_queue_init_params() 返回 -EINVAL。
        // bufRingAlignment 必须是 2 的幂，否则 posix_memalign 返回 EINVAL。
        const bool alignmentIsPowerOfTwo =
            cfg.bufRingAlignment != 0 && (cfg.bufRingAlignment & (cfg.bufRingAlignment - 1)) == 0;
        return cfg.sqEntries >= 1 && cfg.cqEntries >= cfg.sqEntries && cfg.maxAcceptEvents >= 1 &&
               cfg.bufEntries >= 1 && cfg.bufSize >= 1 && cfg.udpBufSize >= 1 && alignmentIsPowerOfTwo &&
               cfg.cqeWaitMs >= 1;
    }

    /**
     * @brief 校验流式连接与请求响应管道配置是否合法
     */
    [[nodiscard]] constexpr bool validConnectionConfig(const ConnectionConfig &cfg) noexcept
    {
        return cfg.responseCapacity >= 1 && cfg.readChunkSize >= 1 && cfg.maxRequestBytes >= 1 &&
               cfg.writeHighWaterMark >= 1 && cfg.writeHardCapFactor >= 1 && cfg.spliceChunkSize >= 1 &&
               cfg.maxWriteIov >= 1 && cfg.readHighWaterMark >= 1 && cfg.maxDrainRounds >= 1;
    }

    /**
     * @brief 校验 UDP 数据报会话与外发队列配置是否合法
     */
    [[nodiscard]] constexpr bool validDatagramConfig(const DatagramConfig &cfg) noexcept
    {
        return cfg.maxDatagramBytes >= 1 && cfg.maxPendingOutgoing >= 1;
    }

    /**
     * @brief 校验 TLS 安全配置是否处于可运行区间
     */
    [[nodiscard]] constexpr bool validSecurityConfig(const SecurityConfig &cfg) noexcept
    {
        return cfg.minVersion >= 0x0303 && (cfg.maxVersion == 0 || cfg.maxVersion >= cfg.minVersion);
    }

    /**
     * @brief 校验 HTTP/1.x 边界限额配置是否处于可运行区间
     */
    [[nodiscard]] constexpr bool validHttp1Config(const Http1Config &cfg) noexcept
    {
        return cfg.maxUrlLength > 0 && cfg.maxHeadersCount > 0 && cfg.maxBodyLength > 0;
    }

    /**
     * @brief 校验 HTTP/2 协议流并发、初始窗口与帧大小配置是否处于可运行区间
     */
    [[nodiscard]] constexpr bool validHttp2Config(const Http2Config &cfg) noexcept
    {
        return cfg.maxConcurrentStreams >= 1 && cfg.initialWindowSize >= 1 && cfg.maxFrameSize >= 16384 &&
               cfg.maxHeaderListSize >= 1;
    }

    /**
     * @brief 校验 HTTP/3 边界限额配置是否处于可运行区间
     */
    [[nodiscard]] constexpr bool validHttp3Config(const Http3Config &cfg) noexcept
    {
        return cfg.maxRequestBodyBytes > 0 && cfg.maxStreamBufferBytes > 0 && cfg.port > 0;
    }

    /**
     * @brief 校验代理配置是否合法
     */
    [[nodiscard]] constexpr bool validProxyConfig(const ProxyConfig & /*cfg*/) noexcept
    {
        return true;
    }

    /**
     * @brief 校验转发中继引擎配置是否合法
     */
    [[nodiscard]] constexpr bool validForwarderConfig(const ForwarderConfig &cfg) noexcept
    {
        return cfg.spliceChunkSize >= 1 && cfg.bufferChunkSize >= 1 && cfg.sessionIdleTimeoutSecs >= 0 &&
               cfg.udpSessionTimeoutSecs >= 0;
    }

    /**
     * @brief 校验策略路由全局引擎配置是否合法
     */
    [[nodiscard]] inline bool validRouterConfig(const RouterConfig &cfg) noexcept
    {
        return !cfg.defaultOutbound.empty();
    }

    /**
     * @brief 校验 DNS 解析与缓存配置是否合法
     */
    [[nodiscard]] inline bool validDnsConfig(const DnsConfig &cfg) noexcept
    {
        return cfg.port > 0 && cfg.ttlSecs > 0;
    }

    /**
     * @brief 校验 eBPF 引擎配置是否合法
     */
    [[nodiscard]] inline bool validEbpfConfig(const EbpfConfig &cfg) noexcept
    {
        return !cfg.wanInterface.empty();
    }

    /**
     * @brief 校验 FakeIP 引擎配置是否合法
     */
    [[nodiscard]] inline bool validFakeIPConfig(const FakeIPConfig &cfg) noexcept
    {
        return cfg.maxCapacity >= 1 && !cfg.inetRange.empty();
    }

    /**
     * @brief 校验 Geo 资产配置是否合法
     */
    [[nodiscard]] constexpr bool validGeoConfig(const GeoConfig &) noexcept
    {
        return true;
    }

    /**
     * @brief 校验 Controller 控制平面配置是否合法
     */
    [[nodiscard]] inline bool validControllerConfig(const ControllerConfig &cfg) noexcept
    {
        return !cfg.host.empty();
    }

    /**
     * @brief 校验入站节点配置列表是否合法
     */
    [[nodiscard]] inline bool validInboundsConfig(const std::vector<InboundConfig> &inbounds) noexcept
    {
        for (const auto &inCfg : inbounds)
        {
            if (inCfg.tag.empty() || inCfg.protocol.empty())
            {
                return false;
            }
        }
        return true;
    }

    /**
     * @brief 校验出站节点配置列表是否合法
     */
    [[nodiscard]] inline bool validOutboundsConfig(const std::vector<OutboundConfig> &outbounds) noexcept
    {
        for (const auto &outCfg : outbounds)
        {
            if (outCfg.tag.empty() || outCfg.type.empty())
            {
                return false;
            }
        }
        return true;
    }

    /**
     * @brief 全局网络配置持有者单例
     */
    class MynetConfigHolder
    {
    public:
        [[nodiscard]] static ConfigHolder<MynetConfig> &getInstance() noexcept
        {
            static ConfigHolder<MynetConfig> instance{};
            return instance;
        }
    };

    /**
     * @brief 网络配置线程局部快照别名
     */
    using MynetConfigSnapshot = ConfigSnapshot<MynetConfig>;

    /**
     * @brief 获取当前全局配置的深拷贝副本
     */
    [[nodiscard]] inline MynetConfig getMynetConfig()
    {
        return MynetConfigHolder::getInstance().duplicate();
    }

    /**
     * @brief 获取当前全局配置的 RCU 共享智能指针 (零拷贝，生命周期自动延续)
     */
    [[nodiscard]] inline std::shared_ptr<const MynetConfig> getMynetConfigShared() noexcept
    {
        return MynetConfigHolder::getInstance().currentConfig();
    }

    // =========================================================================
    // 快照获取函数（Snapshot Accessors）
    // 按分层逻辑严格对齐：
    // 1. 服务端与底层引擎 (Server, Reactor, Proactor)
    // 2. 传输层会话与队列 (Connection, Datagram)
    // 3. 传输安全 (Security)
    // 4. 应用层协议与代理 (Http1, Http2, Http3, Proxy)
    // =========================================================================

    /**
     * @brief 获取当前全局服务端配置的无锁快照
     */
    [[nodiscard]] inline const ServerConfig &getServerConfig() noexcept
    {
        thread_local MynetConfigSnapshot snapshot(MynetConfigHolder::getInstance());
        return snapshot.refConfig().server;
    }

    /**
     * @brief 获取当前全局 Reactor 引擎配置的无锁快照
     */
    [[nodiscard]] inline const ReactorConfig &getReactorConfig() noexcept
    {
        thread_local MynetConfigSnapshot snapshot(MynetConfigHolder::getInstance());
        return snapshot.refConfig().reactor;
    }

    /**
     * @brief 获取当前全局 Proactor 引擎配置的无锁快照
     */
    [[nodiscard]] inline const ProactorConfig &getProactorConfig() noexcept
    {
        thread_local MynetConfigSnapshot snapshot(MynetConfigHolder::getInstance());
        return snapshot.refConfig().proactor;
    }

    /**
     * @brief 获取当前全局连接配置的无锁快照
     */
    [[nodiscard]] inline const ConnectionConfig &getConnectionConfig() noexcept
    {
        thread_local MynetConfigSnapshot snapshot(MynetConfigHolder::getInstance());
        return snapshot.refConfig().connection;
    }

    /**
     * @brief 获取当前全局数据报配置的无锁快照
     */
    [[nodiscard]] inline const DatagramConfig &getDatagramConfig() noexcept
    {
        thread_local MynetConfigSnapshot snapshot(MynetConfigHolder::getInstance());
        return snapshot.refConfig().datagram;
    }

    /**
     * @brief 获取当前全局 TLS 安全配置的无锁快照
     */
    [[nodiscard]] inline const SecurityConfig &getSecurityConfig() noexcept
    {
        thread_local MynetConfigSnapshot snapshot(MynetConfigHolder::getInstance());
        return snapshot.refConfig().security;
    }

    /**
     * @brief 获取当前全局 HTTP/1.x 边界限额配置的无锁快照
     */
    [[nodiscard]] inline const Http1Config &getHttp1Config() noexcept
    {
        thread_local MynetConfigSnapshot snapshot(MynetConfigHolder::getInstance());
        return snapshot.refConfig().http1;
    }

    /**
     * @brief 获取当前全局 HTTP/2 协议配置的无锁快照
     */
    [[nodiscard]] inline const Http2Config &getHttp2Config() noexcept
    {
        thread_local MynetConfigSnapshot snapshot(MynetConfigHolder::getInstance());
        return snapshot.refConfig().http2;
    }

    /**
     * @brief 获取当前全局 HTTP/3 (QUIC) 边界限额配置的无锁快照
     */
    [[nodiscard]] inline const Http3Config &getHttp3Config() noexcept
    {
        thread_local MynetConfigSnapshot snapshot(MynetConfigHolder::getInstance());
        return snapshot.refConfig().http3;
    }

    /**
     * @brief 获取当前全局代理配置的无锁快照
     */
    [[nodiscard]] inline const ProxyConfig &getProxyConfig() noexcept
    {
        thread_local MynetConfigSnapshot snapshot(MynetConfigHolder::getInstance());
        return snapshot.refConfig().proxy;
    }

    /**
     * @brief 获取当前全局转发器配置的无锁快照
     */
    [[nodiscard]] inline const ForwarderConfig &getForwarderConfig() noexcept
    {
        thread_local MynetConfigSnapshot snapshot(MynetConfigHolder::getInstance());
        return snapshot.refConfig().forwarder;
    }

    /**
     * @brief 获取当前全局策略路由配置的无锁快照
     */
    [[nodiscard]] inline const RouterConfig &getRouterConfig() noexcept
    {
        thread_local MynetConfigSnapshot snapshot(MynetConfigHolder::getInstance());
        return snapshot.refConfig().router;
    }

    /**
     * @brief 获取当前全局 DNS 配置的无锁快照
     */
    [[nodiscard]] inline const DnsConfig &getDnsConfig() noexcept
    {
        thread_local MynetConfigSnapshot snapshot(MynetConfigHolder::getInstance());
        return snapshot.refConfig().dns;
    }

    /**
     * @brief 获取当前全局 eBPF 引擎配置的无锁快照
     */
    [[nodiscard]] inline const EbpfConfig &getEbpfConfig() noexcept
    {
        thread_local MynetConfigSnapshot snapshot(MynetConfigHolder::getInstance());
        return snapshot.refConfig().ebpf;
    }

    /**
     * @brief 获取当前全局 FakeIP 引擎配置的无锁快照
     */
    [[nodiscard]] inline const FakeIPConfig &getFakeIPConfig() noexcept
    {
        thread_local MynetConfigSnapshot snapshot(MynetConfigHolder::getInstance());
        return snapshot.refConfig().fakeip;
    }

    /**
     * @brief 获取当前全局 Geo 资产配置的无锁快照
     */
    [[nodiscard]] inline const GeoConfig &getGeoConfig() noexcept
    {
        thread_local MynetConfigSnapshot snapshot(MynetConfigHolder::getInstance());
        return snapshot.refConfig().geo;
    }

    /**
     * @brief 获取当前全局 Controller 控制平面配置的无锁快照
     */
    [[nodiscard]] inline const ControllerConfig &getControllerConfig() noexcept
    {
        thread_local MynetConfigSnapshot snapshot(MynetConfigHolder::getInstance());
        return snapshot.refConfig().controller;
    }

    /**
     * @brief 获取当前全局入站监听节点列表的无锁快照
     */
    [[nodiscard]] inline const std::vector<InboundConfig> &getInboundsConfig() noexcept
    {
        thread_local MynetConfigSnapshot snapshot(MynetConfigHolder::getInstance());
        return snapshot.refConfig().inbounds;
    }

    /**
     * @brief 获取当前全局出站落地节点列表的无锁快照
     */
    [[nodiscard]] inline const std::vector<OutboundConfig> &getOutboundsConfig() noexcept
    {
        thread_local MynetConfigSnapshot snapshot(MynetConfigHolder::getInstance());
        return snapshot.refConfig().outbounds;
    }

    // =========================================================================
    // 配置发布函数（Publishers）
    // 按分层逻辑严格对齐：
    // 0. 全局网络配置 (MynetConfig)
    // 1. 服务端与底层引擎 (Server, Reactor, Proactor)
    // 2. 传输层会话与队列 (Connection, Datagram)
    // 3. 传输安全 (Security)
    // 4. 应用层协议与代理 (Http1, Http2, Http3, Proxy)
    // =========================================================================

    /**
     * @brief 原子发布新的全局网络配置
     */
    inline void publishMynetConfig(MynetConfig cfg)
    {
        MynetConfigHolder::getInstance().publish(std::move(cfg));
    }

    /**
     * @brief 原子发布新的服务端配置
     */
    inline void publishServerConfig(ServerConfig cfg)
    {
        contract_assert(validServerConfig(cfg));
        auto mynetCfg = getMynetConfig();
        mynetCfg.server = std::move(cfg);
        publishMynetConfig(std::move(mynetCfg));
    }

    /**
     * @brief 原子发布新的 Reactor 引擎专属配置
     */
    inline void publishReactorConfig(ReactorConfig cfg)
    {
        contract_assert(validReactorConfig(cfg));
        auto mynetCfg = getMynetConfig();
        mynetCfg.reactor = std::move(cfg);
        publishMynetConfig(std::move(mynetCfg));
    }

    /**
     * @brief 原子发布新的 Proactor 引擎专属配置
     */
    inline void publishProactorConfig(ProactorConfig cfg)
    {
        contract_assert(validProactorConfig(cfg));
        auto mynetCfg = getMynetConfig();
        mynetCfg.proactor = std::move(cfg);
        publishMynetConfig(std::move(mynetCfg));
    }

    /**
     * @brief 原子发布新的连接专属配置
     */
    inline void publishConnectionConfig(ConnectionConfig cfg)
    {
        contract_assert(validConnectionConfig(cfg));
        auto mynetCfg = getMynetConfig();
        mynetCfg.connection = std::move(cfg);
        publishMynetConfig(std::move(mynetCfg));
    }

    /**
     * @brief 原子发布新的数据报专属配置
     */
    inline void publishDatagramConfig(DatagramConfig cfg)
    {
        contract_assert(validDatagramConfig(cfg));
        auto mynetCfg = getMynetConfig();
        mynetCfg.datagram = std::move(cfg);
        publishMynetConfig(std::move(mynetCfg));
    }

    /**
     * @brief 原子发布新的 TLS 安全专属配置
     */
    inline void publishSecurityConfig(SecurityConfig cfg)
    {
        contract_assert(validSecurityConfig(cfg));
        auto mynetCfg = getMynetConfig();
        mynetCfg.security = std::move(cfg);
        publishMynetConfig(std::move(mynetCfg));
    }

    /**
     * @brief 原子发布新的 HTTP/1.x 专属配置
     */
    inline void publishHttp1Config(Http1Config cfg)
    {
        contract_assert(validHttp1Config(cfg));
        auto mynetCfg = getMynetConfig();
        mynetCfg.http1 = std::move(cfg);
        publishMynetConfig(std::move(mynetCfg));
    }

    /**
     * @brief 原子发布新的 HTTP/2 协议配置
     */
    inline void publishHttp2Config(Http2Config cfg)
    {
        contract_assert(validHttp2Config(cfg));
        auto mynetCfg = getMynetConfig();
        mynetCfg.http2 = std::move(cfg);
        publishMynetConfig(std::move(mynetCfg));
    }

    /**
     * @brief 原子发布新的 HTTP/3 专属配置
     */
    inline void publishHttp3Config(Http3Config cfg)
    {
        contract_assert(validHttp3Config(cfg));
        auto mynetCfg = getMynetConfig();
        mynetCfg.http3 = std::move(cfg);
        publishMynetConfig(std::move(mynetCfg));
    }

    /**
     * @brief 原子发布新的代理专属配置
     */
    inline void publishProxyConfig(ProxyConfig cfg)
    {
        contract_assert(validProxyConfig(cfg));
        auto mynetCfg = getMynetConfig();
        mynetCfg.proxy = std::move(cfg);
        publishMynetConfig(std::move(mynetCfg));
    }

    /**
     * @brief 原子发布新的转发中继专属配置
     */
    inline void publishForwarderConfig(ForwarderConfig cfg)
    {
        contract_assert(validForwarderConfig(cfg));
        auto mynetCfg = getMynetConfig();
        mynetCfg.forwarder = std::move(cfg);
        publishMynetConfig(std::move(mynetCfg));
    }

    /**
     * @brief 原子发布新的策略路由全局配置
     */
    inline void publishRouterConfig(RouterConfig cfg)
    {
        contract_assert(validRouterConfig(cfg));
        auto mynetCfg = getMynetConfig();
        mynetCfg.router = std::move(cfg);
        publishMynetConfig(std::move(mynetCfg));
    }

    /**
     * @brief 原子发布新的 DNS 解析配置
     */
    inline void publishDnsConfig(DnsConfig cfg)
    {
        contract_assert(validDnsConfig(cfg));
        auto mynetCfg = getMynetConfig();
        mynetCfg.dns = std::move(cfg);
        publishMynetConfig(std::move(mynetCfg));
    }

    /**
     * @brief 原子发布新的 eBPF 引擎配置
     */
    inline void publishEbpfConfig(EbpfConfig cfg)
    {
        contract_assert(validEbpfConfig(cfg));
        auto mynetCfg = getMynetConfig();
        mynetCfg.ebpf = std::move(cfg);
        publishMynetConfig(std::move(mynetCfg));
    }

    /**
     * @brief 原子发布新的 FakeIP 引擎配置
     */
    inline void publishFakeIPConfig(FakeIPConfig cfg)
    {
        contract_assert(validFakeIPConfig(cfg));
        auto mynetCfg = getMynetConfig();
        mynetCfg.fakeip = std::move(cfg);
        publishMynetConfig(std::move(mynetCfg));
    }

    /**
     * @brief 原子发布新的 Geo 资产配置
     */
    inline void publishGeoConfig(GeoConfig cfg)
    {
        contract_assert(validGeoConfig(cfg));
        auto mynetCfg = getMynetConfig();
        mynetCfg.geo = std::move(cfg);
        publishMynetConfig(std::move(mynetCfg));
    }

    /**
     * @brief 原子发布新的 Controller 控制平面配置
     */
    inline void publishControllerConfig(ControllerConfig cfg)
    {
        contract_assert(validControllerConfig(cfg));
        auto mynetCfg = getMynetConfig();
        mynetCfg.controller = std::move(cfg);
        publishMynetConfig(std::move(mynetCfg));
    }

    /**
     * @brief 原子发布新的入站监听节点列表配置
     */
    inline void publishInboundsConfig(std::vector<InboundConfig> cfg)
    {
        contract_assert(validInboundsConfig(cfg));
        auto mynetCfg = getMynetConfig();
        mynetCfg.inbounds = std::move(cfg);
        publishMynetConfig(std::move(mynetCfg));
    }

    /**
     * @brief 原子发布新的出站落地节点列表配置
     */
    inline void publishOutboundsConfig(std::vector<OutboundConfig> cfg)
    {
        contract_assert(validOutboundsConfig(cfg));
        auto mynetCfg = getMynetConfig();
        mynetCfg.outbounds = std::move(cfg);
        publishMynetConfig(std::move(mynetCfg));
    }

} // namespace mynet
