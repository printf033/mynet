#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>

namespace mynet
{

    /**
     * @brief 线程安全配置容器（发布者）
     *
     * 采用版本代次（Generation Counter）机制实现发布-订阅模式。
     * 配置写入（发布）由互斥锁保护，并通过原子代次递增对外发布版本更新；
     * 配合 ConfigSnapshot 可实现读路径零锁、零竞争的高性能无锁快照访问。
     *
     * @tparam T 配置对象类型，要求支持移动构造与拷贝构造
     */
    template <typename T>
    class ConfigHolder
    {
        mutable std::mutex mtx_;
        T value_{};
        std::atomic<uint32_t> generation_{1};

    public:
        ConfigHolder() = default;
        explicit ConfigHolder(T initial)
            : value_(std::move(initial))
        {
        }
        ConfigHolder(const ConfigHolder &) = delete;
        ConfigHolder &operator=(const ConfigHolder &) = delete;

        /**
         * @brief 发布新配置并递增版本代次
         *
         * 在互斥锁保护下更新内部配置对象，并通过 release 内存序递增代次，
         * 通知所有持有 ConfigSnapshot 的读取线程在下次访问时同步最新配置。
         *
         * @param value 新的配置实例（通过移动语义传入以避免冗余拷贝）
         */
        void publish(T value)
        {
            {
                std::lock_guard<std::mutex> lock(mtx_);
                value_ = std::move(value);
            }
            generation_.fetch_add(1, std::memory_order_release);
        }

        /**
         * @brief 复制当前配置实例
         *
         * 在互斥锁保护下深拷贝当前保存的配置对象，供快照同步或外部查询使用。
         *
         * @return T 当前配置对象的完整副本
         */
        [[nodiscard]] T duplicate() const
        {
            std::lock_guard<std::mutex> lock(mtx_);
            return value_;
        }

        /**
         * @brief 获取当前配置的版本代次
         *
         * 使用 acquire 内存序读取原子代次计数器，用于无锁快速判断配置是否已被修改。
         *
         * @return uint32_t 当前配置版本代次号
         */
        [[nodiscard]] uint32_t getGeneration() const noexcept { return generation_.load(std::memory_order_acquire); }
    };

    /**
     * @brief 线程局部配置快照（订阅者）
     *
     * 绑定至指定的 ConfigHolder，通常作为 thread_local 变量使用。
     * 每次访问时仅需一次原子 acquire 读校验代次；若代次未变则直接返回线程私有引用的只读配置，
     * 做到热路径完全零锁、零内存拷贝与零缓存行争用。
     *
     * @tparam T 配置对象类型
     */
    template <typename T>
    class ConfigSnapshot
    {
        const ConfigHolder<T> &holder_;
        T local_{};
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
         * @brief 获取最新配置的常量引用
         *
         * 快速检查容器版本代次。若版本发生递增，则加锁拉取最新配置副本至本线程私有缓存，
         * 并同步代次号；若未更新则直接返回本线程缓存的配置引用。
         *
         * @return const T& 当前生效配置的常量引用
         */
        inline const T &refConfig() noexcept
        {
            const uint32_t gen = holder_.getGeneration();
            if (gen != generation_)
            {
                local_ = holder_.duplicate();
                generation_ = gen;
            }
            return local_;
        }

        /**
         * @brief 便捷别名接口
         */
        inline const T &get() noexcept { return refConfig(); }
    };

    /**
     * @brief 服务端基础连接与网络配置
     */
    struct ServerConfig
    {
        std::string host = "0.0.0.0";
        uint16_t port = 8888;
        int backlog = 128;
        size_t maxConnections = 65536;
        size_t keepAliveTimeout_ms = 60000;
        size_t writeHighWaterMark = 4 << 20; // 4 MiB
        size_t maxRequestBytes = 4 << 20;    // 4 MiB
        bool tcpNoDelay = true;
        bool tcpQuickAck = false;
        bool enableSplice = true;
    };

    /**
     * @brief io_uring Proactor 引擎专用配置
     */
    struct ProactorConfig
    {
        size_t sqEntries = 2048;
        size_t bufEntries = 1024;
        size_t bufSize = 4096;
    };

    /**
     * @brief HTTP/2 多路复用器流式并发与窗口配置
     */
    struct MultiplexerConfig
    {
        size_t maxConcurrentStreams = 100;
        size_t initialWindowSize = 65535;
        size_t maxFrameSize = 16384;
        size_t maxHeaderListSize = 8192;
    };

    /**
     * @brief TLS 安全传输与 ALPN 协商配置
     */
    struct SecurityConfig
    {
        bool enableTls = false;
        std::string certFile;
        std::string keyFile;
        std::string caFile;
        std::string ciphers = "DEFAULT";
        std::string alpnProtocols = "h2,http/1.1";
    };

    /**
     * @brief mynet 全局综合网络配置
     */
    struct NetConfig
    {
        ServerConfig server{};
        ProactorConfig proactor{};
        MultiplexerConfig multiplexer{};
        SecurityConfig security{};
    };

    /**
     * @brief 全局网络配置持有者单例
     */
    class NetConfigHolder
    {
    public:
        [[nodiscard]] static ConfigHolder<NetConfig> &getInstance() noexcept
        {
            static ConfigHolder<NetConfig> instance{};
            return instance;
        }
    };

    /**
     * @brief 网络配置线程局部快照别名
     */
    using NetConfigSnapshot = ConfigSnapshot<NetConfig>;

    /**
     * @brief 获取当前全局配置的深拷贝副本
     */
    [[nodiscard]] inline NetConfig getNetConfig()
    {
        return NetConfigHolder::getInstance().duplicate();
    }

    /**
     * @brief 原子发布新的全局网络配置
     */
    inline void publishNetConfig(NetConfig cfg)
    {
        NetConfigHolder::getInstance().publish(std::move(cfg));
    }

} // namespace mynet
