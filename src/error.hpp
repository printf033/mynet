#pragma once

#include "reflection.hpp"
#include <array>
#include <cstdint>
#include <expected>
#include <string_view>
#include <utility>

namespace mynet
{

    /**
     * @brief 库级运行时错误强类型枚举
     *
     * 消除所有负整数与魔数返回值。每个可能导致系统调用、OpenSSL 或 io_uring 失败的场景在此具有唯一命名。
     * 参数校验（如空指针、端口越界等调用方编程错误）通过 C++26 contract_assert 契约处理，不属于此枚举。
     */
    enum class ERR : uint8_t
    {
        ADDR_INVALID = 0,       ///< inet_pton() 地址解析失败
        SOCKET_FAILED,          ///< socket() 套接字创建失败
        SETSOCKOPT_FAILED,      ///< setsockopt() 设置选项失败
        BIND_FAILED,            ///< bind() 绑定地址失败
        LISTEN_FAILED,          ///< listen() 监听失败
        CONNECT_FAILED,         ///< connect() 连接对端失败
        EPOLL_CREATE_FAILED,    ///< epoll_create1() 创建失败
        EPOLL_CTL_FAILED,       ///< epoll_ctl() 增删改监听失败
        EPOLL_WAIT_FAILED,      ///< epoll_wait() 等待就绪事件致命错误
        EVENTFD_FAILED,         ///< eventfd() 跨线程唤醒管道创建失败
        SSL_CTX_FAILED,         ///< SSL_CTX_new() 创建上下文失败
        SSL_CERT_FAILED,        ///< 证书文件无法加载
        SSL_KEY_FAILED,         ///< 私钥文件无法加载
        SSL_KEY_MISMATCH,       ///< 私钥与证书不匹配
        SSL_CA_FAILED,          ///< CA 根证书束无法加载
        SSL_NEW_FAILED,         ///< SSL_new() 实例化会话失败
        SSL_SET_FD_FAILED,      ///< SSL_set_fd() 绑定文件描述符失败
        SSL_SNI_FAILED,         ///< SSL_set_tlsext_host_name() 设置 SNI 失败
        URING_QUEUE_FAILED,     ///< io_uring_queue_init_params() 初始化失败
        URING_MEMALIGN_FAILED,  ///< posix_memalign() 分配缓冲环对齐内存失败
        URING_BUF_RING_FAILED,  ///< io_uring_setup_buf_ring() 设置内核缓冲环失败
        URING_ACCEPT_EXHAUSTED, ///< Accept 投递操作池已耗尽
        URING_SQE_FAILED,       ///< io_uring_get_sqe() 提交队列已满
        URING_SUBMIT_FAILED,    ///< io_uring_submit() 提交请求失败
        URING_WAIT_FAILED,      ///< io_uring_wait_cqe() 等待完成队列失败
        ACCEPT_FAILED,          ///< accept4() 接收新连接失败
        STDOUT_FAILED,          ///< 客户端写入 stdout 失败（如对端管道断开）
        TIMER_NOT_FOUND,        ///< 定时器取消失败（已触发或不存在）
        NOT_INITIALISED         ///< 事件循环在初始化完成前被错误调用
    };

    /**
     * @brief 编译期校验 ERR 枚举总数与反射信息一致
     */
    inline constexpr size_t kErrCount = mylog::reflect::countEnumMembers<ERR>();
    static_assert(kErrCount == 29, "Expected 29 library runtime error enumerators");

    /**
     * @brief 非阻塞传输终止原因枚举
     *
     * 明确表达 recv() 或 send() 未传输字节时的常态动向，非系统级致命故障：
     * 需要重试（WOULDBLOCK）、信号中断（INTERRUPTED）、流结束（EOF_REACHED）或管道崩溃（FATAL）。
     */
    enum class IO_END : uint8_t
    {
        WOULDBLOCK = 0, ///< 套接字未就绪：等待下一轮可读或可写事件
        INTERRUPTED,    ///< 信号中断（EINTR）：调用方可立即就地重试
        EOF_REACHED,    ///< 对端有序关闭写入（FIN / close_notify）：流正常结束
        FATAL           ///< 传输链路彻底失效或损坏
    };

    /**
     * @brief 编译期校验 IO_END 枚举总数与反射信息一致
     */
    inline constexpr size_t kIoEndCount = mylog::reflect::countEnumMembers<IO_END>();
    static_assert(kIoEndCount == 4, "Expected 4 IO end outcomes");

    namespace detail
    {
        inline constexpr std::array<std::string_view, kErrCount> kErrDescriptions = {
            "the address could not be parsed",
            "socket() failed",
            "setsockopt() failed",
            "bind() failed",
            "listen() failed",
            "connect() failed",
            "epoll_create1() failed",
            "epoll_ctl() failed",
            "epoll_wait() failed",
            "eventfd() failed",
            "SSL_CTX_new() failed",
            "the certificate file could not be loaded",
            "the private key file could not be loaded",
            "the private key does not match the certificate",
            "the CA bundle could not be loaded",
            "SSL_new() failed",
            "SSL_set_fd() failed",
            "SSL_set_tlsext_host_name() failed",
            "io_uring_queue_init_params() failed",
            "posix_memalign() failed",
            "io_uring_setup_buf_ring() failed",
            "the accept queue had no op left to post",
            "io_uring_get_sqe() returned nothing",
            "io_uring_submit() failed",
            "io_uring_wait_cqe() failed",
            "accept4() failed",
            "write() to stdout failed",
            "no timer with that id is armed",
            "the event loop was not initialised"};

        static_assert(kErrDescriptions.size() == kErrCount, "kErrDescriptions count must match ERR enum member count");

        inline constexpr std::array<std::string_view, kIoEndCount> kIoEndDescriptions = {
            "socket would block", "operation interrupted by signal", "orderly end of stream", "fatal link failure"};

        static_assert(kIoEndDescriptions.size() == kIoEndCount,
                      "kIoEndDescriptions count must match IO_END enum member count");
    } // namespace detail

    /**
     * @brief 获取错误枚举字面量标识符名称
     *
     * 借助 C++26 静态反射在编译期提取枚举项名称（例如 "ADDR_INVALID"）。
     *
     * @param err 错误枚举值
     * @return constexpr std::string_view 对应的枚举标识符
     */
    [[nodiscard]] constexpr std::string_view nameOf(ERR err) noexcept
    {
        return mylog::reflect::enumToString(err);
    }

    /**
     * @brief 获取传输终止原因枚举字面量标识符名称
     *
     * @param end 传输终止原因枚举值
     * @return constexpr std::string_view 对应的枚举标识符（例如 "WOULDBLOCK"）
     */
    [[nodiscard]] constexpr std::string_view nameOf(IO_END end) noexcept
    {
        return mylog::reflect::enumToString(end);
    }

    /**
     * @brief 获取错误枚举的人类可读文本描述
     *
     * 基于编译期静态表进行 O(1) 无分支查表映射，避免传统 switch-case 的跳转开销。
     *
     * @param err 错误枚举值
     * @return constexpr std::string_view 对应的错误解释文本
     */
    [[nodiscard]] constexpr std::string_view toString(ERR err) noexcept
    {
        const auto idx = static_cast<size_t>(std::to_underlying(err));
        if (idx < detail::kErrDescriptions.size()) [[likely]]
        {
            return detail::kErrDescriptions[idx];
        }
        return "unknown error";
    }

    /**
     * @brief 获取传输终止原因枚举的文本描述
     *
     * @param end 传输终止原因枚举值
     * @return constexpr std::string_view 对应的终止描述文本
     */
    [[nodiscard]] constexpr std::string_view toString(IO_END end) noexcept
    {
        const auto idx = static_cast<size_t>(std::to_underlying(end));
        if (idx < detail::kIoEndDescriptions.size()) [[likely]]
        {
            return detail::kIoEndDescriptions[idx];
        }
        return "unknown io outcome";
    }

    inline constexpr int kGenericExitCode = 1;

    /**
     * @brief 标准失败/成功返回类型别名 (C++23 std::expected)
     *
     * 消除语义倒置的 std::optional<ERR>，统一全库错误返回模型：
     * - 成功：返回空值包装 {}
     * - 失败：返回 std::unexpected(ERR::...)
     */
    template <typename T = void>
    using Result = std::expected<T, ERR>;

    /**
     * @brief 将错误枚举转换为标准进程退出状态码
     *
     * 退出码规范：
     * - 0: 成功退出
     * - 1: 未知错误/通用异常退出 (kGenericExitCode)
     * - 2..N: 强类型库级运行时错误码（从 2 起跳，与未知错误 1 彻底隔离）
     *
     * @param err 错误枚举
     * @return constexpr int 返回非 0 退出码
     */
    [[nodiscard]] constexpr int toExitCode(ERR err) noexcept
    {
        const auto idx = static_cast<size_t>(std::to_underlying(err));
        if (idx < detail::kErrDescriptions.size()) [[likely]]
        {
            return static_cast<int>(idx) + 2;
        }
        return kGenericExitCode;
    }

} // namespace mynet
