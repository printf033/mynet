#pragma once

/**
 * @file handler/sockmap.hpp
 * @brief eBPF BPF_MAP_TYPE_SOCKMAP 内核套接字流卸载与 Splice 零拷贝双模抽象
 *
 * 借鉴 dae 的 TCP Stream Offload (control/tcp_offload_linux.go)：
 * 1. 在具备 eBPF 环境的主机上，将握手完成的 clientFd 与 upstreamFd 写入 sockmap；
 *    由内核 sk_skb/tcp_offload_redirect 在套接字层直接重定向转发，达成 0 上下文切换。
 * 2. 在非 eBPF 或降级模式下，无缝回退至 mynet 原生 Linux splice(2) 管道零拷贝直通。
 */

#include "../connection.hpp"
#include "config/log.hpp"
#include <cstdint>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__linux__)
#include <linux/bpf.h>
#include <sys/syscall.h>
#endif

namespace mynet::handler::sockmap
{

    /**
     * @brief eBPF Sockmap 管理器
     */
    class SockmapManager
    {
    public:
        /**
         * @brief 探测当前系统是否挂载 BPF 文件系统或具备 BPF 权限
         */
        [[nodiscard]] static bool isSupported() noexcept
        {
#if defined(__linux__)
            struct stat st{};
            if (::stat("/sys/fs/bpf", &st) == 0 && S_ISDIR(st.st_mode))
            {
                return true;
            }
#endif
            return false;
        }

        /**
         * @brief 将套接字添加到 BPF_MAP_TYPE_SOCKMAP
         *
         * @param mapFd sockmap 的描述符
         * @param key 映射键
         * @param socketFd 待重定向的已连接套接字
         */
        static bool updateSockmap(int mapFd, uint32_t key, int socketFd) noexcept
        {
#if defined(__linux__) && defined(__NR_bpf)
            if (mapFd < 0 || socketFd < 0)
            {
                return false;
            }

            union bpf_attr attr{};
            attr.map_fd = static_cast<uint32_t>(mapFd);
            attr.key = reinterpret_cast<uint64_t>(&key);
            attr.value = reinterpret_cast<uint64_t>(&socketFd);
            attr.flags = BPF_ANY;

            long ret = ::syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
            return ret == 0;
#else
            (void)mapFd;
            (void)key;
            (void)socketFd;
            return false;
#endif
        }

        /**
         * @brief 将套接字从 sockmap 移除
         */
        static bool deleteSockmap(int mapFd, uint32_t key) noexcept
        {
#if defined(__linux__) && defined(__NR_bpf)
            if (mapFd < 0)
            {
                return false;
            }

            union bpf_attr attr{};
            attr.map_fd = static_cast<uint32_t>(mapFd);
            attr.key = reinterpret_cast<uint64_t>(&key);

            long ret = ::syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
            return ret == 0;
#else
            (void)mapFd;
            (void)key;
            return false;
#endif
        }

        /**
         * @brief 将客户端与远端服务端两个套接字关联入 sockmap
         *
         * 约定 key: clientKey = (clientFd << 1), upstreamKey = (clientFd << 1) | 1
         */
        static bool attachPair(int mapFd, int clientFd, int upstreamFd) noexcept
        {
            if (mapFd < 0 || clientFd < 0 || upstreamFd < 0)
            {
                return false;
            }
            const uint32_t key1 = static_cast<uint32_t>(clientFd) * 2;
            const uint32_t key2 = key1 + 1;

            if (!updateSockmap(mapFd, key1, upstreamFd))
            {
                return false;
            }
            if (!updateSockmap(mapFd, key2, clientFd))
            {
                deleteSockmap(mapFd, key1);
                return false;
            }
            return true;
        }

        /**
         * @brief 智能流卸载策略驱动：优先尝试 eBPF Sockmap 卸载，失败或未配置时回退至 splice
         *
         * @param handler 客户端入站处理器
         * @param clientFd 客户端套接字
         * @param upstreamFd 服务端套接字
         * @param sockmapFd 可选的 sockmap 描述符（-1 表示不使用 eBPF，直接使用 splice 零拷贝）
         * @return true 卸载成功（eBPF 或 splice 激活）
         */
        static bool enableOffloadOrSplice(HandlerConnection &handler, int clientFd, int upstreamFd,
                                          int sockmapFd = -1) noexcept
        {
            if (clientFd < 0 || upstreamFd < 0)
            {
                return false;
            }

            // 1. 若配置了有效的 sockmapFd，尝试 eBPF 内核套接字直接转发
            if (sockmapFd >= 0)
            {
                if (attachPair(sockmapFd, clientFd, upstreamFd))
                {
                    LOG_INFO("SockmapManager: eBPF sockmap offload attached between fd {} and {}",
                             clientFd, upstreamFd);
                    return true;
                }
                LOG_WARN("SockmapManager: sockmap attach failed, falling back to splice(2)");
            }

            // 2. 降级回退：使用 Linux splice(2) 管道零拷贝
            handler.setSpliceTarget(upstreamFd);
            return handler.isSpliceActive();
        }
    };

} // namespace mynet::handler::sockmap
