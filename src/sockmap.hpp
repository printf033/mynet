#pragma once

/**
 * @file sockmap.hpp
 * @brief eBPF BPF_MAP_TYPE_SOCKMAP 内核套接字流卸载与 Splice 零拷贝双模抽象（实验性原型接口）
 *
 * 【现状与技术定位说明】：
 * 1. 本类为借鉴 dae TCP Stream Offload 设计的实验性套接字映射接口原型（提供用户态 BPF map 系统调用封装）。
 * 2. 完整的 eBPF 内核重定向必须依赖内核态挂载的 sk_skb 程序（BPF_PROG_TYPE_SK_SKB /
 *    BPF_SK_SKB_STREAM_VERDICT，如通过 tc / bpftool 或外部 daemon 预先挂载至 sockmap 描述符）。
 *    mynet 当前未内置编译、加载或挂载 eBPF 字节码程序，因此单纯写入 sockmap 不会自动产生内核转发行为。
 * 3. 在当前项目的主线业务代理链路中（如 HandlerInboundRedirect / HandlerInboundTProxy），
 *    实际运行的零拷贝转发路径 100% 由原生 Linux splice(2) 双向管道零拷贝直通驱动。
 * 4. enableOffloadOrSplice() 作为双模策略接口：当未提供已挂载转发程序的 sockmapFd 时（默认 -1），
 *    平滑回退至 splice(2) 零拷贝直通。
 */

#include "connection.hpp"
#include "config/log.hpp"
#include <cstdint>
#include <unistd.h>

#if defined(__linux__)
#include <linux/bpf.h>
#include <linux/magic.h>
#include <sys/syscall.h>
#include <sys/vfs.h>

#ifndef BPF_FS_MAGIC
#define BPF_FS_MAGIC 0xcafe4a11
#endif
#endif

namespace mynet
{

    /**
     * @brief eBPF Sockmap 用户态接口管理器（实验性原型 / Splice 降级抽象）
     *
     * 注意：仅向 sockmap 写入套接字 fd 不会自动重定向数据；完整的内核转发需预先将
     * BPF_SK_SKB_STREAM_VERDICT 程序挂载到 sockmapFd 上。未提供有效描述符时默认回退至 splice(2)。
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
            struct statfs fs{};
            if (::statfs("/sys/fs/bpf", &fs) == 0 &&
                static_cast<unsigned long>(fs.f_type) == static_cast<unsigned long>(BPF_FS_MAGIC))
            {
                return true;
            }

#if defined(__NR_bpf)
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
#endif
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

} // namespace mynet

namespace mynet::sockmap
{
    using mynet::SockmapManager;
}

namespace mynet::handler::sockmap
{
    using mynet::SockmapManager;
}
