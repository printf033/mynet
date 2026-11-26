// SPDX-License-Identifier: GPL-2.0-only
/**
 * @file mynet_kernel.bpf.c
 * @brief 真实 Linux 内核态 eBPF TC 分流、SOCKHASH 流卸载、双 Epoch 热重载、旁路由非对称 MAC 改写与 cgroup 感知驱动
 */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ACTION_DIRECT 0
#define ACTION_PROXY  1
#define ACTION_BLOCK  2

#define TASK_COMM_LEN 16

/* 5元组键结构，用于 fast_sock 套接字无锁直连中继与 UDP 连接状态追踪 */
struct tuples_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  proto;
    __u8  pad[3];
};

/* LPM Trie IPv4 键结构 */
struct bpf_lpm_key_ipv4 {
    __u32 prefixlen;
    __u32 ip;
};

/* LPM Trie IPv6 键结构 */
struct bpf_lpm_key_ipv6 {
    __u32 prefixlen;
    __u8  ip[16];
};

/* 进程信息映射 */
struct pid_pname {
    __u32 pid;
    char  pname[TASK_COMM_LEN];
    __u64 last_seen_ns;
};

/* 全局控制配置 */
struct mynet_bpf_config {
    __u16 tproxy_port;
    __u16 pad;
    __u32 fwmark;
    __u8  direct_bypass;
    __u8  drop_quic;
    __u16 wan_ifindex;
    __u8  active_epoch;          /* 0 or 1, 双 Epoch 热重载活跃槽位 */
    __u8  asymmetric_gateway;    /* 旁路由非对称 MAC 改写开关 */
    __u8  gateway_mac[6];        /* 上级物理网关 (Next Hop) MAC */
    __u8  wan_mac[6];            /* 本机 WAN 口源 MAC */
    __u8  enable_sk_assign;      /* 1 = 开启 bpf_sk_assign 内核直绑免 iptables */
    __u8  redirect_ifindex;      /* 内部隔离通道 (veth/netkit/mynet0) ifindex */
    __u16 rate_limit_window_ms;  /* 阻断/泛洪事件内核令牌桶限速窗口毫秒数，默认 1000ms */
    __u8  tproxy_port_protect;   /* 1 = 丢弃未经 eBPF 授权直连 tproxy_port 的外来报文 */
    __u8  pad3;                  /* 保持 32 字节对齐 */
};

/* 1. LPM Trie Maps: 双槽位 (Epoch 0 & 1) 零停机热重载 IPv4 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct bpf_lpm_key_ipv4);
    __type(value, __u32);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} mynet_lpm_trie_ipv4_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct bpf_lpm_key_ipv4);
    __type(value, __u32);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} mynet_lpm_trie_ipv4_1 SEC(".maps");

/* 2. LPM Trie Maps: 双槽位 (Epoch 0 & 1) 零停机热重载 IPv6 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct bpf_lpm_key_ipv6);
    __type(value, __u32);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} mynet_lpm_trie_ipv6_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct bpf_lpm_key_ipv6);
    __type(value, __u32);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} mynet_lpm_trie_ipv6_1 SEC(".maps");

/* 3. Direct IPs Hash Map: 快速直连 IP 哈希表 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 16384);
} mynet_direct_ips SEC(".maps");

/* 4. Global Config Array: 运行时动态参数 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct mynet_bpf_config);
    __uint(max_entries, 1);
} mynet_config SEC(".maps");

/* 5. SOCKHASH: 真正的 TCP 套接字对内核快速转发流表 */
struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __type(key, struct tuples_key);
    __type(value, __u64);
    __uint(max_entries, 65536);
} mynet_fast_sock SEC(".maps");

/* 6. Cookie to PID / Process Name Map: cgroupv2 秒级进程感知表 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct pid_pname);
    __uint(max_entries, 65536);
} mynet_cookie_pid_map SEC(".maps");

/* 7. Direct Stats Map: 内核级直连旁路流量全景统计 (借鉴 dae direct_stats) */
struct direct_stats_val {
    __u64 bytes;
    __u64 packets;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct direct_stats_val);
    __uint(max_entries, 2);
} mynet_direct_stats SEC(".maps");

/* 8. Conn State Map: UDP & TCP 5元组连接状态与保活追踪表 (借鉴 dae conn_state_map) */
struct conn_state_entry {
    __u32 action;
    __u32 fwmark;
    __u64 last_seen_ns;
    __u64 packets;
    __u64 bytes;
    __u8  dscp;
    __u8  pad[7];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct tuples_key);
    __type(value, struct conn_state_entry);
    __uint(max_entries, 65536);
} mynet_conn_state_map SEC(".maps");

/* 9. Listen Socket Map: SOCKMAP 套接字直接绑定表，供 bpf_sk_assign 零开销分流 */
struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __type(key, __u32);   /* 0: tcp4, 1: udp, 2: tcp6 */
    __type(value, __u64); /* socket fd */
    __uint(max_entries, 4);
} mynet_listen_sock_map SEC(".maps");

/* 10. Block Rate Map: 阻断与恶意扫描内核自适应限速表 (借鉴 dae alive_block_rate_map) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64); /* last_seen_ns */
    __uint(max_entries, 256);
} mynet_block_rate_map SEC(".maps");

/* 11. TCP Offload Pause: Sockmap 内核背压熔断表 (借鉴 dae tcp_offload_pause) */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct tuples_key);
    __type(value, __u8);
    __uint(max_entries, 65536);
} mynet_tcp_offload_pause SEC(".maps");

/* 12. Outbound Connectivity Map: 内核态出站节点健康感知表 (借鉴 dae outbound_connectivity_map) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);   /* outbound_id * 6 + domain * 2 + ipversion */
    __type(value, __u32); /* 1: 存活, 0: 离线 */
    __uint(max_entries, 1536);
} mynet_outbound_connectivity SEC(".maps");

/* 13. Event RingBuffer: 内核异步事件通知环形缓冲区 (借鉴 dae event_ringbuf) */
enum mynet_event_type {
    MYNET_EVENT_BLOCKED = 1,
    MYNET_EVENT_BLOCKED_ALIVE = 2,
    MYNET_EVENT_UDP_OVERFLOW = 3,
    MYNET_EVENT_TCP_OVERFLOW = 4,
};

struct mynet_event {
    __u64 timestamp_ns;
    __u32 type;
    __u32 pid;
    __u16 sport;
    __u16 dport;
    __u8  protocol;
    __u8  pad[3];
    __u32 saddr;
    __u32 daddr;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} mynet_event_ringbuf SEC(".maps");

/* 14. BPF Stats Map: 内核数据面性能与异常诊断统计表 (借鉴 dae bpf_stats_map) */
enum mynet_bpf_stat_key {
    MYNET_STAT_DIRECT_PACKETS = 0,
    MYNET_STAT_PROXY_PACKETS = 1,
    MYNET_STAT_BLOCK_PACKETS = 2,
    MYNET_STAT_L3_PACKETS = 3,
    MYNET_STAT_EVENT_DROPS = 4,
    MYNET_STAT_MAX = 8,
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, MYNET_STAT_MAX);
} mynet_bpf_stats_map SEC(".maps");

/* 15. Domain Routing Map: DNS 解析域名分流规则位图内核投影表 (借鉴 dae domain_routing_map) */
struct domain_routing_key {
    __u32 ip;
    __u8  slot;
    __u8  pad[3];
};

struct domain_routing_val {
    __u32 rule_bitmap[4];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct domain_routing_key);
    __type(value, struct domain_routing_val);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} mynet_domain_routing SEC(".maps");

/* 16. Routing Handoff Map: 内核计算路由结果向用户态零拷贝快速交接表 (借鉴 dae routing_handoff_map) */
struct routing_handoff_entry {
    __u64 last_seen_ns;
    __u32 mark;
    __u16 outbound;
    __u8  dscp;
    __u8  must;
    __u8  mac[6];
    __u8  epoch_slot;
    __u8  pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct tuples_key);
    __type(value, struct routing_handoff_entry);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} mynet_routing_handoff SEC(".maps");

/* 17. Redirect Track Map: 代理回包以太网定向直通路由表 (借鉴 dae redirect_track) */
struct redirect_track_entry {
    __u32 ifindex;
    __u8  from_wan;
    __u8  smac[6];
    __u8  dmac[6];
    __u64 last_seen_ns;
};

#define MYNET_EVENT_REDIRECT_REBIND_REJECTED 5
#define MYNET_STAT_REDIRECT_REBIND_REJECTED 10
#define DEFAULT_REDIRECT_REBIND_STALE_NS 5000000000ULL /* 5 seconds */

static __always_inline bool mac6_equal(const __u8 *a, const __u8 *b)
{
    for (int i = 0; i < 6; i++) {
        if (a[i] != b[i])
            return false;
    }
    return true;
}

/* 17.1 Per-CPU Array 暂存表：彻底突破 eBPF 512 字节栈深限制 (借鉴 dae parse_ctx_scratch_map & pkt_scratch_map) */
struct parse_transport_ctx {
    struct tuples_key tuples;
    __u32 l4_offset;
    __u16 payload_len;
    __u8  tcp_flags;
    __u8  dscp;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct parse_transport_ctx);
    __uint(max_entries, 1);
} parse_ctx_scratch_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct mynet_event);
    __uint(max_entries, 1);
} pkt_scratch_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct tuples_key);
    __type(value, struct redirect_track_entry);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} mynet_redirect_track SEC(".maps");

static __always_inline void bump_bpf_stat(__u32 key)
{
    __u64 *val = bpf_map_lookup_elem(&mynet_bpf_stats_map, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
}

static __always_inline void emit_bpf_event(__u32 type, __u32 saddr, __u32 daddr, __u16 sport, __u16 dport, __u8 proto)
{
    struct mynet_event *e = bpf_ringbuf_reserve(&mynet_event_ringbuf, sizeof(*e), 0);
    if (!e) {
        bump_bpf_stat(MYNET_STAT_EVENT_DROPS);
        return;
    }
    e->timestamp_ns = bpf_ktime_get_ns();
    e->type = type;
    e->pid = 0;
    e->sport = sport;
    e->dport = dport;
    e->protocol = proto;
    e->pad[0] = e->pad[1] = e->pad[2] = 0;
    e->saddr = saddr;
    e->daddr = daddr;
    bpf_ringbuf_submit(e, 0);
}

static __always_inline bool is_block_rate_limited(__u32 key, __u16 window_ms)
{
    __u64 *last = bpf_map_lookup_elem(&mynet_block_rate_map, &key);
    if (!last)
        return true;
    __u64 old = *last;
    __u64 now = bpf_ktime_get_ns();
    __u64 window_ns = (__u64)(window_ms > 0 ? window_ms : 1000) * 1000000ULL;
    if (now - old < window_ns)
        return true; /* 已被限速：静默黑洞丢弃 */
    if (__sync_val_compare_and_swap(last, old, now) != old)
        return true;
    return false;
}

static __always_inline void account_direct_traffic(struct __sk_buff *skb)
{
    __u32 key = 0;
    struct direct_stats_val *val = bpf_map_lookup_elem(&mynet_direct_stats, &key);
    if (val) {
        val->bytes += skb->len;
        val->packets += 1;
    }
}

#ifndef TC_ACT_PIPE
#define TC_ACT_PIPE 3
#endif

/* 严格内存对齐内核下的安全 L3 数据包加载器 (借鉴 dae strict-alignment pkt_load16/pkt_load32, 机制 75) */
static __always_inline __u16 mynet_pkt_load16(const void *p, bool is_layer3)
{
    if (!is_layer3)
        return *(const __u16 *)p;
    return *(const volatile __u16 *)p;
}

static __always_inline __u32 mynet_pkt_load32(const void *p, bool is_layer3)
{
    union {
        __u16 half[2];
        __u32 word;
    } v;
    if (!is_layer3)
        return *(const __u32 *)p;
    v.half[0] = mynet_pkt_load16(p, is_layer3);
    v.half[1] = mynet_pkt_load16((const __u16 *)p + 1, is_layer3);
    return v.word;
}

/* 短生命周期 UDP 流量判定 (如 DNS 53 端口查询)，跳过连接跟踪以避免 Map 挤占耗尽 (机制 65: is_short_lived_udp_traffic) */
static __always_inline bool is_short_lived_udp_traffic(__u16 sport, __u16 dport)
{
    if (sport == bpf_htons(53) || dport == bpf_htons(53)) {
        return true;
    }
    return false;
}

/* 直连报文分发与旁路由非对称 MAC 改写 (Asymmetric Gateway Routing) */
static __always_inline int handle_direct_packet(struct __sk_buff *skb, struct ethhdr *eth, void *data_end, struct mynet_bpf_config *cfg, bool is_layer3)
{
    account_direct_traffic(skb);
    bump_bpf_stat(MYNET_STAT_DIRECT_PACKETS);
    if (!is_layer3 && eth && cfg->asymmetric_gateway && cfg->wan_ifindex > 0 && (void *)(eth + 1) <= data_end) {
        __builtin_memcpy(eth->h_dest, cfg->gateway_mac, 6);
        __builtin_memcpy(eth->h_source, cfg->wan_mac, 6);
        return bpf_redirect(cfg->wan_ifindex, 0);
    }
    /* 机制 79: 返回 TC_ACT_PIPE 允许同链后续 TC 过滤器 (QoS, 防火墙等) 继续执行 */
    return TC_ACT_PIPE;
}

/* 代理套接字内核直接指定 (bpf_sk_assign) 与免 iptables 重定向 */
static __always_inline int assign_proxy_listener(struct __sk_buff *skb, __u8 l4proto, int is_ipv6)
{
    __u32 key = 1; /* 1: UDP */
    if (l4proto == IPPROTO_TCP) {
        key = is_ipv6 ? 2 : 0;
    }
    struct bpf_sock *sk = bpf_map_lookup_elem(&mynet_listen_sock_map, &key);
    if (!sk)
        return -1;
    int ret = bpf_sk_assign(skb, sk, 0);
    bpf_sk_release(sk);
    return ret;
}

/* 代理报文统一调度路径：优先 bpf_sk_assign，次选虚拟接口重定向，保底打标 fwmark */
static __always_inline int handle_proxy_packet(struct __sk_buff *skb, __u8 l4proto, int is_ipv6, struct mynet_bpf_config *cfg)
{
    bump_bpf_stat(MYNET_STAT_PROXY_PACKETS);
    if (cfg->enable_sk_assign) {
        if (assign_proxy_listener(skb, l4proto, is_ipv6) == 0) {
            return TC_ACT_OK;
        }
    }
    if (cfg->redirect_ifindex > 0) {
        return bpf_redirect(cfg->redirect_ifindex, 0);
    }
    skb->mark = cfg->fwmark;
    return TC_ACT_OK;
}

/* ========================================================================= */
/* 核心 1：TC / TCX 驱动层分流决断过滤器 (Ingress / Egress)                  */
/* ========================================================================= */

#define HEADER_PULL_SIZE 128

SEC("tc")
int mynet_tc_filter(struct __sk_buff *skb)
{
    /* GRO/GSO 大包重组线性拉取：拉取 128 字节头部确保跨页非线性 SKB 安全访问 */
    if (skb->len >= HEADER_PULL_SIZE) {
        bpf_skb_pull_data(skb, HEADER_PULL_SIZE);
    }

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* L2 (以太网) 与 L3 (WireGuard/TUN/Tailscale) 自适应报文解析 (借鉴 dae l2/l3 separation) */
    void *l3_hdr = NULL;
    __u16 eth_proto = 0;
    bool is_layer3 = false;
    struct ethhdr *eth = NULL;

    if ((void *)(data + sizeof(struct ethhdr)) <= data_end) {
        struct ethhdr *candidate = data;
        __u16 p = bpf_ntohs(candidate->h_proto);
        if (p == ETH_P_IP || p == ETH_P_IPV6) {
            eth = candidate;
            eth_proto = p;
            l3_hdr = (void *)(eth + 1);
        }
    }

    if (!l3_hdr) {
        __u16 skb_proto = bpf_ntohs(skb->protocol);
        if (skb_proto == ETH_P_IP && (void *)(data + sizeof(struct iphdr)) <= data_end) {
            struct iphdr *iph = data;
            if (iph->version == 4) {
                eth_proto = ETH_P_IP;
                l3_hdr = data;
                is_layer3 = true;
                bump_bpf_stat(MYNET_STAT_L3_PACKETS);
            }
        } else if (skb_proto == ETH_P_IPV6 && (void *)(data + sizeof(struct ipv6hdr)) <= data_end) {
            struct ipv6hdr *ip6h = data;
            if (ip6h->version == 6) {
                eth_proto = ETH_P_IPV6;
                l3_hdr = data;
                is_layer3 = true;
                bump_bpf_stat(MYNET_STAT_L3_PACKETS);
            }
        }
    }

    if (!l3_hdr)
        return TC_ACT_OK;

    __u32 key_idx = 0;
    struct mynet_bpf_config *cfg = bpf_map_lookup_elem(&mynet_config, &key_idx);
    if (!cfg)
        return TC_ACT_OK;

    if (eth_proto == ETH_P_IP) {
        struct iphdr *ip = l3_hdr;
        if ((void *)(ip + 1) > data_end)
            return TC_ACT_OK;

        /* 局域网组播 (224.0.0.0/4) 与广播/保留网段 (240.0.0.0/4 - 255.255.255.255) 绝对放行直连 (借鉴 dae 224.0.0.0/3) */
        if ((bpf_ntohl(ip->daddr) & 0xE0000000) == 0xE0000000) {
            return handle_direct_packet(skb, eth, data_end, cfg, is_layer3);
        }

        /* TProxy 端口外网未授权入站硬防护 (借鉴 dae tproxy_port_protect) */
        if (cfg->tproxy_port_protect) {
            __u16 dport_val = 0;
            if (ip->protocol == IPPROTO_TCP) {
                struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
                if ((void *)(tcp + 1) <= data_end) dport_val = bpf_ntohs(tcp->dest);
            } else if (ip->protocol == IPPROTO_UDP) {
                struct udphdr *udp = (void *)ip + (ip->ihl * 4);
                if ((void *)(udp + 1) <= data_end) dport_val = bpf_ntohs(udp->dest);
            }
            if (dport_val == cfg->tproxy_port && skb->mark != cfg->fwmark) {
                bump_bpf_stat(MYNET_STAT_BLOCK_PACKETS);
                return TC_ACT_SHOT;
            }
        }

        /* DNS 域名分流位图内核快速投影匹配 (借鉴 dae domain_routing_map) */
        struct domain_routing_key d_key = {
            .ip = ip->daddr,
            .slot = cfg->active_epoch
        };
        struct domain_routing_val *d_val = bpf_map_lookup_elem(&mynet_domain_routing, &d_key);
        if (d_val && d_val->rule_bitmap[0] != 0) {
            if (d_val->rule_bitmap[0] & 0x01) {
                return handle_direct_packet(skb, eth, data_end, cfg, is_layer3);
            }
            if (d_val->rule_bitmap[0] & 0x02) {
                is_block_rate_limited(0, cfg->rate_limit_window_ms);
                bump_bpf_stat(MYNET_STAT_BLOCK_PACKETS);
                return TC_ACT_SHOT;
            }
        }

        /* TCP 状态流表化快速放行与单网卡双角色反向流匹配 (借鉴 dae TCP flow tracking & wan_lan_ingress) */
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
            if ((void *)(tcp + 1) <= data_end) {
                struct tuples_key tcp_key = {
                    .saddr = ip->saddr,
                    .daddr = ip->daddr,
                    .sport = tcp->source,
                    .dport = tcp->dest,
                    .proto = IPPROTO_TCP
                };
                struct conn_state_entry *cs = bpf_map_lookup_elem(&mynet_conn_state_map, &tcp_key);
                if (cs) {
                    cs->last_seen_ns = bpf_ktime_get_ns();
                    cs->packets += 1;
                    cs->bytes += skb->len;
                    if (cs->action == ACTION_DIRECT) {
                        /* 机制 80: 持续为直连非 SYN 报文补充 fwmark，防止策略路由脱轨 */
                        if (cs->fwmark > 0) {
                            skb->mark = cs->fwmark;
                        }
                        return handle_direct_packet(skb, eth, data_end, cfg, is_layer3);
                    }
                    if (cs->action == ACTION_BLOCK) {
                        is_block_rate_limited(0, cfg->rate_limit_window_ms);
                        emit_bpf_event(MYNET_EVENT_BLOCKED, ip->saddr, ip->daddr, tcp->source, tcp->dest, IPPROTO_TCP);
                        bump_bpf_stat(MYNET_STAT_BLOCK_PACKETS);
                        return TC_ACT_SHOT;
                    }
                    return handle_proxy_packet(skb, IPPROTO_TCP, 0, cfg);
                }

                /* 单网卡双角色 (Dual-role) 返程流量判定 */
                struct tuples_key rev_key = {
                    .saddr = ip->daddr,
                    .daddr = ip->saddr,
                    .sport = tcp->dest,
                    .dport = tcp->source,
                    .proto = IPPROTO_TCP
                };
                struct conn_state_entry *rev_cs = bpf_map_lookup_elem(&mynet_conn_state_map, &rev_key);
                if (rev_cs && rev_cs->action == ACTION_DIRECT) {
                    rev_cs->last_seen_ns = bpf_ktime_get_ns();
                    rev_cs->packets += 1;
                    rev_cs->bytes += skb->len;
                    return handle_direct_packet(skb, eth, data_end, cfg, is_layer3);
                }
            }
        }

        /* QUIC 阻断策略与 UDP 连接状态快速追踪 (借鉴 dae conn_state_map) */
        if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)ip + (ip->ihl * 4);
            if ((void *)(udp + 1) <= data_end) {
                if (cfg->drop_quic && udp->dest == bpf_htons(443)) {
                    bump_bpf_stat(MYNET_STAT_BLOCK_PACKETS);
                    return TC_ACT_SHOT;
                }

                struct tuples_key udp_key = {
                    .saddr = ip->saddr,
                    .daddr = ip->daddr,
                    .sport = udp->source,
                    .dport = udp->dest,
                    .proto = IPPROTO_UDP
                };
                struct conn_state_entry *cs = bpf_map_lookup_elem(&mynet_conn_state_map, &udp_key);
                if (cs) {
                    cs->last_seen_ns = bpf_ktime_get_ns();
                    cs->packets += 1;
                    cs->bytes += skb->len;
                    if (cs->action == ACTION_DIRECT) {
                        /* 机制 80: 持续为直连非 SYN 报文补充 fwmark，防止策略路由脱轨 */
                        if (cs->fwmark > 0) {
                            skb->mark = cs->fwmark;
                        }
                        return handle_direct_packet(skb, eth, data_end, cfg, is_layer3);
                    }
                    if (cs->action == ACTION_BLOCK) {
                        is_block_rate_limited(0, cfg->rate_limit_window_ms);
                        emit_bpf_event(MYNET_EVENT_BLOCKED, ip->saddr, ip->daddr, udp->source, udp->dest, IPPROTO_UDP);
                        bump_bpf_stat(MYNET_STAT_BLOCK_PACKETS);
                        return TC_ACT_SHOT;
                    }
                    return handle_proxy_packet(skb, IPPROTO_UDP, 0, cfg);
                }

                /* 单网卡双角色 (Dual-role) 返程 UDP 判定 */
                struct tuples_key rev_udp = {
                    .saddr = ip->daddr,
                    .daddr = ip->saddr,
                    .sport = udp->dest,
                    .dport = udp->source,
                    .proto = IPPROTO_UDP
                };
                struct conn_state_entry *rev_cs = bpf_map_lookup_elem(&mynet_conn_state_map, &rev_udp);
                if (rev_cs && rev_cs->action == ACTION_DIRECT) {
                    rev_cs->last_seen_ns = bpf_ktime_get_ns();
                    rev_cs->packets += 1;
                    rev_cs->bytes += skb->len;
                    return handle_direct_packet(skb, eth, data_end, cfg, is_layer3);
                }
            }
        }

        /* 快速直连 IP 判定 */
        __u32 dst_ip = ip->daddr;
        __u8 *direct = bpf_map_lookup_elem(&mynet_direct_ips, &dst_ip);
        if (direct && cfg->direct_bypass) {
            if (ip->protocol == IPPROTO_UDP) {
                struct udphdr *udp = (void *)ip + (ip->ihl * 4);
                if ((void *)(udp + 1) <= data_end) {
                    /* 机制 65: 跳过 DNS 短生命周期 UDP 状态插入，防止 Map Churn 挤爆 */
                    if (!is_short_lived_udp_traffic(udp->source, udp->dest)) {
                        struct tuples_key udp_key = {
                            .saddr = ip->saddr, .daddr = ip->daddr,
                            .sport = udp->source, .dport = udp->dest,
                            .proto = IPPROTO_UDP
                        };
                        struct conn_state_entry new_cs = {
                            .action = ACTION_DIRECT, .fwmark = cfg->fwmark,
                            .last_seen_ns = bpf_ktime_get_ns(), .packets = 1, .bytes = skb->len
                        };
                        bpf_map_update_elem(&mynet_conn_state_map, &udp_key, &new_cs, BPF_ANY);
                    }
                }
            }
            return handle_direct_packet(skb, eth, data_end, cfg, is_layer3);
        }

        /* IPv4 最长前缀 (LPM Trie) 双 Epoch 槽位匹配 */
        struct bpf_lpm_key_ipv4 lpm_key = {
            .prefixlen = 32,
            .ip = dst_ip
        };
        __u32 *action = NULL;
        if (cfg->active_epoch == 0) {
            action = bpf_map_lookup_elem(&mynet_lpm_trie_ipv4_0, &lpm_key);
        } else {
            action = bpf_map_lookup_elem(&mynet_lpm_trie_ipv4_1, &lpm_key);
        }

        __u32 final_action = ACTION_PROXY;
        if (action) {
            final_action = *action;
        }

        if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)ip + (ip->ihl * 4);
            if ((void *)(udp + 1) <= data_end) {
                /* 机制 65: 跳过 DNS 短生命周期 UDP 状态插入，防止 Map Churn 挤爆 */
                if (!is_short_lived_udp_traffic(udp->source, udp->dest)) {
                    struct tuples_key udp_key = {
                        .saddr = ip->saddr, .daddr = ip->daddr,
                        .sport = udp->source, .dport = udp->dest,
                        .proto = IPPROTO_UDP
                    };
                    struct conn_state_entry new_cs = {
                        .action = final_action, .fwmark = cfg->fwmark,
                        .last_seen_ns = bpf_ktime_get_ns(), .packets = 1, .bytes = skb->len
                    };
                    bpf_map_update_elem(&mynet_conn_state_map, &udp_key, &new_cs, BPF_ANY);

                    /* 预置反向流状态，加速对称返程回包 */
                    struct tuples_key rev_key = {
                        .saddr = ip->daddr, .daddr = ip->saddr,
                        .sport = udp->dest, .dport = udp->source,
                        .proto = IPPROTO_UDP
                    };
                    bpf_map_update_elem(&mynet_conn_state_map, &rev_key, &new_cs, BPF_NOEXIST);
                }
            }
        }

        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
            if ((void *)(tcp + 1) <= data_end) {
                struct tuples_key tcp_key = {
                    .saddr = ip->saddr, .daddr = ip->daddr,
                    .sport = tcp->source, .dport = tcp->dest,
                    .proto = IPPROTO_TCP
                };
                struct conn_state_entry new_cs = {
                    .action = final_action, .fwmark = cfg->fwmark,
                    .last_seen_ns = bpf_ktime_get_ns(), .packets = 1, .bytes = skb->len
                };
                bpf_map_update_elem(&mynet_conn_state_map, &tcp_key, &new_cs, BPF_ANY);

                /* 预置反向流状态，加速对称返程回包 */
                struct tuples_key rev_key = {
                    .saddr = ip->daddr, .daddr = ip->saddr,
                    .sport = tcp->dest, .dport = tcp->source,
                    .proto = IPPROTO_TCP
                };
                bpf_map_update_elem(&mynet_conn_state_map, &rev_key, &new_cs, BPF_NOEXIST);
            }
        }

        if (final_action == ACTION_DIRECT) {
            return handle_direct_packet(skb, eth, data_end, cfg, is_layer3);
        }
        if (final_action == ACTION_BLOCK) {
            is_block_rate_limited(0, cfg->rate_limit_window_ms);
            emit_bpf_event(MYNET_EVENT_BLOCKED, ip->saddr, ip->daddr, 0, 0, ip->protocol);
            bump_bpf_stat(MYNET_STAT_BLOCK_PACKETS);
            return TC_ACT_SHOT;
        }

        /* 记录回包以太网定向直通与路由交接状态 (借鉴 dae redirect_track & routing_handoff_map) */
        if (eth && (void *)(eth + 1) <= data_end) {
            struct redirect_track_entry r_entry = {
                .ifindex = skb->ifindex,
                .last_seen_ns = bpf_ktime_get_ns()
            };
            __builtin_memcpy(r_entry.smac, eth->h_source, 6);
            __builtin_memcpy(r_entry.dmac, eth->h_dest, 6);
            struct tuples_key t_key = {
                .saddr = ip->saddr, .daddr = ip->daddr,
                .proto = ip->protocol
            };
            if (ip->protocol == IPPROTO_TCP) {
                struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
                if ((void *)(tcp + 1) <= data_end) {
                    t_key.sport = tcp->source;
                    t_key.dport = tcp->dest;
                }
            } else if (ip->protocol == IPPROTO_UDP) {
                struct udphdr *udp = (void *)ip + (ip->ihl * 4);
                if ((void *)(udp + 1) <= data_end) {
                    t_key.sport = udp->source;
                    t_key.dport = udp->dest;
                }
            }
            /* 单写者发布者防伪造保护机制 (借鉴 dae single-writer redirect_track) */
            struct redirect_track_entry *existing = bpf_map_lookup_elem(&mynet_redirect_track, &t_key);
            if (existing) {
                bool same_pub = (existing->ifindex == r_entry.ifindex &&
                                 existing->from_wan == r_entry.from_wan &&
                                 mac6_equal(existing->smac, r_entry.smac));
                if (same_pub) {
                    existing->last_seen_ns = r_entry.last_seen_ns;
                } else if (existing->last_seen_ns <= r_entry.last_seen_ns &&
                           r_entry.last_seen_ns - existing->last_seen_ns < DEFAULT_REDIRECT_REBIND_STALE_NS) {
                    bump_bpf_stat(MYNET_STAT_REDIRECT_REBIND_REJECTED);
                    emit_bpf_event(MYNET_EVENT_REDIRECT_REBIND_REJECTED, t_key.saddr, t_key.daddr, t_key.sport, t_key.dport, t_key.proto);
                } else {
                    /* 静默超过窗口期，允许合法重绑定 (如 Wi-Fi 漫游或虚拟机迁移) */
                    bpf_map_update_elem(&mynet_redirect_track, &t_key, &r_entry, BPF_ANY);
                }
            } else {
                bpf_map_update_elem(&mynet_redirect_track, &t_key, &r_entry, BPF_ANY);
            }

            struct routing_handoff_entry handoff = {
                .last_seen_ns = bpf_ktime_get_ns(),
                .mark = cfg->fwmark,
                .outbound = 1,
                .dscp = (ip->tos & 0xfc) >> 2,
                .epoch_slot = cfg->active_epoch
            };
            __builtin_memcpy(handoff.mac, eth->h_source, 6);
            bpf_map_update_elem(&mynet_routing_handoff, &t_key, &handoff, BPF_ANY);
        }

        /* 代理流量统一通过 handle_proxy_packet 分发 (优先 bpf_sk_assign / 虚拟通道，保底 fwmark) */
        return handle_proxy_packet(skb, ip->protocol, 0, cfg);
    }
    else if (eth_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = l3_hdr;
        if ((void *)(ip6 + 1) > data_end)
            return TC_ACT_OK;

        /* IPv6 组播 (ff00::/8) 绝对放行直连 (借鉴 dae ff00::/8) */
        if (ip6->daddr.s6_addr[0] == 0xFF) {
            return handle_direct_packet(skb, eth, data_end, cfg, is_layer3);
        }

        /* IPv6 QUIC 阻断 */
        if (cfg->drop_quic && ip6->nexthdr == IPPROTO_UDP) {
            struct udphdr *udp = (void *)(ip6 + 1);
            if ((void *)(udp + 1) <= data_end && udp->dest == bpf_htons(443)) {
                bump_bpf_stat(MYNET_STAT_BLOCK_PACKETS);
                return TC_ACT_SHOT;
            }
        }

        /* IPv6 LPM Trie 双 Epoch 匹配 */
        struct bpf_lpm_key_ipv6 lpm6_key = {
            .prefixlen = 128
        };
        __builtin_memcpy(lpm6_key.ip, &ip6->daddr, 16);
        __u32 *action = NULL;
        if (cfg->active_epoch == 0) {
            action = bpf_map_lookup_elem(&mynet_lpm_trie_ipv6_0, &lpm6_key);
        } else {
            action = bpf_map_lookup_elem(&mynet_lpm_trie_ipv6_1, &lpm6_key);
        }

        if (action) {
            if (*action == ACTION_DIRECT) {
                return handle_direct_packet(skb, eth, data_end, cfg, is_layer3);
            }
            if (*action == ACTION_BLOCK) {
                is_block_rate_limited(0, cfg->rate_limit_window_ms);
                bump_bpf_stat(MYNET_STAT_BLOCK_PACKETS);
                return TC_ACT_SHOT;
            }
        }

        return handle_proxy_packet(skb, ip6->nexthdr, 1, cfg);
    }

    return TC_ACT_OK;
}

/* ========================================================================= */
/* 核心 2：SockMap Stream Verdict 套接字内核直接重定向流判决                 */
/* ========================================================================= */

SEC("sk_skb/stream_verdict")
int mynet_sockmap_verdict(struct __sk_buff *skb)
{
    struct tuples_key peer_key = {};
    peer_key.proto = IPPROTO_TCP;
    // 字节序安全转换：在小端内核大端端口位移，大端内核直接取值 (借鉴 dae tcp_offload_remote_port)
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    peer_key.sport = (__u16)(skb->remote_port >> 16);
#else
    peer_key.sport = (__be16)skb->remote_port;
#endif
    peer_key.dport = bpf_htons((__u16)skb->local_port);
    peer_key.saddr = skb->remote_ip4;
    peer_key.daddr = skb->local_ip4;

    /* 背压熔断保险丝：若连接处于暂停状态，返回 SK_PASS 交给用户态泵送排空 (借鉴 dae tcp_offload_pause) */
    if (bpf_map_lookup_elem(&mynet_tcp_offload_pause, &peer_key)) {
        return SK_PASS;
    }

    // 内核将收到数据直接转交至 peer 套接字发送队列
    // 若未命中 peer_key 或重定向失败，返回 SK_PASS 交给用户态 Splice/内存搬运保底，绝不丢包
    long ret = bpf_sk_redirect_hash(skb, &mynet_fast_sock, &peer_key, 0);
    if (ret != SK_PASS) {
        return SK_PASS;
    }
    return ret;
}

/* ========================================================================= */
/* 核心 3：cgroupv2 钩子：实时捕获 Socket Cookie -> PID / 进程名            */
/* ========================================================================= */

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

SEC("cgroup/sendmsg4")
int mynet_cg_sendmsg4(struct bpf_sock_addr *ctx)
{
    update_cookie_process(bpf_get_socket_cookie(ctx));
    return 1;
}

SEC("cgroup/sendmsg6")
int mynet_cg_sendmsg6(struct bpf_sock_addr *ctx)
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

/* ========================================================================= */
/* 核心 4：虚拟网卡回包以太网定向直通判决 (借鉴 dae tproxy_dae0_ingress)     */
/* ========================================================================= */

SEC("tc/egress_reply")
int mynet_tc_egress_reply(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    struct tuples_key reply_key = {
        .saddr = ip->daddr,
        .daddr = ip->saddr,
        .proto = ip->protocol
    };
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) <= data_end) {
            reply_key.sport = tcp->dest;
            reply_key.dport = tcp->source;
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) <= data_end) {
            reply_key.sport = udp->dest;
            reply_key.dport = udp->source;
        }
    }

    struct redirect_track_entry *entry = bpf_map_lookup_elem(&mynet_redirect_track, &reply_key);
    if (entry && entry->ifindex > 0) {
        __builtin_memcpy(eth->h_dest, entry->smac, 6);
        __builtin_memcpy(eth->h_source, entry->dmac, 6);
        return bpf_redirect(entry->ifindex, 0);
    }
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
