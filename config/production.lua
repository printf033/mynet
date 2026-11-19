-- mynet 生产级全协议与智能路由完整配置范例
-- 覆盖：Mixed / SOCKS5 / VLESS / Hysteria 2 / TUN 虚拟网卡入站
--      Direct / Block / VLESS / Hysteria 2 / Shadowsocks / URLTest / Fallback / Selector 出站
--      GeoIP / GeoSite / 域名 / 端口 / 进程 智能策略分流
--      沙箱化内存 FakeIP (198.18.0.0/15) 映射

-- 1. 服务传输层基础配置
server = {
    host = "0.0.0.0",
    port = 8888,
    backlog = 1024,
    maxConnections = 65536,
    idleTimeoutSecs = 300,
    tcpNoDelay = true,
    tcpQuickAck = false,
    enableSplice = true,
    reuseAddr = true,
    reusePort = true,
    engine = "reactor"
}

-- 2. epoll 事件引擎
reactor = {
    maxEvents = 2048,
    idleSweepIntervalMs = 1000
}

-- 3. io_uring 完成态高性能引擎
proactor = {
    sqEntries = 4096,
    cqEntries = 4096,
    maxAcceptEvents = 256,
    bufEntries = 2048,
    bufSize = 4096,
    udpBufSize = 65536,
    bufRingAlignment = 4096,
    cqeWaitMs = 500
}

-- 4. 零拷贝与转发中继配置
forwarder = {
    enableSplice = true,
    spliceChunkSize = 65536,
    bufferChunkSize = 16384,
    sessionIdleTimeoutSecs = 300,
    udpSessionTimeoutSecs = 60
}

-- 5. DNS 解析与内存 FakeIP/缓存配置
dns = {
    servers = {"223.5.5.5", "119.29.29.29", "8.8.8.8"},
    port = 53,
    ttlSecs = 600,
    enableCache = true
}

-- 6. 入站监听节点列表 (Inbounds)
inbounds = {
    {
        tag = "mixed-in",
        type = "mixed",
        host = "127.0.0.1",
        port = 7890,
        sniffing = true
    },
    {
        tag = "socks-in",
        type = "socks5",
        host = "127.0.0.1",
        port = 1080,
        sniffing = true
    },
    {
        tag = "tproxy-in",
        type = "tproxy",
        host = "0.0.0.0",
        port = 12345,
        sniffing = true
    },
    {
        tag = "vless-in",
        type = "vless",
        host = "0.0.0.0",
        port = 8443,
        uuid = "e8a9394f-2f88-4c8d-b7d6-3e0c0b3d68ef",
        sniffing = true
    },
    {
        tag = "hy2-in",
        type = "hysteria2",
        host = "0.0.0.0",
        port = 8444,
        password = "mynet-hy2-secure-pass"
    },
    {
        tag = "tun-in",
        type = "tun",
        ifName = "mynet-tun0",
        inetIp = "172.19.0.1",
        inetMask = "255.255.255.0",
        mtu = 1500,
        sniffing = true
    }
}

-- 7. 出站落地节点列表 (Outbounds)
outbounds = {
    {
        tag = "direct",
        type = "direct"
    },
    {
        tag = "block",
        type = "block"
    },
    {
        tag = "hk-vless",
        type = "vless",
        host = "hk.example.com",
        port = 443,
        uuid = "e8a9394f-2f88-4c8d-b7d6-3e0c0b3d68ef"
    },
    {
        tag = "jp-hy2",
        type = "hysteria2",
        host = "jp.example.com",
        port = 8443,
        password = "mynet-hy2-secure-pass"
    },
    {
        tag = "us-ss",
        type = "socks5",
        host = "us.example.com",
        port = 10808
    },
    {
        -- URLTest: 自动测速优选节点
        tag = "auto-fastest",
        type = "urltest",
        outbounds = {"hk-vless", "jp-hy2", "us-ss"},
        url = "http://www.gstatic.com/generate_204",
        interval = 300,
        tolerance = 50
    },
    {
        -- Fallback: 主备自动降级切换
        tag = "auto-fallback",
        type = "fallback",
        outbounds = {"hk-vless", "jp-hy2", "direct"}
    },
    {
        -- Selector: 手动节点选择器
        tag = "proxy",
        type = "selector",
        outbounds = {"auto-fastest", "hk-vless", "jp-hy2", "us-ss", "direct"},
        default = "auto-fastest"
    }
}

-- 8. 策略路由规则列表 (Router)
router = {
    defaultOutbound = "proxy",
    rules = {
        -- 1. 广告域名拦截
        {
            outbound = "block",
            geoSites = {"category-ads-all"}
        },
        -- 2. 私网与局域网直连
        {
            outbound = "direct",
            geoIps = {"private"},
            ipCidrs = {"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
        },
        -- 3. 国内常见域名与中国大陆 IP 直连
        {
            outbound = "direct",
            geoSites = {"cn"},
            geoIps = {"cn"}
        },
        -- 4. 常见特定服务分流
        {
            outbound = "proxy",
            geoSites = {"google", "github", "telegram", "netflix"}
        },
        -- 5. 本地开发与特定系统进程直连
        {
            outbound = "direct",
            process = "curl"
        }
    }
}

-- 9. Linux TC eBPF 内核级透明代理与旁路加速 (ebpf)
ebpf = {
    enabled = true,
    wanInterface = "eth0",
    lanInterface = "lo",
    tproxyPort = 12345,
    fwmark = 1,
    enableDirectBypass = true,
    enableLpmGeoIp = true,
    dropQuic = true
}

-- 10. FakeIP 虚拟地址池与域名反解配置 (fakeip)
fakeip = {
    enabled = true,
    inetRange = "198.18.0.0/15",
    maxCapacity = 65534
}

-- 11. GeoIP 国家网段与 GeoSite 资产规则配置 (geo)
geo = {
    geoIpPath = "geoip.dat",
    geoSitePath = "geosite.dat",
    autoReload = true
}

-- 12. Clash / sing-box 兼容 RESTful 控制平面 API (controller)
controller = {
    enabled = true,
    host = "127.0.0.1",
    port = 9090,
    secret = "mynet-secret-key"
}

-- 13. 日志子系统
logger = {
    suppressLevel = "info",
    stdoutVivid = true,
    escapeControlChars = true,
    timestampUtc = false,
    maxLogLength = 4096,
    fatalAction = "none"
}
