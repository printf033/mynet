#include "config/lua.hpp"
#include "config/tls.hpp"
#include "connection.hpp"
#include "core.hpp"
#include "direct/direct.hpp"
#include "reactor.hpp"
#include <arpa/inet.h>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <meta>
#include <netinet/tcp.h>
#include <set>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace
{

    inline int g_rcuLiveInstances = 0;
    struct RcuTestResource
    {
        RcuTestResource() { ++g_rcuLiveInstances; }
        ~RcuTestResource() { --g_rcuLiveInstances; }
        RcuTestResource(const RcuTestResource &) { ++g_rcuLiveInstances; }
        RcuTestResource &operator=(const RcuTestResource &) = default;
    };

    struct RcuTestConfig
    {
        uint16_t port = 8080;
        RcuTestResource tracker{};
    };

    void writeTestConfigFile(const std::filesystem::path &path, const std::string &content)
    {
        std::ofstream ofs(path, std::ios::trunc);
        ofs << content;
        ofs.close();
    }

    /**
     * @brief 用 C++26 静态反射取出某结构体的全部非静态成员名。
     */
    template <typename T>
    consteval auto memberNames()
    {
        constexpr auto members =
            std::define_static_array(std::meta::nonstatic_data_members_of(^^T, std::meta::access_context::unchecked()));
        std::array<std::string_view, members.size()> names{};
        for (size_t i = 0; i < members.size(); ++i)
        {
            names[i] = std::meta::identifier_of(members[i]);
        }
        return names;
    }

    template <typename T>
    void collectFieldPaths(const std::string &prefix, std::vector<std::string> &out)
    {
        for (std::string_view name : memberNames<T>())
        {
            out.push_back(prefix + "." + std::string(name));
        }
    }

} // namespace

TEST(ConfigLua, GoodConfigReloadsBothNetAndMylog)
{
    const mynet::MynetConfig saved = mynet::getMynetConfig();
    const std::filesystem::path configPath = "test_config_good.lua";
    writeTestConfigFile(configPath, "server = {\n"
                                    "  host = \"127.0.0.1\",\n"
                                    "  port = 9090,\n"
                                    "  backlog = 512,\n"
                                    "  maxConnections = 10000,\n"
                                    "  tcpNoDelay = true,\n"
                                    "  tcpQuickAck = true,\n"
                                    "  enableSplice = false\n"
                                    "}\n"
                                    "reactor = {\n"
                                    "  maxEvents = 2048,\n"
                                    "  idleSweepIntervalMs = 500\n"
                                    "}\n"
                                    "proactor = {\n"
                                    "  sqEntries = 4096,\n"
                                    "  cqEntries = 4096,\n"
                                    "  bufEntries = 2048,\n"
                                    "  bufSize = 8192,\n"
                                    "  bufRingAlignment = 8192,\n"
                                    "  cqeWaitMs = 200\n"
                                    "}\n"
                                    "connection = {\n"
                                    "  responseCapacity = 128,\n"
                                    "  readChunkSize = 8192,\n"
                                    "  maxRequestBytes = 2097152,\n"
                                    "  writeHighWaterMark = 8388608,\n"
                                    "  writeHardCapFactor = 4,\n"
                                    "  spliceChunkSize = 131072,\n"
                                    "  maxWriteIov = 32\n"
                                    "}\n"
                                    "datagram = {\n"
                                    "  maxDatagramBytes = 32768,\n"
                                    "  maxPendingOutgoing = 512\n"
                                    "}\n"
                                    "security = {\n"
                                    "  certFile = \"mycert.pem\",\n"
                                    "  keyFile = \"mykey.pem\",\n"
                                    "  ciphers = \"ECDHE-RSA-AES128-GCM-SHA256\",\n"
                                    "  alpnProtocols = \"h2\"\n"
                                    "}\n"
                                    "http1 = {\n"
                                    "  maxUrlLength = 4096,\n"
                                    "  maxBodyLength = 8388608\n"
                                    "}\n"
                                    "http2 = {\n"
                                    "  maxConcurrentStreams = 200,\n"
                                    "  initialWindowSize = 131072,\n"
                                    "  maxFrameSize = 32768\n"
                                    "}\n"
                                    "http3 = {\n"
                                    "  port = 8443,\n"
                                    "  maxRequestBodyBytes = 8388608\n"
                                    "}\n"
                                    "proxy = {\n"
                                    "  autoReplyConnectSuccess = false\n"
                                    "}\n"
                                    "forwarder = {\n"
                                    "  enableSplice = true,\n"
                                    "  propagateClose = true,\n"
                                    "  spliceChunkSize = 65536,\n"
                                    "  bufferChunkSize = 16384,\n"
                                    "  sessionIdleTimeoutSecs = 120,\n"
                                    "  udpSessionTimeoutSecs = 30\n"
                                    "}\n"
                                    "dns = {\n"
                                    "  servers = {\"8.8.8.8\", \"1.1.1.1\"},\n"
                                    "  port = 5353,\n"
                                    "  ttlSecs = 600,\n"
                                    "  enableCache = true\n"
                                    "}\n"
                                    "router = {\n"
                                    "  defaultOutbound = \"direct\",\n"
                                    "  rules = {\n"
                                    "    {\n"
                                    "      outbound = \"block\",\n"
                                    "      domainKeywords = {\"adserver\"},\n"
                                    "      domainSuffixes = {\"doubleclick.net\"}\n"
                                    "    },\n"
                                    "    {\n"
                                    "      outbound = \"proxy-out\",\n"
                                    "      ipCidrs = {\"1.1.1.1/32\"},\n"
                                    "      portRanges = {\"443\", \"80-90\"},\n"
                                    "      protocols = {\"tls\"},\n"
                                    "      network = \"tcp\"\n"
                                    "    }\n"
                                    "  }\n"
                                    "}\n"
                                    "inbounds = {\n"
                                    "  {\n"
                                    "    tag = \"mixed-in\",\n"
                                    "    protocol = \"socks5\",\n"
                                    "    host = \"127.0.0.1\",\n"
                                    "    port = 7890,\n"
                                    "    enableSniffing = true\n"
                                    "  },\n"
                                    "  {\n"
                                    "    tag = \"socks-in\",\n"
                                    "    protocol = \"socks5\",\n"
                                    "    host = \"127.0.0.1\",\n"
                                    "    port = 1080\n"
                                    "  }\n"
                                    "}\n"
                                    "outbounds = {\n"
                                    "  {\n"
                                    "    tag = \"direct\",\n"
                                    "    type = \"direct\"\n"
                                    "  },\n"
                                    "  {\n"
                                    "    tag = \"block\",\n"
                                    "    type = \"block\"\n"
                                    "  },\n"
                                    "  {\n"
                                    "    tag = \"proxy-out\",\n"
                                    "    type = \"socks5\",\n"
                                    "    server = \"127.0.0.1\",\n"
                                    "    port = 1081\n"
                                    "  },\n"
                                    "  {\n"
                                    "    tag = \"selector-out\",\n"
                                    "    type = \"selector\",\n"
                                    "    outbounds = {\"proxy-out\", \"direct\"},\n"
                                    "    default = \"proxy-out\"\n"
                                    "  }\n"
                                    "}\n"
                                    "ebpf = {\n"
                                    "  enabled = true,\n"
                                    "  wanInterface = \"eth1\",\n"
                                    "  lanInterface = \"lan0\",\n"
                                    "  tproxyPort = 12345,\n"
                                    "  fwmark = 2,\n"
                                    "  enableDirectBypass = false,\n"
                                    "  enableLpmGeoIp = false,\n"
                                    "  dropQuic = true\n"
                                    "}\n"
                                    "fakeip = {\n"
                                    "  enabled = true,\n"
                                    "  inetRange = \"198.18.0.0/16\",\n"
                                    "  maxCapacity = 32768\n"
                                    "}\n"
                                    "geo = {\n"
                                    "  geoIpPath = \"/etc/geoip.dat\",\n"
                                    "  geoSitePath = \"/etc/geosite.dat\",\n"
                                    "  autoReload = true\n"
                                    "}\n"
                                    "controller = {\n"
                                    "  enabled = true,\n"
                                    "  host = \"0.0.0.0\",\n"
                                    "  port = 9999,\n"
                                    "  secret = \"testsecret\"\n"
                                    "}\n"
                                    "logger = {\n"
                                    "  suppressLevel = \"warn\"\n"
                                    "}\n");

    EXPECT_TRUE(mynet::reloadConfig(configPath));

    const mynet::MynetConfig cfg = mynet::getMynetConfig();
    EXPECT_EQ(cfg.server.host, "127.0.0.1");
    EXPECT_EQ(cfg.server.port, 9090u);
    EXPECT_EQ(cfg.server.backlog, 512);
    EXPECT_EQ(cfg.server.maxConnections, 10000u);
    EXPECT_TRUE(cfg.server.tcpNoDelay);
    EXPECT_TRUE(cfg.server.tcpQuickAck);
    EXPECT_FALSE(cfg.server.enableSplice);

    EXPECT_EQ(cfg.reactor.maxEvents, 2048);
    EXPECT_EQ(cfg.reactor.idleSweepIntervalMs, 500);

    EXPECT_EQ(cfg.proactor.sqEntries, 4096u);
    EXPECT_EQ(cfg.proactor.cqEntries, 4096u);
    EXPECT_EQ(cfg.proactor.bufEntries, 2048u);
    EXPECT_EQ(cfg.proactor.bufSize, 8192u);
    EXPECT_EQ(cfg.proactor.bufRingAlignment, 8192u);
    EXPECT_EQ(cfg.proactor.cqeWaitMs, 200);

    EXPECT_EQ(cfg.connection.responseCapacity, 128u);
    EXPECT_EQ(cfg.connection.readChunkSize, 8192u);
    EXPECT_EQ(cfg.connection.maxRequestBytes, 2097152u);
    EXPECT_EQ(cfg.connection.writeHighWaterMark, 8388608u);
    EXPECT_EQ(cfg.connection.writeHardCapFactor, 4u);
    EXPECT_EQ(cfg.connection.spliceChunkSize, 131072u);
    EXPECT_EQ(cfg.connection.maxWriteIov, 32u);

    EXPECT_EQ(cfg.datagram.maxDatagramBytes, 32768u);
    EXPECT_EQ(cfg.datagram.maxPendingOutgoing, 512u);

    EXPECT_EQ(cfg.security.certFile, "mycert.pem");
    EXPECT_EQ(cfg.security.keyFile, "mykey.pem");
    EXPECT_EQ(cfg.security.ciphers, "ECDHE-RSA-AES128-GCM-SHA256");
    EXPECT_EQ(cfg.security.alpnProtocols, "h2");

    EXPECT_EQ(cfg.http1.maxUrlLength, 4096u);
    EXPECT_EQ(cfg.http1.maxBodyLength, 8388608u);

    EXPECT_EQ(cfg.http2.maxConcurrentStreams, 200u);
    EXPECT_EQ(cfg.http2.initialWindowSize, 131072u);
    EXPECT_EQ(cfg.http2.maxFrameSize, 32768u);

    EXPECT_EQ(cfg.http3.port, 8443u);
    EXPECT_EQ(cfg.http3.maxRequestBodyBytes, 8388608u);

    EXPECT_FALSE(cfg.proxy.autoReplyConnectSuccess);

    EXPECT_TRUE(cfg.forwarder.enableSplice);
    EXPECT_TRUE(cfg.forwarder.propagateClose);
    EXPECT_EQ(cfg.forwarder.spliceChunkSize, 65536u);
    EXPECT_EQ(cfg.forwarder.bufferChunkSize, 16384u);
    EXPECT_EQ(cfg.forwarder.sessionIdleTimeoutSecs, 120);
    EXPECT_EQ(cfg.forwarder.udpSessionTimeoutSecs, 30);

    ASSERT_EQ(cfg.dns.servers.size(), 2u);
    EXPECT_EQ(cfg.dns.servers[0], "8.8.8.8");
    EXPECT_EQ(cfg.dns.port, 5353u);
    EXPECT_EQ(cfg.dns.ttlSecs, 600u);
    EXPECT_TRUE(cfg.dns.enableCache);

    EXPECT_EQ(cfg.router.defaultOutbound, "direct");
    ASSERT_EQ(cfg.router.rules.size(), 2u);
    EXPECT_EQ(cfg.router.rules[0].outbound, "block");
    ASSERT_EQ(cfg.router.rules[0].domainKeywords.size(), 1u);
    EXPECT_EQ(cfg.router.rules[0].domainKeywords[0], "adserver");
    EXPECT_EQ(cfg.router.rules[1].outbound, "proxy-out");
    EXPECT_EQ(cfg.router.rules[1].network, "tcp");

    ASSERT_EQ(cfg.inbounds.size(), 2u);
    EXPECT_EQ(cfg.inbounds[0].tag, "mixed-in");
    EXPECT_EQ(cfg.inbounds[0].port, 7890u);
    EXPECT_TRUE(cfg.inbounds[0].enableSniffing);
    EXPECT_EQ(cfg.inbounds[1].tag, "socks-in");
    EXPECT_EQ(cfg.inbounds[1].port, 1080u);

    ASSERT_EQ(cfg.outbounds.size(), 4u);
    EXPECT_EQ(cfg.outbounds[0].tag, "direct");
    EXPECT_EQ(cfg.outbounds[1].tag, "block");
    EXPECT_EQ(cfg.outbounds[2].tag, "proxy-out");
    EXPECT_EQ(cfg.outbounds[2].type, "socks5");
    EXPECT_EQ(cfg.outbounds[3].tag, "selector-out");
    EXPECT_EQ(cfg.outbounds[3].type, "selector");
    ASSERT_EQ(cfg.outbounds[3].outbounds.size(), 2u);

    EXPECT_TRUE(cfg.ebpf.enabled);
    EXPECT_EQ(cfg.ebpf.wanInterface, "eth1");
    EXPECT_EQ(cfg.ebpf.lanInterface, "lan0");
    EXPECT_EQ(cfg.ebpf.tproxyPort, 12345u);
    EXPECT_EQ(cfg.ebpf.fwmark, 2u);
    EXPECT_FALSE(cfg.ebpf.enableDirectBypass);
    EXPECT_FALSE(cfg.ebpf.enableLpmGeoIp);
    EXPECT_TRUE(cfg.ebpf.dropQuic);

    EXPECT_TRUE(cfg.fakeip.enabled);
    EXPECT_EQ(cfg.fakeip.inetRange, "198.18.0.0/16");
    EXPECT_EQ(cfg.fakeip.maxCapacity, 32768u);

    EXPECT_EQ(cfg.geo.geoIpPath, "/etc/geoip.dat");
    EXPECT_EQ(cfg.geo.geoSitePath, "/etc/geosite.dat");
    EXPECT_TRUE(cfg.geo.autoReload);

    EXPECT_TRUE(cfg.controller.enabled);
    EXPECT_EQ(cfg.controller.host, "0.0.0.0");
    EXPECT_EQ(cfg.controller.port, 9999u);
    EXPECT_EQ(cfg.controller.secret, "testsecret");

    EXPECT_EQ(static_cast<int>(mylog::getCurrentSuppressLevel()), static_cast<int>(mylog::LEVEL::WARN));

    mynet::publishMynetConfig(saved);
    std::filesystem::remove(configPath);
}

TEST(ConfigLua, ClampsOutliersSafely)
{
    const std::filesystem::path clampPath = "test_config_clamp.lua";
    writeTestConfigFile(clampPath, "server = {\n"
                                   "  port = 999999,\n"

                                   "}\n"
                                   "connection = {\n"
                                   "  responseCapacity = 0,\n"
                                   "  readChunkSize = 10,\n"
                                   "  maxWriteIov = 9999,\n"
                                   "  writeHardCapFactor = 100\n"
                                   "}\n"
                                   "http2 = {\n"
                                   "  maxFrameSize = 10\n"
                                   "}\n");

    EXPECT_TRUE(mynet::reloadConfig(clampPath));

    const mynet::MynetConfig cfg = mynet::getMynetConfig();
    EXPECT_EQ(cfg.server.port, 65535u);
    EXPECT_EQ(cfg.connection.responseCapacity, 1u);
    EXPECT_EQ(cfg.connection.readChunkSize, 256u);
    EXPECT_EQ(cfg.connection.maxWriteIov, 64u);
    EXPECT_EQ(cfg.connection.writeHardCapFactor, 64u);
    EXPECT_EQ(cfg.http2.maxFrameSize, 16384u);

    std::filesystem::remove(clampPath);
}

TEST(ConfigLua, InvalidSyntaxOrTypeDoesNotCorruptRunningConfig)
{
    const mynet::MynetConfig before = mynet::getMynetConfig();

    const std::filesystem::path syntaxErrorPath = "test_config_syntax_err.lua";
    writeTestConfigFile(syntaxErrorPath, "server = { port = \n");
    EXPECT_FALSE(mynet::reloadConfig(syntaxErrorPath));

    const std::filesystem::path typeErrorPath = "test_config_type_err.lua";
    writeTestConfigFile(typeErrorPath, "server = \"not a table\"\n");
    EXPECT_FALSE(mynet::reloadConfig(typeErrorPath));

    const mynet::MynetConfig after = mynet::getMynetConfig();
    EXPECT_EQ(before.server.port, after.server.port);
    EXPECT_EQ(before.server.host, after.server.host);

    std::filesystem::remove(syntaxErrorPath);
    std::filesystem::remove(typeErrorPath);
}

TEST(ConfigLua, SandboxBlocksArbitraryCommandExecution)
{
    const std::filesystem::path evilPath = "test_config_evil.lua";
    const std::string marker = "/tmp/mynet_pwned_marker";
    std::error_code ec;
    std::filesystem::remove(marker, ec);

    writeTestConfigFile(evilPath, "os.execute(\"touch " + marker + "\")\n");
    EXPECT_FALSE(mynet::reloadConfig(evilPath));
    EXPECT_FALSE(std::filesystem::exists(marker));

    std::filesystem::remove(evilPath);
}

TEST(ConfigLua, SnapshotTracksGenerationsWithoutLock)
{
    mynet::ConfigHolder<mynet::MynetConfig> holder;
    mynet::ConfigSnapshot<mynet::MynetConfig> snapshot(holder);

    EXPECT_EQ(snapshot.refConfig().server.port, 8888u);

    mynet::MynetConfig updated = holder.duplicate();
    updated.server.port = 12345;
    holder.publish(updated);

    EXPECT_EQ(snapshot.refConfig().server.port, 12345u);
}

TEST(ConfigLua, RcuGracefulDrainKeepsOldConfigAliveUntilSessionReleases)
{
    g_rcuLiveInstances = 0;
    EXPECT_EQ(g_rcuLiveInstances, 0);

    mynet::ConfigHolder<RcuTestConfig> holder(RcuTestConfig{.port = 8080});
    EXPECT_EQ(g_rcuLiveInstances, 1);

    // 会话 A 建连，持有代际 1 的 RCU 智能指针
    std::shared_ptr<const RcuTestConfig> sessionA = holder.currentConfig();
    EXPECT_EQ(sessionA->port, 8080);
    EXPECT_EQ(sessionA.use_count(), 2); // holder + sessionA

    // 控制面热重载发布代际 2
    holder.publish(RcuTestConfig{.port = 9090});
    EXPECT_EQ(holder.currentConfig()->port, 9090);

    // 关键断言：旧代际配置绝不就地析构！会话 A 依然稳定持有，完全杜绝 ECONNRESET
    EXPECT_EQ(sessionA->port, 8080);
    EXPECT_EQ(sessionA.use_count(), 1); // holder 已置换，仅剩 sessionA 活跃
    EXPECT_EQ(g_rcuLiveInstances, 2);   // 代际 1 (sessionA) 与 代际 2 (holder) 共存

    // 会话 A 结束并释放句柄 -> 触发旧代际资源优雅排空 (Drain) 与自动安全析构
    sessionA.reset();
    EXPECT_EQ(g_rcuLiveInstances, 1); // 仅剩当前活跃的代际 2
}

TEST(ConfigLua, ConnectionPinsConfigurationGenerationAcrossLifecycle)
{
    mynet::ConnectionBase conn;
    EXPECT_EQ(conn.fd(), -1);

    // 模拟建连，setFd 自动绑定当前代际并持久持有 RCU 智能指针
    conn.setFd(99);
    const uint32_t pinnedGen = conn.configGeneration();
    EXPECT_GT(pinnedGen, 0u);
    const uint16_t initialPort = conn.config().server.port;

    EXPECT_NE(conn.configShared(), nullptr);

    // 发布新配置 -> 自动同步推进代际版本号
    auto newCfg = mynet::getMynetConfig();
    newCfg.server.port = 34567;
    mynet::publishMynetConfig(newCfg);
    const uint32_t newGen = mynet::MynetConfigHolder::getInstance().getGeneration();
    EXPECT_GT(newGen, pinnedGen);

    // 关键断言：已建连的 conn 保持旧代际一致性，不受热重载影响
    EXPECT_EQ(conn.config().server.port, initialPort);

    // 重置/关闭连接 -> 优雅排空旧代际 RCU 引用
    conn.reset();
    EXPECT_EQ(conn.configShared(), nullptr);
}

TEST(ConfigLua, RejectsInvalidFieldTypes)
{
    const mynet::MynetConfig before = mynet::getMynetConfig();

    const std::filesystem::path badFieldPath = "test_config_bad_field.lua";
    writeTestConfigFile(badFieldPath, "server = {\n"
                                      "  port = \"not_a_number\"\n"
                                      "}\n");
    EXPECT_FALSE(mynet::reloadConfig(badFieldPath));

    const mynet::MynetConfig after = mynet::getMynetConfig();
    EXPECT_EQ(before.server.port, after.server.port);

    std::filesystem::remove(badFieldPath);
}

TEST(ConfigLua, ConnectionConfigLoadsAndAppliesDynamically)
{
    const std::filesystem::path connPath = "test_config_conn.lua";
    writeTestConfigFile(connPath, "connection = {\n"
                                  "  responseCapacity = 32,\n"
                                  "  readChunkSize = 2048,\n"
                                  "  maxRequestBytes = 1048576,\n"
                                  "  writeHighWaterMark = 2097152,\n"
                                  "  writeHardCapFactor = 3,\n"
                                  "  spliceChunkSize = 32768,\n"
                                  "  maxWriteIov = 8\n"
                                  "}\n");

    EXPECT_TRUE(mynet::reloadConfig(connPath));

    const auto &connCfg = mynet::getConnectionConfig();
    EXPECT_EQ(connCfg.responseCapacity, 32u);
    EXPECT_EQ(connCfg.readChunkSize, 2048u);
    EXPECT_EQ(connCfg.maxRequestBytes, 1048576u);
    EXPECT_EQ(connCfg.writeHighWaterMark, 2097152u);
    EXPECT_EQ(connCfg.writeHardCapFactor, 3u);
    EXPECT_EQ(connCfg.spliceChunkSize, 32768u);
    EXPECT_EQ(connCfg.maxWriteIov, 8u);

    // 验证 HandlerConnection 默认构造拾取配置中的容量与读写参数
    mynet::HandlerConnection handler;
    EXPECT_EQ(handler.readCredit(), 1048576u);
    auto prepRes = handler.prepareRequestWritable();
    ASSERT_TRUE(prepRes.has_value());
    EXPECT_GE(handler.requestWritableBytes(), 2048u);

    std::filesystem::remove(connPath);
}

TEST(ConfigLua, ReactorAndProactorSectionsDriveEngineDefaults)
{
    // 引擎入口不再持有默认实参：reactor / proactor / server 三个配置段是唯一来源。
    const mynet::MynetConfig saved = mynet::getMynetConfig();

    const std::filesystem::path enginePath = "test_config_engine.lua";
    writeTestConfigFile(enginePath, "server = {\n"
                                    "  idleTimeoutSecs = 120,\n"
                                    "  maxConnections = 4096\n"
                                    "}\n"
                                    "reactor = {\n"
                                    "  maxEvents = 2048,\n"
                                    "  idleSweepIntervalMs = 250\n"
                                    "}\n"
                                    "proactor = {\n"
                                    "  sqEntries = 4096,\n"
                                    "  cqEntries = 8192,\n"
                                    "  maxAcceptEvents = 512,\n"
                                    "  bufEntries = 2048,\n"
                                    "  bufSize = 8192,\n"
                                    "  udpBufSize = 131072\n"
                                    "}\n");

    EXPECT_TRUE(mynet::reloadConfig(enginePath));

    const auto &reactorCfg = mynet::getReactorConfig();
    EXPECT_EQ(reactorCfg.maxEvents, 2048);
    EXPECT_EQ(reactorCfg.idleSweepIntervalMs, 250);
    EXPECT_TRUE(mynet::validReactorConfig(reactorCfg));

    const auto &proactorCfg = mynet::getProactorConfig();
    EXPECT_EQ(proactorCfg.sqEntries, 4096u);
    EXPECT_EQ(proactorCfg.cqEntries, 8192u);
    EXPECT_EQ(proactorCfg.maxAcceptEvents, 512u);
    EXPECT_EQ(proactorCfg.bufEntries, 2048u);
    EXPECT_EQ(proactorCfg.bufSize, 8192u);
    EXPECT_EQ(proactorCfg.udpBufSize, 131072u);
    EXPECT_TRUE(mynet::validProactorConfig(proactorCfg));

    EXPECT_EQ(mynet::getServerConfig().idleTimeoutSecs, 120);
    EXPECT_EQ(mynet::getServerConfig().maxConnections, 4096u);

    std::filesystem::remove(enginePath);
    mynet::publishMynetConfig(saved);
}

TEST(ConfigLua, EngineSectionOutliersAreClamped)
{
    const mynet::MynetConfig saved = mynet::getMynetConfig();

    const std::filesystem::path clampPath = "test_config_engine_clamp.lua";
    writeTestConfigFile(clampPath, "server = {\n"
                                   "  idleTimeoutSecs = -5\n"
                                   "}\n"
                                   "reactor = {\n"
                                   "  maxEvents = 1,\n"
                                   "  idleSweepIntervalMs = 0\n"
                                   "}\n"
                                   "proactor = {\n"
                                   "  sqEntries = 1,\n"
                                   "  cqEntries = 999999,\n"
                                   "  maxAcceptEvents = 0,\n"
                                   "  bufEntries = 1,\n"
                                   "  bufSize = 1,\n"
                                   "  udpBufSize = 1\n"
                                   "}\n");

    EXPECT_TRUE(mynet::reloadConfig(clampPath));

    EXPECT_EQ(mynet::getServerConfig().idleTimeoutSecs, 0);
    EXPECT_EQ(mynet::getReactorConfig().maxEvents, 16);
    EXPECT_EQ(mynet::getReactorConfig().idleSweepIntervalMs, 10);

    const auto &proactorCfg = mynet::getProactorConfig();
    EXPECT_EQ(proactorCfg.sqEntries, 64u);
    EXPECT_EQ(proactorCfg.cqEntries, 32768u);
    EXPECT_EQ(proactorCfg.maxAcceptEvents, 1u);
    EXPECT_EQ(proactorCfg.bufEntries, 16u);
    EXPECT_EQ(proactorCfg.bufSize, 512u);
    EXPECT_EQ(proactorCfg.udpBufSize, 512u);

    std::filesystem::remove(clampPath);
    mynet::publishMynetConfig(saved);
}

TEST(ConfigLua, EngineConfigValidatorsRejectNonRunnableValues)
{
    mynet::ReactorConfig reactor{};
    EXPECT_TRUE(mynet::validReactorConfig(reactor));
    reactor.maxEvents = 0;
    EXPECT_FALSE(mynet::validReactorConfig(reactor));
    reactor.maxEvents = 16;
    reactor.idleSweepIntervalMs = 0;
    EXPECT_FALSE(mynet::validReactorConfig(reactor));

    mynet::ProactorConfig proactor{};
    EXPECT_TRUE(mynet::validProactorConfig(proactor));

    // 内核对 IORING_SETUP_CQSIZE 的硬性要求：CQ 不得小于 SQ。
    proactor.cqEntries = proactor.sqEntries - 1;
    EXPECT_FALSE(mynet::validProactorConfig(proactor));
    proactor.cqEntries = proactor.sqEntries;

    proactor.sqEntries = 0;
    EXPECT_FALSE(mynet::validProactorConfig(proactor));
    proactor.sqEntries = 64;
    proactor.bufSize = 0;
    EXPECT_FALSE(mynet::validProactorConfig(proactor));
    proactor.bufSize = 4096;
    proactor.cqeWaitMs = 0;
    EXPECT_FALSE(mynet::validProactorConfig(proactor));
    proactor.cqeWaitMs = 1000;
    proactor.bufRingAlignment = 3; // 非 2 的幂，posix_memalign 会拒绝
    EXPECT_FALSE(mynet::validProactorConfig(proactor));
}

TEST(ConfigLua, SecuritySectionFeedsTlsOptions)
{
    mynet::SecurityConfig security{};
    security.ciphers = "ECDHE-RSA-AES128-GCM-SHA256";
    security.alpnProtocols = " h2 , http/1.1 ,, ";

    const mynet::SecurityConfig options = mynet::detail::tlsOptionsFrom(security);
    EXPECT_EQ(options.ciphers, "ECDHE-RSA-AES128-GCM-SHA256");
    auto alpn = mynet::detail::splitAlpnList(options.alpnProtocols);
    ASSERT_EQ(alpn.size(), 2u);
    EXPECT_EQ(alpn[0], "h2");
    EXPECT_EQ(alpn[1], "http/1.1");

    // 空串必须产出空列表，而不是一个空协议名（那会让 ALPN 协商静默失败）。
    security.alpnProtocols.clear();
    EXPECT_TRUE(mynet::detail::splitAlpnList(mynet::detail::tlsOptionsFrom(security).alpnProtocols).empty());
}

TEST(ConfigLua, ProactorCqIsRaisedToCoverSq)
{
    // 两个字段各自合法、凑在一起却会让 io_uring_queue_init_params() 返回 EINVAL，
    // 因此解析期必须把这个跨字段约束收敛掉。
    const mynet::MynetConfig saved = mynet::getMynetConfig();

    const std::filesystem::path skewedPath = "test_config_proactor_cq.lua";
    writeTestConfigFile(skewedPath, "proactor = {\n"
                                    "  sqEntries = 2048,\n"
                                    "  cqEntries = 1024\n"
                                    "}\n");

    EXPECT_TRUE(mynet::reloadConfig(skewedPath));

    const auto &proactorCfg = mynet::getProactorConfig();
    EXPECT_EQ(proactorCfg.sqEntries, 2048u);
    EXPECT_EQ(proactorCfg.cqEntries, 2048u);
    EXPECT_TRUE(mynet::validProactorConfig(proactorCfg));

    std::filesystem::remove(skewedPath);
    mynet::publishMynetConfig(saved);
}

TEST(ConfigLua, ShippedConfigMatchesCompiledInBaseline)
{
    // config/config.lua 与 configHolder.hpp 的结构体默认值必须逐值一致。
    // 一旦有人只在一边改数字，就等于重新引入"双真相源"——同一个参数有两个
    // 默认值，行为取决于程序有没有调用 reloadConfig()。这条测试把这个不变量
    // 变成可检测的，而不是靠评审记得。
    const std::filesystem::path candidates[] = {"../config/config.lua", "config/config.lua", "../../config/config.lua"};
    std::filesystem::path shipped;
    for (const auto &candidate : candidates)
    {
        if (std::filesystem::exists(candidate))
        {
            shipped = candidate;
            break;
        }
    }
    if (shipped.empty())
    {
        GTEST_SKIP() << "config/config.lua not reachable from the test working directory";
    }

    const mynet::MynetConfig saved = mynet::getMynetConfig();

    // 先发布一份**每个字段都偏离基线**的哨兵配置，再加载 config.lua。
    //
    // 这一步是这条测试的关键：reloadConfig 以"当前配置"为起点，缺失的键会保持
    // 原值。若直接在当前配置上 reload，config.lua 少写任何一个键都检测不到——
    // 缺失字段会退回当前值，而当前值恰好等于基线，测试就假通过了。
    // 毒化之后，每个字段必须被 config.lua 显式改写才能回到基线。
    mynet::MynetConfig poison{};
    poison.server.host = "poison.invalid";
    poison.server.port = 1;
    poison.server.backlog = 2;
    poison.server.maxConnections = 3;
    poison.server.idleTimeoutSecs = 3;
    poison.server.tcpNoDelay = !poison.server.tcpNoDelay;
    poison.server.tcpQuickAck = !poison.server.tcpQuickAck;
    poison.server.enableSplice = !poison.server.enableSplice;
    poison.server.reuseAddr = !poison.server.reuseAddr;
    poison.server.reusePort = !poison.server.reusePort;
    poison.server.engine = "proactor";
    poison.reactor.maxEvents = 3;
    poison.reactor.idleSweepIntervalMs = 3;
    poison.connection.responseCapacity = 3;
    poison.connection.readChunkSize = 3;
    poison.connection.maxRequestBytes = 3;
    poison.connection.writeHighWaterMark = 3;
    poison.connection.writeHardCapFactor = 3;
    poison.connection.spliceChunkSize = 3;
    poison.connection.maxWriteIov = 3;
    poison.connection.readHighWaterMark = 3;
    poison.connection.maxDrainRounds = 3;
    poison.datagram.maxDatagramBytes = 3;
    poison.datagram.maxPendingOutgoing = 3;
    poison.proactor.sqEntries = 3;
    poison.proactor.cqEntries = 3;
    poison.proactor.maxAcceptEvents = 3;
    poison.proactor.bufEntries = 3;
    poison.proactor.bufSize = 3;
    poison.proactor.udpBufSize = 3;
    poison.proactor.bufRingAlignment = 8;
    poison.proactor.cqeWaitMs = 3;
    poison.http2.maxConcurrentStreams = 3;
    poison.http2.initialWindowSize = 3;
    poison.http2.maxFrameSize = 3;
    poison.http2.maxHeaderListSize = 3;
    poison.http2.headerTableSize = 3;
    poison.security.certFile = "poison.crt";
    poison.security.keyFile = "poison.key";
    poison.security.caFile = "poison-ca.pem";
    poison.security.ciphers = "POISON";
    poison.security.alpnProtocols = "poison";
    poison.security.sessionIdContext = "poison";
    poison.proxy.autoReplyConnectSuccess = !poison.proxy.autoReplyConnectSuccess;
    poison.http1.maxUrlLength = 3;
    poison.http1.maxHeadersCount = 3;
    poison.http1.maxHeaderFieldLength = 3;
    poison.http1.maxHeaderValueLength = 3;
    poison.http1.maxTotalHeadersLength = 3;
    poison.http1.maxBodyLength = 3;
    poison.http3.maxRequestBodyBytes = 3;
    poison.http3.maxStreamBufferBytes = 3;
    poison.http3.maxHeaderBlockBytes = 3;
    poison.http3.maxHeaderEntries = 3;
    poison.http3.port = 3;
    poison.forwarder.enableSplice = !poison.forwarder.enableSplice;
    poison.forwarder.propagateClose = !poison.forwarder.propagateClose;
    poison.forwarder.spliceChunkSize = 3;
    poison.forwarder.bufferChunkSize = 3;
    poison.forwarder.sessionIdleTimeoutSecs = 3;
    poison.forwarder.udpSessionTimeoutSecs = 3;
    poison.dns.servers = {"9.9.9.9"};
    poison.dns.port = 3;
    poison.dns.ttlSecs = 3;
    poison.dns.enableCache = !poison.dns.enableCache;
    poison.router.defaultOutbound = "poison";
    poison.ebpf.enabled = !poison.ebpf.enabled;
    poison.ebpf.wanInterface = "poison_wan";
    poison.ebpf.lanInterface = "poison_lan";
    poison.ebpf.tproxyPort = 3;
    poison.ebpf.fwmark = 3;
    poison.ebpf.enableDirectBypass = !poison.ebpf.enableDirectBypass;
    poison.ebpf.enableLpmGeoIp = !poison.ebpf.enableLpmGeoIp;
    poison.ebpf.dropQuic = !poison.ebpf.dropQuic;
    poison.fakeip.enabled = !poison.fakeip.enabled;
    poison.fakeip.inetRange = "poison_range";
    poison.fakeip.maxCapacity = 3;
    poison.geo.geoIpPath = "poison_geoip";
    poison.geo.geoSitePath = "poison_geosite";
    poison.geo.autoReload = !poison.geo.autoReload;
    poison.controller.enabled = !poison.controller.enabled;
    poison.controller.host = "poison_host";
    poison.controller.port = 3;
    poison.controller.secret = "poison_secret";
    mynet::publishMynetConfig(poison);

    const bool reloaded = mynet::reloadConfig(shipped, false);
    const mynet::MynetConfig loaded = mynet::getMynetConfig();
    // 无论解析成功与否都恢复现场，避免把半成品配置泄漏给后续用例。
    mynet::publishMynetConfig(saved);
    ASSERT_TRUE(reloaded) << "shipped config.lua must parse cleanly";

    const mynet::MynetConfig baseline{};

    EXPECT_EQ(loaded.server.host, baseline.server.host);
    EXPECT_EQ(loaded.server.port, baseline.server.port);
    EXPECT_EQ(loaded.server.backlog, baseline.server.backlog);
    EXPECT_EQ(loaded.server.maxConnections, baseline.server.maxConnections);
    EXPECT_EQ(loaded.server.idleTimeoutSecs, baseline.server.idleTimeoutSecs);
    EXPECT_EQ(loaded.server.tcpNoDelay, baseline.server.tcpNoDelay);
    EXPECT_EQ(loaded.server.tcpQuickAck, baseline.server.tcpQuickAck);
    EXPECT_EQ(loaded.server.enableSplice, baseline.server.enableSplice);
    EXPECT_EQ(loaded.server.reuseAddr, baseline.server.reuseAddr);
    EXPECT_EQ(loaded.server.reusePort, baseline.server.reusePort);
    EXPECT_EQ(loaded.server.engine, baseline.server.engine);

    EXPECT_EQ(loaded.reactor.maxEvents, baseline.reactor.maxEvents);
    EXPECT_EQ(loaded.reactor.idleSweepIntervalMs, baseline.reactor.idleSweepIntervalMs);

    EXPECT_EQ(loaded.connection.responseCapacity, baseline.connection.responseCapacity);
    EXPECT_EQ(loaded.connection.readChunkSize, baseline.connection.readChunkSize);
    EXPECT_EQ(loaded.connection.maxRequestBytes, baseline.connection.maxRequestBytes);
    EXPECT_EQ(loaded.connection.writeHighWaterMark, baseline.connection.writeHighWaterMark);
    EXPECT_EQ(loaded.connection.writeHardCapFactor, baseline.connection.writeHardCapFactor);
    EXPECT_EQ(loaded.connection.spliceChunkSize, baseline.connection.spliceChunkSize);
    EXPECT_EQ(loaded.connection.maxWriteIov, baseline.connection.maxWriteIov);
    EXPECT_EQ(loaded.connection.readHighWaterMark, baseline.connection.readHighWaterMark);
    EXPECT_EQ(loaded.connection.maxDrainRounds, baseline.connection.maxDrainRounds);

    EXPECT_EQ(loaded.datagram.maxDatagramBytes, baseline.datagram.maxDatagramBytes);
    EXPECT_EQ(loaded.datagram.maxPendingOutgoing, baseline.datagram.maxPendingOutgoing);

    EXPECT_EQ(loaded.proactor.sqEntries, baseline.proactor.sqEntries);
    EXPECT_EQ(loaded.proactor.cqEntries, baseline.proactor.cqEntries);
    EXPECT_EQ(loaded.proactor.maxAcceptEvents, baseline.proactor.maxAcceptEvents);
    EXPECT_EQ(loaded.proactor.bufEntries, baseline.proactor.bufEntries);
    EXPECT_EQ(loaded.proactor.bufSize, baseline.proactor.bufSize);
    EXPECT_EQ(loaded.proactor.udpBufSize, baseline.proactor.udpBufSize);
    EXPECT_EQ(loaded.proactor.bufRingAlignment, baseline.proactor.bufRingAlignment);
    EXPECT_EQ(loaded.proactor.cqeWaitMs, baseline.proactor.cqeWaitMs);

    EXPECT_EQ(loaded.http2.maxConcurrentStreams, baseline.http2.maxConcurrentStreams);
    EXPECT_EQ(loaded.http2.initialWindowSize, baseline.http2.initialWindowSize);
    EXPECT_EQ(loaded.http2.maxFrameSize, baseline.http2.maxFrameSize);
    EXPECT_EQ(loaded.http2.maxHeaderListSize, baseline.http2.maxHeaderListSize);
    EXPECT_EQ(loaded.http2.headerTableSize, baseline.http2.headerTableSize);

    EXPECT_EQ(loaded.security.certFile, baseline.security.certFile);
    EXPECT_EQ(loaded.security.keyFile, baseline.security.keyFile);
    EXPECT_EQ(loaded.security.caFile, baseline.security.caFile);
    EXPECT_EQ(loaded.security.ciphers, baseline.security.ciphers);
    EXPECT_EQ(loaded.security.alpnProtocols, baseline.security.alpnProtocols);
    EXPECT_EQ(loaded.security.sessionIdContext, baseline.security.sessionIdContext);

    EXPECT_EQ(loaded.proxy.autoReplyConnectSuccess, baseline.proxy.autoReplyConnectSuccess);

    EXPECT_EQ(loaded.http1.maxUrlLength, baseline.http1.maxUrlLength);
    EXPECT_EQ(loaded.http1.maxHeadersCount, baseline.http1.maxHeadersCount);
    EXPECT_EQ(loaded.http1.maxHeaderFieldLength, baseline.http1.maxHeaderFieldLength);
    EXPECT_EQ(loaded.http1.maxHeaderValueLength, baseline.http1.maxHeaderValueLength);
    EXPECT_EQ(loaded.http1.maxTotalHeadersLength, baseline.http1.maxTotalHeadersLength);
    EXPECT_EQ(loaded.http1.maxBodyLength, baseline.http1.maxBodyLength);

    EXPECT_EQ(loaded.http3.maxRequestBodyBytes, baseline.http3.maxRequestBodyBytes);
    EXPECT_EQ(loaded.http3.maxStreamBufferBytes, baseline.http3.maxStreamBufferBytes);
    EXPECT_EQ(loaded.http3.maxHeaderBlockBytes, baseline.http3.maxHeaderBlockBytes);
    EXPECT_EQ(loaded.http3.maxHeaderEntries, baseline.http3.maxHeaderEntries);
    EXPECT_EQ(loaded.http3.port, baseline.http3.port);

    EXPECT_EQ(loaded.forwarder.enableSplice, baseline.forwarder.enableSplice);
    EXPECT_EQ(loaded.forwarder.propagateClose, baseline.forwarder.propagateClose);
    EXPECT_EQ(loaded.forwarder.spliceChunkSize, baseline.forwarder.spliceChunkSize);
    EXPECT_EQ(loaded.forwarder.bufferChunkSize, baseline.forwarder.bufferChunkSize);
    EXPECT_EQ(loaded.forwarder.sessionIdleTimeoutSecs, baseline.forwarder.sessionIdleTimeoutSecs);
    EXPECT_EQ(loaded.forwarder.udpSessionTimeoutSecs, baseline.forwarder.udpSessionTimeoutSecs);

    EXPECT_EQ(loaded.dns.servers, baseline.dns.servers);
    EXPECT_EQ(loaded.dns.port, baseline.dns.port);
    EXPECT_EQ(loaded.dns.ttlSecs, baseline.dns.ttlSecs);
    EXPECT_EQ(loaded.dns.enableCache, baseline.dns.enableCache);

    EXPECT_EQ(loaded.router.defaultOutbound, baseline.router.defaultOutbound);
    EXPECT_EQ(loaded.router.rules.size(), baseline.router.rules.size());
    EXPECT_EQ(loaded.inbounds.size(), baseline.inbounds.size());
    EXPECT_EQ(loaded.outbounds.size(), baseline.outbounds.size());

    EXPECT_EQ(loaded.ebpf.enabled, baseline.ebpf.enabled);
    EXPECT_EQ(loaded.ebpf.wanInterface, baseline.ebpf.wanInterface);
    EXPECT_EQ(loaded.ebpf.lanInterface, baseline.ebpf.lanInterface);
    EXPECT_EQ(loaded.ebpf.tproxyPort, baseline.ebpf.tproxyPort);
    EXPECT_EQ(loaded.ebpf.fwmark, baseline.ebpf.fwmark);
    EXPECT_EQ(loaded.ebpf.enableDirectBypass, baseline.ebpf.enableDirectBypass);
    EXPECT_EQ(loaded.ebpf.enableLpmGeoIp, baseline.ebpf.enableLpmGeoIp);
    EXPECT_EQ(loaded.ebpf.dropQuic, baseline.ebpf.dropQuic);

    EXPECT_EQ(loaded.fakeip.enabled, baseline.fakeip.enabled);
    EXPECT_EQ(loaded.fakeip.inetRange, baseline.fakeip.inetRange);
    EXPECT_EQ(loaded.fakeip.maxCapacity, baseline.fakeip.maxCapacity);

    EXPECT_EQ(loaded.geo.geoIpPath, baseline.geo.geoIpPath);
    EXPECT_EQ(loaded.geo.geoSitePath, baseline.geo.geoSitePath);
    EXPECT_EQ(loaded.geo.autoReload, baseline.geo.autoReload);

    EXPECT_EQ(loaded.controller.enabled, baseline.controller.enabled);
    EXPECT_EQ(loaded.controller.host, baseline.controller.host);
    EXPECT_EQ(loaded.controller.port, baseline.controller.port);
    EXPECT_EQ(loaded.controller.secret, baseline.controller.secret);
}

TEST(ConfigLua, EventCapacityFollowsMaxEventsExactly)
{
    // reactor.maxEvents 的价值在于"单次 epoll_wait 最多返回多少个事件"。
    // 若底层只增不减，配置写 512 实际仍按 1024 收事件，这项配置就是空话。
    mynet::EventLoop loop;

    loop.setEventCapacity(512);
    EXPECT_EQ(loop.eventCapacity(), 512u);

    loop.setEventCapacity(2048);
    EXPECT_EQ(loop.eventCapacity(), 2048u);

    // 缩容必须生效——这正是旧实现缺失的一半。
    loop.setEventCapacity(64);
    EXPECT_EQ(loop.eventCapacity(), 64u);

    // epoll_wait 的 maxevents 必须 > 0，0 被抬到 1 而不是留下空数组。
    loop.setEventCapacity(0);
    EXPECT_EQ(loop.eventCapacity(), 1u);
}

TEST(ConfigLua, AlpnIsOptInByDefault)
{
    // 服务端只有在确实实现某协议时才应宣告它。默认必须是"不协商"，
    // 否则一个回声服务器会向客户端谎称自己支持 h2。
    const mynet::SecurityConfig shipped{};
    EXPECT_TRUE(shipped.alpnProtocols.empty());
    EXPECT_TRUE(mynet::detail::tlsOptionsFrom(shipped).alpnProtocols.empty());

    mynet::SecurityConfig optedIn{};
    optedIn.alpnProtocols = "h2,http/1.1";
    const mynet::SecurityConfig options = mynet::detail::tlsOptionsFrom(optedIn);
    auto alpnList = mynet::detail::splitAlpnList(options.alpnProtocols);
    ASSERT_EQ(alpnList.size(), 2u);
    EXPECT_EQ(alpnList[0], "h2");
    EXPECT_EQ(alpnList[1], "http/1.1");
}

TEST(ConfigLua, DefaultSecurityNegotiatesNoAlpnOnTheWire)
{
    // 最强的证据形式：真的跑一次 TLS 握手，看服务端到底有没有选中 ALPN。
    // 只断言"那个字符串是空的"属于同义反复；这里断言的是线级结果。
    const std::filesystem::path candidates[] = {"../../certs/ser.crt", "../certs/ser.crt", "certs/ser.crt"};
    std::filesystem::path cert;
    std::filesystem::path key;
    for (const auto &candidate : candidates)
    {
        std::filesystem::path c = candidate;
        std::filesystem::path k = candidate;
        k.replace_filename("ser.key");
        if (std::filesystem::exists(c) && std::filesystem::exists(k))
        {
            cert = c;
            key = k;
            break;
        }
    }
    if (cert.empty())
    {
        GTEST_SKIP() << "certs/ser.crt not reachable from the test working directory";
    }

    // 在一对内存 BIO 上驱动一次完整握手；返回服务端选中的 ALPN（无则空串）。
    auto handshakeAlpn = [&](const mynet::SecurityConfig &security, const std::string &clientOffer) -> std::string
    {
        const std::string zero{};
        SSL_CTX *serverCtx = SSL_CTX_new(TLS_server_method());
        SSL_CTX *clientCtx = SSL_CTX_new(TLS_client_method());
        if (serverCtx == nullptr || clientCtx == nullptr)
        {
            SSL_CTX_free(serverCtx);
            SSL_CTX_free(clientCtx);
            return "<ctx alloc failed>";
        }

        mynet::SecurityConfig options = mynet::detail::tlsOptionsFrom(security);
        auto alpnList = mynet::detail::splitAlpnList(options.alpnProtocols);
        const bool configured = mynet::detail::configureTlsContext(serverCtx, options, true, &alpnList).has_value();
        const bool loaded = configured && SSL_CTX_use_certificate_file(serverCtx, cert.c_str(), SSL_FILETYPE_PEM) > 0 &&
                            SSL_CTX_use_PrivateKey_file(serverCtx, key.c_str(), SSL_FILETYPE_PEM) > 0;

        BIO *clientBio = nullptr;
        BIO *serverBio = nullptr;
        std::string selected = "<not run>";
        if (loaded && BIO_new_bio_pair(&clientBio, 0, &serverBio, 0) == 1)
        {
            SSL *server = SSL_new(serverCtx);
            SSL *client = SSL_new(clientCtx);
            if (server != nullptr && client != nullptr)
            {
                SSL_set_bio(server, serverBio, serverBio);
                SSL_set_bio(client, clientBio, clientBio);
                SSL_set_connect_state(client);
                SSL_set_accept_state(server);
                if (!clientOffer.empty())
                {
                    std::vector<unsigned char> wire;
                    const auto parts = mynet::detail::splitAlpnList(clientOffer);
                    for (const auto &protocol : parts)
                    {
                        wire.push_back(static_cast<unsigned char>(protocol.size()));
                        wire.insert(wire.end(), protocol.begin(), protocol.end());
                    }
                    (void)SSL_set_alpn_protos(client, wire.data(), static_cast<unsigned int>(wire.size()));
                }
                // 交替推进两端，直到握手完成或明显卡死。
                for (int round = 0; round < 200; ++round)
                {
                    const int cr = SSL_do_handshake(client);
                    const int sr = SSL_do_handshake(server);
                    if (cr == 1 && sr == 1)
                    {
                        const unsigned char *proto = nullptr;
                        unsigned int len = 0;
                        SSL_get0_alpn_selected(server, &proto, &len);
                        selected.assign(proto != nullptr ? reinterpret_cast<const char *>(proto) : "", len);
                        break;
                    }
                    if ((cr < 0 && SSL_get_error(client, cr) != SSL_ERROR_WANT_READ &&
                         SSL_get_error(client, cr) != SSL_ERROR_WANT_WRITE) ||
                        (sr < 0 && SSL_get_error(server, sr) != SSL_ERROR_WANT_READ &&
                         SSL_get_error(server, sr) != SSL_ERROR_WANT_WRITE))
                    {
                        selected = "<handshake failed>";
                        break;
                    }
                    if (cr != 1 || sr != 1)
                    {
                        continue;
                    }
                }
            }
            SSL_free(server);
            SSL_free(client);
        }
        SSL_CTX_free(serverCtx);
        SSL_CTX_free(clientCtx);
        (void)zero;
        return selected;
    };

    // 默认配置：客户端提议 h2，服务端不得选中任何协议。
    EXPECT_EQ(handshakeAlpn(mynet::SecurityConfig{}, "h2,http/1.1"), "");

    // 显式开启后必须能选中 h2 —— 证明上一条不是因为握手根本没跑起来。
    mynet::SecurityConfig optedIn{};
    optedIn.alpnProtocols = "h2,http/1.1";
    EXPECT_EQ(handshakeAlpn(optedIn, "h2,http/1.1"), "h2");
}

TEST(ConfigLua, CipherDefaultDoesNotOverrideSystemPolicy)
{
    // "DEFAULT" 与空串都归一为"不调用 set_cipher_list"。用"配置里写 DEFAULT 后，
    // 调用前后的套件列表指纹不变"来证明——若真的调用了，指纹会变成 DEFAULT
    // 展开后的固定清单，从而覆盖 openssl.cnf 的 system_default 策略。
    auto cipherFingerprint = [](const mynet::SecurityConfig &security)
    {
        SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
        mynet::TlsOptions options = mynet::detail::tlsOptionsFrom(security);
        (void)mynet::detail::configureTlsContext(ctx, options, true);
        std::string out;
        STACK_OF(SSL_CIPHER) *list = SSL_CTX_get_ciphers(ctx);
        const int n = list != nullptr ? sk_SSL_CIPHER_num(list) : 0;
        for (int i = 0; i < n; ++i)
        {
            const SSL_CIPHER *cipher = sk_SSL_CIPHER_value(list, i);
            const char *name = SSL_CIPHER_get_name(cipher);
            out.append(name != nullptr ? name : "?");
            out.push_back(' ');
        }
        SSL_CTX_free(ctx);
        return out;
    };

    mynet::SecurityConfig empty{};
    mynet::SecurityConfig literalDefault{};
    literalDefault.ciphers = "DEFAULT";

    EXPECT_EQ(literalDefault.ciphers, "DEFAULT");
    EXPECT_EQ(cipherFingerprint(empty), cipherFingerprint(literalDefault));
}

TEST(ConfigLua, ReactorAppliesMaxEventsToTheEventLoop)
{
    // setEventCapacity 本身有单测了，但那只能证明 setter 有效。
    // 这里证明**引擎真的把 reactor.maxEvents 传下去了**——否则配置项就是死字段。
    mynet::MynetConfig saved = mynet::getMynetConfig();

    mynet::MynetConfig cfg = saved;
    cfg.reactor.maxEvents = 384;
    cfg.server.maxConnections = 16;
    mynet::publishMynetConfig(cfg);

    mynet::Reactor<mynet::AcceptorBase<mynet::HandlerConnection>> server;
    // 端口 0 交给内核挑，避免与本机其他测试/服务抢端口
    std::thread runner([&] { (void)server.runTcp("127.0.0.1", 0); });
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    const size_t capacity = server.loop().eventCapacity();
    const size_t poolCapacity = server.connectionPoolCapacity();
    server.stop();
    runner.join();

    mynet::publishMynetConfig(saved);

    EXPECT_EQ(capacity, 384u);
    EXPECT_EQ(poolCapacity, 16u);
}

TEST(ConfigLua, EveryConfigFieldIsRegisteredWithAReloadMode)
{
    // 「热配置 / 启动配置」的划分不能只活在文档里。这里用静态反射枚举
    // MynetConfig 的每一个字段，与 kConfigReloadMap 逐项比对：
    //   - 结构体新增了字段却没登记  -> 测试失败（不允许再来一个"配了不读"）
    //   - 登记表里留了已删除的字段  -> 测试失败（不允许幽灵条目）
    std::vector<std::string> actual;
    collectFieldPaths<mynet::ServerConfig>("server", actual);
    collectFieldPaths<mynet::ReactorConfig>("reactor", actual);
    collectFieldPaths<mynet::ProactorConfig>("proactor", actual);
    collectFieldPaths<mynet::ConnectionConfig>("connection", actual);
    collectFieldPaths<mynet::DatagramConfig>("datagram", actual);
    collectFieldPaths<mynet::SecurityConfig>("security", actual);
    collectFieldPaths<mynet::Http1Config>("http1", actual);
    collectFieldPaths<mynet::Http2Config>("http2", actual);
    collectFieldPaths<mynet::Http3Config>("http3", actual);
    collectFieldPaths<mynet::ProxyConfig>("proxy", actual);
    collectFieldPaths<mynet::ForwarderConfig>("forwarder", actual);
    collectFieldPaths<mynet::RouterConfig>("router", actual);
    collectFieldPaths<mynet::DnsConfig>("dns", actual);
    collectFieldPaths<mynet::EbpfConfig>("ebpf", actual);
    collectFieldPaths<mynet::FakeIPConfig>("fakeip", actual);
    collectFieldPaths<mynet::GeoConfig>("geo", actual);
    collectFieldPaths<mynet::ControllerConfig>("controller", actual);

    std::vector<std::string> registered;
    registered.reserve(std::size(mynet::kConfigReloadMap));
    for (const mynet::ConfigFieldReload &entry : mynet::kConfigReloadMap)
    {
        registered.emplace_back(entry.path);
    }

    EXPECT_EQ(actual, registered);

    // 每条登记项都必须能给出明确时机，而不是落到 reloadModeOf 的兜底分支。
    std::set<std::string> unique(registered.begin(), registered.end());
    EXPECT_EQ(unique.size(), registered.size()) << "duplicate entries in kConfigReloadMap";
}

TEST(ConfigLua, HotAndStartupAreBothRepresented)
{
    size_t hot = 0;
    size_t startup = 0;
    for (const mynet::ConfigFieldReload &entry : mynet::kConfigReloadMap)
    {
        (entry.mode == mynet::ReloadMode::Hot ? hot : startup)++;
    }
    EXPECT_GT(hot, 0u);
    EXPECT_GT(startup, 0u);

    // 抽查几个语义明确的归属，防止整表被误改成同一类。
    EXPECT_EQ(mynet::reloadModeOf("connection.readChunkSize"), mynet::ReloadMode::Hot);
    EXPECT_EQ(mynet::reloadModeOf("server.tcpNoDelay"), mynet::ReloadMode::Hot);
    EXPECT_EQ(mynet::reloadModeOf("server.backlog"), mynet::ReloadMode::Startup);
    EXPECT_EQ(mynet::reloadModeOf("reactor.maxEvents"), mynet::ReloadMode::Startup);
    EXPECT_EQ(mynet::reloadModeOf("proactor.cqeWaitMs"), mynet::ReloadMode::Startup);

    // 未登记的路径保守地按启动期处理，绝不谎称热生效。
    EXPECT_EQ(mynet::reloadModeOf("server.doesNotExist"), mynet::ReloadMode::Startup);
}

TEST(ConfigLua, StartupFieldIsNotRetroactivelyAppliedToARunningEngine)
{
    // 这是"启动期"分类的定义本身：reload 之后，已在运行的引擎保持启动时的值，
    // 只有新启动的引擎才看到新值。若哪天有人把 reactor.maxEvents 改成热读，
    // 这条测试会立刻发现分类与实际行为不符。
    const mynet::MynetConfig saved = mynet::getMynetConfig();

    mynet::MynetConfig cfg = saved;
    cfg.reactor.maxEvents = 384;
    mynet::publishMynetConfig(cfg);

    mynet::Reactor<mynet::AcceptorBase<mynet::HandlerConnection>> running;
    std::thread runner([&] { (void)running.runTcp("127.0.0.1", 0); });
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
    ASSERT_EQ(running.loop().eventCapacity(), 384u);

    // 运行中 reload 到 768：分类是 Startup，所以运行中的实例不应改变。
    cfg.reactor.maxEvents = 768;
    mynet::publishMynetConfig(cfg);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(running.loop().eventCapacity(), 384u) << "Startup field must not change a running engine";

    running.stop();
    runner.join();

    // 新启动的实例则采用新值。
    mynet::Reactor<mynet::AcceptorBase<mynet::HandlerConnection>> fresh;
    std::thread runner2([&] { (void)fresh.runTcp("127.0.0.1", 0); });
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
    EXPECT_EQ(fresh.loop().eventCapacity(), 768u);
    fresh.stop();
    runner2.join();

    mynet::publishMynetConfig(saved);
}

TEST(ConfigLua, HotFieldAppliesToConnectionsCreatedAfterReload)
{
    // 对照：connection 段是"热"，新连接必须采用 reload 后的值。
    const mynet::MynetConfig saved = mynet::getMynetConfig();

    mynet::MynetConfig cfg = saved;
    cfg.connection.maxRequestBytes = 1 << 20;
    mynet::publishMynetConfig(cfg);
    mynet::HandlerConnection before;
    EXPECT_EQ(before.readCredit(), 1u << 20);

    cfg.connection.maxRequestBytes = 2 << 20;
    mynet::publishMynetConfig(cfg);
    mynet::HandlerConnection after;
    EXPECT_EQ(after.readCredit(), 2u << 20) << "Hot field must apply without restarting the engine";

    mynet::publishMynetConfig(saved);
}

TEST(ConfigLua, TcpQuickAckActuallyReachesTheSocket)
{
    // 内核新建 TCP 连接的 TCP_QUICKACK 默认就是 1，因此"读出来是 1"什么也证明不了。
    // 先手动清零，再看 setFd 是否把它抬回 1——这才证明配置真的走到了 setsockopt。
    const mynet::MynetConfig saved = mynet::getMynetConfig();

    int listenFd = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(listenFd, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    ASSERT_EQ(::bind(listenFd, reinterpret_cast<sockaddr *>(&addr), sizeof addr), 0);
    ASSERT_EQ(::listen(listenFd, 1), 0);
    socklen_t addrLen = sizeof addr;
    ASSERT_EQ(::getsockname(listenFd, reinterpret_cast<sockaddr *>(&addr), &addrLen), 0);

    int clientFd = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(clientFd, 0);
    ASSERT_EQ(::connect(clientFd, reinterpret_cast<sockaddr *>(&addr), sizeof addr), 0);
    const int serverFd = ::accept(listenFd, nullptr, nullptr);
    ASSERT_GE(serverFd, 0);

    auto readFlag = [serverFd]
    {
        int v = -1;
        socklen_t l = sizeof v;
        ::getsockopt(serverFd, IPPROTO_TCP, TCP_QUICKACK, &v, &l);
        return v;
    };

    int zero = 0;
    ::setsockopt(serverFd, IPPROTO_TCP, TCP_QUICKACK, &zero, sizeof zero);
    ASSERT_EQ(readFlag(), 0) << "failed to clear TCP_QUICKACK for the test precondition";

    mynet::MynetConfig cfg = saved;
    cfg.server.tcpQuickAck = true;
    mynet::publishMynetConfig(cfg);
    {
        mynet::ConnectionBase conn;
        conn.setFd(serverFd);
        EXPECT_EQ(readFlag(), 1) << "tcpQuickAck = true must call setsockopt(TCP_QUICKACK)";
        conn.setFd(-1);
    }

    // 关闭时不得改动 socket（保持我们清零后的状态）。
    ::setsockopt(serverFd, IPPROTO_TCP, TCP_QUICKACK, &zero, sizeof zero);
    cfg.server.tcpQuickAck = false;
    mynet::publishMynetConfig(cfg);
    {
        mynet::ConnectionBase conn;
        conn.setFd(serverFd);
        EXPECT_EQ(readFlag(), 0) << "tcpQuickAck = false must leave the socket untouched";
        conn.setFd(-1);
    }

    ::close(serverFd);
    ::close(clientFd);
    ::close(listenFd);
    mynet::publishMynetConfig(saved);
}

TEST(ConfigLua, SecurityCaFileEnablesClientCertificateVerification)
{
    // caFile 不能只是被解析。配了它，服务端就必须要求并校验客户端证书。
    const std::filesystem::path candidates[] = {"../../certs/ser.crt", "../certs/ser.crt", "certs/ser.crt"};
    std::filesystem::path caPath;
    for (const auto &candidate : candidates)
    {
        if (std::filesystem::exists(candidate))
        {
            caPath = candidate;
            break;
        }
    }
    if (caPath.empty())
    {
        GTEST_SKIP() << "certs/ser.crt not reachable from the test working directory";
    }

    // 未配置 CA：不启用客户端认证
    {
        SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
        ASSERT_NE(ctx, nullptr);
        mynet::TlsOptions options = mynet::detail::tlsOptionsFrom(mynet::SecurityConfig{});
        ASSERT_TRUE(mynet::detail::configureTlsContext(ctx, options, true));
        EXPECT_EQ(SSL_CTX_get_verify_mode(ctx), SSL_VERIFY_NONE);
        SSL_CTX_free(ctx);
    }

    // 配置 CA：必须要求客户端证书（双向认证）
    {
        SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
        ASSERT_NE(ctx, nullptr);
        mynet::SecurityConfig security{};
        security.caFile = caPath.string();
        mynet::TlsOptions options = mynet::detail::tlsOptionsFrom(security);
        ASSERT_TRUE(mynet::detail::configureTlsContext(ctx, options, true));
        const int mode = SSL_CTX_get_verify_mode(ctx);
        EXPECT_NE(mode & SSL_VERIFY_PEER, 0) << "caFile must request a peer certificate";
        EXPECT_NE(mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0) << "a missing client cert must fail the handshake";
        SSL_CTX_free(ctx);
    }

    // 路径不存在时不能静默忽略，必须报错
    {
        SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
        ASSERT_NE(ctx, nullptr);
        mynet::SecurityConfig security{};
        security.caFile = "/nonexistent/ca-does-not-exist.crt";
        mynet::TlsOptions options = mynet::detail::tlsOptionsFrom(security);
        EXPECT_FALSE(mynet::detail::configureTlsContext(ctx, options, true).has_value());
        SSL_CTX_free(ctx);
    }
}

TEST(ConfigLua, CoreLoadLuaConfigEndToEnd)
{
    const std::filesystem::path configPath = "test_config_proxy_core.lua";
    writeTestConfigFile(configPath, "router = {\n"
                                    "  defaultOutbound = \"direct\",\n"
                                    "  rules = {\n"
                                    "    {\n"
                                    "      outbound = \"block\",\n"
                                    "      domainKeywords = {\"ads\"}\n"
                                    "    }\n"
                                    "  }\n"
                                    "}\n"
                                    "inbounds = {\n"
                                    "  {\n"
                                    "    tag = \"mixed-in\",\n"
                                    "    protocol = \"socks5\",\n"
                                    "    host = \"127.0.0.1\",\n"
                                    "    port = 7890\n"
                                    "  }\n"
                                    "}\n"
                                    "outbounds = {\n"
                                    "  {\n"
                                    "    tag = \"proxy-node\",\n"
                                    "    type = \"socks5\",\n"
                                    "    server = \"127.0.0.1\",\n"
                                    "    port = 1080\n"
                                    "  }\n"
                                    "}\n");

    EXPECT_TRUE(mynet::reloadConfig(configPath));
    const auto netCfg = mynet::getMynetConfig();

    mynet::Core core(netCfg);
    EXPECT_TRUE(core.acceptors().has("mixed-in"));
    EXPECT_TRUE(core.dialers().has("direct"));
    EXPECT_TRUE(core.dialers().has("block"));
    EXPECT_TRUE(core.dialers().has("proxy-node"));
    EXPECT_EQ(core.router().defaultOutbound(), "direct");

    // 规则匹配测试
    auto target = mynet::handler::ProxyAddress::fromDomain("test.ads.net", 80);
    mynet::handler::HandlerInboundDirect inbound(target);
    auto res = core.dispatch(inbound, -1, "mixed-in");
    EXPECT_EQ(res.status, mynet::CoreDispatchStatus::BLOCKED);
    EXPECT_EQ(res.outboundTag, "block");

    std::filesystem::remove(configPath);
}

TEST(ConfigLua, LoadTransportAndTlsOnInboundAndOutbound)
{
    const std::filesystem::path configPath = "test_config_transport_lua.lua";
    writeTestConfigFile(configPath, "inbounds = {\n"
                                    "  {\n"
                                    "    tag = \"vless-ws-lua\",\n"
                                    "    protocol = \"vless\",\n"
                                    "    host = \"127.0.0.1\",\n"
                                    "    port = 0,\n"
                                    "    uuid = \"de04add9-5c1a-4b08-8e65-244e45cf5483\",\n"
                                    "    transport = {\n"
                                    "      type = \"ws\",\n"
                                    "      path = \"/lua-in\",\n"
                                    "      host = \"lua.in.test\"\n"
                                    "    }\n"
                                    "  }\n"
                                    "}\n"
                                    "outbounds = {\n"
                                    "  {\n"
                                    "    tag = \"direct-ws-lua\",\n"
                                    "    type = \"direct\",\n"
                                    "    tls = {\n"
                                    "      enabled = true,\n"
                                    "      sni = \"lua.sni.test\",\n"
                                    "      alpn = \"h2,http/1.1\"\n"
                                    "    },\n"
                                    "    transport = {\n"
                                    "      type = \"ws\",\n"
                                    "      path = \"/lua-out\",\n"
                                    "      host = \"lua.out.test\"\n"
                                    "    }\n"
                                    "  }\n"
                                    "}\n");

    ASSERT_TRUE(mynet::reloadConfig(configPath));
    const auto netCfg = mynet::getMynetConfig();
    ASSERT_EQ(netCfg.inbounds.size(), 1u);
    EXPECT_EQ(netCfg.inbounds[0].transport.type, mynet::transport::TransportType::WEBSOCKET);
    EXPECT_EQ(netCfg.inbounds[0].transport.path, "/lua-in");
    EXPECT_EQ(netCfg.inbounds[0].transport.host, "lua.in.test");

    ASSERT_EQ(netCfg.outbounds.size(), 1u);
    EXPECT_TRUE(netCfg.outbounds[0].transport.enableTls);
    EXPECT_EQ(netCfg.outbounds[0].transport.sni, "lua.sni.test");
    EXPECT_EQ(netCfg.outbounds[0].transport.alpnProtocols, "h2,http/1.1");
    EXPECT_EQ(netCfg.outbounds[0].transport.type, mynet::transport::TransportType::WEBSOCKET);
    EXPECT_EQ(netCfg.outbounds[0].transport.path, "/lua-out");
    EXPECT_EQ(netCfg.outbounds[0].transport.host, "lua.out.test");

    mynet::Core core(netCfg);
    auto acc = core.acceptors().get("vless-ws-lua");
    ASSERT_NE(acc, nullptr);
    EXPECT_EQ(acc->transportConfig().type, mynet::transport::TransportType::WEBSOCKET);
    EXPECT_EQ(acc->transportConfig().path, "/lua-in");

    auto dialer = core.dialers().get("direct-ws-lua");
    ASSERT_NE(dialer, nullptr);
    EXPECT_TRUE(dialer->transportConfig().enableTls);
    EXPECT_EQ(dialer->transportConfig().sni, "lua.sni.test");
    EXPECT_EQ(dialer->transportConfig().path, "/lua-out");

    std::filesystem::remove(configPath);
}
