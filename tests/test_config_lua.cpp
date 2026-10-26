#include "configer_lua.hpp"
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>

namespace
{

    void writeTestConfigFile(const std::filesystem::path &path, const std::string &content)
    {
        std::ofstream ofs(path, std::ios::trunc);
        ofs << content;
        ofs.close();
    }

} // namespace

TEST(ConfigLua, GoodConfigReloadsBothNetAndMylog)
{
    const std::filesystem::path configPath = "test_config_good.lua";
    writeTestConfigFile(configPath, "server = {\n"
                                    "  host = \"127.0.0.1\",\n"
                                    "  port = 9090,\n"
                                    "  backlog = 512,\n"
                                    "  maxConnections = 10000,\n"
                                    "  keepAliveTimeoutMs = 30000,\n"
                                    "  writeHighWaterMark = 8388608,\n"
                                    "  maxRequestBytes = 2097152,\n"
                                    "  tcpNoDelay = true,\n"
                                    "  tcpQuickAck = true,\n"
                                    "  enableSplice = false\n"
                                    "}\n"
                                    "proactor = {\n"
                                    "  sqEntries = 4096,\n"
                                    "  bufEntries = 2048,\n"
                                    "  bufSize = 8192\n"
                                    "}\n"
                                    "multiplexer = {\n"
                                    "  maxConcurrentStreams = 200,\n"
                                    "  initialWindowSize = 131072,\n"
                                    "  maxFrameSize = 32768,\n"
                                    "  maxHeaderListSize = 16384\n"
                                    "}\n"
                                    "security = {\n"
                                    "  enableTls = true,\n"
                                    "  certFile = \"mycert.pem\",\n"
                                    "  keyFile = \"mykey.pem\",\n"
                                    "  ciphers = \"ECDHE-RSA-AES128-GCM-SHA256\",\n"
                                    "  alpnProtocols = \"h2\"\n"
                                    "}\n"
                                    "logger = {\n"
                                    "  suppressLevel = \"warn\"\n"
                                    "}\n");

    EXPECT_TRUE(mynet::reloadConfig(configPath));

    const mynet::NetConfig cfg = mynet::getNetConfig();
    EXPECT_EQ(cfg.server.host, "127.0.0.1");
    EXPECT_EQ(cfg.server.port, 9090u);
    EXPECT_EQ(cfg.server.backlog, 512);
    EXPECT_EQ(cfg.server.maxConnections, 10000u);
    EXPECT_EQ(cfg.server.keepAliveTimeout_ms, 30000u);
    EXPECT_EQ(cfg.server.writeHighWaterMark, 8388608u);
    EXPECT_EQ(cfg.server.maxRequestBytes, 2097152u);
    EXPECT_TRUE(cfg.server.tcpNoDelay);
    EXPECT_TRUE(cfg.server.tcpQuickAck);
    EXPECT_FALSE(cfg.server.enableSplice);

    EXPECT_EQ(cfg.proactor.sqEntries, 4096u);
    EXPECT_EQ(cfg.proactor.bufEntries, 2048u);
    EXPECT_EQ(cfg.proactor.bufSize, 8192u);

    EXPECT_EQ(cfg.multiplexer.maxConcurrentStreams, 200u);
    EXPECT_EQ(cfg.multiplexer.initialWindowSize, 131072u);
    EXPECT_EQ(cfg.multiplexer.maxFrameSize, 32768u);
    EXPECT_EQ(cfg.multiplexer.maxHeaderListSize, 16384u);

    EXPECT_TRUE(cfg.security.enableTls);
    EXPECT_EQ(cfg.security.certFile, "mycert.pem");
    EXPECT_EQ(cfg.security.keyFile, "mykey.pem");
    EXPECT_EQ(cfg.security.ciphers, "ECDHE-RSA-AES128-GCM-SHA256");
    EXPECT_EQ(cfg.security.alpnProtocols, "h2");

    EXPECT_EQ(static_cast<int>(mylog::getCurrentSuppressLevel()), static_cast<int>(mylog::LEVEL::WARN));

    std::filesystem::remove(configPath);
}

TEST(ConfigLua, ClampsOutliersSafely)
{
    const std::filesystem::path clampPath = "test_config_clamp.lua";
    writeTestConfigFile(clampPath, "server = {\n"
                                   "  port = 999999,\n"
                                   "  keepAliveTimeoutMs = 1\n"
                                   "}\n"
                                   "multiplexer = {\n"
                                   "  maxFrameSize = 10\n"
                                   "}\n");

    EXPECT_TRUE(mynet::reloadConfig(clampPath));

    const mynet::NetConfig cfg = mynet::getNetConfig();
    EXPECT_EQ(cfg.server.port, 65535u);
    EXPECT_EQ(cfg.server.keepAliveTimeout_ms, 100u);
    EXPECT_EQ(cfg.multiplexer.maxFrameSize, 16384u);

    std::filesystem::remove(clampPath);
}

TEST(ConfigLua, InvalidSyntaxOrTypeDoesNotCorruptRunningConfig)
{
    const mynet::NetConfig before = mynet::getNetConfig();

    const std::filesystem::path syntaxErrorPath = "test_config_syntax_err.lua";
    writeTestConfigFile(syntaxErrorPath, "server = { port = \n");
    EXPECT_FALSE(mynet::reloadConfig(syntaxErrorPath));

    const std::filesystem::path typeErrorPath = "test_config_type_err.lua";
    writeTestConfigFile(typeErrorPath, "server = \"not a table\"\n");
    EXPECT_FALSE(mynet::reloadConfig(typeErrorPath));

    const mynet::NetConfig after = mynet::getNetConfig();
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
    mynet::ConfigHolder<mynet::NetConfig> holder;
    mynet::ConfigSnapshot<mynet::NetConfig> snapshot(holder);

    EXPECT_EQ(snapshot.refConfig().server.port, 8888u);

    mynet::NetConfig updated = holder.duplicate();
    updated.server.port = 12345;
    holder.publish(updated);

    EXPECT_EQ(snapshot.refConfig().server.port, 12345u);
}

TEST(ConfigLua, RejectsInvalidFieldTypes)
{
    const mynet::NetConfig before = mynet::getNetConfig();

    const std::filesystem::path badFieldPath = "test_config_bad_field.lua";
    writeTestConfigFile(badFieldPath, "server = {\n"
                                      "  port = \"not_a_number\"\n"
                                      "}\n");
    EXPECT_FALSE(mynet::reloadConfig(badFieldPath));

    const mynet::NetConfig after = mynet::getNetConfig();
    EXPECT_EQ(before.server.port, after.server.port);

    std::filesystem::remove(badFieldPath);
}
