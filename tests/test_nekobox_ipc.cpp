#include "../src/nekobox/frame.hpp"
#include "../src/nekobox/proto.hpp"
#include "../src/nekobox/service.hpp"
#include <gtest/gtest.h>
#include <sys/socket.h>
#include <thread>
#include <vector>

using namespace mynet::nekobox;

// ============================================================================
// 1. 二进制帧编解码单元测试 (Frame Encoding & Decoding)
// ============================================================================

TEST(NekoBoxIpcTest, RequestFrameEncodeDecode)
{
    uint32_t reqId = 12345;
    std::string method = "Start";
    std::string payload = "\x0a\x0bhello_world";

    std::string encoded = encodeRequestFrame(reqId, method, payload);
    ASSERT_EQ(encoded.size(), 4 + 2 + method.size() + 4 + payload.size());

    std::span<const uint8_t> span(reinterpret_cast<const uint8_t *>(encoded.data()), encoded.size());
    auto frameOpt = decodeRequestFrame(span);

    ASSERT_TRUE(frameOpt.has_value());
    EXPECT_EQ(frameOpt->reqId, reqId);
    EXPECT_EQ(frameOpt->methodName, "Start");
    EXPECT_EQ(frameOpt->payload, payload);
    EXPECT_TRUE(span.empty());
}
TEST(NekoBoxIpcTest, ResponseFrameEncodeDecode)
{
    uint32_t reqId = 8888;
    uint8_t status = 0;
    std::string payload = "test_response_data";

    std::string encoded = encodeResponseFrame(reqId, status, payload);
    ASSERT_EQ(encoded.size(), 9 + payload.size());

    std::span<const uint8_t> span(reinterpret_cast<const uint8_t *>(encoded.data()), encoded.size());
    auto frameOpt = decodeResponseFrame(span);

    ASSERT_TRUE(frameOpt.has_value());
    EXPECT_EQ(frameOpt->reqId, reqId);
    EXPECT_EQ(frameOpt->status, 0);
    EXPECT_EQ(frameOpt->payload, payload);
    EXPECT_TRUE(span.empty());
}

// ============================================================================
// 2. Protobuf 协议结构编解码单元测试 (Protobuf Wire Encoders & Decoders)
// ============================================================================

TEST(NekoBoxIpcTest, ErrorRespEncodeDecode)
{
    std::string errStr = "Invalid JSON syntax at line 42";
    std::string enc = proto::encodeErrorResp(errStr);
    EXPECT_FALSE(enc.empty());

    std::string dec = proto::decodeErrorResp(enc);
    EXPECT_EQ(dec, errStr);

    std::string emptyEnc = proto::encodeErrorResp("");
    EXPECT_TRUE(emptyEnc.empty());
    EXPECT_EQ(proto::decodeErrorResp(emptyEnc), "");
}

TEST(NekoBoxIpcTest, LoadConfigReqEncodeDecode)
{
    proto::LoadConfigReq req;
    req.coreConfig = R"({"inbounds":[{"type":"mixed","listen_port":7890}]})";
    req.disableStats = true;
    req.tunIpv4Cidr = "172.19.0.1/30";

    std::string enc = proto::encodeLoadConfigReq(req);
    EXPECT_FALSE(enc.empty());

    proto::LoadConfigReq dec = proto::decodeLoadConfigReq(enc);
    EXPECT_EQ(dec.coreConfig, req.coreConfig);
    EXPECT_TRUE(dec.disableStats);
    EXPECT_EQ(dec.tunIpv4Cidr, "172.19.0.1/30");
}

TEST(NekoBoxIpcTest, IsPrivilegedResponseEncodeDecode)
{
    proto::IsPrivilegedResponse p;
    p.hasPrivilege = true;
    p.tunDevice = true;
    p.netAdmin = true;
    p.killSwitchPrivilege = true;
    p.detail = "All Linux capabilities granted";
    p.corePid = 54321;

    std::string enc = proto::encodeIsPrivilegedResponse(p);
    proto::IsPrivilegedResponse dec = proto::decodeIsPrivilegedResponse(enc);

    EXPECT_TRUE(dec.hasPrivilege);
    EXPECT_TRUE(dec.tunDevice);
    EXPECT_TRUE(dec.netAdmin);
    EXPECT_TRUE(dec.killSwitchPrivilege);
    EXPECT_EQ(dec.detail, p.detail);
    EXPECT_EQ(dec.corePid, 54321);
}

TEST(NekoBoxIpcTest, QueryStatsResponseEncodeDecode)
{
    std::map<std::string, int64_t> ups = {{"direct", 102400}, {"proxy", 512000}};
    std::map<std::string, int64_t> downs = {{"direct", 204800}, {"proxy", 1048576}};

    std::string enc = proto::encodeQueryStatsResponse(ups, downs);

    std::map<std::string, int64_t> decUps;
    std::map<std::string, int64_t> decDowns;
    proto::decodeQueryStatsResponse(enc, decUps, decDowns);

    EXPECT_EQ(decUps["direct"], 102400);
    EXPECT_EQ(decUps["proxy"], 512000);
    EXPECT_EQ(decDowns["direct"], 204800);
    EXPECT_EQ(decDowns["proxy"], 1048576);
}

TEST(NekoBoxIpcTest, URLTestResponseEncodeDecode)
{
    std::vector<proto::URLTestResult> results = {
        {"hongkong-01", 38, ""},
        {"tokyo-02", 72, ""},
        {"singapore-03", 0, "timeout"},
    };

    std::string enc = proto::encodeTestResponse(results);
    auto dec = proto::decodeTestResponse(enc);

    ASSERT_EQ(dec.size(), 3u);
    EXPECT_EQ(dec[0].outboundTag, "hongkong-01");
    EXPECT_EQ(dec[0].latencyMs, 38);
    EXPECT_TRUE(dec[0].error.empty());

    EXPECT_EQ(dec[1].outboundTag, "tokyo-02");
    EXPECT_EQ(dec[1].latencyMs, 72);

    EXPECT_EQ(dec[2].outboundTag, "singapore-03");
    EXPECT_EQ(dec[2].latencyMs, 0);
    EXPECT_EQ(dec[2].error, "timeout");
}

// ============================================================================
// 3. 端到端 UDS RPC 状态机交互与集成测试 (End-to-End UDS IPC Service)
// ============================================================================

TEST(NekoBoxIpcTest, EndToEndSocketPairInteraction)
{
    int sv[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);

    auto core = std::make_shared<mynet::Core>();
    NekoBoxIpcService service(core);

    bool startCalled = false;
    std::string startedJson;
    service.setOnStart([&](const proto::LoadConfigReq &req) -> std::string {
        startCalled = true;
        startedJson = req.coreConfig;
        return ""; // Success
    });

    bool stopCalled = false;
    service.setOnStop([&]() -> std::string {
        stopCalled = true;
        return "";
    });

    // 启动服务端在 sv[0] 处理
    std::thread srvThread([&service, fd = sv[0]]() {
        service.runOnSocket(fd);
    });

    int clientFd = sv[1];

    auto sendAndRecv = [clientFd](uint32_t reqId, std::string_view method, std::string_view reqPayload) -> ResponseFrame {
        std::string reqBytes = encodeRequestFrame(reqId, method, reqPayload);
        EXPECT_EQ(::send(clientFd, reqBytes.data(), reqBytes.size(), 0), static_cast<ssize_t>(reqBytes.size()));

        std::vector<uint8_t> buf(4096);
        ssize_t n = ::recv(clientFd, buf.data(), buf.size(), 0);
        EXPECT_GT(n, 0);

        std::span<const uint8_t> span(buf.data(), static_cast<size_t>(n));
        auto respOpt = decodeResponseFrame(span);
        EXPECT_TRUE(respOpt.has_value());
        return *respOpt;
    };

    // 1. 模拟 Throne GUI 探针: IsPrivileged
    {
        auto resp = sendAndRecv(1, "IsPrivileged", "");
        EXPECT_EQ(resp.reqId, 1u);
        EXPECT_EQ(resp.status, 0);
        auto priv = proto::decodeIsPrivilegedResponse(resp.payload);
        EXPECT_TRUE(priv.hasPrivilege);
        EXPECT_TRUE(priv.tunDevice);
        EXPECT_TRUE(priv.netAdmin);
        EXPECT_GT(priv.corePid, 0);
    }

    // 2. 模拟 Throne GUI 配置下发: Start
    {
        proto::LoadConfigReq loadReq;
        loadReq.coreConfig = R"({"inbounds":[{"type":"mixed","listen_port":1080}]})";
        std::string payload = proto::encodeLoadConfigReq(loadReq);

        auto resp = sendAndRecv(2, "Start", payload);
        EXPECT_EQ(resp.reqId, 2u);
        EXPECT_EQ(resp.status, 0);
        EXPECT_TRUE(startCalled);
        EXPECT_EQ(startedJson, loadReq.coreConfig);
        EXPECT_TRUE(proto::decodeErrorResp(resp.payload).empty());
    }

    // 3. 模拟 Throne GUI 定时轮询: QueryStats
    {
        auto resp = sendAndRecv(3, "QueryStats", "");
        EXPECT_EQ(resp.reqId, 3u);
        EXPECT_EQ(resp.status, 0);

        std::map<std::string, int64_t> ups;
        std::map<std::string, int64_t> downs;
        proto::decodeQueryStatsResponse(resp.payload, ups, downs);
        EXPECT_TRUE(ups.contains("direct"));
        EXPECT_TRUE(downs.contains("direct"));
    }

    // 4. 模拟 Throne GUI 查询默认网卡: GetDefaultInterface
    {
        auto resp = sendAndRecv(4, "GetDefaultInterface", "");
        EXPECT_EQ(resp.reqId, 4u);
        EXPECT_EQ(resp.status, 0);
    }

    // 5. 模拟 Throne GUI 延迟探测: Test
    {
        proto::TestReq tReq;
        tReq.url = "http://cp.cloudflare.com/generate_204";
        std::string payload;
        proto::appendStringField(payload, 4, tReq.url);

        auto resp = sendAndRecv(5, "Test", payload);
        EXPECT_EQ(resp.reqId, 5u);
        EXPECT_EQ(resp.status, 0);
        auto results = proto::decodeTestResponse(resp.payload);
        EXPECT_FALSE(results.empty());
    }

    // 6. 模拟 Throne GUI 连接监控: QueryConnections & CloseConnections
    {
        auto resp = sendAndRecv(6, "QueryConnections", "");
        EXPECT_EQ(resp.reqId, 6u);
        EXPECT_EQ(resp.status, 0);

        proto::CloseConnectionsReq cReq;
        cReq.ids.push_back("9999");
        std::string cPayload;
        for (const auto &id : cReq.ids)
        {
            proto::appendStringField(cPayload, 1, id);
        }
        auto closeResp = sendAndRecv(7, "CloseConnections", cPayload);
        EXPECT_EQ(closeResp.reqId, 7u);
        EXPECT_EQ(closeResp.status, 0);
    }

    // 7. 模拟 Throne GUI 分组出站选择器: QueryAutoSelectors & AutoSelectorAction
    {
        auto resp = sendAndRecv(8, "QueryAutoSelectors", "");
        EXPECT_EQ(resp.reqId, 8u);
        EXPECT_EQ(resp.status, 0);

        proto::AutoSelectorActionReq aReq;
        aReq.tag = "proxy";
        aReq.member = "node1";
        std::string aPayload;
        proto::appendStringField(aPayload, 1, aReq.tag);
        proto::appendStringField(aPayload, 2, aReq.member);
        auto actResp = sendAndRecv(9, "AutoSelectorAction", aPayload);
        EXPECT_EQ(actResp.reqId, 9u);
        EXPECT_EQ(actResp.status, 0);
    }

    // 8. 模拟 Throne GUI 停止核心: Stop
    {
        auto resp = sendAndRecv(10, "Stop", "");
        EXPECT_EQ(resp.reqId, 10u);
        EXPECT_EQ(resp.status, 0);
        EXPECT_TRUE(stopCalled);
        EXPECT_TRUE(proto::decodeErrorResp(resp.payload).empty());
    }

    // 关闭客户端并回收服务端
    ::close(clientFd);
    service.stop();
    if (srvThread.joinable())
    {
        srvThread.join();
    }
}

// ============================================================================
// 4. sing-box JSON 配置解析与转换单元测试 (JSON & Sing-Box Config Parser)
// ============================================================================

TEST(NekoBoxIpcTest, JsonParserBasics)
{
    std::string_view jsonStr = R"json({
        // 单行注释支持
        "app": "mynet",
        /* 块注释
           支持 */
        "version": 1,
        "pi": 3.1415,
        "enabled": true,
        "empty": null,
        "features": ["splice", "uring", "ebpf",], // 尾逗号支持
        "nested": {
            "key": "val"
        }
    })json";

    auto parsed = mynet::json::parse(jsonStr);
    ASSERT_TRUE(parsed.has_value());
    const auto &val = *parsed;

    EXPECT_EQ(val["app"].asString(), "mynet");
    EXPECT_EQ(val["version"].asInt(), 1);
    EXPECT_DOUBLE_EQ(val["pi"].asDouble(), 3.1415);
    EXPECT_TRUE(val["enabled"].asBool());
    EXPECT_TRUE(val["empty"].isNull());

    ASSERT_EQ(val["features"].asArray().size(), 3u);
    EXPECT_EQ(val["features"][0].asString(), "splice");
    EXPECT_EQ(val["features"][1].asString(), "uring");
    EXPECT_EQ(val["features"][2].asString(), "ebpf");

    EXPECT_EQ(val["nested"]["key"].asString(), "val");
}

TEST(NekoBoxIpcTest, SingBoxConfigParsingAndMapping)
{
    std::string_view singboxJson = R"json({
        "log": {
            "level": "info"
        },
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 7890,
                "sniff": true
            },
            {
                "type": "socks",
                "tag": "socks-in",
                "listen": "0.0.0.0",
                "listen_port": 1080
            }
        ],
        "outbounds": [
            {
                "type": "direct",
                "tag": "direct"
            },
            {
                "type": "block",
                "tag": "block"
            },
            {
                "type": "vless",
                "tag": "vless-out",
                "server": "1.2.3.4",
                "server_port": 443,
                "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
            },
            {
                "type": "selector",
                "tag": "proxy",
                "outbounds": ["vless-out", "direct"],
                "default": "vless-out"
            }
        ],
        "route": {
            "final": "proxy",
            "rules": [
                {
                    "domain_suffix": [".cn", "baidu.com"],
                    "outbound": "direct"
                },
                {
                    "ip_cidr": ["10.0.0.0/8", "192.168.0.0/16"],
                    "outbound": "direct"
                },
                {
                    "port": [80, 443],
                    "outbound": "proxy"
                }
            ]
        },
        "experimental": {
            "clash_api": {
                "external_controller": "127.0.0.1:9090",
                "secret": "my_secret_token"
            }
        }
    })json";

    auto cfgRes = mynet::config::singbox::parseSingBoxConfig(singboxJson);
    ASSERT_TRUE(cfgRes.has_value());
    const auto &cfg = *cfgRes;

    // 校验 Inbounds
    ASSERT_EQ(cfg.inbounds.size(), 2u);
    EXPECT_EQ(cfg.inbounds[0].protocol, "mixed");
    EXPECT_EQ(cfg.inbounds[0].port, 7890);
    EXPECT_TRUE(cfg.inbounds[0].enableSniffing);
    EXPECT_EQ(cfg.inbounds[1].protocol, "socks5");
    EXPECT_EQ(cfg.inbounds[1].port, 1080);

    // 校验 Outbounds
    ASSERT_EQ(cfg.outbounds.size(), 4u);
    EXPECT_EQ(cfg.outbounds[0].type, "direct");
    EXPECT_EQ(cfg.outbounds[1].type, "block");
    EXPECT_EQ(cfg.outbounds[2].type, "vless");
    EXPECT_EQ(cfg.outbounds[2].host, "1.2.3.4");
    EXPECT_EQ(cfg.outbounds[2].port, 443);
    EXPECT_EQ(cfg.outbounds[2].uuid, "a1b2c3d4-e5f6-7890-abcd-ef1234567890");

    EXPECT_EQ(cfg.outbounds[3].type, "selector");
    EXPECT_EQ(cfg.outbounds[3].defaultTag, "vless-out");
    ASSERT_EQ(cfg.outbounds[3].outbounds.size(), 2u);

    // 校验 Route
    EXPECT_EQ(cfg.router.defaultOutbound, "proxy");
    ASSERT_EQ(cfg.router.rules.size(), 3u);
    EXPECT_EQ(cfg.router.rules[0].outbound, "direct");
    ASSERT_EQ(cfg.router.rules[0].domainSuffixes.size(), 2u);
    EXPECT_EQ(cfg.router.rules[0].domainSuffixes[0], ".cn");

    EXPECT_EQ(cfg.router.rules[1].outbound, "direct");
    ASSERT_EQ(cfg.router.rules[1].ipCidrs.size(), 2u);

    EXPECT_EQ(cfg.router.rules[2].outbound, "proxy");
    ASSERT_EQ(cfg.router.rules[2].portRanges.size(), 2u);

    // 校验 Clash API
    EXPECT_TRUE(cfg.controller.enabled);
    EXPECT_EQ(cfg.controller.host, "127.0.0.1");
    EXPECT_EQ(cfg.controller.port, 9090);
    EXPECT_EQ(cfg.controller.secret, "my_secret_token");
}

TEST(NekoBoxIpcTest, NekoBoxStartAppliesSingBoxConfigToCore)
{
    auto core = std::make_shared<mynet::Core>();
    NekoBoxIpcService service(core);

    std::string_view singboxJson = R"json({
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 17890
            }
        ],
        "outbounds": [
            {
                "type": "direct",
                "tag": "direct"
            },
            {
                "type": "vless",
                "tag": "vless-us",
                "server": "us.proxy.example",
                "server_port": 443,
                "uuid": "00000000-0000-0000-0000-000000000000"
            }
        ],
        "route": {
            "final": "vless-us"
        }
    })json";

    proto::LoadConfigReq req;
    req.coreConfig = singboxJson;

    RequestFrame reqFrame{
        .reqId = 101,
        .methodName = "Start",
        .payload = proto::encodeLoadConfigReq(req),
    };

    auto resp = service.dispatch(reqFrame);
    EXPECT_EQ(resp.reqId, 101u);
    EXPECT_EQ(resp.status, 0);
    EXPECT_TRUE(proto::decodeErrorResp(resp.payload).empty());

    // 验证核心已被自动装配
    EXPECT_TRUE(core->acceptors().has("mixed-in"));
    EXPECT_TRUE(core->dialers().has("vless-us"));
    EXPECT_EQ(core->router().defaultOutbound(), "vless-us");

    // 验证 Stop
    RequestFrame stopFrame{
        .reqId = 102,
        .methodName = "Stop",
        .payload = "",
    };
    auto stopResp = service.dispatch(stopFrame);
    EXPECT_EQ(stopResp.reqId, 102u);
    EXPECT_EQ(stopResp.status, 0);
}
