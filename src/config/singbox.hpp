#pragma once

/**
 * @file config/singbox.hpp
 * @brief sing-box / NekoBox 标准 JSON 配置到 MynetConfig 的动态转换与加载引擎。
 *
 * 核心对标特性：
 * 1. inbounds (mixed, socks, http, trojan, vless, hysteria2, shadowsocks, tun)；
 * 2. outbounds (direct, block, socks, http, trojan, vless, vmess, hysteria2, shadowsocks, selector, urltest, fallback)；
 * 3. route (final, rules: domain, domain_suffix, domain_keyword, ip_cidr, port, protocol, geoip, geosite, rule_set, process_name)；
 * 4. experimental (clash_api external_controller & secret)；
 * 5. 严格异常中立 (std::expected<MynetConfig, std::string>)，保证 Fail-Fast 与全链路安全。
 */

#include "../configHolder.hpp"
#include "../tun/packet.hpp"
#include "json.hpp"
#include <cctype>
#include <charconv>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

namespace mynet::config::singbox
{

    inline uint32_t parseDurationSeconds(std::string_view s, uint32_t defaultVal = 300)
    {
        if (s.empty())
            return defaultVal;
        uint32_t num = 0;
        size_t i = 0;
        while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i])))
        {
            num = num * 10 + static_cast<uint32_t>(s[i] - '0');
            ++i;
        }
        if (i == 0)
            return defaultVal;
        if (i < s.size())
        {
            const char unit = s[i];
            if (unit == 's' || unit == 'S')
                return num;
            if (unit == 'm' || unit == 'M')
                return num * 60;
            if (unit == 'h' || unit == 'H')
                return num * 3600;
            if (unit == 'd' || unit == 'D')
                return num * 86400;
        }
        return num;
    }

    inline void appendStringOrArray(std::vector<std::string> &target, const json::Value &val)
    {
        if (val.isString())
        {
            target.push_back(std::string(val.asString()));
        }
        else if (val.isArray())
        {
            for (const auto &item : val.asArray())
            {
                if (item.isString())
                {
                    target.push_back(std::string(item.asString()));
                }
            }
        }
    }

    /**
     * @brief 解析 sing-box 风格 tls 与 transport 子块到 TransportConfig（入站/出站通用复用）
     */
    inline void parseSingBoxTransport(const json::Value &obj, transport::TransportConfig &out)
    {
        if (obj.contains("tls") && obj["tls"].isObject())
        {
            const auto &tlsObj = obj["tls"];
            out.enableTls = tlsObj["enabled"].asBool(false);
            if (tlsObj.contains("server_name"))
            {
                out.sni = std::string(tlsObj["server_name"].asString());
            }
            if (tlsObj.contains("certificate_path"))
            {
                out.certFile = std::string(tlsObj["certificate_path"].asString());
            }
            if (tlsObj.contains("key_path"))
            {
                out.keyFile = std::string(tlsObj["key_path"].asString());
            }
            if (tlsObj.contains("alpn"))
            {
                const auto &alpn = tlsObj["alpn"];
                if (alpn.isString())
                {
                    out.alpnProtocols = std::string(alpn.asString());
                }
                else if (alpn.isArray())
                {
                    std::string joined;
                    for (const auto &p : alpn.asArray())
                    {
                        if (p.isString() && !p.asString().empty())
                        {
                            if (!joined.empty())
                            {
                                joined.push_back(',');
                            }
                            joined.append(p.asString());
                        }
                    }
                    out.alpnProtocols = std::move(joined);
                }
            }
            if (out.enableTls && out.type == transport::TransportType::TCP)
            {
                out.type = transport::TransportType::TLS;
            }
        }

        if (obj.contains("transport") && obj["transport"].isObject())
        {
            const auto &trObj = obj["transport"];
            std::string trType = std::string(trObj["type"].asString());
            if (trType == "ws" || trType == "websocket")
            {
                out.type = transport::TransportType::WEBSOCKET;
            }
            else if (trType == "grpc")
            {
                out.type = transport::TransportType::GRPC;
            }
            else if (trType == "tls")
            {
                out.type = transport::TransportType::TLS;
                out.enableTls = true;
            }

            if (trObj.contains("path"))
            {
                out.path = std::string(trObj["path"].asString("/"));
            }
            if (trObj.contains("service_name"))
            {
                out.serviceName = std::string(trObj["service_name"].asString());
            }
            if (trObj.contains("host"))
            {
                out.host = std::string(trObj["host"].asString());
            }
            if (trObj.contains("headers") && trObj["headers"].isObject() && trObj["headers"].contains("Host"))
            {
                out.host = std::string(trObj["headers"]["Host"].asString());
            }
            if (trObj.contains("max_early_data"))
            {
                out.maxEarlyData = static_cast<uint32_t>(trObj["max_early_data"].asInt(0));
            }
            if (trObj.contains("early_data_header_name"))
            {
                out.earlyDataHeaderName = std::string(trObj["early_data_header_name"].asString());
            }
        }
    }

    /**
     * @brief 将 sing-box JSON 文本解析并转化为 MynetConfig
     */
    [[nodiscard]] inline std::expected<MynetConfig, std::string> parseSingBoxConfig(std::string_view jsonStr)
    {
        auto rootRes = json::parse(jsonStr);
        if (!rootRes)
        {
            return std::unexpected("JSON syntax error: " + rootRes.error());
        }

        const auto &root = *rootRes;
        if (!root.isObject())
        {
            return std::unexpected("Root of sing-box configuration must be a JSON object");
        }

        MynetConfig cfg{};

        // --------------------------------------------------------------------
        // 1. inbounds
        // --------------------------------------------------------------------
        if (root.contains("inbounds"))
        {
            const auto &inArr = root["inbounds"];
            if (inArr.isArray())
            {
                for (const auto &inObj : inArr.asArray())
                {
                    if (!inObj.isObject())
                        continue;

                    InboundConfig inCfg{};
                    std::string type = std::string(inObj["type"].asString());
                    inCfg.tag = inObj["tag"].asString(type);

                    if (type == "mixed")
                    {
                        inCfg.protocol = "mixed";
                    }
                    else if (type == "socks")
                    {
                        inCfg.protocol = "socks5";
                    }
                    else if (type == "http")
                    {
                        inCfg.protocol = "http";
                    }
                    else if (type == "trojan")
                    {
                        inCfg.protocol = "trojan";
                    }
                    else if (type == "vless")
                    {
                        inCfg.protocol = "vless";
                    }
                    else if (type == "hysteria2")
                    {
                        inCfg.protocol = "hysteria2";
                    }
                    else if (type == "shadowsocks")
                    {
                        inCfg.protocol = "shadowsocks";
                    }
                    else if (type == "tun")
                    {
                        inCfg.protocol = "tun";
                    }
                    else if (type == "tproxy")
                    {
                        inCfg.protocol = "tproxy";
                    }
                    else
                    {
                        inCfg.protocol = type;
                    }

                    inCfg.host = inObj["listen"].asString("127.0.0.1");
                    inCfg.port = static_cast<uint16_t>(inObj["listen_port"].asInt(1080));
                    inCfg.enableSniffing = inObj["sniff"].asBool(true);

                    // 认证参数解析
                    if (inObj.contains("users") && inObj["users"].isArray())
                    {
                        for (const auto &u : inObj["users"].asArray())
                        {
                            if (u.isObject())
                            {
                                if (u.contains("username"))
                                    inCfg.username = u["username"].asString();
                                if (u.contains("password"))
                                    inCfg.password = u["password"].asString();
                                if (u.contains("uuid"))
                                    inCfg.uuid = u["uuid"].asString();
                                break;
                            }
                        }
                    }
                    if (inObj.contains("password"))
                    {
                        inCfg.password = inObj["password"].asString();
                    }

                    // TUN 专属参数
                    if (inObj.contains("interface_name"))
                    {
                        inCfg.ifName = inObj["interface_name"].asString("tun0");
                    }
                    if (inObj.contains("inet4_address"))
                    {
                        auto [ip, mask] =
                            tun::parseCidrToIpAndMask(inObj["inet4_address"].asString("172.19.0.1/24"));
                        inCfg.inetIp = ip;
                        inCfg.inetMask = mask;
                    }
                    else if (inObj.contains("address"))
                    {
                        const auto &addr = inObj["address"];
                        std::string addrStr = "172.19.0.1/24";
                        if (addr.isString())
                            addrStr = addr.asString();
                        else if (addr.isArray() && !addr.asArray().empty())
                            addrStr = addr.asArray()[0].asString();
                        auto [ip, mask] = tun::parseCidrToIpAndMask(addrStr);
                        inCfg.inetIp = ip;
                        inCfg.inetMask = mask;
                    }
                    if (inObj.contains("mtu"))
                    {
                        inCfg.mtu = static_cast<uint32_t>(inObj["mtu"].asInt(1500));
                    }

                    parseSingBoxTransport(inObj, inCfg.transport);
                    cfg.inbounds.push_back(std::move(inCfg));
                }
            }
        }

        if (!cfg.inbounds.empty())
        {
            cfg.server.host = cfg.inbounds.front().host;
            cfg.server.port = cfg.inbounds.front().port;
        }

        // --------------------------------------------------------------------
        // 2. outbounds
        // --------------------------------------------------------------------
        if (root.contains("outbounds"))
        {
            const auto &outArr = root["outbounds"];
            if (outArr.isArray())
            {
                for (const auto &outObj : outArr.asArray())
                {
                    if (!outObj.isObject())
                        continue;

                    OutboundConfig outCfg{};
                    std::string type = std::string(outObj["type"].asString());
                    outCfg.tag = outObj["tag"].asString(type);

                    if (type == "direct")
                    {
                        outCfg.type = "direct";
                    }
                    else if (type == "block")
                    {
                        outCfg.type = "block";
                    }
                    else if (type == "socks")
                    {
                        outCfg.type = "socks5";
                    }
                    else if (type == "http")
                    {
                        outCfg.type = "http";
                    }
                    else if (type == "trojan")
                    {
                        outCfg.type = "trojan";
                    }
                    else if (type == "vless")
                    {
                        outCfg.type = "vless";
                    }
                    else if (type == "vmess")
                    {
                        outCfg.type = "vmess";
                    }
                    else if (type == "shadowsocks")
                    {
                        outCfg.type = "shadowsocks";
                    }
                    else if (type == "hysteria2")
                    {
                        outCfg.type = "hysteria2";
                    }
                    else if (type == "selector")
                    {
                        outCfg.type = "selector";
                    }
                    else if (type == "urltest")
                    {
                        outCfg.type = "urltest";
                    }
                    else if (type == "fallback")
                    {
                        outCfg.type = "fallback";
                    }
                    else
                    {
                        outCfg.type = type;
                    }

                    outCfg.host = outObj["server"].asString();
                    outCfg.port = static_cast<uint16_t>(outObj["server_port"].asInt(0));
                    outCfg.username = outObj["username"].asString();
                    outCfg.password = outObj["password"].asString();
                    outCfg.uuid = outObj["uuid"].asString();
                    outCfg.method = outObj["method"].asString();

                    // selector / urltest / fallback 子出站标签列表
                    if (outObj.contains("outbounds") && outObj["outbounds"].isArray())
                    {
                        for (const auto &ob : outObj["outbounds"].asArray())
                        {
                            if (ob.isString())
                            {
                                outCfg.outbounds.push_back(std::string(ob.asString()));
                            }
                        }
                    }

                    if (outObj.contains("default"))
                    {
                        outCfg.defaultTag = outObj["default"].asString();
                    }
                    if (outObj.contains("url"))
                    {
                        outCfg.url = outObj["url"].asString();
                    }
                    if (outObj.contains("interval"))
                    {
                        const auto &inv = outObj["interval"];
                        if (inv.isString())
                        {
                            outCfg.intervalSecs = parseDurationSeconds(inv.asString());
                        }
                        else if (inv.isNumber())
                        {
                            outCfg.intervalSecs = static_cast<uint32_t>(inv.asInt(300));
                        }
                    }
                    if (outObj.contains("tolerance"))
                    {
                        outCfg.toleranceMs = static_cast<uint32_t>(outObj["tolerance"].asInt(50));
                    }

                    parseSingBoxTransport(outObj, outCfg.transport);

                    if (outObj.contains("routing_mark"))
                    {
                        outCfg.dialer.fwmark = static_cast<uint32_t>(outObj["routing_mark"].asInt(0));
                    }
                    else if (outObj.contains("fwmark"))
                    {
                        outCfg.dialer.fwmark = static_cast<uint32_t>(outObj["fwmark"].asInt(0));
                    }
                    if (outObj.contains("bind_interface"))
                    {
                        outCfg.dialer.bindInterface = outObj["bind_interface"].asString();
                    }
                    if (outObj.contains("inet4_bind_address"))
                    {
                        outCfg.dialer.bindAddress = outObj["inet4_bind_address"].asString();
                    }
                    else if (outObj.contains("bind_address"))
                    {
                        outCfg.dialer.bindAddress = outObj["bind_address"].asString();
                    }
                    if (outObj.contains("tcp_fast_open"))
                    {
                        outCfg.dialer.tcpFastOpen = outObj["tcp_fast_open"].asBool(false);
                    }
                    if (outObj.contains("dscp"))
                    {
                        outCfg.dialer.dscp = static_cast<uint8_t>(outObj["dscp"].asInt(0));
                    }
                    if (outObj.contains("mptcp"))
                    {
                        outCfg.dialer.enableMptcp = outObj["mptcp"].asBool(false);
                    }
                    if (outObj.contains("connect_timeout"))
                    {
                        const auto &ct = outObj["connect_timeout"];
                        if (ct.isString())
                        {
                            outCfg.dialer.timeout = std::chrono::seconds(parseDurationSeconds(ct.asString(), 5));
                        }
                        else if (ct.isNumber())
                        {
                            outCfg.dialer.timeout = std::chrono::milliseconds(ct.asInt(5000));
                        }
                    }

                    cfg.outbounds.push_back(std::move(outCfg));
                }
            }
        }

        // --------------------------------------------------------------------
        // 3. route
        // --------------------------------------------------------------------
        if (root.contains("route") && root["route"].isObject() && root["route"].contains("final"))
        {
            cfg.router.defaultOutbound = root["route"]["final"].asString("direct");
        }
        else
        {
            auto it = std::find_if(cfg.outbounds.begin(), cfg.outbounds.end(),
                                   [](const auto &o) { return o.tag == "proxy"; });
            if (it != cfg.outbounds.end())
            {
                cfg.router.defaultOutbound = "proxy";
            }
            else if (!cfg.outbounds.empty())
            {
                cfg.router.defaultOutbound = cfg.outbounds.front().tag;
            }
            else
            {
                cfg.router.defaultOutbound = "direct";
            }
        }

        if (root.contains("route") && root["route"].isObject())
        {
            const auto &routeObj = root["route"];
            if (routeObj.contains("rules") && routeObj["rules"].isArray())
                {
                    for (const auto &ruleVal : routeObj["rules"].asArray())
                    {
                        if (!ruleVal.isObject())
                            continue;

                        RouteRuleConfig rrc{};
                        rrc.outbound = ruleVal["outbound"].asString("direct");
                        rrc.invert = ruleVal["invert"].asBool(false);
                        rrc.network = ruleVal["network"].asString();

                        appendStringOrArray(rrc.domains, ruleVal["domain"]);
                        appendStringOrArray(rrc.domainSuffixes, ruleVal["domain_suffix"]);
                        appendStringOrArray(rrc.domainKeywords, ruleVal["domain_keyword"]);
                        appendStringOrArray(rrc.ipCidrs, ruleVal["ip_cidr"]);
                        appendStringOrArray(rrc.protocols, ruleVal["protocol"]);
                        appendStringOrArray(rrc.geoIps, ruleVal["geoip"]);
                        appendStringOrArray(rrc.geoSites, ruleVal["geosite"]);
                        appendStringOrArray(rrc.geoSites, ruleVal["rule_set"]); // 支持 rule-set
                        if (ruleVal.contains("process_name"))
                        {
                            if (ruleVal["process_name"].isString())
                            {
                                rrc.processName = ruleVal["process_name"].asString();
                            }
                            else if (ruleVal["process_name"].isArray() &&
                                     !ruleVal["process_name"].asArray().empty())
                            {
                                rrc.processName = ruleVal["process_name"].asArray()[0].asString();
                            }
                        }

                        // 端口解析
                        if (ruleVal.contains("port"))
                        {
                            const auto &pVal = ruleVal["port"];
                            if (pVal.isNumber())
                            {
                                rrc.portRanges.push_back(std::to_string(pVal.asInt()));
                            }
                            else if (pVal.isArray())
                            {
                                for (const auto &pItem : pVal.asArray())
                                {
                                    if (pItem.isNumber())
                                        rrc.portRanges.push_back(std::to_string(pItem.asInt()));
                                    else if (pItem.isString())
                                        rrc.portRanges.push_back(std::string(pItem.asString()));
                                }
                            }
                        }
                        if (ruleVal.contains("port_range"))
                        {
                            appendStringOrArray(rrc.portRanges, ruleVal["port_range"]);
                        }

                        cfg.router.rules.push_back(std::move(rrc));
                    }
                }
            }

        // --------------------------------------------------------------------
        // 4. experimental (Clash API controller)
        // --------------------------------------------------------------------
        if (root.contains("experimental"))
        {
            const auto &exp = root["experimental"];
            if (exp.isObject() && exp.contains("clash_api"))
            {
                const auto &clashApi = exp["clash_api"];
                if (clashApi.isObject())
                {
                    std::string ext = std::string(clashApi["external_controller"].asString("127.0.0.1:9090"));
                    std::string secret = std::string(clashApi["secret"].asString());

                    cfg.controller.enabled = true;
                    cfg.controller.secret = std::move(secret);

                    auto colon = ext.find(':');
                    if (colon != std::string::npos)
                    {
                        cfg.controller.host = ext.substr(0, colon);
                        uint16_t port = 9090;
                        auto [ptr, ec] = std::from_chars(ext.data() + colon + 1, ext.data() + ext.size(), port);
                        if (ec == std::errc())
                        {
                            cfg.controller.port = port;
                        }
                    }
                    else
                    {
                        cfg.controller.host = ext;
                        cfg.controller.port = 9090;
                    }
                }
            }
        }

        // --------------------------------------------------------------------
        // 5. dns
        // --------------------------------------------------------------------
        if (root.contains("dns"))
        {
            const auto &dnsObj = root["dns"];
            if (dnsObj.isObject() && dnsObj.contains("servers"))
            {
                const auto &srvArr = dnsObj["servers"];
                if (srvArr.isArray() && !srvArr.asArray().empty())
                {
                    cfg.dns.servers.clear();
                    for (const auto &sItem : srvArr.asArray())
                    {
                        if (sItem.isObject() && sItem.contains("address"))
                        {
                            cfg.dns.servers.push_back(std::string(sItem["address"].asString()));
                        }
                        else if (sItem.isString())
                        {
                            cfg.dns.servers.push_back(std::string(sItem.asString()));
                        }
                    }
                }
            }
        }

        return cfg;
    }

} // namespace mynet::config::singbox
