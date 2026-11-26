#pragma once

/**
 * @file throne/proto.hpp
 * @brief Throne (NekoRay/NekoBox) LibcoreService 协议的高性能零依赖 Protobuf 编解码器。
 *
 * 依据 libcore.proto 规则，完全复用 mynet 内部的高效 uvarint 变长编码实现，
 * 彻底避免引入庞大的 Google Protobuf 运行时依赖。
 */

#include "../uvarint.hpp"
#include <cstdint>
#include <cstring>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mynet::throne::proto
{

    inline constexpr uint32_t kWireTypeVarint = 0;
    inline constexpr uint32_t kWireTypeLengthDelimited = 2;

    inline void appendVarint(std::string &out, uint64_t val)
    {
        while (val >= 0x80)
        {
            out.push_back(static_cast<char>((val & 0x7f) | 0x80));
            val >>= 7;
        }
        out.push_back(static_cast<char>(val & 0x7f));
    }

    inline void appendTag(std::string &out, uint32_t fieldNumber, uint32_t wireType)
    {
        appendVarint(out, (fieldNumber << 3) | (wireType & 7));
    }

    inline void appendStringField(std::string &out, uint32_t fieldNumber, std::string_view val)
    {
        appendTag(out, fieldNumber, kWireTypeLengthDelimited);
        appendVarint(out, val.size());
        out.append(val);
    }

    inline void appendVarintField(std::string &out, uint32_t fieldNumber, uint64_t val)
    {
        appendTag(out, fieldNumber, kWireTypeVarint);
        appendVarint(out, val);
    }

    inline void appendBoolField(std::string &out, uint32_t fieldNumber, bool val)
    {
        appendTag(out, fieldNumber, kWireTypeVarint);
        out.push_back(val ? '\x01' : '\x00');
    }

    struct ProtoField
    {
        uint32_t fieldNumber = 0;
        uint32_t wireType = 0;
        uint64_t varintValue = 0;
        std::string_view lengthDelimited{};
    };

    /**
     * @brief 从 Protobuf 二进制切片中解析出下一个字段
     */
    inline bool parseNextField(std::span<const uint8_t> &data, ProtoField &field)
    {
        if (data.empty())
        {
            return false;
        }

        auto [tag, tagBytes] = uvarint::decode(data);
        if (tagBytes == 0)
        {
            return false;
        }
        data = data.subspan(tagBytes);

        field.fieldNumber = static_cast<uint32_t>(tag >> 3);
        field.wireType = static_cast<uint32_t>(tag & 7);

        if (field.wireType == kWireTypeVarint)
        {
            auto [val, valBytes] = uvarint::decode(data);
            if (valBytes == 0)
            {
                return false;
            }
            field.varintValue = val;
            data = data.subspan(valBytes);
            return true;
        }
        if (field.wireType == kWireTypeLengthDelimited)
        {
            auto [len, lenBytes] = uvarint::decode(data);
            if (lenBytes == 0 || data.size() < lenBytes + len)
            {
                return false;
            }
            data = data.subspan(lenBytes);
            field.lengthDelimited = std::string_view(reinterpret_cast<const char *>(data.data()), len);
            data = data.subspan(len);
            return true;
        }
        if (field.wireType == 5) // 32-bit fixed
        {
            if (data.size() < 4)
                return false;
            uint32_t val = 0;
            std::memcpy(&val, data.data(), 4);
            field.varintValue = val;
            data = data.subspan(4);
            return true;
        }
        if (field.wireType == 1) // 64-bit fixed
        {
            if (data.size() < 8)
                return false;
            uint64_t val = 0;
            std::memcpy(&val, data.data(), 8);
            field.varintValue = val;
            data = data.subspan(8);
            return true;
        }
        return false;
    }

    // ========================================================================
    // 1. ErrorResp (message ErrorResp { optional string error = 1; })
    // ========================================================================
    [[nodiscard]] inline std::string encodeErrorResp(std::string_view error = "")
    {
        std::string out;
        if (!error.empty())
        {
            appendStringField(out, 1, error);
        }
        return out;
    }

    [[nodiscard]] inline std::string decodeErrorResp(std::string_view payload)
    {
        std::span<const uint8_t> span(reinterpret_cast<const uint8_t *>(payload.data()), payload.size());
        ProtoField f;
        while (parseNextField(span, f))
        {
            if (f.fieldNumber == 1 && f.wireType == kWireTypeLengthDelimited)
            {
                return std::string(f.lengthDelimited);
            }
        }
        return {};
    }

    // ========================================================================
    // 2. LoadConfigReq (message LoadConfigReq { optional string core_config = 1; ... })
    // ========================================================================
    struct LoadConfigReq
    {
        std::string coreConfig{};
        bool disableStats = false;
        bool needExtraProcess = false;
        std::string extraProcessPath{};
        std::string tunIpv4Cidr{};
    };

    [[nodiscard]] inline std::string encodeLoadConfigReq(const LoadConfigReq &req)
    {
        std::string out;
        if (!req.coreConfig.empty())
        {
            appendStringField(out, 1, req.coreConfig);
        }
        if (req.disableStats)
        {
            appendBoolField(out, 2, req.disableStats);
        }
        if (req.needExtraProcess)
        {
            appendBoolField(out, 3, req.needExtraProcess);
        }
        if (!req.extraProcessPath.empty())
        {
            appendStringField(out, 4, req.extraProcessPath);
        }
        if (!req.tunIpv4Cidr.empty())
        {
            appendStringField(out, 11, req.tunIpv4Cidr);
        }
        return out;
    }

    [[nodiscard]] inline LoadConfigReq decodeLoadConfigReq(std::string_view payload)
    {
        LoadConfigReq req;
        std::span<const uint8_t> span(reinterpret_cast<const uint8_t *>(payload.data()), payload.size());
        ProtoField f;
        while (parseNextField(span, f))
        {
            if (f.fieldNumber == 1 && f.wireType == kWireTypeLengthDelimited)
            {
                req.coreConfig = f.lengthDelimited;
            }
            else if (f.fieldNumber == 2 && f.wireType == kWireTypeVarint)
            {
                req.disableStats = (f.varintValue != 0);
            }
            else if (f.fieldNumber == 3 && f.wireType == kWireTypeVarint)
            {
                req.needExtraProcess = (f.varintValue != 0);
            }
            else if (f.fieldNumber == 4 && f.wireType == kWireTypeLengthDelimited)
            {
                req.extraProcessPath = f.lengthDelimited;
            }
            else if (f.fieldNumber == 11 && f.wireType == kWireTypeLengthDelimited)
            {
                req.tunIpv4Cidr = f.lengthDelimited;
            }
        }
        return req;
    }

    // ========================================================================
    // 3. IsPrivilegedResponse (message IsPrivilegedResponse { ... })
    // ========================================================================
    struct IsPrivilegedResponse
    {
        bool hasPrivilege = false;
        bool tunDevice = false;
        bool netAdmin = false;
        bool killSwitchPrivilege = false;
        std::string detail{};
        int64_t corePid = 0;
    };

    [[nodiscard]] inline std::string encodeIsPrivilegedResponse(const IsPrivilegedResponse &resp)
    {
        std::string out;
        appendBoolField(out, 1, resp.hasPrivilege);
        appendBoolField(out, 2, resp.tunDevice);
        appendBoolField(out, 3, resp.netAdmin);
        appendBoolField(out, 4, resp.killSwitchPrivilege);
        if (!resp.detail.empty())
        {
            appendStringField(out, 5, resp.detail);
        }
        if (resp.corePid > 0)
        {
            appendVarintField(out, 6, static_cast<uint64_t>(resp.corePid));
        }
        return out;
    }

    [[nodiscard]] inline IsPrivilegedResponse decodeIsPrivilegedResponse(std::string_view payload)
    {
        IsPrivilegedResponse resp;
        std::span<const uint8_t> span(reinterpret_cast<const uint8_t *>(payload.data()), payload.size());
        ProtoField f;
        while (parseNextField(span, f))
        {
            if (f.fieldNumber == 1 && f.wireType == kWireTypeVarint)
            {
                resp.hasPrivilege = (f.varintValue != 0);
            }
            else if (f.fieldNumber == 2 && f.wireType == kWireTypeVarint)
            {
                resp.tunDevice = (f.varintValue != 0);
            }
            else if (f.fieldNumber == 3 && f.wireType == kWireTypeVarint)
            {
                resp.netAdmin = (f.varintValue != 0);
            }
            else if (f.fieldNumber == 4 && f.wireType == kWireTypeVarint)
            {
                resp.killSwitchPrivilege = (f.varintValue != 0);
            }
            else if (f.fieldNumber == 5 && f.wireType == kWireTypeLengthDelimited)
            {
                resp.detail = f.lengthDelimited;
            }
            else if (f.fieldNumber == 6 && f.wireType == kWireTypeVarint)
            {
                resp.corePid = static_cast<int64_t>(f.varintValue);
            }
        }
        return resp;
    }

    // ========================================================================
    // 4. QueryStatsResp (message QueryStatsResp { map<string, int64> ups = 1; map<string, int64> downs = 2; })
    // ========================================================================
    [[nodiscard]] inline std::string encodeQueryStatsResponse(const std::map<std::string, int64_t> &ups,
                                                              const std::map<std::string, int64_t> &downs)
    {
        std::string out;
        for (const auto &[k, v] : ups)
        {
            std::string entry;
            appendStringField(entry, 1, k);
            appendVarintField(entry, 2, static_cast<uint64_t>(v));

            appendTag(out, 1, kWireTypeLengthDelimited);
            appendVarint(out, entry.size());
            out.append(entry);
        }
        for (const auto &[k, v] : downs)
        {
            std::string entry;
            appendStringField(entry, 1, k);
            appendVarintField(entry, 2, static_cast<uint64_t>(v));

            appendTag(out, 2, kWireTypeLengthDelimited);
            appendVarint(out, entry.size());
            out.append(entry);
        }
        return out;
    }

    inline void decodeQueryStatsResponse(std::string_view payload, std::map<std::string, int64_t> &ups,
                                         std::map<std::string, int64_t> &downs)
    {
        ups.clear();
        downs.clear();
        std::span<const uint8_t> span(reinterpret_cast<const uint8_t *>(payload.data()), payload.size());
        ProtoField f;
        while (parseNextField(span, f))
        {
            if ((f.fieldNumber == 1 || f.fieldNumber == 2) && f.wireType == kWireTypeLengthDelimited)
            {
                std::span<const uint8_t> entrySpan(reinterpret_cast<const uint8_t *>(f.lengthDelimited.data()),
                                                    f.lengthDelimited.size());
                ProtoField entryField;
                std::string key;
                int64_t val = 0;
                while (parseNextField(entrySpan, entryField))
                {
                    if (entryField.fieldNumber == 1 && entryField.wireType == kWireTypeLengthDelimited)
                    {
                        key = entryField.lengthDelimited;
                    }
                    else if (entryField.fieldNumber == 2 && entryField.wireType == kWireTypeVarint)
                    {
                        val = static_cast<int64_t>(entryField.varintValue);
                    }
                }
                if (f.fieldNumber == 1)
                {
                    ups[key] = val;
                }
                else
                {
                    downs[key] = val;
                }
            }
        }
    }

    // ========================================================================
    // 5. GetDefaultInterfaceResponse (message GetDefaultInterfaceResponse { optional string name = 1; optional int32 index = 2; })
    // ========================================================================
    [[nodiscard]] inline std::string encodeDefaultInterfaceResponse(std::string_view name, int32_t index)
    {
        std::string out;
        if (!name.empty())
        {
            appendStringField(out, 1, name);
        }
        if (index > 0)
        {
            appendVarintField(out, 2, static_cast<uint64_t>(index));
        }
        return out;
    }

    // ========================================================================
    // 6. TestResp (message TestResp { repeated URLTestResp items = 1; })
    // ========================================================================
    struct URLTestResult
    {
        std::string outboundTag{};
        int32_t latencyMs = 0;
        std::string error{};
    };

    [[nodiscard]] inline std::string encodeTestResponse(const std::vector<URLTestResult> &results)
    {
        std::string out;
        for (const auto &item : results)
        {
            std::string sub;
            if (!item.outboundTag.empty())
            {
                appendStringField(sub, 1, item.outboundTag);
            }
            appendVarintField(sub, 2, static_cast<uint64_t>(item.latencyMs));
            if (!item.error.empty())
            {
                appendStringField(sub, 3, item.error);
            }

            appendTag(out, 1, kWireTypeLengthDelimited);
            appendVarint(out, sub.size());
            out.append(sub);
        }
        return out;
    }

    [[nodiscard]] inline std::vector<URLTestResult> decodeTestResponse(std::string_view payload)
    {
        std::vector<URLTestResult> out;
        std::span<const uint8_t> span(reinterpret_cast<const uint8_t *>(payload.data()), payload.size());
        ProtoField f;
        while (parseNextField(span, f))
        {
            if (f.fieldNumber == 1 && f.wireType == kWireTypeLengthDelimited)
            {
                std::span<const uint8_t> subSpan(reinterpret_cast<const uint8_t *>(f.lengthDelimited.data()),
                                                 f.lengthDelimited.size());
                ProtoField subField;
                URLTestResult res;
                while (parseNextField(subSpan, subField))
                {
                    if (subField.fieldNumber == 1 && subField.wireType == kWireTypeLengthDelimited)
                    {
                        res.outboundTag = subField.lengthDelimited;
                    }
                    else if (subField.fieldNumber == 2 && subField.wireType == kWireTypeVarint)
                    {
                        res.latencyMs = static_cast<int32_t>(subField.varintValue);
                    }
                    else if (subField.fieldNumber == 3 && subField.wireType == kWireTypeLengthDelimited)
                    {
                        res.error = subField.lengthDelimited;
                    }
                }
                out.push_back(std::move(res));
            }
        }
        return out;
    }

    struct TestReq
    {
        std::string config{};
        std::vector<std::string> outboundTags{};
        std::string url{};
        int32_t timeoutMs = 5000;
    };

    [[nodiscard]] inline TestReq decodeTestReq(std::string_view payload)
    {
        TestReq req;
        std::span<const uint8_t> span(reinterpret_cast<const uint8_t *>(payload.data()), payload.size());
        ProtoField f;
        while (parseNextField(span, f))
        {
            if (f.fieldNumber == 1 && f.wireType == kWireTypeLengthDelimited)
            {
                req.config = f.lengthDelimited;
            }
            else if (f.fieldNumber == 2 && f.wireType == kWireTypeLengthDelimited)
            {
                req.outboundTags.push_back(std::string(f.lengthDelimited));
            }
            else if (f.fieldNumber == 4 && f.wireType == kWireTypeLengthDelimited)
            {
                req.url = f.lengthDelimited;
            }
            else if (f.fieldNumber == 7 && f.wireType == kWireTypeVarint)
            {
                req.timeoutMs = static_cast<int32_t>(f.varintValue);
            }
        }
        return req;
    }

    // ========================================================================
    // 7. QueryConnections & CloseConnections
    // ========================================================================
    struct ConnectionMeta
    {
        std::string id{};
        int64_t createdAt = 0;
        int64_t upload = 0;
        int64_t download = 0;
        std::string outbound{};
        std::string network = "tcp";
        std::string dest{};
        std::string protocol{};
        std::string domain{};
    };

    [[nodiscard]] inline std::string encodeQueryConnectionsResponse(const std::vector<ConnectionMeta> &active,
                                                                   const std::vector<ConnectionMeta> &closed = {})
    {
        std::string out;
        for (const auto &c : active)
        {
            std::string sub;
            if (!c.id.empty()) appendStringField(sub, 1, c.id);
            if (c.createdAt > 0) appendVarintField(sub, 2, static_cast<uint64_t>(c.createdAt));
            if (c.upload > 0) appendVarintField(sub, 3, static_cast<uint64_t>(c.upload));
            if (c.download > 0) appendVarintField(sub, 4, static_cast<uint64_t>(c.download));
            if (!c.outbound.empty()) appendStringField(sub, 5, c.outbound);
            if (!c.network.empty()) appendStringField(sub, 6, c.network);
            if (!c.dest.empty()) appendStringField(sub, 7, c.dest);
            if (!c.protocol.empty()) appendStringField(sub, 8, c.protocol);
            if (!c.domain.empty()) appendStringField(sub, 9, c.domain);

            appendTag(out, 1, kWireTypeLengthDelimited);
            appendVarint(out, sub.size());
            out.append(sub);
        }
        for (const auto &c : closed)
        {
            std::string sub;
            if (!c.id.empty()) appendStringField(sub, 1, c.id);
            if (c.createdAt > 0) appendVarintField(sub, 2, static_cast<uint64_t>(c.createdAt));
            if (c.upload > 0) appendVarintField(sub, 3, static_cast<uint64_t>(c.upload));
            if (c.download > 0) appendVarintField(sub, 4, static_cast<uint64_t>(c.download));
            if (!c.outbound.empty()) appendStringField(sub, 5, c.outbound);
            if (!c.network.empty()) appendStringField(sub, 6, c.network);
            if (!c.dest.empty()) appendStringField(sub, 7, c.dest);

            appendTag(out, 2, kWireTypeLengthDelimited);
            appendVarint(out, sub.size());
            out.append(sub);
        }
        return out;
    }

    struct CloseConnectionsReq
    {
        std::vector<std::string> ids;
    };

    [[nodiscard]] inline CloseConnectionsReq decodeCloseConnectionsReq(std::string_view payload)
    {
        CloseConnectionsReq req;
        std::span<const uint8_t> span(reinterpret_cast<const uint8_t *>(payload.data()), payload.size());
        ProtoField f;
        while (parseNextField(span, f))
        {
            if (f.fieldNumber == 1 && f.wireType == kWireTypeLengthDelimited)
            {
                req.ids.push_back(std::string(f.lengthDelimited));
            }
        }
        return req;
    }

    [[nodiscard]] inline std::string encodeCloseConnectionsResponse(int32_t closed, std::string_view error = "")
    {
        std::string out;
        if (closed > 0) appendVarintField(out, 1, static_cast<uint64_t>(closed));
        if (!error.empty()) appendStringField(out, 2, error);
        return out;
    }

    // ========================================================================
    // 8. AutoSelectors
    // ========================================================================
    struct AutoSelectorActionReq
    {
        std::string tag{};
        std::string member{};
    };

    [[nodiscard]] inline AutoSelectorActionReq decodeAutoSelectorActionReq(std::string_view payload)
    {
        AutoSelectorActionReq req;
        std::span<const uint8_t> span(reinterpret_cast<const uint8_t *>(payload.data()), payload.size());
        ProtoField f;
        while (parseNextField(span, f))
        {
            if (f.fieldNumber == 1 && f.wireType == kWireTypeLengthDelimited)
            {
                req.tag = f.lengthDelimited;
            }
            else if (f.fieldNumber == 2 && f.wireType == kWireTypeLengthDelimited)
            {
                req.member = f.lengthDelimited;
            }
        }
        return req;
    }

    struct AutoSelectorGroupInfo
    {
        std::string tag{};
        std::string phase = "ready";
        std::string selected{};
        std::vector<std::string> members{};
    };

    [[nodiscard]] inline std::string encodeQueryAutoSelectorsResponse(const std::vector<AutoSelectorGroupInfo> &groups)
    {
        std::string out;
        for (const auto &g : groups)
        {
            std::string sub;
            if (!g.tag.empty()) appendStringField(sub, 1, g.tag);
            if (!g.phase.empty()) appendStringField(sub, 2, g.phase);
            if (!g.selected.empty()) appendStringField(sub, 3, g.selected);

            for (size_t i = 0; i < g.members.size(); ++i)
            {
                std::string memSub;
                appendStringField(memSub, 1, g.members[i]);
                appendVarintField(memSub, 2, static_cast<uint64_t>(i));
                appendStringField(memSub, 3, "ok");
                if (g.members[i] == g.selected)
                {
                    appendBoolField(memSub, 4, true);
                }
                appendTag(sub, 20, kWireTypeLengthDelimited);
                appendVarint(sub, memSub.size());
                sub.append(memSub);
            }

            appendTag(out, 1, kWireTypeLengthDelimited);
            appendVarint(out, sub.size());
            out.append(sub);
        }
        return out;
    }

} // namespace mynet::throne::proto
