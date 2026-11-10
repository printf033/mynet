#pragma once

/**
 * @file config/lua.hpp
 * @brief 沙箱化 Lua 配置加载与热重载引擎（loadServerSection / reloadConfig）。
 *
 * 把 config.lua 中的 server / reactor / connection / datagram / proactor /
 * http2 / security 各段解析进 configHolder.hpp 定义的配置结构体，并提供
 * reloadConfig() 在信号或 mylog 热重载时重新装载。
 */

#include "configHolder.hpp"
#include "config/log.hpp"
#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <format>
#include <string>
#include <utility>

// 第三方 mylog 子模块的 Lua 配置头。探测成功时把 mylog 自身的日志/文件管理
// 热重载钩子一并联入，失败则退化为只重载 mynet 配置（MYNET_HAS_MYLOG_LUA=0）。
//
// 路径必须与子模块当前的布局保持一致：mylog 曾把它命名为 configer_lua.hpp，
// 后重命名为 lua_config.hpp。探测的是被包含文件而非本文件，因此与本库的
// src/config/lua.hpp 不冲突——包含解析先看各自目录，两个文件互不遮蔽。
#if __has_include("thirdparty/mylog/src/lua_config.hpp")
#include "thirdparty/mylog/src/lua_config.hpp"
#define MYNET_HAS_MYLOG_LUA 1
#else
#define MYNET_HAS_MYLOG_LUA 0
#endif

extern "C"
{
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
}

namespace mynet
{

    namespace detail
    {

        template <typename... Args>
        inline void printError(std::format_string<Args...> fmt, Args &&...args)
        {
            std::fprintf(stderr, "[mynet] config error: %s\n", std::format(fmt, std::forward<Args>(args)...).c_str());
        }

        inline void printError(std::format_string<> fmt)
        {
            std::fprintf(stderr, "[mynet] config error: %s\n", std::format(fmt).c_str());
        }

        /// 用于"已被自动修正、配置仍然生效"的情形，避免把纠偏写成拒绝。
        template <typename... Args>
        inline void printWarning(std::format_string<Args...> fmt, Args &&...args)
        {
            std::fprintf(stderr, "[mynet] config warning: %s\n", std::format(fmt, std::forward<Args>(args)...).c_str());
        }

        template <typename T>
        constexpr T clampValue(T val, T minVal, T maxVal) noexcept
        {
            return std::clamp(val, minVal, maxVal);
        }

        inline bool readNumberField(lua_State *L, int tableIdx, const char *key, lua_Integer &out, bool &valid)
        {
            lua_getfield(L, tableIdx, key);
            const int type = lua_type(L, -1);
            if (type == LUA_TNIL)
            {
                lua_pop(L, 1);
                return false;
            }
            if (type != LUA_TNUMBER)
            {
                printError("field '{}' expected number, got {}", key, lua_typename(L, type));
                valid = false;
                lua_pop(L, 1);
                return false;
            }
            out = lua_tointeger(L, -1);
            lua_pop(L, 1);
            return true;
        }

        inline bool readBoolField(lua_State *L, int tableIdx, const char *key, bool &out, bool &valid)
        {
            lua_getfield(L, tableIdx, key);
            const int type = lua_type(L, -1);
            if (type == LUA_TNIL)
            {
                lua_pop(L, 1);
                return false;
            }
            if (type != LUA_TBOOLEAN)
            {
                printError("field '{}' expected boolean, got {}", key, lua_typename(L, type));
                valid = false;
                lua_pop(L, 1);
                return false;
            }
            out = lua_toboolean(L, -1) != 0;
            lua_pop(L, 1);
            return true;
        }

        inline bool readStringField(lua_State *L, int tableIdx, const char *key, std::string &out, bool &valid)
        {
            lua_getfield(L, tableIdx, key);
            const int type = lua_type(L, -1);
            if (type == LUA_TNIL)
            {
                lua_pop(L, 1);
                return false;
            }
            if (type != LUA_TSTRING)
            {
                printError("field '{}' expected string, got {}", key, lua_typename(L, type));
                valid = false;
                lua_pop(L, 1);
                return false;
            }
            size_t len = 0;
            const char *str = lua_tolstring(L, -1, &len);
            if (str != nullptr)
            {
                out.assign(str, len);
            }
            lua_pop(L, 1);
            return true;
        }

        inline bool loadServerSection(lua_State *L, int idx, ServerConfig &cfg)
        {
            bool valid = true;
            lua_Integer num = 0;
            bool flag = false;
            std::string text;

            if (readStringField(L, idx, "host", text, valid))
            {
                cfg.host = std::move(text);
            }

            if (readNumberField(L, idx, "port", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 1, 65535);
                if (v != num)
                {
                    printError("server.port clamped to range [1, 65535]");
                }
                cfg.port = static_cast<uint16_t>(v);
            }

            if (readNumberField(L, idx, "backlog", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 1, 65535);
                cfg.backlog = static_cast<int>(v);
            }

            if (readNumberField(L, idx, "maxConnections", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 1, 1'000'000);
                cfg.maxConnections = static_cast<size_t>(v);
            }

            if (readNumberField(L, idx, "idleTimeoutSecs", num, valid) ||
                readNumberField(L, idx, "idleTimeout", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 0, 86'400);
                cfg.idleTimeoutSecs = static_cast<int>(v);
            }

            if (readBoolField(L, idx, "tcpNoDelay", flag, valid))
            {
                cfg.tcpNoDelay = flag;
            }

            if (readBoolField(L, idx, "tcpQuickAck", flag, valid))
            {
                cfg.tcpQuickAck = flag;
            }

            if (readBoolField(L, idx, "enableSplice", flag, valid))
            {
                cfg.enableSplice = flag;
            }

            if (readBoolField(L, idx, "reuseAddr", flag, valid))
            {
                cfg.reuseAddr = flag;
            }

            if (readBoolField(L, idx, "reusePort", flag, valid))
            {
                cfg.reusePort = flag;
            }

            return valid;
        }

        inline bool loadReactorSection(lua_State *L, int idx, ReactorConfig &cfg)
        {
            bool valid = true;
            lua_Integer num = 0;

            if (readNumberField(L, idx, "maxEvents", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 16, 65536);
                cfg.maxEvents = static_cast<int>(v);
            }

            if (readNumberField(L, idx, "idleSweepIntervalMs", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 10, 60'000);
                cfg.idleSweepIntervalMs = static_cast<int>(v);
            }

            return valid;
        }

        inline bool loadProactorSection(lua_State *L, int idx, ProactorConfig &cfg)
        {
            bool valid = true;
            lua_Integer num = 0;

            if (readNumberField(L, idx, "sqEntries", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 64, 32768);
                cfg.sqEntries = static_cast<size_t>(v);
            }

            if (readNumberField(L, idx, "cqEntries", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 64, 32768);
                cfg.cqEntries = static_cast<size_t>(v);
            }

            if (readNumberField(L, idx, "maxAcceptEvents", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 1, 4096);
                cfg.maxAcceptEvents = static_cast<size_t>(v);
            }

            if (readNumberField(L, idx, "bufEntries", num, valid) || readNumberField(L, idx, "maxBufEntrs", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 16, 65536);
                cfg.bufEntries = static_cast<size_t>(v);
            }

            if (readNumberField(L, idx, "bufSize", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 512, 1 << 20);
                cfg.bufSize = static_cast<size_t>(v);
            }

            if (readNumberField(L, idx, "udpBufSize", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 512, 1 << 20);
                cfg.udpBufSize = static_cast<size_t>(v);
            }

            if (readNumberField(L, idx, "bufRingAlignment", num, valid))
            {
                // posix_memalign 要求对齐为 2 的幂；非法值收敛到页大小而不是让引擎启动失败。
                const lua_Integer raw = clampValue<lua_Integer>(num, 8, 1 << 20);
                if (raw != 0 && (raw & (raw - 1)) == 0)
                {
                    cfg.bufRingAlignment = static_cast<size_t>(raw);
                }
                else
                {
                    printWarning("proactor.bufRingAlignment ({}) is not a power of two; using {})", raw,
                                 cfg.bufRingAlignment);
                }
            }

            if (readNumberField(L, idx, "cqeWaitMs", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 1, 60'000);
                cfg.cqeWaitMs = static_cast<int>(v);
            }

            // 跨字段一致性：内核在 IORING_SETUP_CQSIZE 下要求 cq_entries >= sq_entries，
            // 否则 io_uring_queue_init_params() 直接返回 -EINVAL。这类约束必须在这里
            // 收敛，否则配置合法的两个数字凑在一起会让引擎启动失败。
            if (cfg.cqEntries < cfg.sqEntries)
            {
                printWarning("proactor.cqEntries ({}) was below sqEntries ({}); raised to sqEntries "
                             "so io_uring can initialise (configuration still applied)",
                             cfg.cqEntries, cfg.sqEntries);
                cfg.cqEntries = cfg.sqEntries;
            }

            return valid;
        }

        inline bool loadConnectionSection(lua_State *L, int idx, ConnectionConfig &cfg)
        {
            bool valid = true;
            lua_Integer num = 0;

            if (readNumberField(L, idx, "responseCapacity", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 1, 65536);
                cfg.responseCapacity = static_cast<size_t>(v);
            }

            if (readNumberField(L, idx, "readChunkSize", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 256, 16 << 20);
                cfg.readChunkSize = static_cast<size_t>(v);
            }

            if (readNumberField(L, idx, "maxRequestBytes", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 1024, 1024 << 20);
                cfg.maxRequestBytes = static_cast<size_t>(v);
            }

            if (readNumberField(L, idx, "writeHighWaterMark", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 1024, 1024 << 20);
                cfg.writeHighWaterMark = static_cast<size_t>(v);
            }

            if (readNumberField(L, idx, "writeHardCapFactor", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 1, 64);
                cfg.writeHardCapFactor = static_cast<size_t>(v);
            }

            if (readNumberField(L, idx, "spliceChunkSize", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 1024, 16 << 20);
                cfg.spliceChunkSize = static_cast<size_t>(v);
            }

            if (readNumberField(L, idx, "maxWriteIov", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 1, 64);
                cfg.maxWriteIov = static_cast<size_t>(v);
            }

            if (readNumberField(L, idx, "readHighWaterMark", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 1024, 1024 << 20);
                cfg.readHighWaterMark = static_cast<size_t>(v);
            }

            if (readNumberField(L, idx, "maxDrainRounds", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 1, 1024);
                cfg.maxDrainRounds = static_cast<size_t>(v);
            }

            return valid;
        }

        inline bool loadDatagramSection(lua_State *L, int idx, DatagramConfig &cfg)
        {
            bool valid = true;
            lua_Integer num = 0;

            if (readNumberField(L, idx, "maxDatagramBytes", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 512, 65535);
                cfg.maxDatagramBytes = static_cast<size_t>(v);
            }

            if (readNumberField(L, idx, "maxPendingOutgoing", num, valid) ||
                readNumberField(L, idx, "maxPendingReplies", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 16, 65536);
                cfg.maxPendingOutgoing = static_cast<size_t>(v);
            }

            return valid;
        }

        inline bool loadSecuritySection(lua_State *L, int idx, SecurityConfig &cfg)
        {
            bool valid = true;
            std::string text;
            lua_Integer num = 0;
            bool flag = false;

            if (readStringField(L, idx, "certFile", text, valid))
            {
                cfg.certFile = std::move(text);
            }

            if (readStringField(L, idx, "keyFile", text, valid))
            {
                cfg.keyFile = std::move(text);
            }

            if (readStringField(L, idx, "caFile", text, valid))
            {
                cfg.caFile = std::move(text);
            }

            if (readStringField(L, idx, "ciphers", text, valid))
            {
                cfg.ciphers = std::move(text);
            }

            if (readStringField(L, idx, "tls13CipherSuites", text, valid))
            {
                cfg.tls13CipherSuites = std::move(text);
            }

            if (readStringField(L, idx, "alpnProtocols", text, valid))
            {
                cfg.alpnProtocols = std::move(text);
            }

            if (readNumberField(L, idx, "minVersion", num, valid))
            {
                cfg.minVersion = static_cast<int>(num);
            }

            if (readNumberField(L, idx, "maxVersion", num, valid))
            {
                cfg.maxVersion = static_cast<int>(num);
            }

            if (readNumberField(L, idx, "sessionTimeout", num, valid))
            {
                cfg.sessionTimeout = static_cast<long>(num);
            }

            if (readBoolField(L, idx, "enableSessionTickets", flag, valid))
            {
                cfg.enableSessionTickets = flag;
            }

            if (readNumberField(L, idx, "numTickets", num, valid))
            {
                cfg.numTickets = static_cast<size_t>(num);
            }

            if (readStringField(L, idx, "sessionIdContext", text, valid))
            {
                cfg.sessionIdContext = std::move(text);
            }

            return valid;
        }

        inline bool loadHttp1Section(lua_State *L, int idx, Http1Config &cfg)
        {
            bool valid = true;
            lua_Integer num = 0;

            if (readNumberField(L, idx, "maxUrlLength", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 256, 1 << 20);
                cfg.maxUrlLength = static_cast<size_t>(v);
            }

            if (readNumberField(L, idx, "maxHeadersCount", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 1, 10000);
                cfg.maxHeadersCount = static_cast<size_t>(v);
            }

            if (readNumberField(L, idx, "maxHeaderFieldLength", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 64, 1 << 20);
                cfg.maxHeaderFieldLength = static_cast<size_t>(v);
            }

            if (readNumberField(L, idx, "maxHeaderValueLength", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 64, 1 << 20);
                cfg.maxHeaderValueLength = static_cast<size_t>(v);
            }

            if (readNumberField(L, idx, "maxTotalHeadersLength", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 256, 16 << 20);
                cfg.maxTotalHeadersLength = static_cast<size_t>(v);
            }

            if (readNumberField(L, idx, "maxBodyLength", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 1024, 1024 << 20);
                cfg.maxBodyLength = static_cast<size_t>(v);
            }

            return valid;
        }

        inline bool loadHttp2Section(lua_State *L, int idx, Http2Config &cfg)
        {
            bool valid = true;
            lua_Integer num = 0;

            if (readNumberField(L, idx, "maxConcurrentStreams", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 1, 10000);
                cfg.maxConcurrentStreams = static_cast<size_t>(v);
            }

            if (readNumberField(L, idx, "initialWindowSize", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 1024, 2147483647);
                cfg.initialWindowSize = static_cast<size_t>(v);
            }

            if (readNumberField(L, idx, "maxFrameSize", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 16384, 16777215);
                cfg.maxFrameSize = static_cast<size_t>(v);
            }

            if (readNumberField(L, idx, "maxHeaderListSize", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 1024, 16 << 20);
                cfg.maxHeaderListSize = static_cast<size_t>(v);
            }

            if (readNumberField(L, idx, "headerTableSize", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 0, 1 << 20);
                cfg.headerTableSize = static_cast<size_t>(v);
            }

            return valid;
        }

        inline bool loadMultiplexerSection(lua_State *L, int idx, Http2Config &cfg)
        {
            return loadHttp2Section(L, idx, cfg);
        }

        inline bool loadHttp3Section(lua_State *L, int idx, Http3Config &cfg)
        {
            bool valid = true;
            lua_Integer num = 0;

            if (readNumberField(L, idx, "maxRequestBodyBytes", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 1024, 1024 << 20);
                cfg.maxRequestBodyBytes = static_cast<size_t>(v);
            }

            if (readNumberField(L, idx, "maxStreamBufferBytes", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 1024, 1024 << 20);
                cfg.maxStreamBufferBytes = static_cast<size_t>(v);
            }

            if (readNumberField(L, idx, "maxHeaderBlockBytes", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 1024, 16 << 20);
                cfg.maxHeaderBlockBytes = static_cast<size_t>(v);
            }

            if (readNumberField(L, idx, "maxHeaderEntries", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 1, 10000);
                cfg.maxHeaderEntries = static_cast<size_t>(v);
            }

            if (readNumberField(L, idx, "port", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 1, 65535);
                cfg.port = static_cast<uint16_t>(v);
            }

            return valid;
        }

        inline bool loadProxySection(lua_State *L, int idx, ProxyConfig &cfg)
        {
            bool valid = true;
            bool flag = false;

            if (readBoolField(L, idx, "autoReplyConnectSuccess", flag, valid))
            {
                cfg.autoReplyConnectSuccess = flag;
            }

            return valid;
        }

    } // namespace detail

    /**
     * @brief 从 Lua 脚本文件重新加载网络库配置与日志子系统配置
     *
     * 执行全量沙箱化原子配置加载：
     * 1. 创建沙箱化隔离 Lua 虚拟机（luaL_newstate() 零加载标准库，杜绝 os、io、package 等任何系统级库与任意代码执行）；
     * 2. 设置单次执行指令配额（50,000,000 条指令）以防死循环拒绝服务；
     * 3. 强制使用 "t" 模式加载文本脚本，杜绝恶意二进制字节码；
     * 4. 解析校验 server、reactor、connection、datagram、proactor、http2、security 等各配置节；
     * 5. 若配置脚本包含 logger 或 fileManager 配置节，自动联合重新加载 mylog 日志配置；
     * 6. 校验全部通过后，原子发布到 NetConfigHolder；若失败则保持运行中配置不发生任何部分修改（All-or-Nothing）。
     *
     * @param config Lua 配置文件所在路径
     * @param syncMylog 是否同步重新加载同文件中的 mylog 日志配置（默认 true）
     * @return true 配置文件加载且校验成功，新配置已原子生效
     * @return false 配置文件不存在、语法错误或包含无法解析的非法项，已沿用原配置
     */
    inline bool reloadConfig(const std::filesystem::path &config, bool syncMylog = true)
    {
        lua_State *L = luaL_newstate();
        if (L == nullptr)
        {
            detail::printError("cannot create lua state");
            return false;
        }

        // 5000 万指令预算上限，防范恶意或误写的死循环脚本
        lua_sethook(
            L, [](lua_State *LS, lua_Debug * /*ar*/)
            { luaL_error(LS, "config script aborted: instruction budget exceeded"); }, LUA_MASKCOUNT, 50'000'000);

        // 仅允许加载文本脚本（"t" 模式），拒绝预编译字节码以规避潜在字节码逃逸漏洞
        if (luaL_loadfilex(L, config.c_str(), "t") != LUA_OK || lua_pcall(L, 0, 0, 0) != LUA_OK)
        {
            const char *err = lua_tostring(L, -1);
            detail::printError("{}", err != nullptr ? err : "lua load failed");
            lua_close(L);
            return false;
        }

        NetConfig newCfg = getNetConfig();
        bool valid = true;
        bool hasMylogSection = false;

        lua_getglobal(L, "server");
        if (lua_istable(L, -1))
        {
            const int idx = lua_gettop(L);
            if (!detail::loadServerSection(L, idx, newCfg.server))
            {
                valid = false;
            }
        }
        else if (lua_type(L, -1) != LUA_TNIL)
        {
            detail::printError("global 'server' must be a table");
            valid = false;
        }
        lua_pop(L, 1);

        lua_getglobal(L, "reactor");
        if (lua_istable(L, -1))
        {
            const int idx = lua_gettop(L);
            if (!detail::loadReactorSection(L, idx, newCfg.reactor))
            {
                valid = false;
            }
        }
        else if (lua_type(L, -1) != LUA_TNIL)
        {
            detail::printError("global 'reactor' must be a table");
            valid = false;
        }
        lua_pop(L, 1);

        lua_getglobal(L, "proactor");
        if (lua_istable(L, -1))
        {
            const int idx = lua_gettop(L);
            if (!detail::loadProactorSection(L, idx, newCfg.proactor))
            {
                valid = false;
            }
        }
        else if (lua_type(L, -1) != LUA_TNIL)
        {
            detail::printError("global 'proactor' must be a table");
            valid = false;
        }
        lua_pop(L, 1);

        lua_getglobal(L, "connection");
        if (lua_istable(L, -1))
        {
            const int idx = lua_gettop(L);
            if (!detail::loadConnectionSection(L, idx, newCfg.connection))
            {
                valid = false;
            }
        }
        else if (lua_type(L, -1) != LUA_TNIL)
        {
            detail::printError("global 'connection' must be a table");
            valid = false;
        }
        lua_pop(L, 1);

        lua_getglobal(L, "datagram");
        if (lua_istable(L, -1))
        {
            const int idx = lua_gettop(L);
            if (!detail::loadDatagramSection(L, idx, newCfg.datagram))
            {
                valid = false;
            }
        }
        else if (lua_type(L, -1) != LUA_TNIL)
        {
            detail::printError("global 'datagram' must be a table");
            valid = false;
        }
        lua_pop(L, 1);

        lua_getglobal(L, "security");
        if (lua_istable(L, -1))
        {
            const int idx = lua_gettop(L);
            if (!detail::loadSecuritySection(L, idx, newCfg.security))
            {
                valid = false;
            }
        }
        else if (lua_type(L, -1) != LUA_TNIL)
        {
            detail::printError("global 'security' must be a table");
            valid = false;
        }
        lua_pop(L, 1);

        lua_getglobal(L, "http1");
        if (lua_istable(L, -1))
        {
            const int idx = lua_gettop(L);
            if (!detail::loadHttp1Section(L, idx, newCfg.http1))
            {
                valid = false;
            }
        }
        else if (lua_type(L, -1) != LUA_TNIL)
        {
            detail::printError("global 'http1' must be a table");
            valid = false;
        }
        lua_pop(L, 1);

        lua_getglobal(L, "http2");
        if (lua_isnil(L, -1))
        {
            lua_pop(L, 1);
            lua_getglobal(L, "multiplexer"); // 兼容旧配置表名
        }
        if (lua_istable(L, -1))
        {
            const int idx = lua_gettop(L);
            if (!detail::loadHttp2Section(L, idx, newCfg.http2))
            {
                valid = false;
            }
        }
        else if (lua_type(L, -1) != LUA_TNIL)
        {
            detail::printError("global 'http2' must be a table");
            valid = false;
        }
        lua_pop(L, 1);

        lua_getglobal(L, "http3");
        if (lua_istable(L, -1))
        {
            const int idx = lua_gettop(L);
            if (!detail::loadHttp3Section(L, idx, newCfg.http3))
            {
                valid = false;
            }
        }
        else if (lua_type(L, -1) != LUA_TNIL)
        {
            detail::printError("global 'http3' must be a table");
            valid = false;
        }
        lua_pop(L, 1);

        lua_getglobal(L, "proxy");
        if (lua_istable(L, -1))
        {
            const int idx = lua_gettop(L);
            if (!detail::loadProxySection(L, idx, newCfg.proxy))
            {
                valid = false;
            }
        }
        else if (lua_type(L, -1) != LUA_TNIL)
        {
            detail::printError("global 'proxy' must be a table");
            valid = false;
        }
        lua_pop(L, 1);

        // 探测是否包含 mylog 日志配置节
        lua_getglobal(L, "logger");
        if (lua_istable(L, -1))
        {
            hasMylogSection = true;
        }
        lua_pop(L, 1);

        lua_getglobal(L, "fileManager");
        if (lua_istable(L, -1))
        {
            hasMylogSection = true;
        }
        lua_pop(L, 1);

        lua_close(L);

        if (!valid)
        {
            return false;
        }

#if MYNET_HAS_MYLOG_LUA
        if (syncMylog && hasMylogSection)
        {
            if (!mylog::reloadConfig(config))
            {
                detail::printError("failed to reload integrated mylog section");
                return false;
            }
        }
#else
        (void)hasMylogSection;
        (void)syncMylog;
#endif

        // 全量校验通过，原子发布生效
        publishNetConfig(std::move(newCfg));
        return true;
    }

} // namespace mynet
