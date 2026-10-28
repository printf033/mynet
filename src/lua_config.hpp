#pragma once

/**
 * @file lua_config.hpp
 * @brief 沙箱化 Lua 配置加载与热重载引擎（loadServerSection / reloadConfig）。
 *
 * 把 config.lua 中的 server / proactor / multiplexer / security 各段解析进
 * configHolder.hpp 定义的配置结构体，并提供 reloadConfig() 在信号或 mylog
 * 热重载时重新装载。
 */

#include "configHolder.hpp"
#include "log_config.hpp"
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
// 后重命名为 lua_config.hpp。探测的是被包含文件而非本文件，因此与本库同名的
// src/lua_config.hpp 不冲突——包含解析先看各自目录，两个文件互不遮蔽。
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

            if (readNumberField(L, idx, "keepAliveTimeout_ms", num, valid) ||
                readNumberField(L, idx, "keepAliveTimeoutMs", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 100, 86'400'000);
                cfg.keepAliveTimeout_ms = static_cast<size_t>(v);
            }

            if (readNumberField(L, idx, "writeHighWaterMark", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 1024, 1024 << 20);
                cfg.writeHighWaterMark = static_cast<size_t>(v);
            }

            if (readNumberField(L, idx, "maxRequestBytes", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 1024, 1024 << 20);
                cfg.maxRequestBytes = static_cast<size_t>(v);
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

            if (readNumberField(L, idx, "bufEntries", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 16, 65536);
                cfg.bufEntries = static_cast<size_t>(v);
            }

            if (readNumberField(L, idx, "bufSize", num, valid))
            {
                const lua_Integer v = clampValue<lua_Integer>(num, 512, 1 << 20);
                cfg.bufSize = static_cast<size_t>(v);
            }

            return valid;
        }

        inline bool loadMultiplexerSection(lua_State *L, int idx, MultiplexerConfig &cfg)
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
                const lua_Integer v = clampValue<lua_Integer>(num, 512, 1 << 20);
                cfg.maxHeaderListSize = static_cast<size_t>(v);
            }

            return valid;
        }

        inline bool loadSecuritySection(lua_State *L, int idx, SecurityConfig &cfg)
        {
            bool valid = true;
            bool flag = false;
            std::string text;

            if (readBoolField(L, idx, "enableTls", flag, valid))
            {
                cfg.enableTls = flag;
            }

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

            if (readStringField(L, idx, "alpnProtocols", text, valid))
            {
                cfg.alpnProtocols = std::move(text);
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
     * 4. 解析校验 server、proactor、multiplexer、security 等各配置节；
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

        lua_getglobal(L, "multiplexer");
        if (lua_istable(L, -1))
        {
            const int idx = lua_gettop(L);
            if (!detail::loadMultiplexerSection(L, idx, newCfg.multiplexer))
            {
                valid = false;
            }
        }
        else if (lua_type(L, -1) != LUA_TNIL)
        {
            detail::printError("global 'multiplexer' must be a table");
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
