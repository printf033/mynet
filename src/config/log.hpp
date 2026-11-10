#pragma once

/**
 * @file config/log.hpp
 * @brief 日志输出与引擎配置：管理 mylog（thirdparty/mylog）的初始化、输出目标及格式策略。
 *
 * 进程启动时可调用 log::init() 或 log::init(cfg)，配置输出落点（默认 stderr）、日志级别等，
 * 从而让 stdout 保持纯净（可作为数据管道使用）。
 *
 * 错误文本转换（errnoText / sslText）属于错误语义，在 error.hpp 中。
 */

#include "logger.hpp"
#include <cstdio>
#include <string>
#include <string_view>

namespace mynet
{

    namespace log
    {

        /**
         * @brief 日志输出目标类型
         */
        enum class OutputTarget : uint8_t
        {
            Stderr, ///< 输出到标准错误（默认，保留 stdout 作为数据管道）
            Stdout, ///< 输出到标准输出
            None    ///< 丢弃所有日志输出
        };

        /**
         * @brief 独立日志配置项（L0 基础设施配置）
         *
         * 在配置解析、网络引擎启动前初始化生效，避免配置解析期错误无处输出。
         */
        struct LogConfig
        {
            /// 日志过滤最低级别（"TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"）
            std::string level = "INFO";
            /// 输出目标（默认 Stderr）
            OutputTarget target = OutputTarget::Stderr;
            /// 时间戳是否使用 UTC 时间（默认 false 为本地时区）
            bool timestampUtc = false;
            /// 是否对控制字符进行转义（默认 true）
            bool escapeControlChars = true;
            /// 遇到 FATAL 日志时的动作（"NONE", "EXIT", "ABORT"，默认 "NONE"）
            std::string fatalAction = "NONE";
            /// 单条日志最大长度限制（默认 1 MiB）
            size_t maxLogLength = 1ULL << 20;
        };

        namespace detail
        {

            /**
             * @brief 将日志消息写入 stderr，避免污染 stdout 管道。
             */
            inline void toStderr(void * /*ctx*/, std::string_view msg) noexcept
            {
                if (!msg.empty())
                {
                    std::fwrite(msg.data(), 1, msg.size(), stderr);
                }
            }

            /**
             * @brief 刷新 stderr 缓冲。
             */
            inline void flushStderr(void * /*ctx*/) noexcept
            {
                std::fflush(stderr);
            }

            /**
             * @brief 将日志消息写入 stdout。
             */
            inline void toStdout(void * /*ctx*/, std::string_view msg) noexcept
            {
                if (!msg.empty())
                {
                    std::fwrite(msg.data(), 1, msg.size(), stdout);
                }
            }

            /**
             * @brief 刷新 stdout 缓冲。
             */
            inline void flushStdout(void * /*ctx*/) noexcept
            {
                std::fflush(stdout);
            }

            /**
             * @brief 丢弃日志（静音）。
             */
            inline void toNull(void * /*ctx*/, std::string_view /*msg*/) noexcept {}
            inline void flushNull(void * /*ctx*/) noexcept {}

        } // namespace detail

        /**
         * @brief 初始化 mynet 的日志配置，支持传入参数化 LogConfig。
         *
         * @param cfg 日志配置结构体
         */
        inline void init(const LogConfig &cfg) noexcept
        {
            auto &logger = mylog::Logger::getInstance();
            auto mylogCfg = logger.getConfig();

            // 1. 设置输出函数与刷盘函数
            switch (cfg.target)
            {
            case OutputTarget::Stderr:
                mylogCfg.outputFunction = {&detail::toStderr, nullptr};
                mylogCfg.flushFunction = {&detail::flushStderr, nullptr};
                break;
            case OutputTarget::Stdout:
                mylogCfg.outputFunction = {&detail::toStdout, nullptr};
                mylogCfg.flushFunction = {&detail::flushStdout, nullptr};
                break;
            case OutputTarget::None:
                mylogCfg.outputFunction = {&detail::toNull, nullptr};
                mylogCfg.flushFunction = {&detail::flushNull, nullptr};
                break;
            }

            // 2. 格式与安全限制
            mylogCfg.timestampUtc = cfg.timestampUtc;
            mylogCfg.escapeControlChars = cfg.escapeControlChars;
            mylogCfg.maxLogLength = cfg.maxLogLength;

            if (cfg.fatalAction == "EXIT")
            {
                mylogCfg.fatalAction = mylog::FATAL_ACTION::EXIT;
            }
            else if (cfg.fatalAction == "ABORT")
            {
                mylogCfg.fatalAction = mylog::FATAL_ACTION::ABORT;
            }
            else
            {
                mylogCfg.fatalAction = mylog::FATAL_ACTION::NONE;
            }

            logger.setConfig(std::move(mylogCfg));

            // 3. 设置日志过滤级别
            auto lvl = mylog::parseLevel(cfg.level);
            if (lvl.has_value())
            {
                logger.setSuppressLevel(*lvl);
            }
        }

        /**
         * @brief 默认初始化（落点定到 stderr，INFO 级别，保持向后兼容）
         */
        inline void init() noexcept
        {
            [[maybe_unused]] static const bool installed = []
            {
                init(LogConfig{});
                return true;
            }();
        }

    } // namespace log

} // namespace mynet
