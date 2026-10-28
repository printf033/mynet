#pragma once

/**
 * @file log_config.hpp
 * @brief 日志输出配置：把 mylog（thirdparty/mylog）的输出落点定到 stderr。
 *
 * 本文件只做一件事——进程启动时调用一次 log::init()，把 mylog 的输出函数与
 * 刷新函数替换为 stderr 版本，从而让 stdout 保持纯净（作为数据管道使用）。
 *
 * 错误文本转换（errnoText / sslText）属于错误语义，已移至 error.hpp，
 * 与 toString(ERR) / nameOf(ERR) 并列。
 */

#include "logger.hpp"
#include <cstdio>
#include <string_view>

namespace mynet
{

    namespace log
    {

        namespace detail
        {

            /**
             * @brief 将日志消息写入 stderr，避免污染 stdout 管道。
             * @param msg 日志消息视图。
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

        } // namespace detail

        /**
         * @brief 初始化 mynet 的日志配置，输出落点定为 stderr。
         */
        inline void init() noexcept
        {
            [[maybe_unused]] static const bool installed = []
            {
                auto &logger = mylog::Logger::getInstance();
                logger.setOutputFunction({&detail::toStderr});
                logger.setFlushFunction({&detail::flushStderr});
                return true;
            }();
        }

    } // namespace log

} // namespace mynet
