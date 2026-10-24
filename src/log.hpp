#pragma once

/**
 * @file log.hpp
 * @brief mynet 与 mylog（third_party/mylog）的集成层。
 */

#include "logger.hpp"
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <openssl/err.h>
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

        /**
         * @brief 获取 errno 的可读字符串描述。
         * @param err errno 值。
         * @return 描述该错误的字符串视图，生命周期至本线程下次调用为止。
         */
        [[nodiscard]] inline std::string_view errnoText(int err) noexcept
        {
            // strerror 非线程安全（POSIX 已弃用），改用 strerror_r；
            // Linux 下 _GNU_SOURCE 恒定义，GNU 版直接返回指向 buf 的指针；
            // 缓冲必须 thread_local，否则返回的 string_view 指向已析构的栈帧
            thread_local char buf[256];
            const char *text = ::strerror_r(err, buf, sizeof(buf));
            return text != nullptr ? std::string_view{text} : std::string_view{"unknown error"};
        }

        /**
         * @brief 取出最早的排队 OpenSSL 错误字符串。
         * @return 描述该 SSL 错误的字符串视图，生命周期至本线程下次调用为止。
         */
        [[nodiscard]] inline std::string_view sslText() noexcept
        {
            thread_local char buf[256];
            const unsigned long code = ::ERR_get_error();
            if (code == 0)
            {
                return std::string_view{"no queued OpenSSL error"};
            }
            ::ERR_error_string_n(code, buf, sizeof(buf));
            ::ERR_clear_error();
            return std::string_view{buf};
        }

    } // namespace log

} // namespace mynet
