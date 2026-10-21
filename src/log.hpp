#pragma once

/**
 * @file log.hpp
 * @brief Integration layer connecting mynet with mylog (third_party/mylog).
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
             * @brief Sink log messages to stderr to avoid corrupting stdout pipes.
             * @param msg The log message view.
             */
            inline void toStderr(void * /*ctx*/, std::string_view msg) noexcept
            {
                if (!msg.empty())
                {
                    std::fwrite(msg.data(), 1, msg.size(), stderr);
                }
            }

            /**
             * @brief Flush stderr buffer.
             */
            inline void flushStderr(void * /*ctx*/) noexcept
            {
                std::fflush(stderr);
            }

        } // namespace detail

        /**
         * @brief Initialize logging configuration for mynet, routing sink to stderr.
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
         * @brief Retrieve human-readable string representation of an errno.
         * @param err The errno value.
         * @return String view describing the error.
         */
        [[nodiscard]] inline std::string_view errnoText(int err) noexcept
        {
            const char *text = std::strerror(err);
            return text != nullptr ? std::string_view{text} : std::string_view{"unknown error"};
        }

        /**
         * @brief Retrieve oldest queued OpenSSL error string.
         * @return String view describing the SSL error.
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
