#pragma once

// The seam between mynet and mylog (third_party/mylog, a git submodule).
//
// mynet reports failure through its return values and nothing else: the public
// entry points hand back std::optional<Err>, the transports hand back
// std::expected<size_t, IoEnd>, and control flow reads only those. This header
// adds the other half of an operable library -- the same failures written down
// with the context an Err cannot carry: the errno behind it, the fd, the peer
// address, the TLS state.
//
// That split is the rule every LOG_* call in src/ follows:
//   * the return path is what the program acts on,
//   * the log line is why, recorded once, where the failure was detected.
// No log call below re-checks an error, retries, or changes a control flow: a
// missing or silenced logger cannot alter the protocol.
//
// The sink is stderr, not mylog's default stdout, because two of the three
// program shapes built from this library stream *data* over stdout:
//
//     cat request.bin | ./peer_tcp host port > response.bin
//
// A library that logged to stdout would corrupt exactly those programs. The
// samples call mynetlog::init() before anything can log; a program embedding
// mynet may install its own mylog config instead -- that is mylog's API, not
// something this seam takes away.
//
// mylog is included by file name: its include directory arrives through the
// interface_mylog target linked by src/CMakeLists.txt, which is also the only
// place in mynet that names the submodule.
#include "logger.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <openssl/err.h>
#include <string_view>

namespace mynetlog
{
    namespace detail
    {
        inline void toStderr(void * /*ctx*/, std::string_view msg) noexcept
        {
            if (!msg.empty())
                std::fwrite(msg.data(), 1, msg.size(), stderr);
        }

        inline void flushStderr(void * /*ctx*/) noexcept
        {
            std::fflush(stderr);
        }
    } // namespace detail

    // Install mynet's logging policy: mylog's formatter and level filtering,
    // with the sink moved from stdout to stderr. Idempotent -- the sink is
    // installed at most once, so calling it again cannot double-wrap it -- and
    // it leaves levels alone, so a program can still tune them afterwards
    // through mylog::Logger::getInstance().
    inline void init() noexcept
    {
        static const bool installed = [] {
            auto &logger = mylog::Logger::getInstance();
            logger.setOutputFunction({&detail::toStderr});
            logger.setFlushFunction({&detail::flushStderr});
            return true;
        }();
        (void)installed;
    }

    // errno text for the failure being logged, read while errno still means
    // that failure. errno is thread-local but any library call may overwrite
    // it, so this belongs at the failing call site, not after the error has
    // travelled up the stack.
    [[nodiscard]] inline std::string_view errnoText(int err) noexcept
    {
        const char *text = std::strerror(err);
        return text != nullptr ? std::string_view{text} : std::string_view{"unknown error"};
    }

    // The text of OpenSSL's oldest queued error. OpenSSL keeps its own
    // per-thread queue rather than errno, and the pointer it returns belongs to
    // that queue, so the text is copied into thread-local storage before the
    // next OpenSSL call can clear it.
    [[nodiscard]] inline std::string_view sslText() noexcept
    {
        thread_local char buf[256];
        const unsigned long code = ::ERR_get_error();
        if (code == 0)
            return std::string_view{"no queued OpenSSL error"};
        ::ERR_error_string_n(code, buf, sizeof(buf));
        return std::string_view{buf};
    }
} // namespace mynetlog
