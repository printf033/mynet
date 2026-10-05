#pragma once

#include "log.hpp"
#include <cstddef>
#include <cstdio>
#include <cstring>

// The one place bytes are written down in full.
//
// Two front ends need it -- the stream handler that shows whatever lands on a
// watched TCP port (handler.hpp's HandlerTrace) and the datagram handler that
// does the same for a watched UDP port (datagram.hpp's DatagramTrace) -- and
// they need the same format, because reading two different hex layouts side by
// side is exactly the friction this library exists to remove. Nothing here
// touches protocol state; a dump is observation only.
namespace mynetdump
{
    // Bytes per log line. Sixteen keeps the hex and text columns aligned at a
    // width that survives being read in a terminal.
    inline constexpr size_t kLineBytes = 16;

    // Name the shape where the first bytes give it away. A TLS record is the
    // one worth spelling out: byte 0 is the content type, bytes 1-2 the
    // protocol version whose major number has been 3 since SSLv3.
    [[nodiscard]] inline const char *shapeOf(const unsigned char *b, size_t n) noexcept
    {
        if (n >= 3 && b[0] == 0x16 && b[1] == 0x03)
            return "TLS handshake record -- a ClientHello, most likely (encrypted)";
        if (n >= 3 && b[0] == 0x15 && b[1] == 0x03)
            return "TLS alert record";
        if (n >= 3 && b[0] == 0x17 && b[1] == 0x03)
            return "TLS application data (encrypted)";
        if (n >= 3 && b[0] == 0x14 && b[1] == 0x03)
            return "TLS change_cipher_spec record";
        if (n >= 1 && b[0] == 0x00 && n >= 2 && b[1] == 0x00)
            return "DTLS handshake record";
        return "unclassified bytes";
    }

    [[nodiscard]] inline char hexDigit(unsigned v) noexcept
    {
        return v < 10 ? static_cast<char>('0' + v) : static_cast<char>('a' + (v - 10));
    }

    // One line per kLineBytes: offset, hex, then the same bytes as text with
    // anything unprintable shown as a dot. The buffer is sized for the worst
    // case, so no line is ever truncated.
    inline void writeDown(const char *tag, const unsigned char *b, size_t n) noexcept
    {
        LOG_INFO("{}: {} byte(s) -- {}", tag, n, shapeOf(b, n));
        char row[16 + 2 + kLineBytes * 3 + kLineBytes + 3];
        for (size_t off = 0; off < n; off += kLineBytes)
        {
            const size_t chunk = (n - off < kLineBytes) ? (n - off) : kLineBytes;
            char offset[24];
            const int written = std::snprintf(offset, sizeof offset, "%04zx", off);
            size_t p = 0;
            if (written > 0 && static_cast<size_t>(written) < sizeof offset)
            {
                std::memcpy(row, offset, static_cast<size_t>(written));
                p = static_cast<size_t>(written);
            }
            row[p++] = ' ';
            row[p++] = ' ';
            for (size_t i = 0; i < kLineBytes; ++i)
            {
                if (i < chunk)
                {
                    row[p++] = hexDigit(static_cast<unsigned>(b[off + i]) >> 4);
                    row[p++] = hexDigit(static_cast<unsigned>(b[off + i]) & 0x0fu);
                }
                else
                {
                    // Pad short final lines so the text column stays put.
                    row[p++] = ' ';
                    row[p++] = ' ';
                }
                row[p++] = ' ';
            }
            row[p++] = '|';
            for (size_t i = 0; i < chunk; ++i)
                row[p++] = (b[off + i] >= 0x20 && b[off + i] < 0x7f)
                               ? static_cast<char>(b[off + i])
                               : '.';
            row[p++] = '|';
            row[p] = '\0';
            LOG_INFO("{}: {}", tag, row);
        }
    }
} // namespace mynetdump
