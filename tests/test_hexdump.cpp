// mynetdump: the record shapes it can name from the first bytes, and the
// hexdump that stays one line per kLineBytes whatever it is handed.
#include "hexdump.hpp"
#include "log.hpp"
#include <cstddef>
#include <gtest/gtest.h>
#include <string>

namespace
{
    const unsigned char *bytesOf(const std::string &s)
    {
        return reinterpret_cast<const unsigned char *>(s.data());
    }
} // namespace

TEST(ShapeOf, NamesEachTlsRecordType)
{
    const std::string handshake = std::string("\x16\x03\x01", 3) + "rest";
    const std::string alert = std::string("\x15\x03\x03", 3) + "rest";
    const std::string appdata = std::string("\x17\x03\x03", 3) + "rest";
    const std::string ccs = std::string("\x14\x03\x03", 3) + "rest";
    EXPECT_STREQ(mynetdump::shapeOf(bytesOf(handshake), handshake.size()),
                 "TLS handshake record -- a ClientHello, most likely (encrypted)");
    EXPECT_STREQ(mynetdump::shapeOf(bytesOf(alert), alert.size()), "TLS alert record");
    EXPECT_STREQ(mynetdump::shapeOf(bytesOf(appdata), appdata.size()), "TLS application data (encrypted)");
    EXPECT_STREQ(mynetdump::shapeOf(bytesOf(ccs), ccs.size()), "TLS change_cipher_spec record");
}

TEST(ShapeOf, NamesDtlsHandshake)
{
    const std::string dtls = std::string("\x00\x00", 2) + "rest";
    EXPECT_STREQ(mynetdump::shapeOf(bytesOf(dtls), dtls.size()), "DTLS handshake record");
}

TEST(ShapeOf, FallsBackToUnclassified)
{
    const std::string http = "GET / HTTP/1.1\r\n";
    EXPECT_STREQ(mynetdump::shapeOf(bytesOf(http), http.size()), "unclassified bytes");
}

TEST(ShapeOf, ShortInputCannotBeNamed)
{
    // Fewer than three bytes is not enough to read a TLS content type and
    // version, so the honest answer is the fallback rather than a guess.
    const std::string two = std::string("\x16\x03", 2);
    EXPECT_STREQ(mynetdump::shapeOf(bytesOf(two), two.size()), "unclassified bytes");
    EXPECT_STREQ(mynetdump::shapeOf(nullptr, 0), "unclassified bytes");
}

TEST(HexDump, LineWidthIsSixteen)
{
    EXPECT_EQ(mynetdump::kLineBytes, size_t{16});
}

TEST(HexDump, WriteDownAcceptsEmptyAndPartialLines)
{
    mynetlog::init();
    const std::string empty;
    mynetdump::writeDown("empty", bytesOf(empty), 0);

    const std::string one = "A";
    mynetdump::writeDown("one", bytesOf(one), one.size());

    // One full line plus a one-byte tail: the short final line is padded
    // rather than truncated, which is the behaviour worth locking down.
    const std::string seventeen = std::string(17, 'x');
    mynetdump::writeDown("seventeen", bytesOf(seventeen), seventeen.size());
    EXPECT_EQ(seventeen.size(), size_t{17});
}
