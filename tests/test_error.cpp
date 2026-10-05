// Err and IoEnd: two enums whose whole point is that every value has exactly
// one name and one meaning, so every value is walked here rather than sampled.
#include "error.hpp"
#include <gtest/gtest.h>
#include <string_view>

namespace
{
    // The number of enumerators in Err. When a value is added this fails until the
    // walk below covers it, which is the reminder the walk exists for.
    constexpr int kErrCount = 30;
} // namespace

TEST(Err, EveryValueHasTextAndAnExitCode)
{
    for (int i = 0; i < kErrCount; ++i)
    {
        const Err err = static_cast<Err>(i);
        const std::string_view text = to_string(err);
        EXPECT_FALSE(text.empty()) << "Err value " << i << " has no text";
        EXPECT_NE(text, "unknown error") << "Err value " << i << " fell through to the default";
        EXPECT_EQ(to_exit_code(err), i + 1) << "exit codes are one-based";
    }
}

TEST(Err, LastEnumeratorIsIncludedInTheWalk)
{
    EXPECT_EQ(std::to_underlying(Err::not_initialised), kErrCount - 1);
}

TEST(Err, UnknownValueIsNamedRatherThanEmpty)
{
    EXPECT_EQ(to_string(static_cast<Err>(0xff)), "unknown error");
}

TEST(Err, TextIsStableForASpotCheckValue)
{
    EXPECT_EQ(to_string(Err::bind_failed), "bind() failed");
    EXPECT_EQ(to_string(Err::ssl_key_mismatch), "the private key does not match the certificate");
    EXPECT_EQ(to_string(Err::not_initialised), "the event loop was not initialised");
}

TEST(IoEnd, CoversTheFourOrdinaryOutcomesOfATransfer)
{
    // None of these is an error, which is the reason they are a separate enum:
    // a reader that gets one is being told whether to retry, wait, or stop.
    EXPECT_EQ(std::to_underlying(IoEnd::wouldblock), 0);
    EXPECT_EQ(std::to_underlying(IoEnd::interrupted), 1);
    EXPECT_EQ(std::to_underlying(IoEnd::eof), 2);
    EXPECT_EQ(std::to_underlying(IoEnd::fatal), 3);
}
