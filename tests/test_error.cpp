// ERR and IO_END: two enums whose whole point is that every value has exactly
// one name and one meaning, so every value is walked here rather than sampled.
#include "error.hpp"
#include <gtest/gtest.h>
#include <string_view>
#include <utility>

using namespace mynet;

TEST(ERR, EveryValueHasTextAndAnExitCode)
{
    for (size_t i = 0; i < kErrCount; ++i)
    {
        const ERR err = static_cast<ERR>(i);
        const std::string_view text = toString(err);
        EXPECT_FALSE(text.empty()) << "ERR value " << i << " has no text";
        EXPECT_NE(text, "unknown error") << "ERR value " << i << " fell through to the default";
        EXPECT_EQ(toExitCode(err), static_cast<int>(i) + 2)
            << "exit codes are two-based (reserving 1 for generic error)";
    }
}

TEST(ERR, LastEnumeratorIsIncludedInTheWalk)
{
    EXPECT_EQ(std::to_underlying(ERR::NOT_INITIALISED), kErrCount - 1);
}

TEST(ERR, UnknownValueIsNamedRatherThanEmpty)
{
    EXPECT_EQ(toString(static_cast<ERR>(0xff)), "unknown error");
    EXPECT_EQ(toExitCode(static_cast<ERR>(0xff)), kGenericExitCode);
}

TEST(ERR, TextIsStableForASpotCheckValue)
{
    EXPECT_EQ(toString(ERR::BIND_FAILED), "bind() failed");
    EXPECT_EQ(toString(ERR::SSL_KEY_MISMATCH), "the private key does not match the certificate");
    EXPECT_EQ(toString(ERR::NOT_INITIALISED), "the event loop was not initialised");
    EXPECT_EQ(toString(ERR::BUF_ALLOC_FAILED), "the buffer could not grow: the allocator returned no memory");
    EXPECT_EQ(toString(ERR::QUEUE_FULL), "the bounded queue is full and the element was refused");
}

TEST(ERR, ReflectionNameOf)
{
    EXPECT_EQ(nameOf(ERR::BIND_FAILED), "BIND_FAILED");
    EXPECT_EQ(nameOf(ERR::SSL_KEY_MISMATCH), "SSL_KEY_MISMATCH");
    EXPECT_EQ(nameOf(ERR::NOT_INITIALISED), "NOT_INITIALISED");
    EXPECT_EQ(kErrCount, 35);
}

TEST(IO_END, CoversTheFourOrdinaryOutcomesOfATransfer)
{
    // None of these is an error, which is the reason they are a separate enum:
    // a reader that gets one is being told whether to retry, wait, or stop.
    EXPECT_EQ(std::to_underlying(IO_END::WOULDBLOCK), 0);
    EXPECT_EQ(std::to_underlying(IO_END::INTERRUPTED), 1);
    EXPECT_EQ(std::to_underlying(IO_END::EOF_REACHED), 2);
    EXPECT_EQ(std::to_underlying(IO_END::FATAL), 3);
    EXPECT_EQ(kIoEndCount, 4);

    EXPECT_EQ(nameOf(IO_END::WOULDBLOCK), "WOULDBLOCK");
    EXPECT_EQ(nameOf(IO_END::INTERRUPTED), "INTERRUPTED");
    EXPECT_EQ(nameOf(IO_END::EOF_REACHED), "EOF_REACHED");
    EXPECT_EQ(nameOf(IO_END::FATAL), "FATAL");

    EXPECT_EQ(toString(IO_END::WOULDBLOCK), "socket would block");
    EXPECT_EQ(toString(IO_END::INTERRUPTED), "operation interrupted by signal");
    EXPECT_EQ(toString(IO_END::EOF_REACHED), "orderly end of stream");
    EXPECT_EQ(toString(IO_END::FATAL), "fatal link failure");
    EXPECT_EQ(toString(static_cast<IO_END>(0xff)), "unknown io outcome");
}
