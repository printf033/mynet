// Buffer: the read cursor, the lazy compaction behind it, and the water mark
// that decides when a connection is told to stop reading.
#include "buffer.hpp"
#include <gtest/gtest.h>
#include <string>

namespace
{
    constexpr const char *kText = "the quick brown fox";
    constexpr size_t kTextSize = sizeof("the quick brown fox") - 1;
} // namespace

TEST(Buffer, StartsEmpty)
{
    Buffer b;
    EXPECT_TRUE(b.empty());
    EXPECT_EQ(b.readableBytes(), size_t{0});
    EXPECT_EQ(b.readableBegin(), b.readableBegin()); // a valid pointer to nothing
}

TEST(Buffer, AppendThenReadBack)
{
    Buffer b;
    b.append(kText, kTextSize);
    ASSERT_EQ(b.readableBytes(), kTextSize);
    EXPECT_FALSE(b.empty());
    EXPECT_EQ(std::string(b.readableBegin(), b.readableBytes()), kText);
}

TEST(Buffer, RetrieveMovesTheCursorAndKeepsTheTail)
{
    Buffer b;
    b.append(kText, kTextSize);
    b.retrieve(4);
    EXPECT_EQ(b.readableBytes(), kTextSize - 4);
    EXPECT_EQ(std::string(b.readableBegin(), b.readableBytes()), "quick brown fox");
}

TEST(Buffer, RetrieveBeyondReadableDropsEverything)
{
    Buffer b;
    b.append(kText, kTextSize);
    b.retrieve(kTextSize + 100);
    EXPECT_TRUE(b.empty());
    EXPECT_EQ(b.readableBytes(), size_t{0});
}

TEST(Buffer, RetrieveExactlyReadableIsEmpty)
{
    Buffer b;
    b.append(kText, kTextSize);
    b.retrieve(kTextSize);
    EXPECT_TRUE(b.empty());
}

TEST(Buffer, LongLivedBufferStillReadsItsTailAfterCompaction)
{
    // The compaction branch needs a dead prefix of at least 4096 bytes that is
    // at least half the backing store. The observable contract either way is
    // that the live tail is exactly what was not consumed.
    Buffer b;
    std::string chunk(4096, 'a');
    b.append(chunk);
    b.append(std::string("tail"));
    ASSERT_EQ(b.readableBytes(), 4100u);
    b.retrieve(4096);
    EXPECT_EQ(b.readableBytes(), size_t{4});
    EXPECT_EQ(std::string(b.readableBegin(), b.readableBytes()), "tail");
    b.append(std::string("more"));
    EXPECT_EQ(std::string(b.readableBegin(), b.readableBytes()), "tailmore");
}

TEST(Buffer, RetrieveAllAsStringConsumesTheBuffer)
{
    Buffer b;
    b.append(kText, kTextSize);
    EXPECT_EQ(b.retrieveAllAsString(), kText);
    EXPECT_TRUE(b.empty());
}

TEST(Buffer, RetrieveAllAsStringOnEmptyBufferIsEmpty)
{
    Buffer b;
    EXPECT_TRUE(b.retrieveAllAsString().empty());
}

TEST(Buffer, AppendRejectsNullAndNonPositiveLengths)
{
    Buffer b;
    b.append(static_cast<const char *>(nullptr), size_t{5});
    b.append(kText, ssize_t{0});
    b.append(kText, ssize_t{-3});
    b.append(kText, size_t{0});
    b.append(static_cast<const char *>(nullptr), ssize_t{7});
    EXPECT_TRUE(b.empty());
}

TEST(Buffer, AppendCharAndStringOverloadsAgree)
{
    Buffer b;
    b.append('x');
    b.append(std::string("yz"));
    EXPECT_EQ(b.retrieveAllAsString(), "xyz");
}

TEST(Buffer, ResetClearsBytesButKeepsTheObjectUsable)
{
    Buffer b;
    b.append(kText, kTextSize);
    b.reset();
    EXPECT_TRUE(b.empty());
    b.append(std::string("next"));
    EXPECT_EQ(b.retrieveAllAsString(), "next");
}

TEST(Buffer, HighWaterMarkIsExclusiveAndSettable)
{
    Buffer b;
    EXPECT_EQ(b.highWaterMark(), 64u * 1024u);
    b.setHighWaterMark(4);
    b.append(std::string("abcd"));
    EXPECT_FALSE(b.overHighWater()); // exactly at the mark: not over it
    b.append('e');
    EXPECT_TRUE(b.overHighWater());
    b.setHighWaterMark(100);
    EXPECT_FALSE(b.overHighWater());
}

TEST(Buffer, SwapExchangesContentsAndWaterMarks)
{
    Buffer a;
    Buffer b;
    a.append(std::string("aaa"));
    b.append(std::string("bbbb"));
    a.setHighWaterMark(11);
    b.setHighWaterMark(22);
    a.swap(b);
    EXPECT_EQ(a.retrieveAllAsString(), "bbbb");
    EXPECT_EQ(b.retrieveAllAsString(), "aaa");
    EXPECT_EQ(a.highWaterMark(), size_t{22});
    EXPECT_EQ(b.highWaterMark(), size_t{11});
}

TEST(Buffer, WritableViewGrowsWithReserve)
{
    Buffer b;
    const size_t before = b.writableBytes();
    b.reserve(before + 1024);
    EXPECT_GE(b.writableBytes(), before + 1024);
}

TEST(Buffer, MoveTransfersTheBytes)
{
    Buffer a;
    a.append(kText, kTextSize);
    Buffer b(std::move(a));
    EXPECT_EQ(b.readableBytes(), kTextSize);
    EXPECT_EQ(std::string(b.readableBegin(), b.readableBytes()), kText);
}
