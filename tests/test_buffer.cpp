// Buffer: the read cursor, the lazy compaction behind it, the water mark
// that decides when a connection is told to stop reading, and the direct
// write window that recv-style callers can fill in place.
#include "buffer.hpp"
#include <gtest/gtest.h>
#include <string>

using namespace mynet;

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
    EXPECT_EQ(b.writableBytes(), size_t{0}); // no storage yet: nothing to write into
    EXPECT_EQ(b.readableBegin(), b.readableBegin()); // a valid pointer to nothing
}

TEST(Buffer, AppendThenReadBack)
{
    Buffer b;
    ASSERT_TRUE(b.append(kText, kTextSize));
    ASSERT_EQ(b.readableBytes(), kTextSize);
    EXPECT_FALSE(b.empty());
    EXPECT_EQ(std::string(b.readableBegin(), b.readableBytes()), kText);
}

TEST(Buffer, AppendRejectsNullAndZeroLength)
{
    Buffer b;
    EXPECT_TRUE(b.append(static_cast<const char *>(nullptr), size_t{5}));
    EXPECT_TRUE(b.append(kText, size_t{0}));
    EXPECT_TRUE(b.append(static_cast<const char *>(nullptr), size_t{0}));
    EXPECT_TRUE(b.empty());
}

TEST(Buffer, AppendNaturalTypesWithoutAmbiguity)
{
    Buffer b;
    EXPECT_TRUE(b.append("0123456789", 10)); // int literal: no ambiguity
    EXPECT_TRUE(b.append(kText, 1u));        // unsigned int: no ambiguity
    EXPECT_TRUE(b.append("tail"));           // const char[] literal: matches string_view unambiguously
    const std::string str = "!";
    EXPECT_TRUE(b.append(str)); // std::string converts to string_view
    EXPECT_EQ(b.readableView(), "0123456789ttail!");
    b.retrieveAll();
}

TEST(Buffer, AppendCharAndStringOverloadsAgree)
{
    Buffer b;
    EXPECT_TRUE(b.append('x'));
    EXPECT_TRUE(b.append("yz"));
    EXPECT_EQ(b.readableView(), "xyz");
    b.retrieveAll();
}

TEST(Buffer, RetrieveMovesTheCursorAndKeepsTheTail)
{
    Buffer b;
    ASSERT_TRUE(b.append(kText, kTextSize));
    b.retrieve(4);
    EXPECT_EQ(b.readableBytes(), kTextSize - 4);
    EXPECT_EQ(std::string(b.readableBegin(), b.readableBytes()), "quick brown fox");
}

TEST(Buffer, RetrieveBeyondReadableDropsEverything)
{
    Buffer b;
    ASSERT_TRUE(b.append(kText, kTextSize));
    b.retrieve(kTextSize + 100);
    EXPECT_TRUE(b.empty());
    EXPECT_EQ(b.readableBytes(), size_t{0});
}

TEST(Buffer, RetrieveExactlyReadableIsEmpty)
{
    Buffer b;
    ASSERT_TRUE(b.append(kText, kTextSize));
    b.retrieve(kTextSize);
    EXPECT_TRUE(b.empty());
}

TEST(Buffer, LongLivedBufferStillReadsItsTailAfterCompaction)
{
    // The compaction branch needs a dead prefix of at least 4096 bytes that is
    // at least half the backing store. The observable contract either way is
    // that the live tail is exactly what was not consumed.
    Buffer b;
    std::string chunk(4 << 10, 'a');
    ASSERT_TRUE(b.append(chunk));
    ASSERT_TRUE(b.append("tail"));
    ASSERT_EQ(b.readableBytes(), (4 << 10) + 4u);
    b.retrieve(4 << 10);
    EXPECT_EQ(b.readableBytes(), size_t{4});
    EXPECT_EQ(std::string(b.readableBegin(), b.readableBytes()), "tail");
    ASSERT_TRUE(b.append("more"));
    EXPECT_EQ(std::string(b.readableBegin(), b.readableBytes()), "tailmore");
}

TEST(Buffer, ReadableViewAndRetrieveAllConsumesTheBuffer)
{
    Buffer b;
    ASSERT_TRUE(b.append(kText, kTextSize));
    EXPECT_EQ(b.readableView(), kText);
    b.retrieveAll();
    EXPECT_TRUE(b.empty());
}

TEST(Buffer, ReadableViewOnEmptyBufferIsEmpty)
{
    Buffer b;
    EXPECT_TRUE(b.readableView().empty());
}

TEST(Buffer, ResetClearsBytesButKeepsTheObjectUsable)
{
    Buffer b;
    ASSERT_TRUE(b.append(kText, kTextSize));
    b.reset();
    EXPECT_TRUE(b.empty());
    ASSERT_TRUE(b.append("next"));
    EXPECT_EQ(b.readableView(), "next");
    b.retrieveAll();
}

TEST(Buffer, HighWaterMarkIsExclusiveAndSettable)
{
    Buffer b;
    EXPECT_EQ(b.highWaterMark(), 64 << 10);
    b.setHighWaterMark(4);
    ASSERT_TRUE(b.append("abcd"));
    EXPECT_FALSE(b.overHighWater()); // exactly at the mark: not over it
    ASSERT_TRUE(b.append('e'));
    EXPECT_TRUE(b.overHighWater());
    b.setHighWaterMark(100);
    EXPECT_FALSE(b.overHighWater());
}

TEST(Buffer, SwapExchangesContentsAndWaterMarks)
{
    Buffer a;
    Buffer b;
    ASSERT_TRUE(a.append("aaa"));
    ASSERT_TRUE(b.append("bbbb"));
    a.setHighWaterMark(11);
    b.setHighWaterMark(22);
    a.swap(b);
    EXPECT_EQ(a.readableView(), "bbbb");
    EXPECT_EQ(b.readableView(), "aaa");
    EXPECT_EQ(a.highWaterMark(), size_t{22});
    EXPECT_EQ(b.highWaterMark(), size_t{11});
}

TEST(Buffer, EnsureWritableCompactsTheConsumedPrefixInPlace)
{
    // Fill exactly the backing store (first growth is exact), consume a prefix,
    // then demand a window that only fits once the dead prefix is reclaimed
    // in place: window + readable must add back up to the original capacity,
    // proving no reallocation happened.
    Buffer b;
    const std::string chunk(4 << 10, 'a');
    ASSERT_TRUE(b.append(chunk));
    ASSERT_EQ(b.writableBytes(), size_t{0}); // exact first allocation
    b.retrieve(2 << 10);
    ASSERT_TRUE(b.ensureWritable(2 << 10));
    EXPECT_EQ(b.readableBytes(), size_t{2 << 10});
    EXPECT_EQ(b.writableBytes() + b.readableBytes(), size_t{4 << 10}); // in place, same block
    EXPECT_EQ(std::string(b.readableBegin(), b.readableBytes()), std::string(2 << 10, 'a'));
    ASSERT_TRUE(b.append("tail"));
    EXPECT_EQ(std::string(b.readableBegin() + (2 << 10), 4), "tail");
}

TEST(Buffer, DirectWriteWindowCommitRoundTrip)
{
    Buffer b;
    ASSERT_TRUE(b.ensureWritable(16));
    ASSERT_GE(b.writableBytes(), size_t{16});
    char *window = b.writableBegin();
    std::memcpy(window, "0123456789abcdef", 16);
    b.commitWritten(16);
    EXPECT_EQ(b.readableBytes(), size_t{16});
    EXPECT_EQ(b.readableView(), "0123456789abcdef");
    EXPECT_EQ(b.writableBytes() + b.readableBytes(), size_t{16}); // window shrank by exactly the commit
}

TEST(Buffer, AppendFailureKeepsTheBufferIntact)
{
    // A nothrow allocation beyond the sanitizer/OS ceiling must fail without
    // touching the buffer; the error path then has to leave prior bytes
    // readable and the object usable.
    Buffer b;
    ASSERT_TRUE(b.append("keep me"));
    EXPECT_FALSE(b.ensureWritable(~size_t{0})); // exact-need growth of SIZE_MAX cannot succeed
    EXPECT_EQ(b.readableView(), "keep me");
    const std::string huge(1 << 10, 'x');
    EXPECT_TRUE(b.append(huge)); // the buffer still works normally afterwards
    EXPECT_EQ(b.readableBytes(), size_t{7} + huge.size());
}

TEST(Buffer, MoveConstructorPreservesInvariantsAndAvoidsUnderflow)
{
    Buffer a;
    ASSERT_TRUE(a.append("0123456789", 10));
    a.retrieve(4); // readIndex_ = 4, readableBytes() = 6
    EXPECT_EQ(a.readableBytes(), size_t{6});

    Buffer b(std::move(a));

    // Verify moved-from object state (must be 0, not underflow to SIZE_MAX - 3)
    EXPECT_TRUE(a.empty());
    EXPECT_EQ(a.readableBytes(), size_t{0});
    EXPECT_EQ(a.readableView(), "");

    // Verify destination object state
    EXPECT_FALSE(b.empty());
    EXPECT_EQ(b.readableBytes(), size_t{6});
    EXPECT_EQ(b.readableView(), "456789");

    // Source object remains fully functional
    ASSERT_TRUE(a.append("fresh"));
    EXPECT_EQ(a.readableBytes(), size_t{5});
    EXPECT_EQ(a.readableView(), "fresh");
}

TEST(Buffer, MoveAssignmentPreservesInvariantsAndAvoidsUnderflow)
{
    Buffer a;
    ASSERT_TRUE(a.append("abcdefgh", 8));
    a.retrieve(3); // readIndex_ = 3, readableBytes() = 5
    EXPECT_EQ(a.readableBytes(), size_t{5});

    Buffer b;
    ASSERT_TRUE(b.append("existing", 8));
    b = std::move(a);

    // Verify moved-from object state
    EXPECT_TRUE(a.empty());
    EXPECT_EQ(a.readableBytes(), size_t{0});
    EXPECT_EQ(a.readableView(), "");

    // Verify destination object state
    EXPECT_FALSE(b.empty());
    EXPECT_EQ(b.readableBytes(), size_t{5});
    EXPECT_EQ(b.readableView(), "defgh");
}

TEST(Buffer, ViewsProvideZeroCopyAccess)
{
    Buffer b;
    ASSERT_TRUE(b.append("hello world"));
    EXPECT_EQ(b.readableView(), "hello world");
    const auto span = b.readableSpan();
    EXPECT_EQ(span.size(), 11u);
    EXPECT_EQ(span[0], 'h');
    EXPECT_EQ(span[10], 'd');
}
