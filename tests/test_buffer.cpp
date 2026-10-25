// Buffer：读游标推进、惰性紧凑整理、触发连接背压的水位线，
// 以及供 recv 系系统调用原地直写的连续可写窗口。
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
    EXPECT_EQ(b.writableBytes(), size_t{0});         // 初始无底层存储：无可写空间
    EXPECT_EQ(b.readableBegin(), b.readableBegin()); // 指向空缓冲区的安全指针
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
    EXPECT_TRUE(b.append("0123456789", 10)); // 整数字面量：无重载二义性
    EXPECT_TRUE(b.append(kText, 1u));        // 无符号整数：无重载二义性
    EXPECT_TRUE(b.append("tail"));           // const char[] 字符数组：明确匹配 string_view
    const std::string str = "!";
    EXPECT_TRUE(b.append(str)); // std::string 自动转为 string_view
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
    // 紧凑整理分支要求已被消费的前缀至少达 4096 字节且占底层存储的一半以上。
    // 无论是否触发整理，可观测的契约均保证存活的尾部数据即为未被消费的数据。
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
    EXPECT_FALSE(b.overHighWater()); // 恰好在水位线上：不算超出
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
    // 精确填满底层存储（首次扩容为精确分配），消费部分前缀，
    // 随后请求只有在就地回收已消费前缀后才放得下的写入窗口：
    // 窗口大小与可读字节数相加必须严格等于原容量，证明未发生重新分配。
    Buffer b;
    const std::string chunk(4 << 10, 'a');
    ASSERT_TRUE(b.append(chunk));
    ASSERT_EQ(b.writableBytes(), size_t{0}); // 首次精确分配
    b.retrieve(2 << 10);
    ASSERT_TRUE(b.ensureWritable(2 << 10));
    EXPECT_EQ(b.readableBytes(), size_t{2 << 10});
    EXPECT_EQ(b.writableBytes() + b.readableBytes(), size_t{4 << 10}); // 原地就地复用同一内存块
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
    EXPECT_EQ(b.writableBytes() + b.readableBytes(), size_t{16}); // 可写窗口恰好扣减了提交的字节数
}

TEST(Buffer, AppendFailureKeepsTheBufferIntact)
{
    // 超出系统限制的 nothrow 分配失败时不得污染缓冲区；
    // 错误路径必须保持已有字节可读且对象依然可用。
    Buffer b;
    ASSERT_TRUE(b.append("keep me"));
    EXPECT_FALSE(b.ensureWritable(~size_t{0})); // 请求 SIZE_MAX 容量必然失败
    EXPECT_EQ(b.readableView(), "keep me");
    const std::string huge(1 << 10, 'x');
    EXPECT_TRUE(b.append(huge)); // 之后缓冲区仍可正常工作
    EXPECT_EQ(b.readableBytes(), size_t{7} + huge.size());
}

TEST(Buffer, MoveConstructorPreservesInvariantsAndAvoidsUnderflow)
{
    Buffer a;
    ASSERT_TRUE(a.append("0123456789", 10));
    a.retrieve(4); // 此时 readIndex_ = 4，readableBytes() = 6
    EXPECT_EQ(a.readableBytes(), size_t{6});

    Buffer b(std::move(a));

    // 校验被移动源对象状态（必须清零，不能下溢为 SIZE_MAX - 3）
    EXPECT_TRUE(a.empty());
    EXPECT_EQ(a.readableBytes(), size_t{0});
    EXPECT_EQ(a.readableView(), "");

    // 校验移动目标对象状态
    EXPECT_FALSE(b.empty());
    EXPECT_EQ(b.readableBytes(), size_t{6});
    EXPECT_EQ(b.readableView(), "456789");

    // 源对象依然完全可用
    ASSERT_TRUE(a.append("fresh"));
    EXPECT_EQ(a.readableBytes(), size_t{5});
    EXPECT_EQ(a.readableView(), "fresh");
}

TEST(Buffer, MoveAssignmentPreservesInvariantsAndAvoidsUnderflow)
{
    Buffer a;
    ASSERT_TRUE(a.append("abcdefgh", 8));
    a.retrieve(3); // 此时 readIndex_ = 3，readableBytes() = 5
    EXPECT_EQ(a.readableBytes(), size_t{5});

    Buffer b;
    ASSERT_TRUE(b.append("existing", 8));
    b = std::move(a);

    // 校验被移动源对象状态
    EXPECT_TRUE(a.empty());
    EXPECT_EQ(a.readableBytes(), size_t{0});
    EXPECT_EQ(a.readableView(), "");

    // 校验移动目标对象状态
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
