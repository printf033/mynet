// ObjectPool：容量管理、耗尽处理、复用逻辑以及一并释放所有槽位的 reset()。
// 对象池分发具有稳定内存地址的对象，这是 epoll 与 io_uring 注册机制的核心依赖。
#include "objectPool.hpp"
#include <algorithm>
#include <cstdio>
#include <gtest/gtest.h>
#include <set>
#include <thread>
#include <vector>

using namespace mynet;

namespace
{
    struct Tracked
    {
        static inline int live = 0;
        int resets = 0;

        Tracked() { ++live; }
        ~Tracked() { --live; }
        void reset() noexcept { ++resets; }
    };
} // namespace

TEST(ObjectPool, StartsAtZeroCapacity)
{
    ObjectPool<Tracked> pool;
    EXPECT_EQ(pool.capacity(), size_t{0});
    EXPECT_EQ(pool.available(), size_t{0});
    EXPECT_EQ(pool.acquire(), nullptr);
}

TEST(ObjectPool, InitCreatesCapacityObjects)
{
    ObjectPool<Tracked> pool;
    ASSERT_TRUE(pool.init(4));
    EXPECT_EQ(pool.capacity(), size_t{4});
    EXPECT_EQ(pool.available(), size_t{4});
}

TEST(ObjectPool, AcquireConsumesAvailabilityAndExhaustsToNull)
{
    ObjectPool<Tracked> pool;
    ASSERT_TRUE(pool.init(2));
    EXPECT_NE(pool.acquire(), nullptr);
    EXPECT_EQ(pool.available(), size_t{1});
    EXPECT_NE(pool.acquire(), nullptr);
    EXPECT_EQ(pool.available(), size_t{0});
    EXPECT_EQ(pool.acquire(), nullptr); // 空对象池返回 nullptr，绝不抛出异常
}

TEST(ObjectPool, AcquireHandsOutDistinctSlots)
{
    ObjectPool<Tracked> pool;
    ASSERT_TRUE(pool.init(8));
    std::set<Tracked *> seen;
    for (int i = 0; i < 8; ++i)
    {
        Tracked *object = pool.acquire();
        ASSERT_NE(object, nullptr);
        EXPECT_TRUE(seen.insert(object).second);
    }
    EXPECT_EQ(seen.size(), size_t{8});
}

TEST(ObjectPool, ReleaseMakesTheSameSlotAvailableAgain)
{
    ObjectPool<Tracked> pool;
    ASSERT_TRUE(pool.init(1));
    Tracked *first = pool.acquire();
    ASSERT_NE(first, nullptr);
    EXPECT_EQ(pool.acquire(), nullptr);
    pool.release(first);
    EXPECT_EQ(pool.available(), size_t{1});
    EXPECT_EQ(pool.acquire(), first); // 对象内存地址保持不变
}

TEST(ObjectPool, ResetDropsEverySlotIncludingLiveOnes)
{
    const int before = Tracked::live;
    ObjectPool<Tracked> pool;
    ASSERT_TRUE(pool.init(3));
    EXPECT_EQ(Tracked::live, before + 3);
    EXPECT_NE(pool.acquire(), nullptr); // 在途借出的槽位不得跨 reset() 存活
    pool.reset();
    EXPECT_EQ(Tracked::live, before); // 全部对象均被正确销毁
    EXPECT_EQ(pool.capacity(), size_t{0});
    EXPECT_EQ(pool.available(), size_t{0});
    EXPECT_EQ(pool.acquire(), nullptr);
}

TEST(ObjectPool, ReleaseOfNullIsIgnored)
{
    ObjectPool<Tracked> pool;
    ASSERT_TRUE(pool.init(1));
    EXPECT_FALSE(pool.release(nullptr));
    EXPECT_EQ(pool.available(), size_t{1});
}

TEST(ObjectPool, DoubleReleaseIsSafelyRejectedWithoutCorruptingPool)
{
    ObjectPool<Tracked> pool;
    ASSERT_TRUE(pool.init(2));

    Tracked *a = pool.acquire();
    Tracked *b = pool.acquire();
    ASSERT_NE(a, nullptr);
    ASSERT_NE(b, nullptr);
    EXPECT_EQ(pool.available(), size_t{0});

    // 首次释放成功
    EXPECT_TRUE(pool.release(a));
    EXPECT_EQ(pool.available(), size_t{1});

    // 缺陷验证：同一指针二次释放必须失败，且不得虚增 available_ 可用计数
    EXPECT_FALSE(pool.release(a));
    EXPECT_EQ(pool.available(), size_t{1});
    EXPECT_LE(pool.available(), pool.capacity());

    // 释放对象 b
    EXPECT_TRUE(pool.release(b));
    EXPECT_EQ(pool.available(), size_t{2});
    EXPECT_FALSE(pool.release(b)); // b 二次释放必然失败
    EXPECT_EQ(pool.available(), size_t{2});
    EXPECT_LE(pool.available(), pool.capacity());

    // 后续获取返回不同的有效对象
    Tracked *r1 = pool.acquire();
    Tracked *r2 = pool.acquire();
    EXPECT_NE(r1, nullptr);
    EXPECT_NE(r2, nullptr);
    EXPECT_NE(r1, r2);
    EXPECT_EQ(pool.acquire(), nullptr);
}

TEST(ObjectPool, ForeignPointerReleaseIsRejectedWithoutLeak)
{
    ObjectPool<Tracked> pool;
    ASSERT_TRUE(pool.init(2));

    auto *foreign = new Tracked();
    EXPECT_FALSE(pool.release(foreign)); // 外部指针拒绝释放回池
    EXPECT_EQ(pool.available(), size_t{2});
    delete foreign; // 由调用方安全管理，绝不泄漏至对象池
}

TEST(ObjectPool, MisalignedPointerReleaseIsRejected)
{
    ObjectPool<Tracked> pool;
    ASSERT_TRUE(pool.init(2));
    Tracked *a = pool.acquire();
    ASSERT_NE(a, nullptr);

    // 偏移非对齐的池内非法指针
    auto *misaligned = reinterpret_cast<Tracked *>(reinterpret_cast<char *>(a) + 1);
    EXPECT_FALSE(pool.release(misaligned));
    EXPECT_EQ(pool.available(), size_t{1});

    EXPECT_TRUE(pool.release(a));
    EXPECT_EQ(pool.available(), size_t{2});
}

TEST(ObjectPool, ReinitReplacesTheWholeSet)
{
    const int before = Tracked::live;
    ObjectPool<Tracked> pool;
    ASSERT_TRUE(pool.init(2));
    [[maybe_unused]] Tracked *old = pool.acquire();
    ASSERT_TRUE(pool.init(5)); // init() 语义为“重新调整容量至指定大小”，而非“追加”
    EXPECT_EQ(Tracked::live, before + 5);
    EXPECT_EQ(pool.capacity(), size_t{5});
    EXPECT_EQ(pool.available(), size_t{5});
    // 此处 old 变为悬垂指针是符合预期的：init() 释放了旧对象集，
    // 因此调用端必须确保在无存活流时才执行重新初始化。
}

TEST(ObjectPool, InitZeroIsAnEmptyPool)
{
    ObjectPool<Tracked> pool;
    ASSERT_TRUE(pool.init(0));
    EXPECT_EQ(pool.capacity(), size_t{0});
    EXPECT_EQ(pool.acquire(), nullptr);
}

TEST(ObjectPool, ReleasedSlotsAreReusedBeforeFreshOnes)
{
    ObjectPool<Tracked> pool;
    ASSERT_TRUE(pool.init(3));
    Tracked *a = pool.acquire();
    Tracked *b = pool.acquire();
    Tracked *c = pool.acquire();
    ASSERT_NE(a, nullptr);
    ASSERT_NE(b, nullptr);
    ASSERT_NE(c, nullptr);
    pool.release(b);
    pool.release(a);
    Tracked *first = pool.acquire();
    Tracked *second = pool.acquire();
    EXPECT_TRUE(first == a || first == b);
    EXPECT_TRUE(second == a || second == b);
    EXPECT_NE(first, second);
}

#ifdef MYNET_DEBUG
namespace
{
    // 供死亡测试使用的跨线程借用：线程创建与 join 必须整体发生在被 fork 的
    // 死亡语句内部（gtest fast 风格只复制调用线程，外部创建的线程在子进程中不存在）。
    void crossThreadAcquire(ObjectPool<Tracked> &pool)
    {
        std::thread cross([&pool] { [[maybe_unused]] auto _ = pool.acquire(); });
        cross.join();
    }
} // namespace

TEST(ObjectPoolDeath, CrossThreadUseAborts)
{
    // D4：Debug 构建下，非 init 线程借用/归还应确定性中止（非静默 UB）。
    ObjectPool<Tracked> pool;
    std::thread binder([&pool] { [[maybe_unused]] auto _ = pool.init(4); });
    binder.join();
    EXPECT_DEATH(crossThreadAcquire(pool), "ObjectPool used across threads");
}
#endif
