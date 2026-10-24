// ObjectPool: capacity, exhaustion, reuse and the reset() that drops every
// slot at once. The pool hands out addresses held stable behind unique_ptr,
// which is the property an epoll registration depends on.
#include "objectPool.hpp"
#include <algorithm>
#include <cstdio>
#include <thread>
#include <gtest/gtest.h>
#include <set>
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
    EXPECT_EQ(pool.acquire(), nullptr); // an empty pool is a nullptr, not a throw
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
    EXPECT_EQ(pool.acquire(), first); // the address never moves
}

TEST(ObjectPool, ResetDropsEverySlotIncludingLiveOnes)
{
    const int before = Tracked::live;
    ObjectPool<Tracked> pool;
    ASSERT_TRUE(pool.init(3));
    EXPECT_EQ(Tracked::live, before + 3);
    EXPECT_NE(pool.acquire(), nullptr); // an outstanding slot must not survive reset()
    pool.reset();
    EXPECT_EQ(Tracked::live, before); // every object is destroyed
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

    // First release succeeds
    EXPECT_TRUE(pool.release(a));
    EXPECT_EQ(pool.available(), size_t{1});

    // Bug 1 verification: second release of same pointer MUST fail and MUST NOT inflate available_
    EXPECT_FALSE(pool.release(a));
    EXPECT_EQ(pool.available(), size_t{1});
    EXPECT_LE(pool.available(), pool.capacity());

    // Release b
    EXPECT_TRUE(pool.release(b));
    EXPECT_EQ(pool.available(), size_t{2});
    EXPECT_FALSE(pool.release(b)); // second release of b fails
    EXPECT_EQ(pool.available(), size_t{2});
    EXPECT_LE(pool.available(), pool.capacity());

    // Subsequent acquires return distinct valid objects
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
    EXPECT_FALSE(pool.release(foreign)); // Bug 2 verification: foreign pointer rejected
    EXPECT_EQ(pool.available(), size_t{2});
    delete foreign; // cleanly managed by caller, never leaked into pool
}

TEST(ObjectPool, MisalignedPointerReleaseIsRejected)
{
    ObjectPool<Tracked> pool;
    ASSERT_TRUE(pool.init(2));
    Tracked *a = pool.acquire();
    ASSERT_NE(a, nullptr);

    // Byte-offset pointer into the pool storage
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
    Tracked *old = pool.acquire();
    ASSERT_TRUE(pool.init(5)); // init() is defined as "make room for this many", not "add"
    EXPECT_EQ(Tracked::live, before + 5);
    EXPECT_EQ(pool.capacity(), size_t{5});
    EXPECT_EQ(pool.available(), size_t{5});
    // `old` is dangling here on purpose: init() freed the previous set, which
    // is exactly why the code that calls it only does so with no live stream.
    (void)old;
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
        std::thread cross([&pool] { (void)pool.acquire(); });
        cross.join();
    }
} // namespace

TEST(ObjectPoolDeath, CrossThreadUseAborts)
{
    // D4：Debug 构建下，非 init 线程借用/归还应确定性中止（非静默 UB）。
    ObjectPool<Tracked> pool;
    std::thread binder([&pool] { (void)pool.init(4); });
    binder.join();
    EXPECT_DEATH(crossThreadAcquire(pool), "ObjectPool used across threads");
}
#endif
