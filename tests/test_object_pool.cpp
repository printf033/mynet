// ObjectPool: capacity, exhaustion, reuse and the reset() that drops every
// slot at once. The pool hands out addresses held stable behind unique_ptr,
// which is the property an epoll registration depends on.
#include "objectPool.hpp"
#include <algorithm>
#include <gtest/gtest.h>
#include <set>
#include <vector>

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
    pool.init(4);
    EXPECT_EQ(pool.capacity(), size_t{4});
    EXPECT_EQ(pool.available(), size_t{4});
}

TEST(ObjectPool, AcquireConsumesAvailabilityAndExhaustsToNull)
{
    ObjectPool<Tracked> pool;
    pool.init(2);
    EXPECT_NE(pool.acquire(), nullptr);
    EXPECT_EQ(pool.available(), size_t{1});
    EXPECT_NE(pool.acquire(), nullptr);
    EXPECT_EQ(pool.available(), size_t{0});
    EXPECT_EQ(pool.acquire(), nullptr); // an empty pool is a nullptr, not a throw
}

TEST(ObjectPool, AcquireHandsOutDistinctSlots)
{
    ObjectPool<Tracked> pool;
    pool.init(8);
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
    pool.init(1);
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
    pool.init(3);
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
    pool.init(1);
    pool.release(nullptr);
    EXPECT_EQ(pool.available(), size_t{1});
}

TEST(ObjectPool, ReinitReplacesTheWholeSet)
{
    const int before = Tracked::live;
    ObjectPool<Tracked> pool;
    pool.init(2);
    Tracked *old = pool.acquire();
    pool.init(5); // init() is defined as "make room for this many", not "add"
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
    pool.init(0);
    EXPECT_EQ(pool.capacity(), size_t{0});
    EXPECT_EQ(pool.acquire(), nullptr);
}

TEST(ObjectPool, ReleasedSlotsAreReusedBeforeFreshOnes)
{
    ObjectPool<Tracked> pool;
    pool.init(3);
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
