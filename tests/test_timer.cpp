#include "timer.hpp"
#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <thread>
#include <vector>

using namespace mynet;
using namespace std::chrono_literals;

TEST(TimerQueue, EmptyQueueState)
{
    TimerQueue q;
    EXPECT_EQ(q.size(), 0u);
    EXPECT_EQ(q.nextExpire(), TimerQueue::Time::max());
    EXPECT_EQ(q.handleExpired(TimerQueue::Clock::now()), 0u);
    EXPECT_EQ(q.cancelTimer(1).error(), ERR::TIMER_NOT_FOUND);
}

TEST(TimerQueue, SingleShotTimerExpiresAndCleansUp)
{
    TimerQueue q;
    const auto now = TimerQueue::Clock::now();
    bool fired = false;

    const uint64_t id = q.addTimer(now + 100ms, [&fired] { fired = true; });
    EXPECT_GT(id, 0u);
    EXPECT_EQ(q.size(), 1u);
    EXPECT_EQ(q.nextExpire(), now + 100ms);

    // Before deadline: should not expire
    EXPECT_EQ(q.handleExpired(now + 50ms), 0u);
    EXPECT_FALSE(fired);
    EXPECT_EQ(q.size(), 1u);

    // After deadline: expires and fires callback
    EXPECT_EQ(q.handleExpired(now + 150ms), 1u);
    EXPECT_TRUE(fired);

    // Bug 1 verification: single-shot timer is completely erased from timers_
    EXPECT_EQ(q.size(), 0u);
    EXPECT_EQ(q.nextExpire(), TimerQueue::Time::max());

    // Calling cancelTimer on an already-expired single-shot timer returns TIMER_NOT_FOUND
    EXPECT_EQ(q.cancelTimer(id).error(), ERR::TIMER_NOT_FOUND);
}

TEST(TimerQueue, DoubleCancelReturnsNotFoundError)
{
    TimerQueue q;
    const auto now = TimerQueue::Clock::now();
    bool fired = false;

    const uint64_t id = q.addTimer(now + 200ms, [&fired] { fired = true; });
    EXPECT_EQ(q.size(), 1u);

    // First cancel succeeds
    EXPECT_TRUE(q.cancelTimer(id).has_value());
    // Optimization 2 verification: size() reflects active timers immediately
    EXPECT_EQ(q.size(), 0u);

    // Bug 2 verification: second cancel returns TIMER_NOT_FOUND
    EXPECT_EQ(q.cancelTimer(id).error(), ERR::TIMER_NOT_FOUND);

    // When time passes, the cancelled timer never runs
    EXPECT_EQ(q.handleExpired(now + 300ms), 0u);
    EXPECT_FALSE(fired);
    EXPECT_EQ(q.size(), 0u);
}

TEST(TimerQueue, RepeatingTimerReschedulesUntilCancelled)
{
    TimerQueue q;
    const auto now = TimerQueue::Clock::now();
    int count = 0;

    const uint64_t id = q.addTimer(now + 50ms, [&count] { ++count; }, 50ms);
    EXPECT_EQ(q.size(), 1u);

    // First tick
    EXPECT_EQ(q.handleExpired(now + 55ms), 1u);
    EXPECT_EQ(count, 1);
    EXPECT_EQ(q.size(), 1u);
    EXPECT_GE(q.nextExpire(), now + 100ms);

    // Second tick
    EXPECT_EQ(q.handleExpired(now + 105ms), 1u);
    EXPECT_EQ(count, 2);
    EXPECT_EQ(q.size(), 1u);

    // Cancel repeating timer
    EXPECT_TRUE(q.cancelTimer(id).has_value());
    EXPECT_EQ(q.size(), 0u);

    // Third tick: should not run
    EXPECT_EQ(q.handleExpired(now + 200ms), 0u);
    EXPECT_EQ(count, 2);
    EXPECT_EQ(q.cancelTimer(id).error(), ERR::TIMER_NOT_FOUND);
}

TEST(TimerQueue, RepeatingTimerSelfCancelInsideCallback)
{
    TimerQueue q;
    const auto now = TimerQueue::Clock::now();
    int count = 0;
    uint64_t id = 0;

    id = q.addTimer(
        now + 50ms,
        [&]
        {
            ++count;
            EXPECT_TRUE(q.cancelTimer(id).has_value());
        },
        50ms);

    EXPECT_EQ(q.size(), 1u);

    // First trigger cancels itself
    EXPECT_EQ(q.handleExpired(now + 60ms), 1u);
    EXPECT_EQ(count, 1);
    EXPECT_EQ(q.size(), 0u);

    // Second trigger should not execute
    EXPECT_EQ(q.handleExpired(now + 200ms), 0u);
    EXPECT_EQ(count, 1);
    EXPECT_EQ(q.cancelTimer(id).error(), ERR::TIMER_NOT_FOUND);
}

TEST(TimerQueue, HeapOrderingAndDropDeadTop)
{
    TimerQueue q;
    const auto now = TimerQueue::Clock::now();

    std::vector<int> executionOrder;

    // Add timers in out-of-order deadlines: t3 (300ms), t1 (100ms), t2 (200ms)
    q.addTimer(now + 300ms, [&] { executionOrder.push_back(3); });
    uint64_t id1 = q.addTimer(now + 100ms, [&] { executionOrder.push_back(1); });
    q.addTimer(now + 200ms, [&] { executionOrder.push_back(2); });

    EXPECT_EQ(q.size(), 3u);
    EXPECT_EQ(q.nextExpire(), now + 100ms);

    // Cancel t1 (which sits at top of min-heap)
    EXPECT_TRUE(q.cancelTimer(id1).has_value());
    EXPECT_EQ(q.size(), 2u);

    // nextExpire() should automatically drop dead top t1 and return t2 (now + 200ms)
    EXPECT_EQ(q.nextExpire(), now + 200ms);

    // Fire at 250ms -> only t2 executes
    EXPECT_EQ(q.handleExpired(now + 250ms), 1u);
    ASSERT_EQ(executionOrder.size(), 1u);
    EXPECT_EQ(executionOrder[0], 2);
    EXPECT_EQ(q.size(), 1u);
    EXPECT_EQ(q.nextExpire(), now + 300ms);

    // Fire at 350ms -> t3 executes
    EXPECT_EQ(q.handleExpired(now + 350ms), 1u);
    ASSERT_EQ(executionOrder.size(), 2u);
    EXPECT_EQ(executionOrder[1], 3);
    EXPECT_EQ(q.size(), 0u);
    EXPECT_EQ(q.nextExpire(), TimerQueue::Time::max());
}

TEST(TimerQueue, ConcurrentAddCancelThreadSafety)
{
    TimerQueue q;
    const auto now = TimerQueue::Clock::now();
    std::atomic<int> executed{0};
    constexpr int kTimersPerThread = 200;

    std::vector<std::thread> workers;
    workers.reserve(4);

    for (int t = 0; t < 4; ++t)
    {
        workers.emplace_back(
            [&q, &executed, now, t]
            {
                std::vector<uint64_t> ids;
                ids.reserve(kTimersPerThread);
                for (int i = 0; i < kTimersPerThread; ++i)
                {
                    uint64_t id =
                        q.addTimer(now + 10ms + std::chrono::milliseconds(i + t), [&executed] { ++executed; });
                    ids.push_back(id);
                }

                // Cancel half of the timers
                for (size_t i = 0; i < ids.size(); i += 2)
                {
                    (void)q.cancelTimer(ids[i]);
                }
            });
    }

    for (auto &w : workers)
    {
        w.join();
    }

    // 4 threads * 200 timers = 800 added, half cancelled = 400 active
    EXPECT_EQ(q.size(), 400u);

    // Trigger all remaining timers
    size_t fired = q.handleExpired(now + 10s);
    EXPECT_EQ(fired, 400u);
    EXPECT_EQ(executed.load(), 400);
    EXPECT_EQ(q.size(), 0u);
}

TEST(TimerQueue, InvariantsHoldDuringRepeatingCallbackExecution)
{
    TimerQueue q;
    const auto now = TimerQueue::Clock::now();
    uint64_t id = 0;
    bool callbackRan = false;

    id = q.addTimer(
        now + 100ms,
        [&]
        {
            callbackRan = true;
            // Invariant check: during callback execution, the repeating timer must
            // ALREADY be in the heap with its rescheduled deadline, not in limbo!
            EXPECT_EQ(q.size(), 1u);
            EXPECT_NE(q.nextExpire(), TimerQueue::Time::max());
            EXPECT_GE(q.nextExpire(), now + 150ms);
        },
        50ms);

    EXPECT_EQ(q.handleExpired(now + 100ms), 1u);
    EXPECT_TRUE(callbackRan);
    EXPECT_EQ(q.size(), 1u);
    EXPECT_GE(q.nextExpire(), now + 150ms);

    EXPECT_TRUE(q.cancelTimer(id).has_value());
    EXPECT_EQ(q.size(), 0u);
}

TEST(TimerQueue, MixedBatchReschedulesRepeatingTimerWithoutStarvation)
{
    TimerQueue q;
    const auto now = TimerQueue::Clock::now();
    bool singleFired = false;
    int repeatCount = 0;

    // Add a single-shot timer and a repeating timer both expiring at now + 50ms
    q.addTimer(now + 50ms, [&] { singleFired = true; });
    uint64_t repeatId = q.addTimer(now + 50ms, [&] { ++repeatCount; }, 100ms);

    EXPECT_EQ(q.size(), 2u);

    // Both expire in the same batch
    size_t fired = q.handleExpired(now + 60ms);
    EXPECT_EQ(fired, 2u);
    EXPECT_TRUE(singleFired);
    EXPECT_EQ(repeatCount, 1);

    // Key invariant: nextExpire() must reflect the rescheduled repeating timer (now + 150ms)
    // and NEVER falsely report Time::max() (which would starve epoll_wait with timeout -1)
    EXPECT_EQ(q.size(), 1u);
    EXPECT_NE(q.nextExpire(), TimerQueue::Time::max());
    EXPECT_GE(q.nextExpire(), now + 150ms);

    // Clean up
    EXPECT_TRUE(q.cancelTimer(repeatId).has_value());
    EXPECT_EQ(q.size(), 0u);
    EXPECT_EQ(q.nextExpire(), TimerQueue::Time::max());
}
