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

    // 超时时间之前：不应触发
    EXPECT_EQ(q.handleExpired(now + 50ms), 0u);
    EXPECT_FALSE(fired);
    EXPECT_EQ(q.size(), 1u);

    // 达到超时时间：触发并执行回调
    EXPECT_EQ(q.handleExpired(now + 150ms), 1u);
    EXPECT_TRUE(fired);

    // 缺陷验证：单次定时器在触发后被彻底从 timers_ 集合中清除
    EXPECT_EQ(q.size(), 0u);
    EXPECT_EQ(q.nextExpire(), TimerQueue::Time::max());

    // 对已过期的单次定时器调用 cancelTimer 必须返回 TIMER_NOT_FOUND
    EXPECT_EQ(q.cancelTimer(id).error(), ERR::TIMER_NOT_FOUND);
}

TEST(TimerQueue, DoubleCancelReturnsNotFoundError)
{
    TimerQueue q;
    const auto now = TimerQueue::Clock::now();
    bool fired = false;

    const uint64_t id = q.addTimer(now + 200ms, [&fired] { fired = true; });
    EXPECT_EQ(q.size(), 1u);

    // 首次取消成功
    EXPECT_TRUE(q.cancelTimer(id).has_value());
    // 优化验证：size() 立即准确反映当前活跃定时器数量
    EXPECT_EQ(q.size(), 0u);

    // 缺陷验证：二次取消返回 TIMER_NOT_FOUND
    EXPECT_EQ(q.cancelTimer(id).error(), ERR::TIMER_NOT_FOUND);

    // 经过超时时间后，已取消的定时器绝不执行
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

    // 第一次触发
    EXPECT_EQ(q.handleExpired(now + 55ms), 1u);
    EXPECT_EQ(count, 1);
    EXPECT_EQ(q.size(), 1u);
    EXPECT_GE(q.nextExpire(), now + 100ms);

    // 第二次触发
    EXPECT_EQ(q.handleExpired(now + 105ms), 1u);
    EXPECT_EQ(count, 2);
    EXPECT_EQ(q.size(), 1u);

    // 取消周期定时器
    EXPECT_TRUE(q.cancelTimer(id).has_value());
    EXPECT_EQ(q.size(), 0u);

    // 第三次触发：已取消，不再执行
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

    // 首次触发时在回调内自我取消
    EXPECT_EQ(q.handleExpired(now + 60ms), 1u);
    EXPECT_EQ(count, 1);
    EXPECT_EQ(q.size(), 0u);

    // 第二次触发不应执行
    EXPECT_EQ(q.handleExpired(now + 200ms), 0u);
    EXPECT_EQ(count, 1);
    EXPECT_EQ(q.cancelTimer(id).error(), ERR::TIMER_NOT_FOUND);
}

TEST(TimerQueue, HeapOrderingAndDropDeadTop)
{
    TimerQueue q;
    const auto now = TimerQueue::Clock::now();

    std::vector<int> executionOrder;

    // 以乱序的截止时间添加定时器：t3 (300ms), t1 (100ms), t2 (200ms)
    q.addTimer(now + 300ms, [&] { executionOrder.push_back(3); });
    uint64_t id1 = q.addTimer(now + 100ms, [&] { executionOrder.push_back(1); });
    q.addTimer(now + 200ms, [&] { executionOrder.push_back(2); });

    EXPECT_EQ(q.size(), 3u);
    EXPECT_EQ(q.nextExpire(), now + 100ms);

    // 取消位于最小堆堆顶的 t1
    EXPECT_TRUE(q.cancelTimer(id1).has_value());
    EXPECT_EQ(q.size(), 2u);

    // nextExpire() 自动丢弃堆顶无效的 t1，并返回 t2 的时间 (now + 200ms)
    EXPECT_EQ(q.nextExpire(), now + 200ms);

    // 在 250ms 时触发 -> 仅 t2 执行
    EXPECT_EQ(q.handleExpired(now + 250ms), 1u);
    ASSERT_EQ(executionOrder.size(), 1u);
    EXPECT_EQ(executionOrder[0], 2);
    EXPECT_EQ(q.size(), 1u);
    EXPECT_EQ(q.nextExpire(), now + 300ms);

    // 在 350ms 时触发 -> t3 执行
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

                // 取消其中一半定时器
                for (size_t i = 0; i < ids.size(); i += 2)
                {
                    [[maybe_unused]] auto _ = q.cancelTimer(ids[i]);
                }
            });
    }

    for (auto &w : workers)
    {
        w.join();
    }

    // 4 线程 * 200 个定时器 = 800 个，取消一半 = 400 个存活
    EXPECT_EQ(q.size(), 400u);

    // 触发所有剩余定时器
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
            // 不变量校验：在回调执行期间，周期定时器必须
            // 已经以重新调度的截止时间驻留在堆中，而不是处于悬空游离态！
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

    // 添加一个单次定时器和一个周期定时器，均在 now + 50ms 到期
    q.addTimer(now + 50ms, [&] { singleFired = true; });
    uint64_t repeatId = q.addTimer(now + 50ms, [&] { ++repeatCount; }, 100ms);

    EXPECT_EQ(q.size(), 2u);

    // 两者在同一个批次中到期
    size_t fired = q.handleExpired(now + 60ms);
    EXPECT_EQ(fired, 2u);
    EXPECT_TRUE(singleFired);
    EXPECT_EQ(repeatCount, 1);

    // 关键不变量：nextExpire() 必须准确反映重新调度的周期定时器 (now + 150ms)，
    // 绝不能误报 Time::max()（否则会导致 epoll_wait 以 -1 超时陷入永久阻塞）
    EXPECT_EQ(q.size(), 1u);
    EXPECT_NE(q.nextExpire(), TimerQueue::Time::max());
    EXPECT_GE(q.nextExpire(), now + 150ms);

    // 清理资源
    EXPECT_TRUE(q.cancelTimer(repeatId).has_value());
    EXPECT_EQ(q.size(), 0u);
    EXPECT_EQ(q.nextExpire(), TimerQueue::Time::max());
}
