#ifndef ATOMQUEUE_HPP
#define ATOMQUEUE_HPP

#include <atomic>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <new>
#include <utility>
#include <thread>

template <typename E>
class AtomQueue
{
    struct Slot
    {
        std::atomic<size_t> sequence;
        alignas(E) unsigned char element[sizeof(E)];
        Slot() = default;
        ~Slot() = default;
    } *queue_ = nullptr;
    const size_t capacity_;
    const size_t mask_;
    std::atomic<size_t> head_ = 0;
    std::atomic<size_t> tail_ = 0;
    int maxtime_to_put_;
    int maxtime_to_take_;

    // 0 success
    // -1 queue is full or not ready
    template <typename T>
    int put_(T &&element)
    {
        Slot *slot;
        size_t tail = tail_.load(std::memory_order_relaxed);
        while (true)
        {
            slot = &queue_[tail & mask_];
            size_t sequence = slot->sequence.load(std::memory_order_acquire);
            intptr_t dif = (intptr_t)sequence - (intptr_t)tail;
            if (dif == 0)
            {
                if (tail_.compare_exchange_weak(tail, tail + 1, std::memory_order_relaxed))
                {
                    new (&slot->element) E(std::forward<T>(element));
                    slot->sequence.store(tail + 1, std::memory_order_release);
                    return 0;
                }
            }
            else if (dif < 0)
                return -1;
            else
                tail = tail_.load(std::memory_order_relaxed);
        }
    }
    // 0 success
    // -1 queue is empty or not ready
    int take_(E &element)
    {
        Slot *slot;
        size_t head = head_.load(std::memory_order_relaxed);
        while (true)
        {
            slot = &queue_[head & mask_];
            size_t sequence = slot->sequence.load(std::memory_order_acquire);
            intptr_t dif = (intptr_t)sequence - (intptr_t)(head + 1);
            if (dif == 0)
            {
                if (head_.compare_exchange_weak(head, head + 1, std::memory_order_relaxed))
                {
                    auto elem = reinterpret_cast<E *>(&slot->element);
                    element = std::move(*elem);
                    elem->~E();
                    slot->sequence.store(head + capacity_, std::memory_order_release);
                    return 0;
                }
            }
            else if (dif < 0)
                return -1;
            else
                head = head_.load(std::memory_order_relaxed);
        }
    }

public:
    // !!! capacity must be power of two !!!
    explicit AtomQueue(size_t capacity,
                       int maxtime_to_put = 10,
                       int maxtime_to_take = 100)
        : capacity_(capacity),
          mask_(capacity - 1),
          maxtime_to_put_(maxtime_to_put),
          maxtime_to_take_(maxtime_to_take)
    {
        assert(capacity >= 2 && (capacity & (capacity - 1)) == 0 && "capacity must be power of two");
        queue_ = reinterpret_cast<Slot *>(operator new[](sizeof(Slot) * capacity_));
        for (size_t i = 0; i < capacity_; ++i)
        {
            new (&queue_[i]) Slot();
            queue_[i].sequence.store(i, std::memory_order_relaxed);
        }
    }
    ~AtomQueue()
    {
        size_t head = head_.load(std::memory_order_relaxed);
        size_t tail = tail_.load(std::memory_order_relaxed);
        while (head != tail)
        {
            auto &slot = queue_[head & mask_];
            reinterpret_cast<E *>(&slot.element)->~E();
            ++head;
        }
        for (size_t i = 0; i < capacity_; ++i)
            queue_[i].~Slot();
        operator delete[](queue_);
    }
    AtomQueue(const AtomQueue &) = delete;
    AtomQueue &operator=(const AtomQueue &) = delete;
    AtomQueue(AtomQueue &&) = delete;
    AtomQueue &operator=(AtomQueue &&) = delete;
    // 0 success
    // -1 timeout
    template <typename T>
    int put(T &&element)
    {
        using U = std::decay_t<T>;
        U tmp(std::forward<T>(element));
        int n = put_(tmp);
        if (0 == n)
            return 0;
        int times = maxtime_to_put_;
        while (times-- > 0 && n == -1)
        {
            n = put_(tmp);
            std::this_thread::yield();
        }
        return n;
    }
    // 0 success
    // -1 timeout
    int take(E &element)
    {
        int n = take_(element);
        if (0 == n)
            return 0;
        int times = maxtime_to_take_;
        while (times-- > 0 && n == -1)
        {
            n = take_(element);
            std::this_thread::yield();
        }
        return n;
    }
};

#endif