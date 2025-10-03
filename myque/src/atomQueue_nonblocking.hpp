#ifndef MYQUE_SRC_ATOMQUEUE_NONBLOCKING_HPP
#define MYQUE_SRC_ATOMQUEUE_NONBLOCKING_HPP

#include <atomic>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <new>
#include <utility>

template <typename E>
class AtomQueue_nonblocking
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

public:
    // !!! capacity must be power of two !!!
    explicit AtomQueue_nonblocking(size_t capacity = 1024)
        : capacity_(capacity), mask_(capacity - 1)
    {
        assert(capacity >= 2 && (capacity & (capacity - 1)) == 0 && "capacity must be power of two");
        queue_ = reinterpret_cast<Slot *>(operator new[](sizeof(Slot) * capacity_));
        for (size_t i = 0; i < capacity_; ++i)
        {
            new (&queue_[i]) Slot();
            queue_[i].sequence.store(i, std::memory_order_relaxed);
        }
    }
    ~AtomQueue_nonblocking()
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
    AtomQueue_nonblocking(const AtomQueue_nonblocking &) = delete;
    AtomQueue_nonblocking &operator=(const AtomQueue_nonblocking &) = delete;
    AtomQueue_nonblocking(AtomQueue_nonblocking &&) = delete;
    AtomQueue_nonblocking &operator=(AtomQueue_nonblocking &&) = delete;
    // 0 success
    // -1 queue is full or not ready
    template <typename T>
    int put(T &&element)
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
    int take(E &element)
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
};

#endif