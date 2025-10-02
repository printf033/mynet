#ifndef SYNCQUEUE_NONBLOCKING_HPP
#define SYNCQUEUE_NONBLOCKING_HPP

#include <queue>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <chrono>

template <typename E>
class SyncQueue_nonblocking
{
    std::queue<E> queue_;
    mutable std::shared_mutex mtx_;
    std::atomic<bool> is_running_{true};
    size_t capacity_;

    inline bool isFull() const { return queue_.size() >= capacity_; }
    inline bool isEmpty() const { return queue_.empty(); }

public:
    SyncQueue_nonblocking(size_t capacity = 10000)
        : capacity_(capacity) {}
    ~SyncQueue_nonblocking()
    {
        is_running_.store(false, std::memory_order_release);
        while (!empty())
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    SyncQueue_nonblocking(const SyncQueue_nonblocking &) = delete;
    SyncQueue_nonblocking &operator=(const SyncQueue_nonblocking &) = delete;
    SyncQueue_nonblocking(SyncQueue_nonblocking &&) = delete;
    SyncQueue_nonblocking &operator=(SyncQueue_nonblocking &&) = delete;
    // 0 success
    // -1 queue is full
    // -2 queue stopped
    template <typename T>
    int put(T &&element)
    {
        std::unique_lock<std::shared_mutex> locker(mtx_);
        if (!is_running_.load(std::memory_order_acquire))
            return -2;
        if (isFull())
            return -1;
        queue_.push(std::forward<T>(element));
        return 0;
    }
    // 0 success
    // -1 queue is empty
    int take(E &element) // 必须通过引用传递方式获取element，防止返回值传递方式超越locker生命周期引起的数据竞争（move或RVO）
    {
        std::unique_lock<std::shared_mutex> locker(mtx_);
        if (isEmpty())
            return -1;
        element = std::move(queue_.front());
        queue_.pop();
        return 0;
    }
    // 0 success
    // -1 queue is empty
    int take_all(std::queue<E> &queue)
    {
        std::unique_lock<std::shared_mutex> locker(mtx_);
        if (isEmpty())
            return -1;
        queue = std::move(queue_);
        return 0;
    }
    inline bool empty() const
    {
        std::shared_lock<std::shared_mutex> locker(mtx_);
        return queue_.empty();
    }
    inline bool full() const
    {
        std::shared_lock<std::shared_mutex> locker(mtx_);
        return queue_.size() >= capacity_;
    }
    inline size_t size() const
    {
        std::shared_lock<std::shared_mutex> locker(mtx_);
        return queue_.size();
    }
};

#endif
