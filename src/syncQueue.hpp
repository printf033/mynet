#ifndef SYNCQUEUE_HPP
#define SYNCQUEUE_HPP

#include <queue>
#include <shared_mutex>
#include <shared_mutex>
#include <condition_variable>
#include <atomic>
#include <chrono>

template <typename E>
class SyncQueue
{
    std::queue<E> queue_;
    mutable std::shared_mutex mtx_;
    std::condition_variable_any cv_que_empty_;
    std::condition_variable_any cv_que_full_;
    std::atomic<bool> is_running_{true};
    size_t capacity_;
    std::chrono::milliseconds maxtime_to_put_;
    std::chrono::milliseconds maxtime_to_take_;

    inline bool isFull() const { return queue_.size() >= capacity_; }
    inline bool isEmpty() const { return queue_.empty(); }

public:
    SyncQueue(size_t capacity = 10000,
              std::chrono::milliseconds maxtime_to_put = 10,
              std::chrono::milliseconds maxtime_to_take = 100)
        : capacity_(capacity),
          maxtime_to_put_(maxtime_to_put),
          maxtime_to_take_(maxtime_to_take) {}
    ~SyncQueue()
    {
        is_running_.store(false, std::memory_order_release);
        cv_que_full_.notify_all();
        while (!empty())
        {
            cv_que_empty_.notify_all();
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    SyncQueue(const SyncQueue &) = delete;
    SyncQueue &operator=(const SyncQueue &) = delete;
    SyncQueue(SyncQueue &&) = delete;
    SyncQueue &operator=(SyncQueue &&) = delete;
    // 0 success
    // -1 timeout
    // -2 queue stopped
    template <typename T>
    int put(T &&element)
    {
        std::unique_lock<std::shared_mutex> locker(mtx_);
        bool is_running = true;
        while ((is_running = is_running_.load(std::memory_order_acquire)) && isFull())
            if (std::cv_status::timeout ==
                cv_que_full_.wait_for(locker, maxtime_to_put_))
                return -1;
        if (!is_running)
            return -2;
        queue_.push(std::forward<T>(element));
        cv_que_empty_.notify_one();
        return 0;
    }
    // 0 success
    // -1 timeout
    int take(E &element) // 必须通过引用传递方式获取element，防止返回值传递方式超越locker生命周期引起的数据竞争（move或RVO）
    {
        std::unique_lock<std::shared_mutex> locker(mtx_);
        while (isEmpty())
            if (std::cv_status::timeout ==
                cv_que_empty_.wait_for(locker, maxtime_to_take_))
                return -1;
        element = std::move(queue_.front());
        queue_.pop();
        cv_que_full_.notify_one();
        return 0;
    }
    // 0 success
    // -1 timeout
    int take_all(std::queue<E> &queue)
    {
        std::unique_lock<std::shared_mutex> locker(mtx_);
        while (isEmpty())
            if (std::cv_status::timeout ==
                cv_que_empty_.wait_for(locker, maxtime_to_take_))
                return -1;
        queue = std::move(queue_);
        cv_que_full_.notify_all();
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
