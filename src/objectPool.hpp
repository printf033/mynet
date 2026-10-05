#pragma once

#include "myconcepts.hpp"
#include <memory>
#include <vector>

// Fixed capacity pool of long-lived objects.
//
// Objects are held behind unique_ptr on purpose: an epoll registration stores
// a pointer to the pooled object, so its address must never move. A plain
// std::vector<Object> would invalidate every outstanding pointer the moment
// the pool grows.
template <mustResettable Object>
class ObjectPool
{
    std::vector<std::unique_ptr<Object>> pool_;
    std::vector<Object *> available_;

public:
    ObjectPool() noexcept = default;
    ~ObjectPool() noexcept { reset(); }
    ObjectPool(const ObjectPool &) = delete("the pool hands out stable slots; a copy would orphan every outstanding pointer");
    ObjectPool &operator=(const ObjectPool &) = delete("the pool hands out stable slots; a copy would orphan every outstanding pointer");
    ObjectPool(ObjectPool &&) noexcept = delete("the pool hands out stable slots; moving would orphan every outstanding pointer");
    ObjectPool &operator=(ObjectPool &&) noexcept = delete("the pool hands out stable slots; moving would orphan every outstanding pointer");
    inline void init(size_t capacity)
    {
        reset();
        pool_.reserve(capacity);
        available_.reserve(capacity);
        for (size_t i = 0; i < capacity; ++i)
        {
            pool_.push_back(std::make_unique<Object>());
            available_.push_back(pool_.back().get());
        }
    }
    inline void reset() noexcept
    {
        available_.clear();
        pool_.clear();
    }
    inline Object *acquire() noexcept
    {
        if (available_.empty())
            return nullptr;
        Object *object = available_.back();
        available_.pop_back();
        return object;
    }
    inline void release(Object *object) noexcept
    {
        if (object == nullptr)
            return;
        object->reset();
        available_.push_back(object);
    }
    inline size_t capacity() const noexcept { return pool_.size(); }
    inline size_t available() const noexcept { return available_.size(); }
};
