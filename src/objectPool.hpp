#pragma once

#include "myconcepts.hpp"

template <mustResettable Object>
class ObjectPool
{
    std::vector<Object> pool_;
    std::vector<Object *> available_;

public:
    ObjectPool() noexcept = default;
    ~ObjectPool() noexcept { reset(); }
    ObjectPool(const ObjectPool &) = delete;
    ObjectPool &operator=(const ObjectPool &) = delete;
    ObjectPool(ObjectPool &&) noexcept = delete;
    ObjectPool &operator=(ObjectPool &&) noexcept = delete;
    inline void init(size_t capacity)
    {
        pool_.resize(capacity);
        available_.reserve(capacity);
        for (auto &object : pool_)
            available_.push_back(&object);
    }
    inline void reset() noexcept
    {
        for (auto &object : pool_)
            object.reset();
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
};
