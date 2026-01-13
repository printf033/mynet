#pragma once

#include "myconcepts.hpp"
#include "transporter.hpp"
#include "handler.hpp"

template <mustDerivedFromTransporter Transporter, mustDerivedFromHandler Handler>
    requires mustResettable<Transporter> && mustResettable<Handler>
struct Event
{
    int type = 0;
    Handler *handler = nullptr;
    Transporter transporter{};

public:
    inline void reset() noexcept
    {
        type = 0;
        handler = nullptr;
        transporter.reset();
    }
};
