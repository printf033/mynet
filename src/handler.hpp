#ifndef MYNET_SRC_HANDLER_HPP
#define MYNET_SRC_HANDLER_HPP

#include "protocol.hpp"
#include <string>

class Handler
{

public:
    Handler() = default;
    ~Handler() = default;
    Handler(const Handler &) = delete;
    Handler &operator=(const Handler &) = delete;
    Handler(Handler &&) = delete;
    Handler &operator=(Handler &&) = delete;
    const std::string process(const std::string &data)
    {
        return data;
    }
};

#endif