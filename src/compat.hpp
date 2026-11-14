#pragma once

/**
 * @file compat.hpp
 * @brief 编译器与跨平台特性兼容适配层（C++26 契约、反射与平台降级适配）
 */

#ifndef __cpp_contracts
#include <cassert>
#ifndef contract_assert
#define contract_assert(expr) assert(expr)
#endif
#endif
