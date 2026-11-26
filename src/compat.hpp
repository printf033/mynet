#pragma once

/**
 * @file compat.hpp
 * @brief 编译器与跨平台特性兼容适配层（C++26 契约、反射与平台降级适配）
 */

#include <cassert>

#ifndef contract_assert
#if defined(__cpp_contracts)
#if __cpp_contracts < 202502L
#define contract_assert(expr) [[assert: expr]]
#endif
#else
#define contract_assert(expr) assert(expr)
#endif
#endif
