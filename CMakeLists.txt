cmake_minimum_required(VERSION 3.25)

project(mynet)

set(CMAKE_CXX_STANDARD 26)

set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/build)

# C++26 contracts. The public API states its preconditions -- a non-null
# address, a port inside the 16-bit range -- with contract_assert, and a
# header-defined contract is checked in the translation unit that instantiates
# it. That is the samples, not the (three-line) library object, so the flag is
# added at this level to reach both.
#
# It is added a second time as a *link* option on purpose: when -fcontracts is
# on the link line the GCC driver adds -lstdc++exp, and that library is where
# handle_contract_violation() lives -- the function a violated contract calls
# into. With the flag only on compiles, every sample still compiled and then
# failed to link with an undefined reference to it, because CMake's link line
# is the object files alone and the driver had no way to know they came from
# contract-checked code.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    add_compile_options(-fcontracts)
    add_link_options(-fcontracts)
endif()

# ---- logging: third_party/mylog, as a submodule ----
#
# mylog comes in as a submodule rather than through find_package because it is
# meant to be improved upstream: the pinned commit is what this checkout
# builds against, and bumping the submodule is how a change gets picked up.
#
# Its own samples, tests and benchmarks are switched off so that building
# mynet stays building mynet. Those are cache options, and the FORCE below only
# decides what a fresh configure of this tree sees.
#
# One configure-time requirement travels with it: mylog's src/CMakeLists.txt
# asks pkg-config for LuaJIT unconditionally, even though only its optional Lua
# config loader (configer_lua.hpp) uses it. A machine without luajit therefore
# stops at configure time with mylog's own message; nothing in mynet links Lua.
set(MYLOG_BUILD_SAMPLES OFF CACHE BOOL "" FORCE)
set(MYLOG_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(MYLOG_BUILD_BENCH OFF CACHE BOOL "" FORCE)
add_subdirectory(third_party/mylog)

# mylog derives its include directory from CMAKE_SOURCE_DIR, which is the
# top-level project. That is right when mylog builds on its own and wrong for
# the src/ of a submodule, so the real directory is added here. This is
# additive: the upstream CMakeLists is left untouched.
target_include_directories(interface_mylog INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/mylog/src)

add_subdirectory(src)

add_subdirectory(samples)

# ---- tests and benchmarks ----
#
# include(CTest) supplies enable_testing() and the BUILD_TESTING switch in one
# line, so a packager can turn the suite off with -DBUILD_TESTING=OFF instead of
# having to know which targets to skip.
#
# Benchmarks build by default but link nothing the tests link, so they are
# their own switch: they are worth running on a developer's machine and not
# worth the build time anywhere that only needs the library.
include(CTest)

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

option(MYNET_BUILD_BENCH "Build the micro-benchmarks in bench/" ON)

if(MYNET_BUILD_BENCH)
    add_subdirectory(bench)
endif()
