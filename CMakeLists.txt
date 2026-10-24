cmake_minimum_required(VERSION 3.20)

project(mynet
    VERSION 1.0.0
    DESCRIPTION "A modern, high-performance, asynchronous networking library in C++26"
    LANGUAGES CXX
)

# -----------------------------------------------------------------------------
# Detect if mynet is built as a top-level project or included as a subproject
# -----------------------------------------------------------------------------
set(MYNET_IS_TOP_LEVEL OFF)
if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(MYNET_IS_TOP_LEVEL ON)
endif()

# Global C++ standard settings (primarily for top-level targets)
set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Top-level defaults
if(MYNET_IS_TOP_LEVEL)
    if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
        set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
    endif()
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
endif()

# C++26 contracts and reflection flags for GCC
# 全库 no-exception 策略：错误处理统一走 Result<T>/std::expected 与 contract_assert，
# 源码不使用任何 try/catch/throw；-fno-exceptions 使编译器强制该约定，
# 遗漏的隐式异常路径（如 STL 扩容 OOM）在此模式下直接 abort，显式可预测。
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    add_compile_options(-fcontracts -freflection -fno-exceptions)
    add_link_options(-fcontracts)
endif()

# -----------------------------------------------------------------------------
# Options: default to ON for standalone builds, OFF when consumed as a subproject
# -----------------------------------------------------------------------------
option(MYNET_BUILD_SAMPLES "Build sample applications" ${MYNET_IS_TOP_LEVEL})
option(MYNET_BUILD_TESTS   "Build tests"               ${MYNET_IS_TOP_LEVEL})
option(MYNET_BUILD_BENCH   "Build benchmarks"          ${MYNET_IS_TOP_LEVEL})

# -----------------------------------------------------------------------------
# Subprojects & Dependencies
# -----------------------------------------------------------------------------
# Disable subproject samples/tests/benchmarks so building mynet stays focused
set(MYLOG_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(MYLOG_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(MYLOG_BUILD_BENCH OFF CACHE BOOL "" FORCE)
add_subdirectory(third_party/mylog)

# -----------------------------------------------------------------------------
# Targets
# -----------------------------------------------------------------------------
add_subdirectory(src)

if(MYNET_BUILD_SAMPLES)
    add_subdirectory(samples)
endif()

if(MYNET_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(MYNET_BUILD_BENCH)
    add_subdirectory(bench)
endif()

# -----------------------------------------------------------------------------
# Developer Tooling (only active when building as top-level project)
# -----------------------------------------------------------------------------
if(MYNET_IS_TOP_LEVEL)
    find_program(CLANG_FORMAT_EXE clang-format)
    if(CLANG_FORMAT_EXE)
        file(GLOB_RECURSE MYNET_CXX_FILES
            "${CMAKE_CURRENT_SOURCE_DIR}/src/*.hpp"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
            "${CMAKE_CURRENT_SOURCE_DIR}/samples/*.hpp"
            "${CMAKE_CURRENT_SOURCE_DIR}/samples/*.cpp"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.hpp"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.cpp"
            "${CMAKE_CURRENT_SOURCE_DIR}/bench/*.hpp"
            "${CMAKE_CURRENT_SOURCE_DIR}/bench/*.cpp"
        )

        add_custom_target(format
            COMMAND ${CLANG_FORMAT_EXE} -i ${MYNET_CXX_FILES}
            COMMENT "Auto-formatting all C++ files with clang-format"
        )

        add_custom_target(format-check
            COMMAND ${CLANG_FORMAT_EXE} --dry-run -Werror ${MYNET_CXX_FILES}
            COMMENT "Checking C++ files with clang-format"
        )
    endif()

    find_package(Git QUIET)
    if(GIT_FOUND AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.githooks/pre-commit")
        if(UNIX)
            execute_process(
                COMMAND chmod +x "${CMAKE_CURRENT_SOURCE_DIR}/.githooks/pre-commit"
                OUTPUT_QUIET ERROR_QUIET
            )
        endif()
        execute_process(
            COMMAND ${GIT_EXECUTABLE} -C "${CMAKE_CURRENT_SOURCE_DIR}" rev-parse --is-inside-work-tree
            RESULT_VARIABLE _GIT_WORK_TREE_RES
            OUTPUT_QUIET ERROR_QUIET
        )
        if(_GIT_WORK_TREE_RES EQUAL 0)
            execute_process(
                COMMAND ${GIT_EXECUTABLE} config core.hooksPath .githooks
                WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
                RESULT_VARIABLE _GIT_HOOK_RES
                OUTPUT_QUIET ERROR_QUIET
            )
            if(_GIT_HOOK_RES EQUAL 0)
                message(STATUS "Git pre-commit hook configured: core.hooksPath -> .githooks")
            endif()
        endif()
    endif()
endif()
