cmake_minimum_required(VERSION 3.15)
project(mynet
    VERSION 0.1.0
    DESCRIPTION "I plan to make my own network library 2025-9-4"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(GNUInstallDirs)

add_subdirectory(src)
add_subdirectory(examples)
