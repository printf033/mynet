add_library(mynet STATIC
    peer.hpp
    peer.cpp
)

target_include_directories(mynet PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(mynet PRIVATE -Wall -Wextra -Wpedantic)
