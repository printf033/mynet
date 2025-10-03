add_library(myque STATIC inc.cpp)

target_include_directories(myque PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_compile_options(myque PRIVATE -Wall -Wextra -Wpedantic)
