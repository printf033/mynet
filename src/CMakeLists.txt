add_library(mynet STATIC mynet.cpp)

target_include_directories(mynet PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

find_package(OpenSSL REQUIRED)

target_link_libraries(mynet PRIVATE OpenSSL::SSL uring llhttp)

target_compile_options(mynet PRIVATE -Wall -Wextra -Wpedantic)
