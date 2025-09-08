add_library(mynet STATIC
    inc.cpp
    peer.hpp
    cryptor.hpp
)

target_include_directories(mynet PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
find_package(OpenSSL REQUIRED)
target_link_libraries(mynet PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(mynet PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_compile_options(mynet PRIVATE -Wall -Wextra -Wpedantic)
