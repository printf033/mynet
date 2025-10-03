add_library(mynet STATIC inc.cpp)

target_include_directories(mynet PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

find_package(OpenSSL REQUIRED)
target_link_libraries(mynet PRIVATE OpenSSL::SSL OpenSSL::Crypto)

target_include_directories(mynet PUBLIC ${PROJECT_SOURCE_DIR}/myque/src)

target_link_libraries(mynet PRIVATE myque)

target_compile_options(mynet PRIVATE -Wall -Wextra -Wpedantic)
