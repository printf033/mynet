add_library(mynet STATIC mynet.cpp)

target_include_directories(mynet PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

find_package(OpenSSL REQUIRED)

find_package(PkgConfig REQUIRED)

pkg_check_modules(LIBURING REQUIRED liburing)

target_link_libraries(mynet PRIVATE OpenSSL::SSL ${LIBURING_LIBRARIES})

target_compile_options(mynet PRIVATE -Wall -Wextra -Wpedantic)
