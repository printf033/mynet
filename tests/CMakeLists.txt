# Unit tests.
#
# GTest comes from the system rather than through FetchContent: this project
# already builds against system OpenSSL, llhttp and liburing, and a test-only
# vendored copy would be one more toolchain to keep current for no gain.
find_package(GTest REQUIRED)

# One executable per source file. The library is small, the link is cheap, and
# a crash in one case cannot take the rest of the suite with it.
#
# The include directory is spelled out because src/CMakeLists.txt keeps it
# PRIVATE to the library: a test reaches the headers the same way a program
# that links mynet does, rather than through a path it happens to inherit.
#
# Sanitised, like the samples: the buffer and the pool are the two places where
# an off-by-one is a memory error rather than a wrong number, and a unit test
# is where that should be loud rather than latent.
function(mynet_unit_test name)
    add_executable(${name} ${name}.cpp)
    target_include_directories(${name} PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(${name} PRIVATE mynet GTest::gtest GTest::gtest_main)
    target_compile_options(${name} PRIVATE -Wall -Wextra -Wpedantic -g -fsanitize=address)
    target_link_options(${name} PRIVATE -fsanitize=address)
    add_test(NAME ${name} COMMAND ${name})
    set_tests_properties(${name} PROPERTIES TIMEOUT 120)
endfunction()

mynet_unit_test(test_buffer)
mynet_unit_test(test_error)
mynet_unit_test(test_frame)
mynet_unit_test(test_handler)
mynet_unit_test(test_hexdump)
mynet_unit_test(test_multiplexer)
mynet_unit_test(test_object_pool)
