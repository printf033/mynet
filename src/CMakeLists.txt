add_library(mynet STATIC mynet.cpp)

target_include_directories(mynet PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

find_package(OpenSSL REQUIRED)

# interface_mylog is PUBLIC because it is part of mynet's public interface, not
# an implementation detail: src/log.hpp includes logger.hpp, so every program
# that includes a mynet header needs mylog's include directory and its
# Threads::Threads link to be able to compile that header.
target_link_libraries(mynet PUBLIC interface_mylog PRIVATE OpenSSL::SSL uring llhttp)

target_compile_options(mynet PRIVATE -Wall -Wextra -Wpedantic)
