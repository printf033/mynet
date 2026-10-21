add_library(mynet INTERFACE)
add_library(mynet::mynet ALIAS mynet)

target_include_directories(mynet INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include>
)

target_compile_features(mynet INTERFACE
    cxx_std_26
)

target_compile_options(mynet INTERFACE
    $<$<OR:$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>>:-Wall -Wextra -Wpedantic>
)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

target_link_libraries(mynet INTERFACE
    mylog::mylog
    OpenSSL::SSL
    Threads::Threads
    uring
    llhttp
)

# Sanitizer helper target (used in tests and samples)
option(MYNET_SANITIZE "Enable ASan/UBSan for Debug builds" ${MYNET_IS_TOP_LEVEL})

add_library(mynet_sanitized INTERFACE)
add_library(mynet::mynet_sanitized ALIAS mynet_sanitized)

if(MYNET_SANITIZE)
    target_compile_options(mynet_sanitized INTERFACE
        $<$<AND:$<CONFIG:Debug>,$<NOT:$<CXX_COMPILER_ID:MSVC>>>:-fsanitize=address,undefined -fno-omit-frame-pointer -g>
    )
    target_link_options(mynet_sanitized INTERFACE
        $<$<AND:$<CONFIG:Debug>,$<NOT:$<CXX_COMPILER_ID:MSVC>>>:-fsanitize=address,undefined>
    )
endif()
