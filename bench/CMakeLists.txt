function(mynet_bench name)
    add_executable(${name} ${name}.cpp)
    target_link_libraries(${name} PRIVATE mynet::mynet)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${name} PRIVATE -O2 -DNDEBUG -g)
    endif()
endfunction()

mynet_bench(bench)
