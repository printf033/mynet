# Micro-benchmarks.
#
# No sanitizer here on purpose. ASan's instrumentation is itself a large part
# of what would be measured, and a number taken through it describes the
# sanitizer rather than the code. Correctness is the unit tests' job; this
# target only answers "how long does it take".
#
# -O2 is requested explicitly because this tree configures as Debug by default,
# and an unoptimised ns/op is not a measurement of anything. -g is kept so a
# profile of a benchmark still has line numbers.
function(mynet_bench name)
    add_executable(${name} ${name}.cpp)
    target_include_directories(${name} PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(${name} PRIVATE mynet)
    target_compile_options(${name} PRIVATE -Wall -Wextra -Wpedantic -O2 -g)
endfunction()

mynet_bench(bench_core)
