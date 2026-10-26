find_package(GTest REQUIRED)

function(mynet_unit_test name)
    add_executable(${name} ${name}.cpp)
    target_link_libraries(${name} PRIVATE
        mynet::mynet
        mynet::mynet_sanitized
        GTest::gtest
        GTest::gtest_main
    )
    add_test(NAME ${name} COMMAND ${name})
    # OOM 探针用例（如 Buffer 扩容失败路径）依赖分配器返回 null 而非直接 abort：
    # 对 ASan/UBSan 构建统一放宽 allocator_may_return_null，普通构建无影响。
    set_tests_properties(${name} PROPERTIES TIMEOUT 120
        ENVIRONMENT "ASAN_OPTIONS=allocator_may_return_null=1:abort_on_error=0")
endfunction()

mynet_unit_test(test_buffer)
mynet_unit_test(test_concepts)
mynet_unit_test(test_error)
mynet_unit_test(test_frame)
mynet_unit_test(test_handler)
mynet_unit_test(test_http3)
mynet_unit_test(test_multiplexer)
mynet_unit_test(test_object_pool)
mynet_unit_test(test_timer)

if(MYNET_ENABLE_LUA)
    add_executable(test_config_lua test_config_lua.cpp)
    target_link_libraries(test_config_lua PRIVATE
        mynet::mynet_lua
        mynet::mynet_sanitized
        GTest::gtest
        GTest::gtest_main
    )
    add_test(NAME test_config_lua COMMAND test_config_lua)
    set_tests_properties(test_config_lua PROPERTIES TIMEOUT 120
        ENVIRONMENT "ASAN_OPTIONS=allocator_may_return_null=1:abort_on_error=0")
endif()
