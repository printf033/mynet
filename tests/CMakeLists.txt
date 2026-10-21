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
    set_tests_properties(${name} PROPERTIES TIMEOUT 120)
endfunction()

mynet_unit_test(test_buffer)
mynet_unit_test(test_concepts)
mynet_unit_test(test_error)
mynet_unit_test(test_frame)
mynet_unit_test(test_handler)
mynet_unit_test(test_multiplexer)
mynet_unit_test(test_object_pool)
mynet_unit_test(test_timer)
