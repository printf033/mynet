add_executable(ser ser.cpp)
add_executable(cli cli.cpp)

target_link_libraries(ser PRIVATE mynet)
target_link_libraries(cli PRIVATE mynet)

add_executable(s_ser s_ser.cpp)
add_executable(s_cli s_cli.cpp)

target_link_libraries(s_ser PRIVATE mynet)
target_link_libraries(s_cli PRIVATE mynet)
