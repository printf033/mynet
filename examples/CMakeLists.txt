add_executable(ser ser.cpp)
add_executable(cli cli.cpp)

target_link_libraries(ser PRIVATE mynet)
target_link_libraries(cli PRIVATE mynet)
