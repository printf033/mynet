add_executable(ser ser.cpp)
add_executable(cli cli.cpp)

target_link_libraries(ser PRIVATE mynet)
target_link_libraries(cli PRIVATE mynet)

add_executable(ser_s ser_s.cpp)
add_executable(cli_s cli_s.cpp)

target_link_libraries(ser_s PRIVATE mynet)
target_link_libraries(cli_s PRIVATE mynet)

add_executable(viewer_s viewer_s.cpp)

target_link_libraries(viewer_s PRIVATE mynet)
