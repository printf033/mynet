# 示例程序按"调用方 × 协议"组织：
#
#   client/     Client 客户端（传输级，不解析应用协议）
#   reactor/    epoll Reactor 服务端
#   proactor/   io_uring Proactor 服务端
#   common/     共享头文件（端点解析、处理器定义）
#
# 目标名统一为 <角色>_<协议>：客户端为 client_{tcp,ssl,udp}，
# 服务端为 {reactor,proactor}_{tcp,ssl,udp,http1,http2,http3}，
# 两侧都可以对接，同一个 client 目标既能连 reactor 也能连 proactor 服务端。
# 每个示例都接受单个位置参数 <host>:<port>，省略时使用各自的默认端点。

function(gen_example name source)
    add_executable(${name} ${source})
    target_link_libraries(${name} PRIVATE mynet::mynet mynet::mynet_sanitized)
    # 示例用 "common/endpoint.hpp" 这样的仓库内相对路径互相引用，
    # 因此把 examples/ 本身加入包含路径。
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
endfunction()

# ---- Client：传输级客户端（两个引擎通用） ----
gen_example(client_tcp client/tcp.cpp)
gen_example(client_ssl client/ssl.cpp)
gen_example(client_udp client/udp.cpp)

# ---- Reactor：epoll 边沿触发 ----
gen_example(reactor_tcp   reactor/tcp.cpp)
gen_example(reactor_ssl   reactor/ssl.cpp)
gen_example(reactor_udp   reactor/udp.cpp)
gen_example(reactor_http1 reactor/http1.cpp)
gen_example(reactor_http2 reactor/http2.cpp)
gen_example(reactor_http3 reactor/http3.cpp)

# ---- Proactor：io_uring 完成事件驱动 ----
gen_example(proactor_tcp   proactor/tcp.cpp)
gen_example(proactor_ssl   proactor/ssl.cpp)
gen_example(proactor_udp   proactor/udp.cpp)
gen_example(proactor_http1 proactor/http1.cpp)
gen_example(proactor_http2 proactor/http2.cpp)
gen_example(proactor_http3 proactor/http3.cpp)
