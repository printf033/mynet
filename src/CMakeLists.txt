add_library(mynet INTERFACE)
add_library(mynet::mynet ALIAS mynet)

target_include_directories(mynet INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
    $<INSTALL_INTERFACE:include>
)

target_compile_features(mynet INTERFACE
    cxx_std_26
)

target_compile_options(mynet INTERFACE
    $<$<OR:$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>>:-Wall -Wextra -Wpedantic>
)

if(ANDROID)
    find_library(CRYPTO_LIB crypto)
    find_library(SSL_LIB ssl)
    if(NOT TARGET OpenSSL::SSL)
        add_library(OpenSSL::SSL INTERFACE IMPORTED)
        target_link_libraries(OpenSSL::SSL INTERFACE ${SSL_LIB} ${CRYPTO_LIB})
    endif()
    option(MYNET_ENABLE_URING "Enable Linux io_uring Proactor engine" OFF)
else()
    find_package(OpenSSL REQUIRED)
    find_package(ZLIB REQUIRED)
    option(MYNET_ENABLE_URING "Enable Linux io_uring Proactor engine" ON)
endif()
find_package(Threads REQUIRED)

# -----------------------------------------------------------------------------
# kTLS RX capability probe (D1: TLS receive via io_uring multishot)
# 探测 OpenSSL 是否具备 kTLS offload 能力（SSL_OP_ENABLE_KTLS + BIO_get_ktls_recv）。
# 命中后定义 MYNET_HAVE_KTLS=1：握手成功的 TLS 连接若内核完成 RX offload，
# Proactor 可让其复用明文 recv_multishot + kernel buffer ring 快路径；
# 未命中则维持 SSL_read 同步慢路径，行为零回归。
# 必须在 find_package(OpenSSL) 之后，否则探测链接不到 libssl。
# -----------------------------------------------------------------------------
if(NOT ANDROID)
    include(CheckCXXSourceCompiles)
    set(CMAKE_REQUIRED_LIBRARIES OpenSSL::SSL)
    set(MYNET_KTLS_PROBE_SOURCE [[
#include <openssl/ssl.h>
#include <openssl/bio.h>
int main()
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    SSL *ssl = SSL_new(ctx);
    (void)SSL_set_options(ssl, SSL_OP_ENABLE_KTLS);
    (void)BIO_get_ktls_recv(SSL_get_rbio(ssl));
    (void)BIO_get_ktls_send(SSL_get_wbio(ssl));
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}
]])
    check_cxx_source_compiles("${MYNET_KTLS_PROBE_SOURCE}" MYNET_HAVE_KTLS)
    unset(CMAKE_REQUIRED_LIBRARIES)
    if(MYNET_HAVE_KTLS)
        target_compile_definitions(mynet INTERFACE MYNET_HAVE_KTLS=1)
    endif()
endif()

# D4：Debug 配置下自动定义 MYNET_DEBUG，启用 ObjectPool 线程归属断言等诊断；
# Release/RelWithDebInfo/MinSizeRel 不定义，断言与所有者记录整体编译剔除，零开销。
target_compile_definitions(mynet INTERFACE
    $<$<CONFIG:Debug>:MYNET_DEBUG=1>
    $<$<BOOL:${MYNET_ENABLE_URING}>:MYNET_ENABLE_URING=1>
)

target_link_libraries(mynet INTERFACE
    mylog::mylog
    OpenSSL::SSL
    ZLIB::ZLIB
    Threads::Threads
    $<$<BOOL:${MYNET_ENABLE_URING}>:uring>
    llhttp
)

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(LIBBPF QUIET IMPORTED_TARGET libbpf)
    if(TARGET PkgConfig::LIBBPF)
        target_link_libraries(mynet INTERFACE PkgConfig::LIBBPF)
        target_compile_definitions(mynet INTERFACE MYNET_HAVE_LIBBPF=1)
    elseif(LIBBPF_FOUND)
        target_include_directories(mynet INTERFACE ${LIBBPF_INCLUDE_DIRS})
        target_link_libraries(mynet INTERFACE ${LIBBPF_LIBRARIES})
        target_compile_definitions(mynet INTERFACE MYNET_HAVE_LIBBPF=1)
    endif()
endif()

find_program(CLANG_BPF_EXE clang)
if(CLANG_BPF_EXE)
    set(MYNET_BPF_SRC "${CMAKE_CURRENT_SOURCE_DIR}/ebpf/kern/mynet_kernel.bpf.c")
    set(MYNET_BPF_OBJ "${CMAKE_CURRENT_BINARY_DIR}/mynet_kernel.bpf.o")
    set(MYNET_BPF_EMBED "${CMAKE_CURRENT_SOURCE_DIR}/ebpf/kern/mynet_kernel_bpf_embedded.hpp")
    add_custom_command(
        OUTPUT "${MYNET_BPF_OBJ}" "${MYNET_BPF_EMBED}"
        COMMAND ${CLANG_BPF_EXE} -O2 -g -target bpf -c "${MYNET_BPF_SRC}" -o "${MYNET_BPF_OBJ}"
        COMMAND ${CMAKE_COMMAND} -E echo "eBPF kernel bytecode compiled: ${MYNET_BPF_OBJ}"
        DEPENDS "${MYNET_BPF_SRC}"
        COMMENT "Compiling eBPF kernel program ${MYNET_BPF_SRC}"
        VERBATIM
    )
    add_custom_target(mynet_bpf ALL DEPENDS "${MYNET_BPF_OBJ}")
endif()

# Sanitizer 辅助目标（用于 tests 和 examples）
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

# -----------------------------------------------------------------------------
# Optional sandboxed Lua hot-configuration support
# -----------------------------------------------------------------------------
if(MYNET_ENABLE_LUA)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LUAJIT REQUIRED IMPORTED_TARGET luajit)

    add_library(mynet_lua INTERFACE)
    add_library(mynet::mynet_lua ALIAS mynet_lua)
    target_link_libraries(mynet_lua INTERFACE
        mynet::mynet
        mylog::mylog_lua
        PkgConfig::LUAJIT
    )
    target_compile_definitions(mynet_lua INTERFACE MYNET_HAVE_LUA=1)
endif()

# -----------------------------------------------------------------------------
# Standalone Proxy Kernel Executable (mynetd)
# -----------------------------------------------------------------------------
add_executable(mynetd mynetd.cpp)
if(MYNET_ENABLE_LUA)
    target_link_libraries(mynetd PRIVATE mynet::mynet_lua mynet::mynet_sanitized)
else()
    target_link_libraries(mynetd PRIVATE mynet::mynet mynet::mynet_sanitized)
endif()

