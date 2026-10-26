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

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# -----------------------------------------------------------------------------
# kTLS RX capability probe (D1: TLS receive via io_uring multishot)
# 探测 OpenSSL 是否具备 kTLS offload 能力（SSL_OP_ENABLE_KTLS + BIO_get_ktls_recv）。
# 命中后定义 MYNET_HAVE_KTLS=1：握手成功的 TLS 连接若内核完成 RX offload，
# Proactor 可让其复用明文 recv_multishot + kernel buffer ring 快路径；
# 未命中则维持 SSL_read 同步慢路径，行为零回归。
# 必须在 find_package(OpenSSL) 之后，否则探测链接不到 libssl。
# -----------------------------------------------------------------------------
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

# D4：Debug 配置下自动定义 MYNET_DEBUG，启用 ObjectPool 线程归属断言等诊断；
# Release/RelWithDebInfo/MinSizeRel 不定义，断言与所有者记录整体编译剔除，零开销。
target_compile_definitions(mynet INTERFACE
    $<$<CONFIG:Debug>:MYNET_DEBUG=1>
)

target_link_libraries(mynet INTERFACE
    mylog::mylog
    OpenSSL::SSL
    Threads::Threads
    uring
    llhttp
)

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
