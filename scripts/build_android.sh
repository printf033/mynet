#!/usr/bin/env bash
set -euo pipefail

NDK_ROOT="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-/home/aaa/Android/Sdk/ndk/27.2.12479018}}"
TARGET_ARCH="arm64-v8a"
API_LEVEL="34"
TOOLCHAIN="$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin"
CLANG="$TOOLCHAIN/aarch64-linux-android${API_LEVEL}-clang++"
CLANG_C="$TOOLCHAIN/aarch64-linux-android${API_LEVEL}-clang"

OUTPUT_DIR="thirdparty/nekobox/app/src/main/jniLibs/$TARGET_ARCH"
mkdir -p "$OUTPUT_DIR"

echo "Building llhttp for $TARGET_ARCH..."
LLHTTP_OBJ_DIR="/tmp/mynet_llhttp_$TARGET_ARCH"
mkdir -p "$LLHTTP_OBJ_DIR"
for cfile in thirdparty/llhttp/src/*.c; do
  base="$(basename "$cfile" .c)"
  "$CLANG_C" -O3 -fPIC -I thirdparty/llhttp/include -c "$cfile" -o "$LLHTTP_OBJ_DIR/${base}.o"
done

OPENSSL_PREFIX="${OPENSSL_ANDROID_PREFIX:-/tmp/openssl-android-arm64}"

echo "Building libmynetd.so with 16 KB page-size alignment..."

"$CLANG" \
  -std=c++26 -fno-exceptions -static-libstdc++ \
  -Wl,-z,max-page-size=16384 \
  -I src -I thirdparty/mylog/src -I "$OPENSSL_PREFIX/include" -I thirdparty/llhttp/include \
  -DMYNET_DEBUG=0 -Wno-defaulted-function-deleted -Wno-inconsistent-missing-override \
  src/mynetd.cpp "$LLHTTP_OBJ_DIR"/*.o \
  "$OPENSSL_PREFIX/lib/libssl.a" "$OPENSSL_PREFIX/lib/libcrypto.a" -lz -llog \
  -o "$OUTPUT_DIR/libmynetd.so"

echo "Verifying ELF LOAD segment alignment:"
readelf -l "$OUTPUT_DIR/libmynetd.so" | grep -A 1 LOAD
echo "Done! Built $OUTPUT_DIR/libmynetd.so"
