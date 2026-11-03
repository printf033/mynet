# =============================================================================
# Stage 1: Build environment based on latest Arch Linux
# =============================================================================
FROM archlinux:latest AS builder

WORKDIR /mynet

# Configure fast and reliable Arch Linux mirrors & install build dependencies
RUN echo 'Server = https://mirrors.aliyun.com/archlinux/$repo/os/$arch' > /etc/pacman.d/mirrorlist && \
    echo 'Server = https://mirrors.ustc.edu.cn/archlinux/$repo/os/$arch' >> /etc/pacman.d/mirrorlist && \
    echo 'Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch' >> /etc/pacman.d/mirrorlist && \
    pacman -Syu --noconfirm --needed \
        base-devel \
        gcc \
        cmake \
        ninja \
        pkgconf \
        git \
        openssl \
        liburing \
        llhttp \
        luajit \
        gtest && \
    pacman -Scc --noconfirm

# Copy repository source code (including submodules such as thirdparty/mylog)
COPY . .

# Configure and build mynet in Release mode
WORKDIR /mynet/build

RUN cmake -GNinja -DCMAKE_BUILD_TYPE=Release .. && \
    ninja

# =============================================================================
# Stage 2: Minimal runtime environment based on latest Arch Linux
# =============================================================================
FROM archlinux:latest

WORKDIR /mynet

# Install runtime shared libraries only
RUN echo 'Server = https://mirrors.aliyun.com/archlinux/$repo/os/$arch' > /etc/pacman.d/mirrorlist && \
    echo 'Server = https://mirrors.ustc.edu.cn/archlinux/$repo/os/$arch' >> /etc/pacman.d/mirrorlist && \
    echo 'Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch' >> /etc/pacman.d/mirrorlist && \
    pacman -Syu --noconfirm --needed \
        openssl \
        liburing \
        llhttp \
        luajit && \
    pacman -Scc --noconfirm && \
    rm -rf /var/cache/pacman/pkg/*

# Copy build artifacts and runtime resources
COPY --from=builder /mynet/build /mynet/build
COPY --from=builder /mynet/certs /mynet/certs
COPY --from=builder /mynet/config /mynet/config

ENV PATH="/mynet/build:${PATH}"

# Common listening ports:
#   8888: TCP / TLS / HTTP1 / HTTP2 / UDP
#   4433: HTTP/3 (QUIC / UDP)
#   1080: SOCKS5 Proxy
EXPOSE 8888 8888/udp 8443 4433/udp 1080

# Default to Reactor TCP server (epoll-based, universal container compatibility)
CMD ["./build/reactor_tcp"]
