FROM ubuntu:25.10 AS builder

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /mynet

RUN sed -i "s|http://archive.ubuntu.com/ubuntu/|http://mirrors.aliyun.com/ubuntu/|g" /etc/apt/sources.list.d/ubuntu.sources && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    g++ \
    cmake \
    make \
    pkg-config \
    libssl-dev \
    liburing-dev && \
    rm -rf /var/lib/apt/lists/*

COPY . .

WORKDIR /mynet/build

RUN cmake -DCMAKE_BUILD_TYPE=Release .. &&\
    make -j$(nproc)

FROM ubuntu:25.10

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /mynet/build

RUN sed -i "s|http://archive.ubuntu.com/ubuntu/|http://mirrors.aliyun.com/ubuntu/|g" /etc/apt/sources.list.d/ubuntu.sources && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    libssl3t64 \
    liburing2 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /mynet/build/proactor_tcp .

CMD ["./proactor_tcp"]
