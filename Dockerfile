FROM ubuntu:25.04

WORKDIR /mynet

COPY . .

RUN sed -i "s|http://archive.ubuntu.com/ubuntu/|http://mirrors.aliyun.com/ubuntu/|g" /etc/apt/sources.list.d/ubuntu.sources &&\
    apt-get update &&\
    apt-get install -y g++ cmake make libssl-dev &&\
    rm -rf /var/lib/apt/lists/*

WORKDIR /mynet/build

RUN cmake .. &&\
    make -j$(nproc)

WORKDIR /mynet/build/examples

CMD ["./ser"]
