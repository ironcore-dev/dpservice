FROM debian:11-slim as builder

ARG DPDK_VER=21.11
ARG DPS_VER

WORKDIR /workspace

# Install prerequisite packages
RUN apt-get update && apt-get install -y --no-install-recommends ON \
libibverbs-dev \
libmnl-dev \
libnuma-dev \
numactl \
libnuma1 \
unzip \
wget \
make \
gcc \
g++ \
ethtool \
pciutils \
procps \
ninja-build \
meson \
python3-pyelftools \
iproute2 \
net-tools \
xz-utils \
build-essential \
pkg-config \
protobuf-compiler-grpc \
libgrpc++1 \
libgrpc++-dev \
linux-headers-${OSARCH} \
&& rm -rf /var/lib/apt/lists/*

# Download and compile DPDK
RUN wget http://git.dpdk.org/dpdk/snapshot/dpdk-${DPDK_VER}.zip
RUN unzip dpdk-${DPDK_VER}.zip

ENV DPDK_DIR=/workspace/dpdk-${DPDK_VER}

RUN cd $DPDK_DIR && meson build
RUN cd $DPDK_DIR/build && ninja
RUN cd $DPDK_DIR/build && ninja install

ARG DPS_VER
COPY . .
RUN meson build
RUN cd ./build && ninja

FROM debian:11-slim
WORKDIR /
COPY --from=builder /workspace/build/src/dp_service .
COPY --from=builder /usr/local/lib /usr/local/lib
COPY --from=builder /lib/* /lib/
RUN ldconfig

RUN apt-get update && apt-get install -y --no-install-recommends ON \
libibverbs-dev \
numactl \
libnuma1 \
pciutils \
procps \
libgrpc++1 \
&& rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/dp_service"]
