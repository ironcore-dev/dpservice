ARG OS_VER=11-slim
ARG DPDK_VER=21.11
ARG DPS_VER
FROM debian:${OS_VER}
MAINTAINER sachin
WORKDIR /
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
iproute2 \
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
linux-headers-$(uname -r) \
&& rm -rf /var/lib/apt/lists/*
# Download and compile DPDK
ARG DPDK_VER
RUN cd /usr/src/ &&  wget http://git.dpdk.org/dpdk/snapshot/dpdk-${DPDK_VER}.zip && unzip dpdk-${DPDK_VER}.zip
ENV DPDK_DIR=/usr/src/dpdk-${DPDK_VER}
RUN cd $DPDK_DIR && meson build
RUN cd $DPDK_DIR/build && ninja
RUN cd $DPDK_DIR/build && ninja install
ARG DPS_VER
ADD /dp_service-${DPS_VER}.tar.xz /tmp/
RUN cd /tmp/dp_service-${DPS_VER} && meson build
RUN cd /tmp/dp_service-${DPS_VER}/build && ninja
# Remove unnecessary packages and files
RUN rm -fr ${DPDK_DIR}* && rm -f /tmp/dp_service-${DPS_VER}.tar.gz
RUN apt-get -y remove gcc unzip wget make
RUN apt-get -y autoremove
RUN apt-get -y clean
