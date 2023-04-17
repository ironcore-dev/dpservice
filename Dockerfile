FROM debian:11-slim as builder

ARG DPDK_VER=21.11

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
clang \
git \
ethtool \
pciutils \
procps \
ninja-build \
meson \
python3-pyelftools \
iproute2 \
libuuid1 \
uuid-dev \
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

COPY . .
RUN cd $DPDK_DIR && patch -p1 < ../hack/dpdk_21_11_clang.patch

RUN cd $DPDK_DIR && meson -Dmax_ethports=132 -Dplatform=generic -Ddisable_drivers=common/dpaax,\
common/cpt,common/iavf,\
common/octeontx,common/octeontx2,common/cnxk,common/qat,regex/octeontx2,net/cnxk,dma/cnxk,\
common/sfc_efx,common/auxiliary,common/dpaa,common/fslmc,common/ifpga,common/vdev,common/vmbus,\
mempool/octeontx,mempool/octeontx2,baseband/*,event/*,net/ark,net/atlantic,net/avp,net/axgbe,\
net/bnxt,net/bond,net/cxgbe,net/dpaa,net/dpaa2,net/e1000,net/ena,net/enetc,net/enetfec,net/enic,\
net/failsafe,net/fm10k,net/hinic,net/hns3,net/i40e,net/iavf,net/ice,net/igc,net/ionic,net/ipn3ke,\
net/ixgbe,net/liquidio,net/memif,net/netsvs,net/nfp,net/ngbe,net/null,net/octeontx,net/octeontx2,\
net/octeontx_ep,net/pcap,net/pfe,net/qede,net/sfc,net/softnic,net/thunderx,net/txgbe,\
net/vdev_ntsvc,net/vhost,net/virtio,net/vmxnet3,net/bnx2x,net/netsvc,net/vdev_netsvc,\
crypto/dpaa_sec,crypto/bcmfs,crypto/caam_jr,crypto/cnxk,dpaa_sec,crypto/dpaa2_sec,crypto/nitrox,\
crypto/null,crypto/octeontx,crypto/octeontx2,crypto/scheduler,crypto/virtio -Ddisable_libs=power,\
vhost,gpudev build
RUN cd $DPDK_DIR/build && ninja
RUN cd $DPDK_DIR/build && ninja install

RUN CC=clang CXX=clang++ meson build && cd ./build && ninja
RUN rm -rf build && meson build --buildtype=release && cd ./build && ninja
RUN rm -rf build && meson build && cd ./build && ninja

FROM debian:11-slim

RUN apt-get update && apt-get install -y --no-install-recommends ON \
libibverbs-dev \
numactl \
libnuma1 \
pciutils \
procps \
libuuid1 \
libgrpc++1 \
iproute2 \
udev \
gawk \
&& rm -rf /var/lib/apt/lists/*

WORKDIR /
COPY --from=builder /workspace/build/src/dp_service .
COPY --from=builder /workspace/build/tools/dp_grpc_client .
COPY --from=builder /workspace/hack/prepare.sh .
COPY --from=builder /usr/local/lib /usr/local/lib
COPY --from=builder /lib/* /lib/
RUN ldconfig

ENTRYPOINT ["/dp_service"]
