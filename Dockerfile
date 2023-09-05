FROM debian:12-slim as builder

ARG DPDK_VER=21.11
ARG DPSERVICE_FEATURES=""

WORKDIR /workspace

# Install prerequisite packages
RUN apt-get update && apt-get upgrade && apt-get install -y --no-install-recommends ON \
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
tar \
findutils \
jq \
curl \
build-essential \
pkg-config \
protobuf-compiler-grpc \
libgrpc++1.51 \
libgrpc++-dev \
linux-headers-${OSARCH} \
&& rm -rf /var/lib/apt/lists/*

# Download DPDK
RUN wget http://git.dpdk.org/dpdk/snapshot/dpdk-${DPDK_VER}.zip
RUN unzip dpdk-${DPDK_VER}.zip

ENV DPDK_DIR=/workspace/dpdk-${DPDK_VER}

# Copy DPDK patches
COPY hack/*.patch hack/
RUN cd $DPDK_DIR && patch -p1 < ../hack/dpdk_21_11_gcc12.patch
RUN cd $DPDK_DIR && patch -p1 < ../hack/dpdk_21_11_clang.patch
RUN cd $DPDK_DIR && patch -p1 < ../hack/dpdk_21_11_log.patch
RUN cd $DPDK_DIR && patch -p1 < ../hack/dpdk_21_11_xstats_mem_leak.patch
RUN cd $DPDK_DIR && patch -p1 < ../hack/dpdk_21_11_graph_alloc.patch

# Compile DPDK
RUN cd $DPDK_DIR && meson setup -Dmax_ethports=132 -Dplatform=generic -Ddisable_drivers=common/dpaax,\
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

# Copy additional repo's tools
COPY hack/rel_download.sh hack/rel_download.sh
RUN --mount=type=secret,id=github_token,dst=/run/secrets/github_token \
sh -c 'GITHUB_TOKEN=$(if [ -f /run/secrets/github_token ]; then cat /run/secrets/github_token; else echo ""; fi) \
&& ./hack/rel_download.sh -dir=exporter -owner=onmetal -repo=prometheus-dpdk-exporter -pat=$GITHUB_TOKEN \
&& ./hack/rel_download.sh -dir=client -owner=onmetal -repo=dpservice-cli -pat=$GITHUB_TOKEN \'

# Now copy the rest to enable DPDK layer caching
COPY meson.build meson.build
COPY meson_options.txt meson_options.txt
COPY src/ src/
COPY include/ include/
COPY test/ test/
COPY hack/* hack/
COPY proto/ proto/
COPY tools/ tools/
# Needed for version extraction by meson
COPY .git/ .git/

RUN meson setup build $DPSERVICE_FEATURES && cd ./build && ninja

FROM builder AS testbuilder
RUN rm -rf build && meson setup build $DPSERVICE_FEATURES --buildtype=release && cd ./build && ninja
RUN rm -rf build && CC=clang CXX=clang++ meson setup build $DPSERVICE_FEATURES && cd ./build && ninja

FROM debian:12-slim as tester

RUN apt-get update && apt-get install -y --no-install-recommends ON \
libibverbs-dev \
numactl \
libnuma1 \
pciutils \
procps \
libuuid1 \
libgrpc++1.51 \
iproute2 \
udev \
gawk \
python3 \
python3-pytest \
python3-scapy \
&& rm -rf /var/lib/apt/lists/*

WORKDIR /
COPY --from=testbuilder /workspace/test ./test
COPY --from=testbuilder /workspace/build/src/dp_service ./build/src/dp_service
COPY --from=testbuilder /usr/local/lib /usr/local/lib
COPY --from=testbuilder /workspace/client/github.com/onmetal/* ./build
RUN ldconfig

WORKDIR /test
ENTRYPOINT ["pytest-3", "-x", "-v"]

FROM debian:12-slim as production

RUN apt-get update && apt-get upgrade && apt-get install -y --no-install-recommends ON \
libibverbs-dev \
numactl \
libnuma1 \
pciutils \
procps \
libuuid1 \
libgrpc++1.51 \
iproute2 \
udev \
gawk \
&& rm -rf /var/lib/apt/lists/*

WORKDIR /
COPY --from=builder /workspace/build/src/dp_service .
COPY --from=builder /workspace/build/tools/dp_grpc_client /workspace/build/tools/dump/dpservice-dump .
COPY --from=builder /workspace/hack/prepare.sh .
COPY --from=builder /usr/local/lib /usr/local/lib
COPY --from=builder /workspace/exporter/* /workspace/client/github.com/onmetal/* .
RUN ldconfig

ENTRYPOINT ["/dp_service"]
