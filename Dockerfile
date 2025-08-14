# Build image with DPDK, etc.
FROM --platform=${TARGETPLATFORM} debian:13-slim AS builder

ARG TARGETARCH
ARG DPDK_VER=24.11.1
ARG DPDK_BUILDTYPE=release
ARG DPSERVICE_BUILDTYPE=debug
ARG DPSERVICE_FEATURES=""

WORKDIR /workspace

# Install prerequisite packages
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends ON \
libibverbs-dev \
libmnl-dev \
libnuma-dev \
numactl \
libnuma1 \
unzip \
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
libpcap0.8-dev

# Need at least Golang 1.20 which is not part of Debian-12 stable
RUN curl -Ls https://golang.org/dl/go1.20.14.linux-${TARGETARCH}.tar.gz | tar xz -C /usr/local/
ENV PATH="${PATH}:/usr/local/go/bin"

# Download DPDK
ADD http://fast.dpdk.org/rel/dpdk-${DPDK_VER}.tar.xz dpdk.tar.xz
RUN tar -xJf dpdk.tar.xz

ENV DPDK_DIR=/workspace/dpdk-stable-${DPDK_VER}

# Copy DPDK patches
COPY hack/*.patch hack/
RUN cd $DPDK_DIR \
&& patch -p1 -R < ../hack/dpdk_24_11_mtu.patch \
&& patch -p1 < ../hack/dpdk_24_11_fdb_def_rule.patch \
&& patch -p1 < ../hack/dpdk_24_11_log.patch \
&& patch -p1 < ../hack/dpdk_24_11_telemetry_key.patch \
&& patch -p1 < ../hack/dpdk_24_11_no_pattern_template_validation.patch \
&& patch -p1 < ../hack/dpdk_24_11_ethdev_conversion.patch

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
vhost,gpudev build -Ddisable_apps="*" -Dtests=false -Dbuildtype=$DPDK_BUILDTYPE
RUN cd $DPDK_DIR/build && ninja
RUN cd $DPDK_DIR/build && ninja install

# Prepare tools and sources
COPY meson.build meson.build
COPY meson_options.txt meson_options.txt
COPY hack/* hack/
COPY proto/ proto/
COPY go/ go/
COPY cli/ cli/
COPY tools/ tools/
COPY test/local/ test/
COPY src/ src/
COPY include/ include/
# Needed for version extraction by meson
COPY .git/ .git/

# Compile dpservice itself
RUN meson setup build -Dbuild_dpservice_cli=true -Dbuildtype=$DPSERVICE_BUILDTYPE $DPSERVICE_FEATURES && ninja -C build


# Extended build image for test-image
FROM builder AS testbuilder
ARG DPSERVICE_FEATURES=""
RUN meson setup release_build $DPSERVICE_FEATURES --buildtype=release && ninja -C release_build
RUN CC=clang CXX=clang++ meson setup clang_build $DPSERVICE_FEATURES && ninja -C clang_build
RUN meson setup xtratest_build $DPSERVICE_FEATURES -Denable_tests=true && ninja -C xtratest_build


# Test-image to run pytest
FROM debian:13-slim AS tester

RUN apt-get update && apt-get install -y --no-install-recommends ON \
libibverbs-dev \
numactl \
libnuma1 \
pciutils \
procps \
libuuid1 \
libgrpc++1.51 \
libpcap0.8-dev \
iproute2 \
udev \
gawk \
python3-pytest \
python3-scapy \
&& apt-get purge g++-12 ipython3 -y \
&& apt-get autoremove -y \
&& apt-get clean -y \
&& rm -rf /var/lib/apt/lists/*
# some packages are for some reason part of python3-scapy installation:
#   g++-12 with 900MB installed size
#   ipython3 with 264MB installed size

WORKDIR /
COPY --from=testbuilder /workspace/test ./test
COPY --from=testbuilder /workspace/build/src/dpservice-bin ./build/src/dpservice-bin
COPY --from=testbuilder /workspace/build/cli/dpservice-cli/dpservice-cli ./build/cli/dpservice-cli/dpservice-cli
COPY --from=testbuilder /workspace/build/cli/dpservice-exporter/dpservice-exporter ./build/cli/dpservice-exporter/dpservice-exporter
COPY --from=testbuilder /workspace/xtratest_build/src/dpservice-bin ./xtratest_build/src/dpservice-bin
COPY --from=testbuilder /workspace/build/cli/dpservice-cli/dpservice-cli ./xtratest_build/cli/dpservice-cli/dpservice-cli
COPY --from=testbuilder /workspace/build/cli/dpservice-exporter/dpservice-exporter ./xtratest_build/cli/dpservice-exporter/dpservice-exporter
COPY --from=testbuilder /usr/local/lib /usr/local/lib
RUN ldconfig

WORKDIR /test
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["./runtest.py", "../build", "../xtratest_build"]


# Deployed pod image itself
FROM debian:13-slim AS production

RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends ON \
libibverbs-dev \
numactl \
libnuma1 \
pciutils \
procps \
libuuid1 \
libgrpc++1.51 \
libpcap0.8-dev \
iproute2 \
udev \
gawk \
jq \
bash-completion \
&& rm -rf /var/lib/apt/lists/*

WORKDIR /
COPY --from=builder \
/workspace/build/src/dpservice-bin \
/workspace/build/tools/dump/dpservice-dump \
/workspace/build/tools/inspect/dpservice-inspect \
/workspace/build/cli/dpservice-cli/dpservice-cli \
/workspace/build/cli/dpservice-exporter/dpservice-exporter \
/workspace/hack/prepare.sh \
/usr/local/bin/
COPY --from=builder /usr/local/lib /usr/local/lib
RUN ldconfig

# Ensure bash-completion is working in operations
RUN echo 'PATH=${PATH}:/\nsource /etc/bash_completion\nsource <(dpservice-cli completion bash)' >> /root/.bashrc

ENTRYPOINT ["dpservice-bin"]
