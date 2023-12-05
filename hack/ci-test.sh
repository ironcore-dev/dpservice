#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
REPO_ROOT="$SCRIPT_DIR/.."

DPDK_VER=22.11
DPSERVICE_FEATURES=""

# create working directory
mkdir -p "$REPO_ROOT"/workspace
WORKSPACE_DIR="$REPO_ROOT"/workspace

# Install prerequisite packages
sudo apt-get update && sudo sudo apt-get install -y --no-install-recommends ON \
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
protobuf-compiler-grpc \
libpcap0.8-dev \
linux-headers-$(uname -r) \
udev \
gawk \
libc-ares-dev \
libre2-dev \
libssl-dev \
pkgconf \
zlib1g-dev

wget http://de.archive.ubuntu.com/ubuntu/pool/main/p/protobuf/libprotoc32_3.21.12-1ubuntu7_amd64.deb -P "$WORKSPACE_DIR"
wget http://de.archive.ubuntu.com/ubuntu/pool/main/r/re2/libre2-10_20230201-1_amd64.deb -P "$WORKSPACE_DIR"
wget http://de.archive.ubuntu.com/ubuntu/pool/main/a/abseil/libabsl20220623_20220623.1-1_amd64.deb -P "$WORKSPACE_DIR"
wget http://de.archive.ubuntu.com/ubuntu/pool/universe/g/grpc/libgrpc++1.51_1.51.1-3build3_amd64.deb -P "$WORKSPACE_DIR"
wget http://de.archive.ubuntu.com/ubuntu/pool/universe/g/grpc/libgrpc29_1.51.1-3build3_amd64.deb -P "$WORKSPACE_DIR"
wget http://de.archive.ubuntu.com/ubuntu/pool/main/p/protobuf/libprotobuf32_3.21.12-1ubuntu7_amd64.deb -P "$WORKSPACE_DIR"
wget http://de.archive.ubuntu.com/ubuntu/pool/main/a/abseil/libabsl-dev_20220623.1-1_amd64.deb -P "$WORKSPACE_DIR"
wget http://de.archive.ubuntu.com/ubuntu/pool/universe/g/grpc/libgrpc-dev_1.51.1-3build3_amd64.deb -P "$WORKSPACE_DIR"
wget http://de.archive.ubuntu.com/ubuntu/pool/universe/g/grpc/libgrpc++-dev_1.51.1-3build3_amd64.deb -P "$WORKSPACE_DIR"

sudo dpkg -i "$WORKSPACE_DIR"/libre2-10_20230201-1_amd64.deb
sudo dpkg -i "$WORKSPACE_DIR"/libabsl20220623_20220623.1-1_amd64.deb
sudo dpkg -i "$WORKSPACE_DIR"/libabsl-dev_20220623.1-1_amd64.deb
sudo dpkg -i "$WORKSPACE_DIR"/libprotobuf32_3.21.12-1ubuntu7_amd64.deb
sudo dpkg -i "$WORKSPACE_DIR"/libprotoc32_3.21.12-1ubuntu7_amd64.deb
sudo dpkg -i "$WORKSPACE_DIR"/libgrpc29_1.51.1-3build3_amd64.deb
sudo dpkg -i "$WORKSPACE_DIR"/libgrpc++1.51_1.51.1-3build3_amd64.deb
sudo dpkg -i "$WORKSPACE_DIR"/libgrpc-dev_1.51.1-3build3_amd64.deb
sudo dpkg -i "$WORKSPACE_DIR"/libgrpc++-dev_1.51.1-3build3_amd64.deb

# Download DPDK
wget http://git.dpdk.org/dpdk/snapshot/dpdk-${DPDK_VER}.zip -P "$WORKSPACE_DIR" > /dev/null 2>&1
cd "$WORKSPACE_DIR" && unzip dpdk-${DPDK_VER}.zip > /dev/null 2>&1

DPDK_DIR="$WORKSPACE_DIR"/dpdk-${DPDK_VER}

# Copy DPDK patches
cd $DPDK_DIR && patch -p1 < "$REPO_ROOT"/hack/dpdk_22_11_gcc12.patch
cd $DPDK_DIR && patch -p1 < "$REPO_ROOT"/hack/dpdk_22_11_log.patch
cd $DPDK_DIR && patch -p1 < "$REPO_ROOT"/hack/dpdk_22_11_telemetry_key.patch
cd $DPDK_DIR && patch -p1 < "$REPO_ROOT"/hack/dpdk_22_11_ethdev_conversion.patch

# Compile DPDK
cd $DPDK_DIR && meson setup -Dmax_ethports=132 -Dplatform=generic -Ddisable_drivers=common/dpaax,\
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
vhost,gpudev build -Ddisable_apps="*" -Dtests=false > /dev/null 2>&1
cd $DPDK_DIR/build && ninja > /dev/null 2>&1
cd $DPDK_DIR/build && sudo ninja install > /dev/null 2>&1

sudo ldconfig

# Build dpservice
cd "$REPO_ROOT"

# Compile dpservice-bin itself
meson setup build $DPSERVICE_FEATURES && ninja -C build

meson setup release_build $DPSERVICE_FEATURES --buildtype=release && ninja -C release_build
CC=clang CXX=clang++ meson setup clang_build $DPSERVICE_FEATURES && ninja -C clang_build
meson setup xtratest_build $DPSERVICE_FEATURES -Denable_tests=true && ninja -C xtratest_build

sudo ldconfig

"$REPO_ROOT"/hack/rel_download.sh -dir=client -owner=ironcore-dev -repo=dpservice-cli -strip=2 -pat=$GITHUB_TOKEN

ls -la "$REPO_ROOT"

cd "$REPO_ROOT"

echo "finding dpservice-bin"
find . -name "dpservice-bin"
ls -al "$REPO_ROOT"/build/

#cp "$WORKSPACE_DIR"/build/src/dpservice-bin "$REPO_ROOT"/build/src/dpservice-bin
#cp "$WORKSPACE_DIR"/client/* "$REPO_ROOT"/build/
#cp "$WORKSPACE_DIR"/xtratest_build/src/dpservice-bin "$REPO_ROOT"/xtratest_build/src/dpservice-bin
#cp "$WORKSPACE_DIR"/client/* "$REPO_ROOT"/xtratest_build

export PYTHONUNBUFFERED=1
sudo "$REPO_ROOT"/test/runtest.py "$REPO_ROOT"/build "$REPO_ROOT"/xtratest_build
