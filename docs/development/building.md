# Building Dataplane Service from source

## Prerequisities

### Operating System
Dataplane service is only currently supported on Linux. Recent debian (or derivative) should work best.

### Toolchain
To [build DPDK](#dpdk) you should only need these packages:
```bash
sudo apt install meson build-essential python3-pyelftools
```
> DPDK has many optional features that are autodetected by Meson. You can install more libraries as needed, for example `libnuma-dev`, `libpcap-dev`, `libjansson-dev`, etc.

To [build dp-service](#building-the-service) you also need:
```bash
sudo apt install git pkgconf cmake protobuf-compiler-grpc libgrpc++-dev uuid-dev
```
For [automated testing](../testing/) (enabled via meson option `-Denable_tests=true`) also install:
```bash
sudo apt install python3-pytest python3-scapy
```

### DPDK
The dataplane service is built upon the [DPDK library](https://dpdk.org). Currently, the only supported version is 21.x, which most distros do not have in stable trees. Building from source also has the advantage of easier debugging later.
```bash
wget http://fast.dpdk.org/rel/dpdk-21.11.2.tar.xz
tar xf dpdk-21.11.2.tar.xz
cd dpdk-stable-21.11.2
meson setup build
ninja -C build
sudo ninja -C build install
sudo ldconfig
```
This is highly dependant on your installed libraries. If you want to use a Mellanox card for example, you need to install [specific libraries](mellanox.md#building-dpdk) too.

If you want to test DPDK's functionality, please refer to [DPDK documentation](http://core.dpdk.org/doc/quick-start/).

Some systems do not put the resulting (installed) `pkgconf` directory with DPDK's information into `PKG_CONFIG_PATH`. This results in meson complaining about missing DPDK dependency when [building the service](#building-the-service). If that happens, add the right path according to your systems guidelines, e.g. put `PKG_CONFIG_PATH="/usr/local/lib64/pkgconfig"` into `/etc/env.d/99dpdk`).

> To support high number of connected VMs in dp-service, use `meson setup -Dmax-ethports=` to specify the maximum number of ports to be supported. The default is 32.


## Building the service
```bash
git clone https://github.com/onmetal/net-dpservice.git
cd net-dpservice/
meson setup build
ninja -C build
```
Now you can try [running the service](running.md).

### Usermode dpservice
For [easier debugging](debugging.md) you can configure meson to build additional `dp_service_user` binary that does not require root privileges to run.
```bash
meson setup --reconfigure -Denable_usermode=true build
ninja -C build
```
You need `sudo` configured to enable you to run `setcap`. You will be prompted for it at the end of the build unless you configure it to not require one in `/etc/sudoers.d/dpservice`:
```bash
username ALL=(root) NOPASSWD: /usr/sbin/setcap
```
