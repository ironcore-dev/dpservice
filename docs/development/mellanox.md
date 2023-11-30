# Mellanox-specific information
If you want to build DPDK and/or dp-service on a computer with Mellanox NIC, use this additional info along with the basic guides.


## nVidia OFED
The nVidia OpenFabrics Enterprise Distribution for Linux privides a [set of tools and drivers](https://network.nvidia.com/products/infiniband-drivers/linux/mlnx_ofed/) for Mellanox cards. It is the official way supported by nVidia, but the kernel community has already made enough progress that you can use mainline drivers and FOSS alternatives.

This guide therefore does not utilize this package.


## Kernel setup
Default recent kernel in Debian (tested with 5.15.75) works well out of the box. In case of having problems see [here](kernel.md#mellanox-drivers).


## Enabling IOMMU
To bind virtual interfaces into VMs, [VFIO](https://docs.kernel.org/driver-api/vfio.html) is needed. For proper operation [IOMMU](https://en.wikipedia.org/wiki/Input%E2%80%93output_memory_management_unit) needs to be enabled.

The easiest way is via kernel command-line:
```
sudo sed -i -r 's/GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="intel_iommu=on iommu=pt /' /etc/default/grub
sudo update-grub
```
Of course, for AMD processors, use `amd_iommu=on` instead.

The other way is enabling IOMMU by default directly in [the kernel](kernel.md#iommu).

### Enable unsafe interrupts
In some older configurations, additional kernel command-line option is needed: `vfio_iommu_type1.allow_unsafe_interrupts=1`, [see above](#enabling-iommu) for the actual commands to use.

Alternatively you can do this in module configuration (`/etc/modprobe.d/ironcore.conf`):
```
options vfio_iommu_type1 allow_unsafe_interrupts=1
```

Alternatively you can do this temporarily at runtime via `echo 1 > /sys/module/vfio_iommu_type1/parameters/allow_unsafe_interrupts`.

### IOMMU groups isolation
In rare cases (mostly indicating old/inadequate hardware), all virtual interfaces will be put into one IOMMU group. This will stop VMs from binding them. As a last resort you may want to try ACS override kernel patch. Due to the nature of it, it will not be documented here further as it requires you to really know what you are doing and be aware of severe security risks.


## Enabling SR-IOV
To create virtual interfaces, Mellanox cards use [SR-IOV](https://en.wikipedia.org/wiki/Single-root_input/output_virtualization). This should be enabled by default in your kernel.

In some hardware however, `pci=realloc` kernel command-line parameter is required (or `CONFIG_PCI_REALLOC_ENABLE_AUTO` kernel option to be built-in). [See above](#enabling-iommu) for the actual commands to use.


## Firmware configuration
For reading and writing Mellanox firmware options, `mlxconfig` command-line tool is needed. This is part of the offical [nVidia OFED package](#nvidia-ofed), which can be hard to install and overrides your kernel mainline NIC drivers, which is not the way dp-service is deployed. An open-source package `mstflint` can be used instead (should be part of your distro's package tree). Some motherboards support setting Mellanox values in BIOS too.

To query firmware values use `mstconfig -d <pci-device-address> q`, to write values use `mstconfig -d <pci-device-address> set KEY1=value KEY2=value ...`.

### Enabling SR-IOV
For dp-service to properly function as a virtual router for VMs running on a host, firmware value `SRIOV_EN` needs to be `True` and `NUM_OF_VFS` needs to be non-zero (set to the number of VMs that will be run).

### Setting UCTX (Nvidia DevX)
Having User Context Objects (DevX) enabled seems to impact I/O privileges on the NIC, especially for non-root users. If you find any specific documentation to explain this, please add the info here.

Running dp-service on ConnectX-4 Lx requires `UCTX_EN` to be `False`, otherwise DPDK will fail to establish default flows.

Running dp-service on ConnectX-6 Lx with offloading requires `UCTX_EN` to be `True`, otherwise hairpins to PF1 will fail to initialize.

Running dp-service on ConnectX-6 Lx in user-mode (non-root) requires `UCTX_EN` to be `False`, otherwise PF to VF traffic is not working at all. Offloading is not possible then.


## Building DPDK
As DPDK automatically detects present libraries and only build the necessary (compatible) parts. You need to install libraries for DPDK to use to be compatible with Mellanox cards.

On Debian, the only required package should be `libiverbs-dev`, on Gentoo it's part of the `rdma-core` package. DPDK may require you to also install `pkgconfig` for it to be able to locate the library on your system.

Don't forget to rebuild and reinstall DPDK after installing these.


## Running dp-service
For convenience, there is a `prepare.sh` shell script in `hack/` that prepares the interfaces and memory, and generates a config file that the service can use, removing the necessity to provide the right command-line options for running the service with Mellanox NICs (and their virtual interfaces). The is also a [systemd unit file](running.md#mellanox-cards) you can use.

This script uses the IPv6 address assigned to your loopback interface as the underlay address for uplink traffic of dp-service.


## Caveats
Keep in mind, that many NICs require a working connection on their ports to actually put the ports up, i.e. connect them to a switch before looking for a problem elsewhere.

### MTU
Because of the fact, that dp-service uses IP-IP tunnel, the VM's MTU must be smaller than the host's to accomodate an IPv6 header. This can be done either by lowering the MTU of all VMs or by using jumbo-frames on the host:
```bash
ip link set enp3s0f0np0 mtu 9100
ip link set enp3s0f1np1 mtu 9100
```
