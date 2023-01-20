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
In some configurations, additional kernel command-line option is needed: `vfio_iommu_type1.allow_unsafe_interrupts=1`, [see above](#enabling-iommu) for the actual commands to use.

Alternatively you can do this in module configuration (`/etc/modprobe.d/onmetal.conf`):
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
For reading and writing Mellanox firmware options, `mstflint` command-line tool can be used (should be part of your distro's package tree). You can also use the offical [nVidia OFED counterpart](#nvidia-ofed).

To query firmware values use `mstflint -d <pci-device-address> q`, to write values use `mstflint -d <pci-device-address> set KEY1=value KEY2=value ...` or the appropriate `mlxconfig` equivalent.

### Enabling SR-IOV
Firmware value `SRIOV_EN` needs to be `True` and `NUM_OF_VFS` needs to be non-zero. Some cards may also require `UCTX_EN` to be `False` (ConnectX-4 Lx), otherwise DPDK will fail to establish default flows.


## Building DPDK
As DPDK automatically detects present libraries and only build the necessary (compatible) parts. You need to install libraries for DPDK to use to be compatible with Mellanox cards.

On Debian, the only required package should be `libiverbs-dev`, on Gentoo it's part of the `rdma-core` package. DPDK may require you to also install `pkgconfig` for it to be able to locate the library on your system.

Don't forget to rebuild and reinstall DPDK after installing these.


## Running dp-service
For convenience, there is a `prepare.sh` shell script in `hack/` that prepares the interfaces and memory, and generates a config file that the service can use, removing the necessity to provide the right command-line options for running the service with Mellanox NICs (and their virtual interfaces).

This script uses the IPv6 address assigned to your loopback interface as the underlay address for uplink traffic of dp-service.


## Caveats
Keep in mind, that many NICs require a working connection on their ports to actually put the ports up, i.e. connect them to a switch before looking for a problem elsewhere.
