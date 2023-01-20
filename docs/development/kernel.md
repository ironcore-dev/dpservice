# Kernel configuration
This guide is intended for machines running a custom-built or minimalistic kernel. Most distros should have the kernel configured in a way that supports Dataplane Service and DPDK out of the box. The act of configuring the kerner will not be covered as it is out of the scope of this documentation.

Keep in mind that it is not easy to properly isolate all kernel options. Therefore there may be some missing from this guide due to them already being required by another part of the documenter's machine setup.


## Virtual interfaces
For [testing](../testing/) and experimenting, virtual network interfaces are recommended to have in your kernel. At least `CONFIG_TUN` for automated testing and `CONFIG_VETH` for some interesting manual setups. Also having network namespaces (`CONFIG_NET_NS`) is great unless you only want to use a smart switch for testing.

Automated tests also employ QoS and scheduling. The minimal set of options is `CONFIG_NET_SCH_MULTIQ`, `CONFIG_NET_SCH_NETEM`, and `CONFIG_NET_SCH_INGRESS`.


## VFIO drivers
To use most NICs in DPDK (e.g. Intel) and to use Mellanox's Virtual Functions, you need to have VFIO drivers: `CONFIG_VFIO`, `CONFIG_VFIO_PCI`. To actually use VFs in KVM you also need `CONFIG_KVM_VFIO`. DPDK also documents (but discourages) no-IOMMU mode, enabled via `CONFIG_VFIO_NOIOMMU`.


## Mellanox drivers
As Mellanox card drivers are implemented using InifiniBand, you need to enable at least `CONFIG_INFINIBAND`, `CONFIG_INFINIBAND_MLX5` (or `MLX4` based on your card) and `CONFIG_INFINIBAND_USER_ACCESS`.

Then of course you need to enable the driver itself, i.e. `CONFIG_MLX5_CORE`. To enable eswitch mode you also need `CONFIG_MLX5_ESWITCH` and `CONFIG_NET_SWITCHDEV`.

To support Virtual Functions in these cards, you need SR-IOV: `CONFIG_PCI_IOV` and if needed, `CONFIG_PCI_REALLOC_ENABLE_AUTO`.


## IOMMU
To properly support most cards, IOMMU is required: `CONFIG_IOMMU_SUPPORT`, `CONFIG_IOMMU_API` and `CONFIG_INTEL_IOMMU` (or the AMD variant).

If you do not want to edit kernel command-line (`intel_iommu=on iommu=pt`), you can enable it by default directly in the kernel: `INTEL_IOMMU_DEFAULT_ON` and `IOMMU_DEFAULT_PASSTHROUGH`.


## Hugepages
DPDK-based programs need hugepage allocations. Therefore `CONFIG_HUGETLBFS` is mandatory.


## High-Resolution Precision Event Timer
If you want to use this timer in your DPDK-based programs, enable `CONFIG_HPET` and `CONFIG_HPET_MMAP`.


## FS capabilities
To run `dp_service` as a user, [linux capabilites](https://man7.org/linux/man-pages/man7/capabilities.7.html) are employed. For that to happen, your filesystem needs to support security labels. For Ext4, the right option is `CONFIG_EXT4_FS_SECURITY`. Other filesystems should have a similar option available.


## Caveats
Remember that DPDK compilation depends on current machine setup. Recompile DPDK after replacing the kernel as some parts (drivers) may have changed and will prompt a new library to be compiled into DPDK installation.
