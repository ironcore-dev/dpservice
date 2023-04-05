# Dataplane service packet analysis using tcpdump
Due to the fact, that dp-service uses DPDK and thus a poll-mode driver (PMD) instead of kernel network stack, traditional tools are unable to see traffic passing through dp-service-bound network cards.

## Offloaded mode
Unfortunately, there is no way to see traffic going directly through the card itself as it never enters the host's I/O layer.

## Non-offloaded mode
Normally, all traffic goes though the PMD and is accessed by the host's CPU via RDMA (Remote Direct Memory Access). `libpcap` (the library tcpdump uses) has support for RDMA devices and can use hardware-specific bindings to provide a virtual network interface for tcpdump (and other libpcap-based tools) to listen on.

For Mellanox cards, such interfaces are usually `mlx5_0` and `mlx5_1` (given that the kernel driver used is `mlx5`). `mlx5_0` then shows traffic for the first physical port and **all** virtual ports (VMs) in one stream. `mlx5_1` only shows traffic for the secondary physical port.

This support is not enabled by default though.

### Enabling RDMA support in libpcap
If `libibverbs` library is installed during configuration and compilation of `libpcap`, RDMA support gets compiled-in. As this is not the case for packages provided by the standard distributions' package trees, `libpcap` needs to be recompiled manually.

#### Debian
A good place to start with is the [building tutorial](https://wiki.debian.org/BuildingTutorial). There is no need to actually do any changes whatsoever, just make sure `libibverbs-dev` is installed first and then build `libpcap0.8` from source and install it using `dpkg -i`.

To prevent the system from re-installing the original package, you need to provide a repository do download the manually-compiled package from. The simplest way is to use [a local repository](https://wiki.debian.org/DebianRepository/Setup#Quick_instructions_to_create_a_trivial_local_archive_with_apt-ftparchive).

### AppArmor
Because of the changed behavior of custom-built tcpdump package, changes to AppArmor rules are needed. On Debian this is done easily by adding rules to `/etc/apparmor.d/local/usr.bin.tcpdump`:
```
  /etc/libibverbs.d/ r,
  /etc/libibverbs.d/* r,
  /dev/infiniband/* rw,
```
