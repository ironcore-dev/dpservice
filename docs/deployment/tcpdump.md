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


## Dumping dp-service traffic
Unfortunately `tcpdump -i any` does not work for RDMA interfaces, specifying `mlx5_0` and later `mlx5_1` is the only way to see traffic for both physical ports (`mlx5_1` never shows any VF traffic).

### VF communication
To see VF-VF or VF-PF communication, i.e. overlay communication, you can simply use the standard `ip` BPF filtering as ususal, e.g. `tcpdump -n -i mlx5_0 "ip host 10.0.0.1"`.

### PF communication
To see PF communication (to/from the router), you can either look at the underlay communication and use `ip6` BPF filtering, as all VF communication is tunneled via IPIP tunneling.

To filter based on overlay communication (i.e. the actual IPv4 packets from earlier), an advanced filter is needed. Unfortunately tcpdump does not support tunneled filters, therefore raw packet addressing has to be used.

Example filter for IPv4 source IP in IPv6 tunnel: `ip6[52:4] = 0x01020304`, where the hex number is IPv4 in hexadecimal form.

There are helper functions for bash in `hack/tcpdump_helpers.inc` you can source and use instead: `tcpdump -n -i mlx5_0 "ip6 proto 4 and $(ipip_host 1.2.3.4)"`
