# Testing performance
Performace testing of dp-service can be carried out in several ways, including more traditional methods (iperf) and stress-tests relying on DPDK (pktgen).

## iPerf
On one VM (server):
```
iperf -s
```

On the other VM (client):
```
iperf -c <server IP> -i1
```

> Iperf tests usually cannot generate traffic at line rate to fully discover the capacity of DPDK applications.

## Pktgen
To perform stress tests, the current solution is to use [pktgen](https://pktgen-dpdk.readthedocs.io/en/latest/) inside virtual machines. One is for generating traffic and the other one is for observing incoming flow rates.

### Installing pktgen
To install pktgen inside a VM, DPDK and related libraries and NIC-related drivers need to be installed and working. To achieve this, please follow the instructions for [building](../development/building.md) and [running](../development/running.md) of dp-service, stopping at the point of actually using dp-service (since pktgen is 'just' another DPDK application, like dp-service).

Additionaly, DPDK for pktgen needs to be installed with `libpcap-dev` and `libnuma-dev` (and `libibverbs-dev` for Mellanox cards). After DPDK is installed, pktgen can be compiled and installed as follows:

```
wget https://github.com/pktgen/Pktgen-DPDK/archive/refs/tags/pktgen-21.11.0.zip
unzip pktgen-21.11.0.zip
cd Pktgen-DPDK-tags-pktgen-21.11.0
make
cp usr/local/bin/pktgen /usr/local/bin/
```

This guide is using the same DPDK for Pktgen as for dp-service. If you want to use newer DPDK and pktgen, build and install using `meson build && ninja -C build && sudo ninja -C build install` instead.

### Using pktgen
To run, pktgen (as any DPDK application) requires [hugepages](../development/running.md#huge-pages). Also make sure the VM's CPU supports SSSE3.

To generate traffic, start pktgen like this (see [pktgen docs](https://pktgen-dpdk.readthedocs.io/en/latest/usage_pktgen.html) for explanation).

```
pktgen -l 1-4 -n 2  -- -P -m '[2-5].0' -T -f test.conf
```

The `test.conf` file is an example provided here to generate UDP traffic in one direction, for details see [pktgen docs](https://pktgen-dpdk.readthedocs.io/en/latest/commands.html#runtime-options-and-commands):
```
stop 0
set 0 rate 40
set 0 ttl 3
set 0 proto udp
set 0 src mac be:41:c3:aa:10:54 
set 0 dst mac ab:cd:00:00:00:01
set 0 dst ip <dst_vm_ip>
set 0 src ip <src_vm_ip>/32
set 0 size 128
start 0
```
To run pktgen on the receiving side, you can use this file and simply switch `src` and `dst`.

## VTune by Intel
In addition to the above described stress test, it is also possible to [profile](https://www.intel.com/content/www/us/en/developer/articles/technical/profile-dpdk-with-intel-vtune-amplifier.html) DPDK applications' code. 

An official docker [image](https://hub.docker.com/r/intel/oneapi-vtune) is provided. Thus start this docker image with `sudo docker run -it --rm --net host -v /home/tli/.ssh:/etc/ssh -d intel/oneapi-vtune vtune-backend --allow-remote-access`, and its URL to log in can be found in the container's log. The steps to run a profiling test can be found [here](https://www.intel.com/content/www/us/en/develop/documentation/get-started-with-vtune/top/linux-os.html).

One limitation for such code profiler for the DPDK application is that the identified function that consumes many CPU cycles may not be a complex function, but due to too many repetitions of it during the CPU polling without actual incoming packets. Thus, this code profiling is used as a first impression on code complexity. In the end, the actual stress tests using packet injection matters.


# Performance optimization (non-offloading)
Several aspects can be explored to perform such host optimization. Intel provides an official [documentation](http://doc.dpdk.org/guides/prog_guide/writing_efficient_code.html) and a [blog](https://www.intel.com/content/www/us/en/developer/articles/guide/dpdk-performance-optimization-guidelines-white-paper.html) dedicated for this topic. 
We highlight several points that were tested and summarize their impacts. 

## Host optimization
A proper running environment is important to achieve good performance. Two important host optimization directions are:

### Numa
Enforce to use CPU cores that share the socket with NIC. This optimization can enable observable performance enhancement.

Use the following command to find out NIC's numa node: `cat /sys/bus/pci/devices/0000\:06\:00.0/numa_node`

And check the numa node attachment of CPU cores: `/dpdk/usertools/cpu_layout.py`

### CPU isolation
Isolating CPU core that is used by DPDK application and removing it from Linux scheduler is mentioned in the above optimization document. The experiment was carried out on a lenovo machine as follows:
1. Add `isolcpus=2` to `GRUB_CMDLINE_LINUX_DEFAULT` in `/etc/default/grub`,
2. run `update-grub` to make it take effect,
3. reboot.

This approach does not bring observable performance enhancement. It is possibly due to it is experimented on a machine with few tasks.

## Compilation optimization
By default, DPDK library is configured to compile as the release mode. dp-service needs to be configured in the release mode as well using `meson build --buildtype=release`.

This brings observable performance enhancement.

Additional flags (-march=native -mcpu=native -mtune=native) to compile source code for the native platform can be also added into meson build file. 
```
project('dp_service', 'c', 'cpp',
  default_options: ['c_args=-Wno-deprecated-declarations -march=native -mcpu=native -mtune=native -Werror -Wno-format-truncation', 'cpp_args=-fpermissive'],
  ...
```

This does not bring observable performance enhancement.

## Hash lookups
Hash lookups in the hot code path of packet processing contribute most to the performance optimization so far. Careless usage of hash lookups can bring performance penalty at the level of one million pkts per second. The reason is that, the hash computation over the key consumes non-neglectable CPU cycles, which is supported by the data from [Intel](https://www.intel.com/content/www/us/en/developer/articles/guide/dpdk-performance-optimization-guidelines-white-paper.html) and a small [experiment](https://gist.github.com/anubhav-choudhary/c0d83d882fa0e871323a1ec5eeb8d86d). It is necessary to avoid unnecessary hash computation and use short hash keys. 

Reducing the number of accessing hash tables by performing batch lookups seems to be able to improve the performance. One potential function is `rte_hash_lookup_bulk_data`.
But in practice, the control logic that partitions incoming pkts and tracks different processing results brings more penalty than benefits of memory accessing.

### Hash function selection
DPDK offers multiple hashing functions. Some of them are optimized based on the key length. A helper function `dp_create_jhash_table()` already selects the proper function automatically.

## Graph node
Using the graph node framework also brings non-negligible performance penalty, due to the movement of pkts among nodes. Under the assumption of retaining the number of the graph nodes in dp-service, optimizing the approach of handling packets in each node is the direction to go.

### Move pkts more efficiently
Avoiding to move packets one by one from one node to another can bring observable peformance enhancement. One of the ways is to use functions like `rte_node_next_stream_move`. But due to the fact that you have to give hints on the most highly possible next node, it is applicable for some nodes with few next node options.
