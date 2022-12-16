# Data Plane Development Kit
The Dataplane Service is built upon the DPDK library. It is recommended for developers to familiarize themselves with [its documentation](http://core.dpdk.org/doc/). This page should highlight the essential parts of it to focus on.

To build your own DPDK please refer to the [building documentation](building.md).


## Basic functionality
After reviewing the documentation structure and getting started guides, see the [Programmer's guide](http://doc.dpdk.org/guides/prog_guide/overview.html)

Parts of the runtime environment that are heavily used are:
 - [EAL - Environment Abstraction Layer](http://doc.dpdk.org/guides/prog_guide/env_abstraction_layer.html)
 - [Service Cores](http://doc.dpdk.org/guides/prog_guide/service_cores.html)
 - [Ring Library](http://doc.dpdk.org/guides/prog_guide/ring_lib.html)
 - [Mempool Library](http://doc.dpdk.org/guides/prog_guide/mempool_lib.html)
 - [Mbuf Library](http://doc.dpdk.org/guides/prog_guide/mbuf_lib.html)
 - [Timer Library](http://doc.dpdk.org/guides/prog_guide/timer_lib.html)


## Network Interfaces
DPDK works with NICs using [PMDs (Poll-Mode Drivers)](http://doc.dpdk.org/guides/prog_guide/poll_mode_drv.html). To leverage their full potential for running VMs, [SR-IOV and Switch Representation](http://doc.dpdk.org/guides/prog_guide/switch_representation.html) is key.


## Packet Processing
For increased abstraction, dp-service uses [Graph Architecture](http://doc.dpdk.org/guides/prog_guide/graph_lib.html) for data processing.

To implement hardware offloading of processing packets, [Flow API](http://doc.dpdk.org/guides/prog_guide/rte_flow.html) is being used.

