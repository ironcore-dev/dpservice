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


## Graph source list
Every port has an Rx node (`rx-<port>-<queue>`), which DPDK calls as a source node on every graph walk. To not call the Rx nodes of VFs without an interface, the worker disables them with `rte_graph_source_node_enable()` between walks (`dp_graph_update_sources()` in `graph_main_loop()`, after `dp_start_port()` or `dp_stop_port()` changed a port). PFs, `rx_periodic` and `sync` always run. Graph statistics (calls, cycles) of a disabled Rx node do not advance.

`rte_graph_source_node_enable()` is not part of DPDK, it is added by `hack/dpdk_25_11_graph_source_enable.patch`. On a DPDK update, it is rebased like the other patches in `hack/`.

To check that it works, start dpservice with `sudo ./dp_service.py` in `test/local` (creates the interfaces of VM1 to VM3 only) and query the graph call counts twice a few seconds apart (see [telemetry](../deployment/telemetry.md)): `echo "/dp_service/graph/call_count,0" | socat - UNIX:/var/run/dpdk/rte/dpdk_telemetry.v2,socktype=5`. `rx-5-0` (VM4, no interface) must stay at 0 while `rx-2-0` (VM1) grows.
