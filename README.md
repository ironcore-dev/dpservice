Dataplane Service
=================
This is an early beta version which 
- Uses [DPDK Graph Framework](https://doc.dpdk.org/guides/prog_guide/graph_lib.html) for the data plane.
- Uses a private pointer in [mbuf](https://doc.dpdk.org/guides/prog_guide/mbuf_lib.html#dynamic-fields-and-flags) structure to carry offloading rte_flow
data around.
- [rte_flow](https://doc.dpdk.org/guides/prog_guide/rte_flow.html) offloading between the Virtual Machines(VMs) on a single heypervisor.
- GRPC support to add VMs and routes. There is a C++ based GRPC
test client (CLI) which can connect to the GRPC server. See the examples below.
- DHCPv4, DHCPv6, Neighbour Discovery, ARP protocols supported (Sub-set implementations.).
- Currently IPv4 overlay and IPv6 underlay support. IPv6 overlay support in progress.

Prerequisites
-------------

Working DPDK installation to link to and a SmartNIC to 
operate on. (Currently only Mellanox)

Building
--------

This project uses meson and ninja to build the C application. On the top level directory:

    meson build
    ninja -C build

Run the application as root or use sudo:

    sudo ./build/src/dpservice -l 0,1 -- --pf0=ens1f0np0 --pf1=ens1f1np1 --ipv6=2a10:afc0:e01f:209::
pf0 and pf1 are the ethernet names of the uplink ports of the hypervisor on the smartnic. ipv6 is the underlay ipv6 address which should be used by the DP service for egress packets leaving the smartnic.


How to use GRPC test client
--------
### Add Virtual Machine
	./build/test/dp_grpc_client --addmachine 1 --vni 100 --ipv4 172.32.4.9
This adds a virtual machine with VNI 100 (Virtual Network Identifier) and IPv4 overlay 172.32.4.9
### Add Route
	./build/test/dp_grpc_client --addroute 1 --vni 100 --ipv4 192.168.129.0 --length 24 --t_vni 200 --t_ipv6 2a10:afc0:e01f:209::
This adds a route to VNI 100 with overlay prefix 192.168.129.0/24 on the current hypervisor which can be routed to a vni 200 on another hypervisor with an underlay IPv6 address 2a10:afc0:e01f:209::

License
-------
Licensed under [Apache License v2](LICENSE).

Copyright 2021 by the Gardener on Metal maintainers.
