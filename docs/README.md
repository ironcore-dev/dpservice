# Dataplane Service (dp-service)

## Overview
This is a beta version which
- Uses [DPDK Graph Framework](https://doc.dpdk.org/guides/prog_guide/graph_lib.html) for the data plane. DPDK version 24.11 LTS or compatible needed.
- [rte_flow](https://doc.dpdk.org/guides/prog_guide/rte_flow.html) offloading between the virtual network interfaces on a single heypervisor.
- Uses GRPC to add virtual interfaces, loadbalancers, NAT Gateways and routes. There is a golang based GRPC
test client (CLI) which can connect to the GRPC server
- Supports DHCPv4, DHCPv6, Neighbour Discovery, ARP protocols (sub-set implementations.).
- Has IPv4 overlay and IPv6 underlay support. IPv6 overlay support in progress.
- Supports [high-availability](ha/)
