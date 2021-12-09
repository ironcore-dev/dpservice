# Dataplane Service
 [![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com) 
[![GitHub License](https://img.shields.io/static/v1?label=License&message=Apache-2.0&color=blue&style=flat-square)](LICENSE)

## Overview 
This is an early beta version which:  
- Uses [DPDK Graph Framework](https://doc.dpdk.org/guides/prog_guide/graph_lib.html) for the data plane.
- Uses a private pointer in [mbuf](https://doc.dpdk.org/guides/prog_guide/mbuf_lib.html#dynamic-fields-and-flags) structure to carry offloading rte_flow
data around.
- [rte_flow](https://doc.dpdk.org/guides/prog_guide/rte_flow.html) offloading between the Virtual Machines(VMs) on a single heypervisor.
- GRPC support to add VMs and routes. There is a C++ based GRPC
test client (CLI) which can connect to the GRPC server. See the examples below.
- DHCPv4, DHCPv6, Neighbour Discovery, ARP protocols supported (Sub-set implementations.).
- Currently IPv4 overlay and IPv6 underlay support. IPv6 overlay support in progress.

## Installation, using and developing 

For more details please refer to documentation folder [docs](/docs) 

## Contributing 

We`d love to get a feedback from you. 
Please report bugs, suggestions or post question by opening a [Github issue](https://github.com/onmetal/net-dpservice/pulls)

## License

[Apache License 2.0](/LICENSE)


