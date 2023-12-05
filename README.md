# Dataplane Service

[![REUSE status](https://api.reuse.software/badge/github.com/ironcore-dev/dpservice)](https://api.reuse.software/info/github.com/ironcore-dev/dpservice)
[![GitHub License](https://img.shields.io/static/v1?label=License&message=Apache-2.0&color=blue)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://makeapullrequest.com)

## Overview 

Dataplane Service in short form dp-service is a L3 virtual router with basic L2 capabilites and with IP in IPv6 tunneling for the uplink traffic. It uses [SRIOV](https://en.wikipedia.org/wiki/Single-root_input/output_virtualization) based Virtual Functions as its virtual ports. A virtual machine or a bare metal machine (In case dp-service running directly on SmartNIC) can be plugged to SRIOV VFs.

- It can operate in offloaded and non-offloaded mode.
  - Offload mode means first packet of each flow flowing over dp-service will be handled in software and then the flow will be offloaded to the hardware. (Using [DPDK](https://core.dpdk.org/doc/) rte_flow)
  - Non-offloaded mode handles the whole traffic in software using [PMD](https://doc.dpdk.org/guides/prog_guide/poll_mode_drv.html) drivers and dedicated CPU cores.

- Uses [DPDK Graph Framework](https://doc.dpdk.org/guides/prog_guide/graph_lib.html) for the data plane.
- [rte_flow](https://doc.dpdk.org/guides/prog_guide/rte_flow.html) offloading between the Virtual Machines(VMs) on a single hypervisor and ip in ipv6 decap/encap offloading between hypervisors.
- GRPC support to add virtual network interfaces and routes. There is a C++ based GRPC
  test client (CLI) which can connect to the GRPC server. See the examples under [docs](/docs).
- There is also a golang based [GRPC client](https://github.com/ironcore-dev/dpservice-cli) which is easier to used.
- A kubernetes controller abstraction on top of the provided GRPC interface is availiable as well. It is called [metalnet](https://github.com/ironcore-dev/metalnet).
- DHCPv4, DHCPv6, Neighbour Discovery, ARP protocols supported (Sub-set implementations.).
- IPv4 and limited IPv6 overlay support.
- Virtual IP support for the virtual network interfaces.
- Loadbalancer support.
- Horizantally scalable NAT Gateway support.
- Automated test support with [pytest](https://docs.pytest.org/) and [scapy](https://scapy.net/).

## Installation, using and developing 

For more details please refer to documentation folder [docs](/docs) 

## Contributing 

We`d love to get a feedback from you. 
Please report bugs, suggestions or post question by opening a [Github issue](https://github.com/ironcore-dev/dpservice/pulls)

## License

[Apache License 2.0](/LICENSE)
