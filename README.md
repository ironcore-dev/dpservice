# Dataplane Service

[![REUSE status](https://api.reuse.software/badge/github.com/ironcore-dev/dpservice)](https://api.reuse.software/info/github.com/ironcore-dev/dpservice)
[![GitHub License](https://img.shields.io/static/v1?label=License&message=Apache-2.0&color=blue)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://makeapullrequest.com)

## New: IPsec for the underlay tunnel (proof of concept)

Underlay tunnel traffic can be encrypted with ESP, enabled at runtime with `--enable-ipsec`.
See [docs/concepts/ipsec.md](/docs/concepts/ipsec.md) for the full concept.

- ESP (AES-128-GCM, RFC 4106) over the existing IPv6 tunnel, framed by `librte_ipsec`; two new
  graph nodes, `ipsec_encap` and `ipsec_decap`. Refused together with hardware offloading.
  The crypto is done by DPDK's `crypto_openssl` software PMD, which - unlike the x86-only
  `ipsec_mb` family - is not architecture-specific, so this runs on arm64 as well as on x86.
- Security Associations are provisioned at runtime over gRPC - `Create`/`Get`/`DeleteSecurityAssociation`,
  also in `dpservice-cli`. See [the gRPC interface](/docs/concepts/ipsec.md#the-grpc-interface).
- Per-association **anti-replay window** (`replay_window`, ingress only, max 4096, off by default).
- **The egress SPI is the VNI** from where the packet is originating. This can be improved and can 
be looked up from a table filled during GRPC SA creation.
- Tested dpservice-to-dpservice: a full encrypted round trip against a scapy peer holding a
  different key per direction, with the SAs installed over gRPC by the test itself.
- Tested dpservice-to-Linux: `xtratest_ipsec_xfrm.py` runs the same round trip against a kernel
  XFRM peer in a namespace, and requires every `/proc/net/xfrm_stat` counter to stay zero.
- The replay window is exercised both ways: a replayed frame is asserted to be dropped against
  the scapy peer, and the XFRM round trip runs with a window of 64 to prove it interoperates.
- [`ipsec-xfrm/`](/ipsec-xfrm) - standalone Linux XFRM scripts demonstrating a per-VNI IPsec mesh
  with **SPI = VNI**, in network namespaces, independent of dpservice.
- Builds and runs in Docker: `docker build --target tester` gives an image whose `ipsec` suite
  runs alongside all the others.


## Overview

Dataplane Service in short form dpservice is a L3 virtual router with basic L2 capabilites and with IP in IPv6 tunneling for the uplink traffic. It uses [SRIOV](https://en.wikipedia.org/wiki/Single-root_input/output_virtualization) based Virtual Functions as its virtual ports. A virtual machine or a bare metal machine (In case dpservice running directly on SmartNIC) can be plugged to SRIOV VFs.

- It can operate in offloaded and non-offloaded mode.
  - Offload mode means first packet of each flow flowing over dpservice will be handled in software and then the flow will be offloaded to the hardware. (Using [DPDK](https://core.dpdk.org/doc/) rte_flow)
  - Non-offloaded mode handles the whole traffic in software using [PMD](https://doc.dpdk.org/guides/prog_guide/poll_mode_drv.html) drivers and dedicated CPU cores.

- Uses [DPDK Graph Framework](https://doc.dpdk.org/guides/prog_guide/graph_lib.html) for the data plane.
- [rte_flow](https://doc.dpdk.org/guides/prog_guide/rte_flow.html) offloading between the Virtual Machines(VMs) on a single hypervisor and ip in ipv6 decap/encap offloading between hypervisors.
- GRPC support to add virtual network interfaces and routes. There is a C++ based GRPC
  test client (CLI) which can connect to the GRPC server. See the examples under [docs](/docs).
- There is also a golang based [GRPC client](https://github.com/ironcore-dev/dpservice/tree/main/cli/dpservice-cli) which is easier to use.
- A kubernetes controller abstraction on top of the provided GRPC interface is availiable as well. It is called [metalnet](https://github.com/ironcore-dev/metalnet).
- DHCPv4, DHCPv6, Neighbour Discovery, ARP protocols supported (Sub-set implementations.).
- IPv4 and IPv6 overlay support.
- Virtual IP support for the virtual network interfaces.
- Loadbalancer support with maglev hashing.
- Horizantally scalable NAT Gateway support.
- Automated test support with [pytest](https://docs.pytest.org/) and [scapy](https://scapy.net/).

## Installation, using and developing

For more details please refer to documentation folder [docs](/docs)

## Contributing

We`d love to get a feedback from you.
Please report bugs, suggestions or post question by opening a [Github issue](https://github.com/ironcore-dev/dpservice/issues)

## Licensing

Copyright 2025 SAP SE or an SAP affiliate company and IronCore contributors. Please see our [LICENSE](/LICENSES) for
copyright and license information. Detailed information including third-party components and their licensing/copyright
information is available [via the REUSE tool](https://api.reuse.software/info/github.com/ironcore-dev/dpservice).

<p align="center"><img alt="Bundesministerium für Wirtschaft und Energie (BMWE)-EU funding logo" src="https://apeirora.eu/assets/img/BMWK-EU.png" width="400"/></p>
