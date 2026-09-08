# Dataplane Service

[![REUSE status](https://api.reuse.software/badge/github.com/ironcore-dev/dpservice)](https://api.reuse.software/info/github.com/ironcore-dev/dpservice)
[![GitHub License](https://img.shields.io/static/v1?label=License&message=Apache-2.0&color=blue)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://makeapullrequest.com)

## New: IPsec for the underlay tunnel (proof of concept)

Underlay tunnel traffic can be encrypted with ESP. `--enable-ipsec` brings up the crypto
subsystem, and a per-interface `encrypt` flag decides which traffic is protected; both are off by
default. See [docs/concepts/ipsec.md](/docs/concepts/ipsec.md) for the full concept.

- ESP (AES-GCM, RFC 4106) over the existing IPv6 tunnel, framed by `librte_ipsec`; two new
  graph nodes, `ipsec_encap` and `ipsec_decap`. Refused together with hardware offloading.
  The crypto is done by DPDK's `crypto_openssl` software PMD, which - unlike the x86-only
  `ipsec_mb` family - is not architecture-specific, so this runs on arm64 as well as on x86.
- Security Associations are provisioned at runtime over gRPC -
  `Create`/`Get`/`Update`/`DeleteSecurityAssociation`, also in `dpservice-cli`. See
  [the gRPC interface](/docs/concepts/ipsec.md#the-grpc-interface), and
  [a copy-paste walkthrough](/docs/concepts/ipsec_example.md) of the whole API on TAP devices.
- **Encryption is a property of the interface**, set on `CreateInterface` or toggled at runtime
  with `Enable`/`Disable`/`GetInterfaceEncryption`. It is symmetric: an encrypting interface
  neither sends nor accepts underlay traffic in the clear, so both ends of a tunnel must agree.
  An encrypting interface with no association drops rather than falling back to cleartext.
- Per-association **anti-replay window** (`replay_window`, ingress only, max 4096, off by default).
- Per-association **extended sequence numbers** (`esn`, RFC 4304, off by default) and a choice of
  **AES-128-GCM or AES-256-GCM** (`algorithm`), both covered in each direction by the test suite.
- An association is named by its **VNI, SPI, direction and underlay address pair**, and all five
  are matched. What it is found under depends on the direction - the VNI on egress, since a packet
  is not ESP yet and has no SPI to read, and the SPI on ingress - so the value in the ESP header
  is free of the VNI. See [ADR 0004](/docs/adr/0004-the-lookup-spi-is-not-the-wire-spi.md).
- An **ingress association is bound to its VNI**: `ipsec_decap` resolves the endpoint the frame is
  addressed at and drops it if that endpoint belongs to another tenant, so one association does not
  authorise delivery into every interface on the host. See
  [ADR 0005](/docs/adr/0005-ingress-associations-are-bound-to-their-vni.md).
- **Rekeying is gapless, and the two directions rotate differently.** An egress association is
  found under its VNI, so it is *replaced* in place - `UpdateSecurityAssociation` switches key and
  wire SPI together, between two packets. Ingress associations are found under the SPI on the
  frame, so several coexist: the new one is added beside the live one and the old one deleted once
  the peer has switched. Ordering the two ends is the control plane's job. See
  [ADR 0006](/docs/adr/0006-egress-associations-are-rekeyed-by-replacement.md).
- Tested dpservice-to-dpservice: a full encrypted round trip against a scapy peer holding a
  different key and SPI per direction, with the SAs installed over gRPC by the test itself.
- Tested dpservice-to-Linux: `xtratest_ipsec_xfrm.py` runs the same round trip against a kernel
  XFRM peer in a namespace, and requires every `/proc/net/xfrm_stat` counter to stay zero.
- The replay window is exercised both ways: a replayed frame is asserted to be dropped against
  the scapy peer, and the XFRM round trip runs with a window of 64 to prove it interoperates.
- Tested rekeying: `xtratest_ipsec_rekey.py` rotates both directions of one tunnel in the order
  above, and requires all nine packets of the three bursts around the switch to arrive.
- [`ipsec-xfrm/`](/ipsec-xfrm) - standalone Linux XFRM scripts, independent of dpservice, for the
  case where the receiver cannot choose its own SPIs: a per-VNI mesh in network namespaces with
  **SPI = VNI**. Linux keys an inbound SA on `(dst, spi, proto, mark)`, so every peer of a node
  collides there and has to be separated by a packet mark carrying the sender id. dpservice's SAD
  is keyed on the source `/64` as well, so the same fan-in needs no such trick.
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
