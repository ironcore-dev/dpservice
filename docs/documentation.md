# Dataplane Service

## **Overview**
This is a beta version which 
- Uses [DPDK Graph Framework](https://doc.dpdk.org/guides/prog_guide/graph_lib.html) for the data plane. DPDK version 21.11 LTS or higher needed.
- [rte_flow](https://doc.dpdk.org/guides/prog_guide/rte_flow.html) offloading between the virtual network interfaces on a single heypervisor.
- GRPC support to add virtual interfaces, loadbalancers, NAT Gateways and routes. There is a golang based GRPC
test client (CLI) which can connect to the GRPC server. See the examples below.
- DHCPv4, DHCPv6, Neighbour Discovery, ARP protocols supported (Sub-set implementations.).
- IPv4 overlay and IPv6 underlay support. IPv6 overlay support in progress.
## **Prerequisites**
Working DPDK installation with huge pages support to link to and a SmartNIC to operate on. (Currently only Mellanox) Enabled SRIOV and at least one enabled VF on SmartNIC firmware level.

## **Building**

This project uses meson and ninja to build the C application. On the top level directory:

```bash
meson build
ninja -C build
```

## **How to run dpservice**
Before you run the application, make sure that you generate a config file using the script hack/prepare.sh. This script expects an IPv6 Address assigned to "lo" interface which will be then used by dp-service as underlay address for its uplink traffic. The configuration file is generated under /tmp/ and the provided command line parameters will override the configuration file.

Example how to run without the generated configuration file:

```bash
./build/src/dp_service -a 0000:3b:00.0,representor=0-5 -a 0000:3b:00.1 -l 0,1 -- --pf0=enp59s0f1 --pf1=enp59s0f1 --vf-pattern=enp59s0f0_ --ipv6=2a10:afc0:e01f:209:: --no-stats --no-offload
```
**pf0** and **pf1** are the ethernet names of the uplink ports of the hypervisor on the smartnic. **ipv6** is the underlay ipv6 address which should be used by the dp-service for egress/ingress packets leaving/coming to the smartnic.

**vf_pattern** defines the prefix used by the virtual functions created by the smartnic and which need to be controlled by the dpservice. **no-stats** disables the graph framework statistics printed to the console. **no-offload** disables the offloading to the smartnic. (For the NICs which do not support 
rte_flow)

All the parameters beforre the first "--" is for [DPDK EAL](https://doc.dpdk.org/guides/linux_gsg/linux_eal_parameters.html) subsystem and documented in DPDK documentation.  **no-stats** and **no-offload** are optional parameters. The other ones are mandatory.

## Testing
See [this section](testing/README.md) for more information.
