# Feature: capture offloaded rx packets on interfaces
In offloaded mode, packets that are processed by hardware offload rules cannot be seen anymore even on the software path. To increase the visibility of this type of traffic flows, we use special rte flow rules to instrument packet processing on hardware to duplicate and capture these packets on interfaces.

## What can be achieved and what cannot
Through tedious and complex experiment, the following features are identified and thus currently supported:

1. Capture offloaded packets on the RX side of a VF (packets that are sent from VMs).
2. Capture offloaded packets on the RX side of PF0 (IPinIP packets that are transmitted to PF0 from the wire).

Due to the constraint of Mellanox HW or driver, the following features currently are not supported:

1. Capture offloaded packets on the TX side of interfaces.
2. Capture offloaded packets on the RX side of PF1. PF1 is currently not in switchdev mode, thus the used special rte flow rule does not work for it.
3. The configured UDP src port is not really respected by HW, and UDP dst port is respected instead.


## Capture and understand offloaded rx packets
Capturing must be started via dpservice-cli before the first packets of new flows on an interface. The target interfaces, especially VFs, need to be started first, and in total, 16 interfaces can be specified as part of the cmdline parameters. Again, as capturing on PF1 is currently not supported by HW, please only specify `--pf=0`.


```
./bin/dpservice-cli capture start --sink-node-ip=<underlay IP of the hypervisor or a remote host> --udp-src-port=<selected port ID> --udp-dst-port=<selected port ID>  --vf=<list of started interfaces> --pf=0
```

for example:
```
./bin/dpservice-cli capture start --sink-node-ip=abcd:efgh:1234:4321::1 --udp-src-port=3000 --udp-dst-port=3010  --vf=vm-1,vm-2 --pf=0
```

The captured packets will be transmitted back in an encapped format to the interface (via router) of your selected sink machine, either the hypervisor where dp-service is running or a remote host. These packets are visible on physical interfaces using a regular tcpdump tool. For example, these packets can be dumped to a pcap file using a command:

```
sudo tcpdump -ni any udp dst port 3010 -w test.pcap
```

The generated test.pcap file can be opened using Wireshark(graphic). As captured packets are encaped as UDP payload, this file can be firstly modified by removing the first 62 bytes of all packets.

```
editcap -C 62 -F pcap test.pcap test_no_udp.pcap
```

The resulted test_no_udp.pcap file can be recognized by wireshark.

The following command is used to stop capturing on all configured interfaces. Note that, to start capturing on a new set of interfaces, this stopping command has to be called first.
```
/bin/dpservice-cli capture stop
```

or before you start capturing, it is also recommended to check the operation status of this capturing feature by using:
```
/bin/dpservice-cli capture status
```
The returned values incude this feature's operation status, as well as the configuration information using the "capture start" subcommand.

## How offloaded packets are captured
Offloaded packets are captured by using special rte flow rules, especially the one that enables packet sampling on the RX side of an interface. The captured packets are encapsulated by prepending extra headers. Despite the fact that captured Ethernet frames are treated as UDP payload, it is flexible to use other customized headers as well. The format of encapsulation is as follows:

```
| Outer Ether header | Outer IPv6 header | UDP header | Captured Ether frame |
```

[Figure1](docs/sys_design/pkt_capture_flow_rules-VF.drawio.png) and [Figure2](docs/sys_design/pkt_capture_flow_rules-PF.drawio.png) illustrate the organization of flow rules for VF and PF. The differences between handling VF and PF are empirical.
