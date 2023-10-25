# Feature: capture offloaded rx packets on interfaces
In offloaded mode, packets that are processed by hardware offloed rules cannot be seen anymore even on the software path. To increase the visibility of this type of traffic flows, we use special rte flow rules to instrument packet processing on hardware to duplicate and capture these packets on interfaces.

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
./bin/dpservice-cli capture start --sink-node-ip=<underly IP of the hypervisor> --udp-src-port=<selected port ID> --udp-dst-port=<selected port ID>  --vf=<list of started interfaces> --pf=0
```

for example:
```
./bin/dpservice-cli capture start --sink-node-ip=abcd:efgh:1234:4321::1 --udp-src-port=3000 --udp-dst-port=3010  --vf=vm-1,vm-2 --pf=0
```

The captured packets will be transmitted back to the hypervisors interface (via router) in an encapped format, which is visible on pf0 interface using a regular tcpdump tool. For example, these packets can be dumped to a pcap file using a command:

```
sudo tcpdump -ni any udp dst port 3010 -w test.pcap
```

The generated test.pcap file can be opened using Wireshark(graphic). As captured packets are encaped as UDP payload, this file can be firstly modified by removingß the first 62 bytes of all packets.

```
editcap -C 62 -F pcap test.pcap test_no_udp.pcap
```

The resulted test_no_udp.pcap file can be recognized by wireshark.

## How offloaded packets are captured
Offloaded packets are captured by using special rte flow rules, especial the one that enables pkt sampling on the RX side of an interface. The captured packets are encapsulated by prepending extra headers. Despite of the fact that captured Ethernet frames are treated as UDP payload, it is flexible to use other customized headers as well. The format of encapsulation is as following:

```
| Outter Ether header | Outter IPv6 header | UDP header | Captured Ether frame |
```

[Figure1](docs/sys_design/pkt_capture_flow_rules-VF.drawio.png) and [Figure2](docs/sys_design/pkt_capture_flow_rules-PF.drawio.png) illustrate the organization of flow rules for VF and PF. The differences between handling VF and PF are empirical.
