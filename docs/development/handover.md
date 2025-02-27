# Findings about dpservice related to handover/rolling update

## Packet duplication
When two `dpservice-bin` processes are running, packets get duplicated. This is due to the fact, that `rte_eth_dev_start()` internally creates an RTE flow rule that puts packets to queue 0 (group 0) for Rx and Tx (details are in the DPDK source code in `mlx5_trigger.c:1284` calling `mlx5_traffic_enable()`).

As `rte_eth_dev_start()` needs to be called for the device to even be able to orchestrate, we would need to patch DPDK to prevent this duplication, but it's unclear what will actually happen, see below how complicated this behavior is.

To test, the setup is 2VMs on one hypervisor, with two `dpservice-bin` processes, each with separate hugepages and gRPC port and `dpservice-dump` running on each.
```
# ping 192.168.123.10 -c1
PING 192.168.123.10 (192.168.123.10) 56(84) bytes of data.
64 bytes from 192.168.123.10: icmp_seq=1 ttl=64 time=2.69 ms
```

### Two running dpservice-bin instances, one of them is *not* asking for packets
Dpservice needs to call `rte_eth_rx_burst()` to receive a burst of packets from DPDK (not sure if this is a queue in the card or in the DPDK layer). This scenario is such that one dpservice calls the function and other is not.

Active dpservice (the one asking for packets):
```
23:05:03.941 451: PORT 3         >> rx-3-0        : 0E:68:B9:29:17:7D -> 0E:68:B9:29:17:7D / 192.168.123.11 -> 192.168.123.10 / ICMP 8-0 id 31530 seq 1
23:05:03.941 452: PORT 3         >> rx-3-0        : 0E:68:B9:29:17:7D -> 0E:68:B9:29:17:7D / 192.168.123.11 -> 192.168.123.10 / ICMP 8-0 id 31530 seq 1
23:05:03.941 451: tx-2           >> PORT 2        : D2:BB:79:76:F3:26 -> D2:BB:79:76:F3:26 / 192.168.123.11 -> 192.168.123.10 / ICMP 8-0 id 31530 seq 1
23:05:03.941 452: tx-2           >> PORT 2        : D2:BB:79:76:F3:26 -> D2:BB:79:76:F3:26 / 192.168.123.11 -> 192.168.123.10 / ICMP 8-0 id 31530 seq 1
23:05:03.941 453: PORT 2         >> rx-2-0        : D2:BB:79:76:F3:26 -> D2:BB:79:76:F3:26 / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 31530 seq 1
23:05:03.941 454: PORT 2         >> rx-2-0        : D2:BB:79:76:F3:26 -> D2:BB:79:76:F3:26 / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 31530 seq 1
23:05:03.941 455: PORT 2         >> rx-2-0        : D2:BB:79:76:F3:26 -> D2:BB:79:76:F3:26 / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 31530 seq 1
23:05:03.941 456: PORT 2         >> rx-2-0        : D2:BB:79:76:F3:26 -> D2:BB:79:76:F3:26 / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 31530 seq 1
23:05:03.941 453: tx-3           >> PORT 3        : 0E:68:B9:29:17:7D -> 0E:68:B9:29:17:7D / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 31530 seq 1
23:05:03.941 454: tx-3           >> PORT 3        : 0E:68:B9:29:17:7D -> 0E:68:B9:29:17:7D / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 31530 seq 1
23:05:03.941 455: tx-3           >> PORT 3        : 0E:68:B9:29:17:7D -> 0E:68:B9:29:17:7D / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 31530 seq 1
23:05:03.941 456: tx-3           >> PORT 3        : 0E:68:B9:29:17:7D -> 0E:68:B9:29:17:7D / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 31530 seq 1
```

Standby dpservice (the one *not* asking for packets):
```
```

#### Analysis
1. The packet leaves the VM, get duplicated by RTE flow rule and "put into Rx queue" (hypothesis). Then one dpservice asks for a burst of packets and gets 2 packets.
2. Both packets pass through dpservice and are sent via dpdk call to send packets. These two packets reach the other VM. 
3. The other VM responds to both packets.
4. 2 responses get again duplicated by RTE flow rule, thus 4 packets reach dpservice.
5. dpservice routes all 4 packets and sends them out to the original VM. These four packets now reach the other VM. (ping would show duplicates if not for the `-c1` which ends immediately - tested).


### Two running dpservice-bin instance, *both* asking for packets
Now both instances are calling `rte_eth_rx_burst()`

First dpservice (the original one):
```
23:22:13.440 2446: PORT 3         >> rx-3-0        : 0E:68:B9:29:17:7D -> 0E:68:B9:29:17:7D / 192.168.123.11 -> 192.168.123.10 / ICMP 8-0 id 27593 seq 1
23:22:13.440 2447: PORT 3         >> rx-3-0        : 0E:68:B9:29:17:7D -> 0E:68:B9:29:17:7D / 192.168.123.11 -> 192.168.123.10 / ICMP 8-0 id 27593 seq 1
23:22:13.440 2446: tx-2           >> PORT 2        : D2:BB:79:76:F3:26 -> D2:BB:79:76:F3:26 / 192.168.123.11 -> 192.168.123.10 / ICMP 8-0 id 27593 seq 1
23:22:13.440 2447: tx-2           >> PORT 2        : D2:BB:79:76:F3:26 -> D2:BB:79:76:F3:26 / 192.168.123.11 -> 192.168.123.10 / ICMP 8-0 id 27593 seq 1
23:22:13.440 2448: PORT 2         >> rx-2-0        : D2:BB:79:76:F3:26 -> D2:BB:79:76:F3:26 / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 27593 seq 1
23:22:13.440 2449: PORT 2         >> rx-2-0        : D2:BB:79:76:F3:26 -> D2:BB:79:76:F3:26 / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 27593 seq 1
23:22:13.440 2450: PORT 2         >> rx-2-0        : D2:BB:79:76:F3:26 -> D2:BB:79:76:F3:26 / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 27593 seq 1
23:22:13.440 2451: PORT 2         >> rx-2-0        : D2:BB:79:76:F3:26 -> D2:BB:79:76:F3:26 / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 27593 seq 1
23:22:13.440 2448: tx-3           >> PORT 3        : 0E:68:B9:29:17:7D -> 0E:68:B9:29:17:7D / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 27593 seq 1
23:22:13.440 2449: tx-3           >> PORT 3        : 0E:68:B9:29:17:7D -> 0E:68:B9:29:17:7D / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 27593 seq 1
23:22:13.440 2450: tx-3           >> PORT 3        : 0E:68:B9:29:17:7D -> 0E:68:B9:29:17:7D / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 27593 seq 1
23:22:13.440 2451: tx-3           >> PORT 3        : 0E:68:B9:29:17:7D -> 0E:68:B9:29:17:7D / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 27593 seq 1
23:22:13.440 2452: PORT 2         >> rx-2-0        : D2:BB:79:76:F3:26 -> D2:BB:79:76:F3:26 / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 27593 seq 1
23:22:13.440 2453: PORT 2         >> rx-2-0        : D2:BB:79:76:F3:26 -> D2:BB:79:76:F3:26 / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 27593 seq 1
23:22:13.440 2454: PORT 2         >> rx-2-0        : D2:BB:79:76:F3:26 -> D2:BB:79:76:F3:26 / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 27593 seq 1
23:22:13.440 2455: PORT 2         >> rx-2-0        : D2:BB:79:76:F3:26 -> D2:BB:79:76:F3:26 / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 27593 seq 1
23:22:13.440 2452: tx-3           >> PORT 3        : 0E:68:B9:29:17:7D -> 0E:68:B9:29:17:7D / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 27593 seq 1
23:22:13.440 2453: tx-3           >> PORT 3        : 0E:68:B9:29:17:7D -> 0E:68:B9:29:17:7D / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 27593 seq 1
23:22:13.440 2454: tx-3           >> PORT 3        : 0E:68:B9:29:17:7D -> 0E:68:B9:29:17:7D / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 27593 seq 1
23:22:13.440 2455: tx-3           >> PORT 3        : 0E:68:B9:29:17:7D -> 0E:68:B9:29:17:7D / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 27593 seq 1
```

Second dpservice:
```
23:22:13.485 2303: PORT 2         >> rx-2-0        : D2:BB:79:76:F3:26 -> D2:BB:79:76:F3:26 / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 27593 seq 1
23:22:13.485 2304: PORT 2         >> rx-2-0        : D2:BB:79:76:F3:26 -> D2:BB:79:76:F3:26 / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 27593 seq 1
23:22:13.485 2305: PORT 2         >> rx-2-0        : D2:BB:79:76:F3:26 -> D2:BB:79:76:F3:26 / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 27593 seq 1
23:22:13.485 2306: PORT 2         >> rx-2-0        : D2:BB:79:76:F3:26 -> D2:BB:79:76:F3:26 / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 27593 seq 1
23:22:13.485 2303: tx-3           >> PORT 3        : 0E:68:B9:29:17:7D -> 0E:68:B9:29:17:7D / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 27593 seq 1
23:22:13.485 2304: tx-3           >> PORT 3        : 0E:68:B9:29:17:7D -> 0E:68:B9:29:17:7D / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 27593 seq 1
23:22:13.485 2305: tx-3           >> PORT 3        : 0E:68:B9:29:17:7D -> 0E:68:B9:29:17:7D / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 27593 seq 1
23:22:13.485 2306: tx-3           >> PORT 3        : 0E:68:B9:29:17:7D -> 0E:68:B9:29:17:7D / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 27593 seq 1
23:22:13.485 2307: PORT 3         >> rx-3-0        : 0E:68:B9:29:17:7D -> 0E:68:B9:29:17:7D / 192.168.123.11 -> 192.168.123.10 / ICMP 8-0 id 27593 seq 1
23:22:13.485 2308: PORT 3         >> rx-3-0        : 0E:68:B9:29:17:7D -> 0E:68:B9:29:17:7D / 192.168.123.11 -> 192.168.123.10 / ICMP 8-0 id 27593 seq 1
23:22:13.485 2307: tx-2           >> PORT 2        : D2:BB:79:76:F3:26 -> D2:BB:79:76:F3:26 / 192.168.123.11 -> 192.168.123.10 / ICMP 8-0 id 27593 seq 1
23:22:13.485 2308: tx-2           >> PORT 2        : D2:BB:79:76:F3:26 -> D2:BB:79:76:F3:26 / 192.168.123.11 -> 192.168.123.10 / ICMP 8-0 id 27593 seq 1
23:22:13.485 2309: PORT 2         >> rx-2-0        : D2:BB:79:76:F3:26 -> D2:BB:79:76:F3:26 / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 27593 seq 1
23:22:13.485 2310: PORT 2         >> rx-2-0        : D2:BB:79:76:F3:26 -> D2:BB:79:76:F3:26 / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 27593 seq 1
23:22:13.485 2311: PORT 2         >> rx-2-0        : D2:BB:79:76:F3:26 -> D2:BB:79:76:F3:26 / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 27593 seq 1
23:22:13.485 2312: PORT 2         >> rx-2-0        : D2:BB:79:76:F3:26 -> D2:BB:79:76:F3:26 / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 27593 seq 1
23:22:13.485 2309: tx-3           >> PORT 3        : 0E:68:B9:29:17:7D -> 0E:68:B9:29:17:7D / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 27593 seq 1
23:22:13.485 2310: tx-3           >> PORT 3        : 0E:68:B9:29:17:7D -> 0E:68:B9:29:17:7D / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 27593 seq 1
23:22:13.485 2311: tx-3           >> PORT 3        : 0E:68:B9:29:17:7D -> 0E:68:B9:29:17:7D / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 27593 seq 1
23:22:13.485 2312: tx-3           >> PORT 3        : 0E:68:B9:29:17:7D -> 0E:68:B9:29:17:7D / 192.168.123.10 -> 192.168.123.11 / ICMP 0-0 id 27593 seq 1
```

#### Analysis
The output seems crazy. Ignore the timestamps as unfortunately those are generated by the dump tool, not by dpservice itself.

Looking at graphtrace directly from dpservice (I can put it into logging but it's a mess) I see something better, that *both* dpservices get the original two duplicated packets, thus creating *eight* in the end.
 - first instance gets two, sends out two
 - the other instance also gets two, sends two, now we have four outgoing packets
 - this way we have four responses, that not only get duplicated (eight), but also *both* dpservices get these eight and route them, thus 16

```
# ping 192.168.123.10 -c2
PING 192.168.123.10 (192.168.123.10) 56(84) bytes of data.
64 bytes from 192.168.123.10: icmp_seq=1 ttl=64 time=0.519 ms
64 bytes from 192.168.123.10: icmp_seq=1 ttl=64 time=0.519 ms (DUP!)
64 bytes from 192.168.123.10: icmp_seq=1 ttl=64 time=0.519 ms (DUP!)
64 bytes from 192.168.123.10: icmp_seq=1 ttl=64 time=0.519 ms (DUP!)
64 bytes from 192.168.123.10: icmp_seq=1 ttl=64 time=1.34 ms (DUP!)
64 bytes from 192.168.123.10: icmp_seq=1 ttl=64 time=1.34 ms (DUP!)
64 bytes from 192.168.123.10: icmp_seq=1 ttl=64 time=1.34 ms (DUP!)
64 bytes from 192.168.123.10: icmp_seq=1 ttl=64 time=1.34 ms (DUP!)
64 bytes from 192.168.123.10: icmp_seq=1 ttl=64 time=1.56 ms (DUP!)
64 bytes from 192.168.123.10: icmp_seq=1 ttl=64 time=1.56 ms (DUP!)
64 bytes from 192.168.123.10: icmp_seq=1 ttl=64 time=1.56 ms (DUP!)
64 bytes from 192.168.123.10: icmp_seq=1 ttl=64 time=1.56 ms (DUP!)
64 bytes from 192.168.123.10: icmp_seq=1 ttl=64 time=5.28 ms (DUP!)
64 bytes from 192.168.123.10: icmp_seq=1 ttl=64 time=5.28 ms (DUP!)
64 bytes from 192.168.123.10: icmp_seq=1 ttl=64 time=5.28 ms (DUP!)
64 bytes from 192.168.123.10: icmp_seq=1 ttl=64 time=5.28 ms (DUP!)
64 bytes from 192.168.123.10: icmp_seq=2 ttl=64 time=0.421 ms
```

This is consistent with the dump showed earlier, just the ordering is kind of strage, sure dpservices are sharing CPU, so apparently the Rx queue ordering is not first-come first-serve when some packets come from VM1 and some from VM2?

## Conclusion
Going by this output, this seems, that *both* dpservices get the same traffic, but duplicated. The duplication could be maybe preventing by changing the RTE flow rule. that way we only get the original packet, but sent to *both* dpservices for some reason, hopefully.
