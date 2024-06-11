# Dataplane Service GRPC Client

To communicate with the `dpservice-bin` process, you need to use GRPC (running on localhost at default port 1337).

There is a golang command-line client [dpservice-cli](https://github.com/ironcore-dev/dpservice/tree/main/cli/dpservice-cli), with full [command-line documentation](https://github.com/ironcore-dev/dpservice/tree/main/cli/dpservice-cli/docs/commands).


## Sample commands for testing
```bash
dpservice-cli init
dpservice-cli add interface --id testvm1 --device 0000:01:00.0_representor_vf0 --vni 100 --ip 172.32.0.1 --ip 2010::1
dpservice-cli add interface --id testvm2 --device 0000:01:00.0_representor_vf1 --vni 100 --ip 172.32.0.2 --ip 2010::2
dpservice-cli add route --vni 100 --prefix 192.168.129.0/24 --next-hop-vni 200 --next-hop-ip 2a10:afc0:e01f:209::
dpservice-cli add nat --interface-id testvm1 --nat-ip 192.168.0.1 --minport 1024 --maxport 2048
# ...
dpservice-cli del nat --interface-id testvm1
dpservice-cli del route --vni 100 --prefix 192.168.129.0/24
dpservice-cli del interface --id testvm2
dpservice-cli del interface --id testvm1
```


## Useful debugging commands
Get list of managed interfaces:
```bash
$ dpservice-cli list interfaces
 ID   VNI  Device                        IPs                         UnderlayRoute
 vm1  100  0000:03:00.0_representor_vf0  [10.100.1.1 2000:100:1::1]  fc00:1::7a:0:1
 vm2  100  0000:03:00.0_representor_vf1  [10.100.1.2 2000:100:1::2]  fc00:1::7a:0:2
 vm3  200  0000:03:00.0_representor_vf2  [10.200.1.3 2000:200:1::3]  fc00:1::7a:0:3
```
What is the NAT setting for interface `vm1`:
```bash
$ dpservice-cli get nat --interface-id=vm1
 InterfaceID  NatIP       MinPort  MaxPort  UnderlayRoute
 vm1          172.21.1.1      100      102  fc00:1::f8:0:4
```
Alternatively, you can list all NATs by using `list nats` or use the `--wide` option for `list interfaces`:
```bash
$ dpservice-cli list interfaces -w
 ID   VNI  Device                        IPs                         UnderlayRoute   Nat                       VirtualIP
 vm1  100  0000:03:00.0_representor_vf0  [10.100.1.1 2000:100:1::1]  fc00:1::7a:0:1  192.168.0.1 <1024, 2048>
 vm2  100  0000:03:00.0_representor_vf1  [10.100.1.2 2000:100:1::2]  fc00:1::7a:0:2
 vm3  200  0000:03:00.0_representor_vf2  [10.200.1.3 2000:200:1::3]  fc00:1::7a:0:3
```
Who are other members of this NAT:
```bash
$ ./dpservice-cli get natinfo --nat-ip=172.21.1.1
 VNI  IP          MinPort  MaxPort  UnderlayRoute   NatInfoType
 100  10.100.1.2      112      113  <nil>           Local
 100  10.100.1.1      100      102  <nil>           Local
 100  <nil>           500      520  fc00:2::64:0:1  Neighbor
 100  <nil>           521      522  fc00:2::64:0:1  Neighbor
```
List loadbalancer targets (round-robin):
```bash
$ dpservice-cli list lbtargets --lb-id=my_lb
 IpVersion  Address
      IPv6  fc00:1::30:0:7
      IPv6  fc00:1::30:0:8
```
List all loadbalancers:
```bash
$ dpservice-cli list lb
 ID  VNI  LbVipIP      Lbports           UnderlayRoute
 4   100  10.20.30.40  [TCP/443 UDP/53]  fc00:1::f1:0:95
```
Get info on the loadbalancer setting:
```bash
$ dpservice-cli get lb --id=my_lb
 ID     VNI  LbVipIP  Lbports   UnderlayRoute
 my_lb  100  1.2.3.4  [TCP/80]  fc00:1::c0:0:6
```
