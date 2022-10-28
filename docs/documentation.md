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


## **Automated Testing**

The test infrastructure uses [pytest](https://docs.pytest.org/) and [scapy](https://scapy.net/).
Please make sure that these tools are installed before you start the test. meson build system checks also for the existence of these tools during build phase.


Test can be started in the build directory after the dp service is built. The test will need root rights and uses TAP interfaces behind the scenes. So no SmartNIC is neceded for the tests to run.

```bash
cd ./build
sudo meson test test-ipip -v
```

This will list all the test cases which are passed and failed. The test cases do not need a SmartNIC but only hugepages support. Test cases use TAP devices to "unit-test" specific traffic scenarios. 

## **How to use GRPC test client**

Get the client built under test directory and have a dp-service which is up and running. You can run the client on the same machine where the dp-service is running. Connection will be via localhost. You need to init the dp-service before you can run any other command.

**Init dp-service**

```bash
dp_grpc_client --init
```



### **Add Virtual Interface (Machine)**

----
```bash
dp_grpc_client --addmachine testvm1 --vni 100 --ipv4 172.32.4.9 [--ipv6 2010::1 --pxe_ip 192.168.129.1 --pxe_str /ipxe/boot.ipxe]
```
This adds a virtual machine with VNI 100 (Virtual Network Identifier) and IPv4 overlay 172.32.4.9 and assigns the name "testvm1" to the VM. It also prints the PCI details of the to virtual machine assigned virtual port. (with --ipv6 also an overlay IPv6 assignment possible. Overlay dual stack possible.)
Use the name "testvm1" in order to address this VM again.  
	In case the VM needs to pxe-boot, the options for the pxe-boot can be added to --addmachine parameters as shown in the example. (--pxe_ip is the overlay IP where tftp and http pxe servers are residing, --pxe_str is the path for ipxe file on http server.)
<br>

### **Delete Virtual Interface (Machine)**
-----
```bash
dp_grpc_client --delmachine testvm1
```
This deletes a virtual machine with the name "testvm1". If this VM is the last one using the VNI assigned to it, the corresponding VNI will be also deleted.
<br>

### **List Virtual Interfaces (Machines)**
------
```bash
dp_grpc_client --getmachines
```
This lists all the virtual machines controlled (assigned virtual port) by dp_service.
<br><br>

### **Add Route**
------
```bash
dp_grpc_client --addroute --vni 100 --ipv4 192.168.129.0 --length 24 --t_vni 200 --t_ipv6 2a10:afc0:e01f:209::
```
This adds a route to VNI 100 with overlay prefix 192.168.129.0/24 on the current hypervisor which can be routed to a vni 200 on another hypervisor with an underlay IPv6 address 2a10:afc0:e01f:209::
<br><br>

### **Delete Route**
------
```bash
dp_grpc_client --delroute --vni 100 --ipv4 192.168.129.0 --length 24 --t_vni 200 --t_ipv6 2a10:afc0:e01f:209::
```
This deletes a route of VNI 100 with overlay prefix 192.168.129.0/24 on the current hypervisor which can be routed to a vni 200 on another hypervisor with an underlay IPv6 address 2a10:afc0:e01f:209::
<br><br>

### **List Routes**
------
```bash
dp_grpc_client --listroutes --vni 100
```
This list all routes of VNI 100 on current hypervisor.
<br><br>

### **Add Virtual IP to VM**
------
```bash
dp_grpc_client --addvip testvm1 --ipv4 172.32.20.2
```
This adds a virtual ip to VM "testvm1" which will be used for egress traffic of the VM as a source address. (SNAT)
<br><br>

### **Delete Virtual IP from VM**
------
```bash
dp_grpc_client --delvip testvm1
```
This deletes the virtual ip of the VM "testvm1". After deletion the VM will continue its original IP address which was obtained via DHCP. If there is no virtual IP assigned then this command does nothing.
<br><br>

### **List Virtual IP from VM**
------
```bash
dp_grpc_client --getvip testvm1
```
This lists the virtual ip of the VM "testvm1". (If any)
<br><br>
