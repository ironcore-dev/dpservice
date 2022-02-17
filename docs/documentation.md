# Dataplane Service

## **Overview**
This is an early beta version which 
- Uses [DPDK Graph Framework](https://doc.dpdk.org/guides/prog_guide/graph_lib.html) for the data plane. DPDK version 21.11 LTS or higher needed.
- Uses a private pointer in [mbuf](https://doc.dpdk.org/guides/prog_guide/mbuf_lib.html#dynamic-fields-and-flags) structure to carry offloading rte_flow
data around.
- [rte_flow](https://doc.dpdk.org/guides/prog_guide/rte_flow.html) offloading between the Virtual Machines(VMs) on a single heypervisor.
- GRPC support to add VMs and routes. There is a C++ based GRPC
test client (CLI) which can connect to the GRPC server. See the examples below.
- DHCPv4, DHCPv6, Neighbour Discovery, ARP protocols supported (Sub-set implementations.).
- Currently IPv4 overlay and IPv6 underlay support. IPv6 overlay support in progress.
<br><br>
## **Prerequisites**
Working DPDK installation with huge pages support to link to and a SmartNIC to operate on. (Currently only Mellanox)

## **Building**

This project uses meson and ninja to build the C application. On the top level directory:

    meson build
    ninja -C build

### **Building docker image**

    meson dist --no-tests    //To build dp_service dist package
    sudo docker build --build-arg DPS_VER=1.0.0 -t debian11/dpservice:1.0 .

## **How to run dpservice**
Run the application as root or use sudo:

    sudo ./build/src/dp_service -l 0,1 -- --pf0=ens1f0np0 --pf1=ens1f1np1 --vf-pattern=enp59s0f0_ --ipv6=2a10:afc0:e01f:209:: --no-stats --no-offload 
**pf0** and **pf1** are the ethernet names of the uplink ports of the hypervisor on the smartnic. **ipv6** is the underlay ipv6 address which should be used by the DP service for egress/ingress packets leaving/coming to the smartnic.


**vf_pattern** defines the prefix used by the virtual functions created by the smartnic and which need to be controlled by the dpservice. **no-stats** disables the graph framework statistics printed to the console. **no-offload** disables the offloading to the smartnic. (For the NICs which do not support 
rte_flow)


**no-stats** and **no-offload** are optional parameters. The other ones are mandatory.


## **Automated Testing**

The test infrastructure uses [pytest](https://docs.pytest.org/) and [scapy](https://scapy.net/).
Please make sure that these tools are installed before you start the test. meson build system checks also for the existence of these tools during build phase.


Test can be started in the build directory after the dp service is built. The test will need root rights and uses TAP interfaces behind the scenes. So no SmartNIC is neceded for the tests to run.

    cd ./build
	meson test -v


This will list all the test cases which are passed and failed.
<br><br>

## **How to use GRPC test client**

### **Add Virtual Machine**
----
	./build/test/dp_grpc_client --addmachine testvm1 --vni 100 --ipv4 172.32.4.9
This adds a virtual machine with VNI 100 (Virtual Network Identifier) and IPv4 overlay 172.32.4.9 and assigns the name "testvm1" to the VM. It also prints the PCI details of the to virtual machine assigned virtual port. (with --ipv6 also an overlay IPv6 assignment possible. Overlay dual stack possible.)
Use the name "testvm1" in order to address this VM again.
<br><br>

### **Delete Virtual Machine**
-----
	./build/test/dp_grpc_client --delmachine testvm1
This deletes a virtual machine with the name "testvm1". If this VM is the last one using the VNI assigned to it, the corresponding VNI will be also deleted.
<br><br>

### **List Virtual Machines**
------
	./build/test/dp_grpc_client --getmachines
This lists all the virtual machines controlled (assigned virtual port) by dp_service.
<br><br>

### **Add Route**
------
	./build/test/dp_grpc_client --addroute --vni 100 --ipv4 192.168.129.0 --length 24 --t_vni 200 --t_ipv6 2a10:afc0:e01f:209::
This adds a route to VNI 100 with overlay prefix 192.168.129.0/24 on the current hypervisor which can be routed to a vni 200 on another hypervisor with an underlay IPv6 address 2a10:afc0:e01f:209::
<br><br>

### **Delete Route**
------
	./build/test/dp_grpc_client --delroute --vni 100 --ipv4 192.168.129.0 --length 24 --t_vni 200 --t_ipv6 2a10:afc0:e01f:209::
This deletes a route of VNI 100 with overlay prefix 192.168.129.0/24 on the current hypervisor which can be routed to a vni 200 on another hypervisor with an underlay IPv6 address 2a10:afc0:e01f:209::
<br><br>

### **List Routes**
------
	./build/test/dp_grpc_client --listroutes --vni 100
This list all routes of VNI 100 on current hypervisor.
<br><br>

### **Add Virtual IP to VM**
------
	./build/test/dp_grpc_client --addvip testvm1 --ipv4 172.32.20.2
This adds a virtual ip to VM "testvm1" which will be used for egress traffic of the VM as a source address. (SNAT)
<br><br>

### **Delete Virtual IP from VM**
------
	./build/test/dp_grpc_client --delvip testvm1
This deletes the virtual ip of the VM "testvm1". After deletion the VM will continue its original IP address which was obtained via DHCP. If there is no virtual IP assigned then this command does nothing.
<br><br>

### **List Virtual IP from VM**
------
	./build/test/dp_grpc_client --getvip testvm1
This lists the virtual ip of the VM "testvm1". (If any)
<br><br>
