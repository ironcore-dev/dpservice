# Dataplane Service GRPC Client

To communicate with the `dp_service` process, you need to use GRPC (currently running hardcoded at localhost on port 1337).

This repository comes with a simple command-line GRPC client with dataplane service commands presented as command-line arguments. You can find it in the build directory as `test/dp_grpc_client`. To communicate with dp-service, you need to first [initialize a connection](#initialize-a-connection) with it.


## Initialize a connection
```bash
dp_grpc_client --init
```
This command needs to be run once after starting a new `dp_service` process. Only then you can run other commands. You need to have dp-service up and running on the same machine.

## Add a virtual interface (machine)
```bash
dp_grpc_client --addmachine testvm1 --vm_pci 0000:01:00.0_representor_vf0 --vni 100 --ipv4 172.32.4.9
```
This command adds a virtual machine with VNI 100 (Virtual Network Identifier) and IPv4 overlay 172.32.4.9 and assigns the name `testvm1` to the VM. You need to specify the virtual port to assign to the VM. (In case of TAP devices, use the `net_tap#` EAL name instead of a PCI address.)

Use the name `testvm1` in order to address this VM again.
```bash
dp_grpc_client --addmachine testvm1 --vm_pci 0000:01:00.0_representor_vf0 --vni 100 --ipv4 172.32.4.9 --ipv6 2010::1
```
You can also specify overlay IPv6 to assign. The overlay can be dual-stack possible.
```bash
dp_grpc_client --addmachine testvm1 --vm_pci 0000:01:00.0_representor_vf0 --vni 100 --ipv4 172.32.4.9 --ipv6 2010::1 --pxe_ip 192.168.129.1 --pxe_str /ipxe/boot.ipxe
```
In case the VM needs pxe-boot, the options for the pxe-boot can be added. `--pxe_ip` is the overlay IP where TFTP and HTTP pxe servers are residing, `--pxe_str` is the path for ipxe file on the HTTP server.


## Delete a virtual interface (machine)
```bash
dp_grpc_client --delmachine testvm1
```
This command deletes a virtual machine with the name `testvm1`.
> If this VM is the last one using the VNI assigned to it, the corresponding VNI will also be deleted.


## List virtual interfaces
```bash
dp_grpc_client --getmachines
```
This command lists all the virtual machines (i.e. their virtual port) controlled by the service.


## Add a route
```bash
dp_grpc_client --addroute --vni 100 --ipv4 192.168.129.0 --length 24 --t_vni 200 --t_ipv6 2a10:afc0:e01f:209::
```
This command adds a route to VNI 100 with an overlay prefix 192.168.129.0/24 on the current hypervisor which can be routed to VNI 200 on another hypervisor with an underlay IPv6 address 2a10:afc0:e01f:209::


## Delete a route
```bash
dp_grpc_client --delroute --vni 100 --ipv4 192.168.129.0 --length 24 --t_vni 200 --t_ipv6 2a10:afc0:e01f:209::
```
This command deletes a route of VNI 100 with an overlay prefix 192.168.129.0/24 on the current hypervisor which can be routed to VNI 200 on another hypervisor with an underlay IPv6 address 2a10:afc0:e01f:209::


## List routes
```bash
dp_grpc_client --listroutes --vni 100
```
This command lists all routes of VNI 100 on current hypervisor.


## Set virtual IP of an existing VM
```bash
dp_grpc_client --addvip testvm1 --ipv4 172.32.20.2
```
This command assigns a virtual IP to "testvm1" VM which will be used for egress traffic of the VM as a source address (SNAT).


## Delete the virtual IP of a VM
```bash
dp_grpc_client --delvip testvm1
```
This command deletes the virtual ip of "testvm1" VM. After deletion the VM will continue using its original IP address which it has obtained via DHCP. If there is no virtual IP assigned then this command does nothing.


## Get the virtual IP of a VM
```bash
dp_grpc_client --getvip testvm1
```
This reads the virtual ip of the "testvm1" VM (if present).
