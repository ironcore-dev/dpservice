# Testing Dataplane Service with Mellanox cards
As dp-service is intended as a virtual router for hosting VMs, testing on real hardware is a bit tricky since it requires SR-IOV to use virtual functions. In practice this means that you cannot directly communicate with VFs, instead a running VM is needed.

It is also possible to run the whole set of tests that `meson test` runs using `pytest`. See below for details.

## Hardware setup
To simplify starting `dp_service`, it accepts a configuration file (currently hardcoded `/tmp/dp_service.conf`) so that most command-line arguments concerning hardware options are not needed.

This file is generated for you by calling a shell script, `hack/prepare.sh`.

This script also sets up hugepages, Mellanox's virtual functions (VFs), and eswitch mode.


## Virtual machines
For a VM to use a VF, that VF must use VFIO driver. Let the address of an available VF be `01:00.2`. Then the easiest way to do this is via `dpdk-devbind -b vfio-pci 01:00.2`. KVM should then be able to bind to a VF using vfio: `-net none -device vfio-pci,host=01:00.02`.

If running `dp_service_user`, don't forget to adjust privileges for the appropriate `/dev/vfio/?` devices.

You can then register the VM in the running service via [grpc](grpc_client.md):
```bash
./dp_grpc_client --init
./dp_grpc_client --addmachine test10 --vm_pci 0000:01:00.0_representor_vf0 --vni 123 --ipv4 192.168.123.10 --ipv6 2001::10
```

If you set two VMs like this, they should be able to connect to each other (ping, netcat, ...).

### Pytest suite
As `scapy` cannot directly communicate with VFs, running VMs with two anonymous bridged interfaces are needed. One interface is connected to Mellanox VF using VFIO and the other is a simple TAP device created by KVM. Then dp-service communicates using the VF and test suite uses the TAP device, e.g.
```
-net none -device vfio-pci,host=03:00.02 -device e1000,netdev=tap0 -netdev tap,id=tap0,script=no,downscript=no
```

Tests have been done using basic Debian 11 installation, but any fresh distro should work, just configure interface like this:
```
allow-hotplug ens4
iface ens4 inet manual
        hwaddress 22:00:00:00:00:01

allow-hotplug ens5
iface ens5 inet manual
        hwaddress 22:00:00:00:00:01

allow-hotplug br0
iface br0 inet static
        address 0.0.0.0
        bridge_ports ens4 ens5
```
The changing of MAC is important (the actual value is not) as without this change, the VM's kernel will refuse to forward packets with the VF's MAC through the bridge and "consumes them" (as it should).


## Outside (host) connectivity
Normally, to implement outside communication (not only VM-VM), you need to connect the physical ports of the Mellanox card to a switch that then connects to other computers.

It is also possible however, to connect the switch back to another card on your machine. Even further, you can actually connect both ports of your Mellanox card using a dingle cable to achieve this without additional NICs (at the cost of not being able to use port redundancy).

### Additional NICs and a bridge
This setup uses a switch in bridge mode to simply connect one Mellanox port to another NIC inside the same machine.

You need to use [network namespaces](https://man7.org/linux/man-pages/man7/network_namespaces.7.html) to isolate your cards. Otherwise your kernel would send packets directly through the internal stack instead of sending them 'out' through the NIC ports.

Let `enp3s0` and `enp4s0` be respective single ports of another two NICs. Then to set them up as to be able to communicate with dp-service properly, create two namespaces and add the supplementary ports into them:
```bash
ip netns add nic3
ip netns add nic4
ip link set dev enp3s0 netns nic3
ip link set dev enp4s0 netns nic4
ip -n nic3 link set dev enp3s0 up
ip -n nic4 link set dev enp4s0 up
```

To run commands using `enp3s0` card, use `ip netns exec nic3 <command>`. It is practical to simply call `ip netns exec system1 su <username>` in a separate terminal. Then it is trivial to listen on this interface to monitor outbound communication for example.

### Single NIC with two ports
This is actually the setup `pytest` suite uses to test on Mellanox. You need to connect the two ports of your NIC. Then the first (the SR-IOV capable) port will be used normally and the second one can be bound to to communicate with dp-service from the outside (host-host communication).

This requires dp-service running in a mode without a second physical interface. For that to happen you need to compile it with `-Denable_pytest=true` meson flag and not use `--wcmp-frac` command-line option (or any test using port redundancy).
