# Testing Dataplane Service with Mellanox cards


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


## Outside (host) connectivity
Normally, to implement outside communication (not only VM-VM), you need to connect the physical ports of the Mellanox card to a switch that then connects to other computers.

It is also possible however, to connect the switch back to another card on your machine. Even further, you can use a virtual ethernet pair (veth) and bridging to achieve this without additional NICs.

In both of these cases, you need to use [network namespaces](https://man7.org/linux/man-pages/man7/network_namespaces.7.html) to isolate your cards. Otherwise your kernel would send packets directly through the internal stack instead of sending them 'out' through the NIC ports.

### Additional NICs and a bridge
This setup uses a switch in bridge mode to simply connect one Mellanox port to another NIC inside the same machine.

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

### Virtual ethernet pair
This setup does away with the need for a switch and additional NICs. Instead you create a `veth` pair and put one end of it in a bridge with Mellanox and the other into a separate namespace. You can think about the pair as a "virtual cable".

> This does not seem to be working with ConnectX-4 cards.

Creating namespaces is similar to the physical example:
```bash
ip netns add virt1
ip netns add virt2
ip link add veth1 type veth peer name veth1p
ip link add veth2 type veth peer name veth2p
ip link set dev veth1 netns virt1
ip link set dev veth2 netns virt2
ip -n virt1 link set dev veth1 up
ip -n virt2 link set dev veth2 up
```

Additionally you also need to create the bridge in software (let `enp1s0f0np0` and `enp1s0f1np1` be the physical ports of the Mellanox NIC):
```bash
ip link add name br1 type bridge
ip link add name br2 type bridge
ip link set dev enp1s0f0np0 master br1
ip link set dev veth1p master br1
ip link set dev enp1s0f1np1 master br2
ip link set dev veth2p master br2
ip link set dev br1 up
ip link set dev br2 up
ip link set dev veth1p up
ip link set dev veth2p up
```

As with the physical setup, you should now be able to utilize `ip netns exec` for issuing commands on the outside.
