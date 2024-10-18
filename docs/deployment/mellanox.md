# Deployment guide for Mellanox ConnectX cards
Before running dp-service for the first time on Mellanox ConnectX cards, use this guide to check the proper configuration.


## Firmware configuration
SR-IOV needs to be enabled on the card itself and maximum number of virtual functions (thus available NICs for VMs) must be set.

To check the firmware configuration an official tool `mlxconfig` is available. There is also an open-source alternative that is present in Debian package tree called `mstflint`.

To use the configuration tool, the PCI address of the first physical port is needed, use `lspci` to list all devices and use the lowest PCI address of any Mellanox entries:
```
# lspci | grep Mellanox
0000:03:00.0 Ethernet controller: Mellanox Technologies MT2894 Family [ConnectX-6 Lx]
0000:03:00.1 Ethernet controller: Mellanox Technologies MT2894 Family [ConnectX-6 Lx]
0000:03:00.2 Ethernet controller: Mellanox Technologies ConnectX Family mlx5Gen Virtual Function
0000:03:00.3 Ethernet controller: Mellanox Technologies ConnectX Family mlx5Gen Virtual Function
0000:03:00.4 Ethernet controller: Mellanox Technologies ConnectX Family mlx5Gen Virtual Function
0000:03:00.5 Ethernet controller: Mellanox Technologies ConnectX Family mlx5Gen Virtual Function
0000:03:00.6 Ethernet controller: Mellanox Technologies ConnectX Family mlx5Gen Virtual Function
0000:03:00.7 Ethernet controller: Mellanox Technologies ConnectX Family mlx5Gen Virtual Function
0000:03:01.0 Ethernet controller: Mellanox Technologies ConnectX Family mlx5Gen Virtual Function
0000:03:01.1 Ethernet controller: Mellanox Technologies ConnectX Family mlx5Gen Virtual Function
```

Then check the current firmware status:
```
# apt install mstflint
# mstconfig -d 0000:03:00.0 q | grep -E 'SRIOV_EN|UCTX_EN|NUM_OF_VFS'
         NUM_OF_VFS                          8
         SRIOV_EN                            False(0)
         UCTX_EN                             True(1)
```

Set the number of VFs to the needed value (max 126 at the moment) and enable both SR-IOV and UCTX:
```
# mstconfig -d 0000:03:00.0 s SRIOV_EN=1 UCTX_EN=1 NUM_OF_VFS=126
```
Restart the machine for the changes to take effect.
> These changes are done in the NIC itself, it does not matter if the host is an ephemeral image or if another host OS will boot later.

### Multiport-eswitch
For this mode to be functional, an additional firmware setting `LAG_RESOURCE_ALLOCATION=1` is needed.

In some cases (looks like a nic/switch combination) performance is severly affected when VM traffic is happening. This has been observed to be fixed by setting `ROCE_CONTROL=1` (this means "disabled", the default is `2` meaning "enabled"). The actual cause of this is yet to be discovered.


## Dp-service setup
Either `prepare.sh` script or `preparedp.service` systemd unit needs to be run before dp-service can work properly. This should already be done automatically if using the Docker image provided. Make sure this does not produce any errors.

### Multiport-eswitch
The `prepare.sh` script supports `--multiport-eswitch` argument to set the card up in multiport-eswitch mode. There is an additional `--pf1-proxy` argument to also create a VF on PF1 for proxying PF1 traffic. Currently both arguments are needed to properly run dpservice in multiport-eswitch mode due to a (suspected) driver bug.
