# Dataplane service telemetry
As a DPDK-based application, dp-service supports telemetry over a UNIX socket. DPDK provides a command-line tool called `dpdk-telemetry.py`, but that is part of the whole DPDK package and as such it is not usually available on machines running dp-service.

## Direct socket access
Any standard tool that supports UNIX sockets can communicate with telemetry. This guide covers the simplest tool (not part of any programming/scripting language), `socat`. For easier output handling, python's socket module is probably more suitable.

The socket to use is of type `SOCK_SEQPACKET` (5), the file path is `/var/run/dpdk/rte/dpdk_telemetry.v2` for root and `/run/user/<uid>/dpdk/rte/dpdk_telemetry.v2` for non-root users.

To send telemetry requests, a node name with a parameter (must be zero if not present) is sent and a JSON responses can be read:
```
# echo "/dp_service/nat/used_port_count,0" | socat - UNIX:/var/run/dpdk/rte/dpdk_telemetry.v2,socktype=5
{"version":"DPDK 22.11.0","pid":1369006,"max_output_len":16384}{"/dp_service/nat/used_port_count":{"vm1":1,"vm2":0,"vm3":0}}
```

For the complete list of commands (telemetry nodes), send `/,0`.
