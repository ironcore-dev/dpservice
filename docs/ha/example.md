# Example use of dpservice in HA mode


## Preparation
`prepare.sh` only needs to be ran once, both dpservice instances will use the resulting config as they should both be set up the same.

Special argument `--sync-bridge` has been created to facilitate the shared bridge and TAP devices creation. Currently, only `--multiport-eswitch` setup has been properly tested, so it is recommended too.

> When two dpservice pods are deployed, two init containers with `--sync-bridge` can be spawned. The code is idempotent, so no issue should arise from creating the bridge twice.


## Running dpservice processes
The process itself can be run as usual, with the following required changes:
 - EAL argument `--file-prefix` is needed to differentiate DPDK internal state for each
 - EAL argument `--vdev` needs to be used to use previously created (see above) TAP device
 - dpservice argument `--sync-tap` needs to be used to give the TAP device name to dpservice itself
 - dpservice argument `--active-lockfile` is needed to atomically synchronize process states
 - dpservice argument `--grpc-port` is required to differentiate the gRPC endpoint for each process

Example `dpservice-a` process:
```
dpservice-bin -l3,5 --file-prefix=dpservice-a --vdev=net_tap_sync,iface=dps_sync_a,persist -- --sync-tap=dps_sync_a --active-lockfile=/run/dpservice/common/active.lock --grpc-port=1338 --no-offload
```

Example `dpservice-b` process:
```
dpservice-bin -l3,5 --file-prefix=dpservice-b --vdev=net_tap_sync,iface=dps_sync_b,persist -- --sync-tap=dps_sync_b --active-lockfile=/run/dpservice/common/active.lock --grpc-port=1339 --no-offload
```

These processes should automatically take up the role of active and standby based on which one locked the `--active-lockfile` first.

Any data needed by the standby process will be sent over via the bridge created earlier by the active process.


## Monitoring dpservice
For monitoring, `dpservice-exporter` needs to be ran in two instances with `--grpc-port` and `--file-prefix` set accordingly. Alternatively `DP_GRPC_PORT` and `DP_FILE_PREFIX` environment variables can be used instead (helpful for container shell environment).


## Orchestraing dpservice
To orchestrate these processes, simply use `dpservice-cli` with proper `--address` argument. Alternatively `DP_GRPC_PORT` environment variable can be used (helpful for container shell environment).

To make sure both dpservices are orchestrated the same way, underlay addresses need to be set externally!

Example with real Mellanox card:
```
# 2 VMs on dpservice-a
dpservice-cli --address localhost:1338 add interface --id test10 --device 0000:03:00.0_representor_c0pf0vf0 --vni 123 --ipv4 192.168.123.10 --ipv6 fe80::10 --underlay fc00::8000:0:10
dpservice-cli --address localhost:1338 add interface --id test11 --device 0000:03:00.0_representor_c0pf0vf1 --vni 123 --ipv4 192.168.123.11 --ipv6 fe80::11 --underlay fc00::8000:0:11
# 2 VMs on dpservice-b
dpservice-cli --address localhost:1339 add interface --id test10 --device 0000:03:00.0_representor_c0pf0vf0 --vni 123 --ipv4 192.168.123.10 --ipv6 fe80::10 --underlay fc00::8000:0:10
dpservice-cli --address localhost:1339 add interface --id test11 --device 0000:03:00.0_representor_c0pf0vf1 --vni 123 --ipv4 192.168.123.11 --ipv6 fe80::11 --underlay fc00::8000:0:11
```

Now connected VMs can communicate, for example one running `iperf -s` and the other `iperf -c 192.168.123.10 -i1 -t300`.

Then even after the active process is killed, communication should still work.

This must also be true for NAT flows, but setting up such example manually is beyond the scope of this document, please refer to the [pytest suite](../../test/local/xtratest_ha.py) for more details.
