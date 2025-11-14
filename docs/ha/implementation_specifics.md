# Dpservice synchronization specifics
The two instances are connected via a bridge and TAP devices created by `prepare.sh` (init container).

This has been chosen to leverage the graph loop and shy away from any threading/locking otherwise required.

For ease of implementation, the communication happens using Ethernet packets with custom payload. Due to the fact that both instances will by definition run on the same machine and thus the same architecture and will be built the same way, endianness is not forced, but rather defined by the process binaries. Packing is used only for efficiency.

There is a simple message protocol defined in `../../include/dp_sync.h`.


## Roles
Message handling differs based on the state of dpservice. The active one only accepts requests (e.g. "send tables") and the standy one only accepts data synchronization (e.g. "create/delete new NAT entry").

While the standby dpservice does not process packets from PFs/VFs, it does process packets from the synchronization TAP device.

The standby dpservice graph loop is intentionally slowed down by sleeping during iterations. To make it responsive when synchronization happens, the graph node responsibel for handling synchronization messages can read packets multiple times before returning control to the graph loop.


## Protocol
Both processes start in standby mode. The first one to acquire an exclusive file lock on `--active-lockfile` file becomes the active process.

1. On activation the process takes any pending NAT entries from synchonization and creates flow table entries for them.
2. When the standby process starts, it sends a request to the active one to dump all entries and then only updates are sent. This is helpful when only the standby process is restarted (e.g. updates).
3. When the active process encounters a change in internal state that the standby process requires, it is sent over to the standby process.
4. When the active process dies (crash or update), Linux automatically opens the exclusive file lock and the standby process automatically takes it over, thus becoming active again.
5. Repeat from step 1, the process roles are now swapped.


## Concurrency
Given the atomicity of exclusive file locking and the fact that the lock is **NEVER** released voluntarily, there is no way of an active process becoming a standby one. There should be no situation where there are two active processes and both processes should always know their roles. 

When a message arrives over the synchronization TAP interface, messages not applicable to the current role (active/standby) are reacted upon.

Since the two processes are connected via a bridge and TAP devices, the messages are guaranteed to be in order.

The active process always sends over changes and when requested by a new standby process, it dumps all needed entries, but uses the same messages, thus essentialy "just" sends over many changes in a burst. This means the protocol is basically stateless.

All the above taken into account, there should be no way apart from dropped packets to arrive at a split-brain situation.


## Losses
It is theoretically possible (but except for the queue overflowing it should be highly improbable) that a synchronization packet does not arrive. This will result in a missed entry creation or deletion. However, packet flows are highly dynamic, so this loss should have no effect after an hour or less.

Missing the "please send all changes" message is worse, but again, this will fix itself over time as the new packet flows will be sent over and the old ones simply time out anyway.


## TAP device configuration
These TAP devices should normally be created by DPDK, i.e. via `--vdev` EAL parameter. However due to the bridge requirement, it is preferrable to only connect them to the bridge once. This is why `prepare.sh` pre-creates both TAP devices and then the `--vdev` EAL parameter needs to also contain `,persist` option.

It is essential that the TAP device is created with `mode tap multi_queue` option, otherwise DPDK refuses to use it.

It is highly recommended to set `txqueuelen` really high (e.g. 100000), because the queue acts as a buffer for situation where many synchronization messages are being sent (i.e. after restart of the standby process).

It is also beneficial to disable IPv6 and multicast snooping, thus eliminating non-dpservice traffic on the connection.
