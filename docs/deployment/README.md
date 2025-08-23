# Dataplane Service deployment
This repository only provides a compiled binary of `dpservice-bin`. To properly use it, you need to use the provided Docker file to generate an image and run it using the [metalnet project](https://github.com/ironcore-dev/metalnet).

All command-line arguments and configuration files are already handled by the Docker image.

For development, direct use of dp-service is covered by the [development section](../development/).

## Host machine setup
For dpservice to work properly, host IPv6 address needs to set up on `lo` instead of separately on the NIC ports, this way the address is shared.

This address must be in the form of a network prefix `/64`, i.e. the last 64 bits of the host address must be zero. This way the 64 bit suffix can be used for containers or VMs running on the host.

Dpservice will generate addresses in the range from `<host-prefix>:d000::` to `<host-prefix>:dfff::`.

It is suggested that `<host-prefix>:0000::/65` is used for host itself and `<host-prefix>:8000::/65` is then assigned special role, e.g. `<host-prefix>:f000::/68` for PodIPs, `<host-prefix>:d000::/68` for dpservice, etc.

## Command-line tools
All tool binaries are designed to be prefixed with `dpservice-` to enable the operator to simply type `dps<TAB>` for list of possible tools.

The provided Docker image contains:
 - `dpservice-bin`, the main process (already started by being the entrypoint)
 - `dpservice-cli`, gRPC client connecting to the main process, [documentation](../../cli/dpservice-cli/docs/)
 - `dpservice-dump`, tool to provide a way to see the actual traffic handled by dp-service, [documentation](dpservice-dump.md)
 - `dpservice-inspect`, tool to view internal state of dp-service, [documentation](dpservice-inspect.md)
 - `dpservice-exporter`, a Prometheus exporter that can export various statistics about dpservice (interface stats, NAT port usage, hash table fullness, ...)


## Running in HA mode
Dpservice can be run in two instances in parallel. You need to specify `--file-prefix` EAL argument, `--grpc-port` dpservice argument and `--active-lockfile` dpservice argument for this to work properly.

In this mode, both dpservices should be orchestrated in the same way, arriving at the same configuration. This can be achived by providing underlay addresses in gRPC calls instead of relying on dpservice to generate one.

Then while both processes are running, only one of them is ever "active", the other(s) are "backup". The active one behaves the same way as a single dpservice. The backup one(s) only process gRPC commands and no network packets. They also do not run a busy loop, but sleep between polling to lower CPU usage (the intent is to run all instances on the same cores).

When the active one dies (or is gracefully stopped) a backup instance detects this (via a file lock) and becomes active.

This is how rolling updates and crash recovery for dpservice-bin can behandled in k8s.
