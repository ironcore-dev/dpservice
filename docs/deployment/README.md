# Dataplane Service deployment
This repository only provides a compiled binary of `dpservice-bin`. To properly use it, you need to use the provided Docker file to generate an image and run it using the [metalnet project](https://github.com/ironcore-dev/metalnet).

All command-line arguments and configuration files are already handled by the Docker image.

For development, direct use of dp-service is covered by the [development section](../development/).

## Command-line tools
All tool binaries are designed to be prefixed with `dpservice-` to enable the operator to simply type `dps<TAB>` for list of possible tools.

The provided Docker image contains:
 - `dpservice-bin`, the main process (already started by being the entrypoint)
 - `dpservice-cli`, gRPC client connecting to the main process, [documentation](../../cli/dpservice-cli/docs/)
 - `dpservice-dump`, tool to provide a way to see the actual traffic handled by dp-service, [documentation](dpservice-dump.md)
 - `dpservice-inspect`, tool to view internal state of dp-service, [documentation](dpservice-inspect.md)
 - `dpservice-exporter`, a Prometheus exporter that can export various statistics about dpservice (interface stats, NAT port usage, hash table fullness, ...)
