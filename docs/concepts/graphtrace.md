# Packet tracing during graph traversal
As dp-service uses DPDK's [graph library](https://doc.dpdk.org/guides/prog_guide/graph_lib.html) to handle packets, a method to debug the movement of the packet through this graph (graphtrace) is provided.

## Using packet tracing
A command-line tool `dp_graphtrace` is provided in the `tools/` directory and is part of the docker image. Currently, there are no command-line options.

## Packet tracing in logs
For easier development, packet tracing can also be shown as debug-level messages. For this, a command-line option `--graphtrace-loglevel` is used. It is off (zero) by default. By setting it to `1`, tracing messages are logged after being sent out to the ring buffer. Level `2` can also be specified to provide messages on entering a graph-node, which can be useful in development.

Trace logging is only available if `-Denable_tests=true` meson feature is enabled. And as it is pronted using `debug` level messages, an EAL argument `--log-leel=user*:8` is also needed when running dp-service.

## Things of note
This feature is implemented using a DPDK ring buffer. Its size has been arbitrarily chosen and may need fine-tuning for deployment. It does not overwrite existing elements when full, so it needs to be dumped before showing current data (the command-line client already does this).

As the packet traverses through the graph, its layers are being stripped and added, therefore no standardized output like Pcap is possible as there often is no link-layer to use.

It is recommended to run `dp_graphtrace` on a separate CPU core to dp-service's worker threads. This is currently done by using the primary core, which is actually not under load by dp-service (it is only used for timers and statistics).
