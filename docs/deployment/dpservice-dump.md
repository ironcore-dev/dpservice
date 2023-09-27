# Dataplane Service Packet Dump Utility
`dpservice-dump` is a tool to see packets going through dp-service packet processing.

## Command-line Options
All options are described in `dpservice-dump --help`, see [the markdown version of it](help_dpservice-dump.md)

## Disclaimer
As this tool attaches to a live packet-processing dp-service, it can cause performance degradation in packet-processing.

Always make sure that the tool detaches cleanly (i.e. prints out `Graphtrace successfully disabled in dp-service`. If this does not happen (or the user is unable to verify), make sure to call `dpservice-dump --stop` to perform a manual clean-up.

## Examples
`dpservice-dump` prints all ingress/egress packets processed by dp-service.
`dpservice-dump --drops` also prints dropped packets.
`dpservice-dump --nodes` also prints packets as they are [going through the graph](../concepts/graphtrace.md)

