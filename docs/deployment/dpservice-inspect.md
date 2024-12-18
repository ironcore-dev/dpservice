# Dataplane Service Internal Inspection Tool
`dpservice-inspect` is a tool to see internal state of dp-service. Currently, only hash-tables are accessible.

## Command-line Options
All options are described in `dpservice-inspect --help`, see [the markdown version of it](help_dpservice-inspect.md)

## Disclaimer
As this tool attaches to a live packet-processing dp-service, use it with caution. It should not cause performance degradation in packet-processing since the tool only reads shared-memory in a separate process.

## Examples
`dpservice-inspect` prints all supported hash-tables that can be viewed.

`dpservice-inspect -t <table>` prints the number of entries in a given table

`dpservice-inspect -t <table> --dump` prints the contents of the table

You can choose the output format using `-o`.

> By default, this tool uses `-1` as the NUMA socket. In practice dp-service will be utilizing NUMA and you need to specify it via `-s`.
