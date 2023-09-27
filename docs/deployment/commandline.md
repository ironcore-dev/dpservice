# Dataplane Service Command-line Options
`dp_service` accepts two sets of options separated by `--`. The first set contains DPDK options, the second `dp_service` options proper. Both sets support `--help`

## EAL Options
For more information on EAL options, please see [the official docs](https://doc.dpdk.org/guides/linux_gsg/linux_eal_parameters.html)

## Dataplane Service Options
All options are described in `dpservice-bin --help`, see [the markdown version of it](help_dpservice-bin.md)

## Configuration file
Unless an environment variable `DP_CONF` is set to override the path, `dp_service` uses `/tmp/dp_service.conf` to read configuration before processing any arguments.
This way you can provide any arguments via such file and simplify the commandline use. The helper script `prepare.sh` generates such a file for Mellanox users.
