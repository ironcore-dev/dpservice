Dataplane Service
=================
This is an early protoype version without proper error 
and memory handling.
- Uses [DPDK Graph Framework](https://doc.dpdk.org/guides/prog_guide/graph_lib.html) for the data plane.
- Uses a private pointer in [mbuf](https://doc.dpdk.org/guides/prog_guide/mbuf_lib.html#dynamic-fields-and-flags) structure to carry offloading rte_flow
data around.
- Basic hardcoded [rte_flow](https://doc.dpdk.org/guides/prog_guide/rte_flow.html). 
- Settings are still hard-coded.

Prerequisites
-------------

Working DPDK installation to link to and a SmartNIC to 
operate on. (Currently only Mellanox)

Building
--------

This project uses meson and ninja to build the C application. On the top level directory:

    meson build
    ninja -C build

Run the application as root or use sudo:

    sudo ./build/src/dpservice

License
-------
Licensed under [Apache License v2](LICENSE).

Copyright 2021 by the Gardener on Metal maintainers.
