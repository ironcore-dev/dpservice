Dataplane Service
=================
This is an early protoype version without proper error 
and memory handling.

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
