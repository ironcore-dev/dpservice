# Dataplane Service testing

Dataplane service comes with a set of tests to verify basic functionality. Running these tests requires root privileges and uses TAP interfaces instead of a real NIC. SmartNIC is therefore not needed to run them.

The test infrastructure uses [pytest](https://docs.pytest.org/) and [scapy](https://scapy.net/), meson build system will check for them being installed during configuration phase.


## Running tests

The easiest way to run unit tests is through **meson**:
```bash
cd build
sudo meson test
```

If a test fails, meson will print out the right command to re-run the failing test:
```bash
1/2 Base tests             FAIL           13.94s   exit status 1
>>> MALLOC_PERTURB_=101 /usr/bin/pytest --build-path=/home/onmetal/git/net-dpservice/build --tun-opt=ipip /home/onmetal/git/net-dpservice/test
```
Running that command will show you full test output for reporting or fixing the problem (don't forget you need to run it as root).

> Developers might consider running `pytest` directly in the `test/` directory to specify individual unit-tests


## GRPC test client

If you want to do some manual testing, you need to use GRPC to communicate with the `dp_service` process. A simple client is provided by this repository. For more information about the client, see [this section](grpc_client.md).
