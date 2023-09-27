# Dataplane Service testing

Dataplane service comes with a set of tests to verify basic functionality. Running these tests requires root privileges and uses TAP interfaces instead of a real NIC. SmartNIC is therefore not needed to run them.

The test infrastructure uses [pytest](https://docs.pytest.org/) and [scapy](https://scapy.net/), meson build system will check for them being installed during configuration phase if the option is set, use `meson setup -Denable_tests=true build` or `meson setup --reconfigure -Denable_tests=true build` on an existing build directory.


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

### Pytest
Developers might consider running `pytest` directly in the `test/` directory to see more detailed information (via `-v` or even full output (via `-s`). With no positional arguments, all tests will run, specify individual unit-test files for making the testing set smaller. When multiple tests are broken, consider using the stop-at-first-error argument `-x`.

Since one test-run only applies to a specific set of options for `dpservice-bin`, argument specifying the type of underlay tunnel (`--tun-opt`, default `ipip`) and whether or not port redundancy should be utilized (`--port-redundancy`) are needed to fully test all code paths.

If one should want to instead run your own `dpservice-bin` instance (e.g. for running under a debugger), the `--attach` argument connects to an already running service instead of starting its own. This comes with the caveat of ensuring the right arguments are passed to the service at startup.


## GRPC test client
If you want to do some manual testing, you need to use GRPC to communicate with the `dpservice-bin` process. A simple client is provided by this repository. For more information about the client, see [this section](grpc_client.md).


## Mellanox test setup
If you have a Mellanox card, you can run dp-service along with KVM and use GRPC client to setup your own 'datacenter server'. You can even use another NIC or even a virtual ethernet pair to emulate inter-hypervisor communication. See [Mellanox testing guide](mellanox.md) for additional information.
