# Dataplane Service testing

Dataplane service comes with a set of tests to verify basic functionality. Running these tests requires root privileges and uses TAP interfaces instead of a real NIC. SmartNIC is therefore not needed to run them.

The test infrastructure uses [pytest](https://docs.pytest.org/), [scapy](https://scapy.net/) and golang, meson build system will check for them being installed during configuration phase if the option is set, use `meson setup -Denable_tests=true build` or `meson setup --reconfigure -Denable_tests=true build` on an existing build directory.

Enabling tests via meson also adds some compiled-in testing code, which is beyond the scope of this document. Automated tests already utilize this feature.


## Running tests

The easiest way to run unit tests is through `test/runtest.py`.
```bash
cd test
sudo ./runtest.py
```

The script prints out all `pytest` commands it uses, so in case of a failure, you can easily re-run it manually:
```
TEST 1/3 - base tests:
pytest-3 -x -v --build-path=/home/plague/git/dpservice/test/../build --virtsvc /home/plague/git/dpservice/test
...
(error output here)
...
TEST FAILED with returncode 1
pytest-3 -x -v --build-path=/home/plague/git/dpservice/test/../build --virtsvc /home/plague/git/dpservice/test
```

### Pytest
When running `pytest` directly in the `test/` directory, only a specific set of options for `dpservice-bin` is used. Arguments specifying whether or not port redundancy should be utilized (`--port-redundancy`) or if a shortened flow timeout should be used (`--fast-flow-timeout`) are needed to fully test all code paths. This is done automatically by `runtest.py`.

If one should want to instead run your own `dpservice-bin` instance (e.g. for running under a debugger), the `--attach` argument connects to an already running service instead of starting its own (which in turn can be started via a helper `dp_service.py` script). This comes with the caveat of ensuring the right arguments are passed to the service at startup.

#### Pytest on Mellanox
By default, `pytest` runs using virtual intefaces (TAPs). By providing `--hw` command-line option, it can instead use real NIC based on the contents of `/tmp/dp_service.conf`. For more information [see Mellanox testing guide](mellanox.md#two-machine-setup).

## Docker
There is a tester image provided by this repo, simply build it using this repo's `Dockerfile` and use `--target tester`. For fully working images a GitHub PAT is needed: `docker build --secret=id=github_token,src=<path/to/github_token> --target tester .`

To run the image, you need to provide more arguments for privileged access: `sudo docker run -it --rm --privileged --mount type=bind,source=/dev/hugepages,target=/dev/hugepages <image>`.


## GRPC client
If you want to do some manual testing, you need to use GRPC to communicate with the `dpservice-bin` process. A full-featured command-line client is provided by this repository. For more information about the client, see [this section](grpc_client.md).


## Mellanox test setup
If you have a Mellanox card, you can run dp-service along with KVM and use GRPC client to setup your own 'datacenter server'. You can even use another NIC or even a virtual ethernet pair to emulate inter-hypervisor communication. See [Mellanox testing guide](mellanox.md) for additional information.
