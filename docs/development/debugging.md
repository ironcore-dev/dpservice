# Debugging Dataplane Service
Due to the fact that dp-service needs to handle large amount of traffic, along with needing higher privileges than most programs, can make debugging it difficult. This page aims to provide some helpful information to make it easier.

## Command-line arguments
By default, DPDK does not print out debug log messages. There are two command-line options that handle logging:
1. `--log-level=<global level>`, default 8 (debug), thus you don't need to set this
2. `--log-level=<type>:<level>`, default 7 (info), you need to set this to 8 to show debug messages

The appropriate types for dp-service log entries are:
1. `user1` for general messages
2. `user2` for graph messages

You can use a pattern, like `*:8` for all debug messages (including DPDK). To only show dp-service debug messages, `--log-level=user*:8` is recommended.


## Run the service as a user
There is an option in the [build system](building#usermode-dpservice) to generate an additional binary `dp_service_user` that can be run as user instead of root. This is not only a safer way to debug, but enables you to easily use any GUI on top of `gdb` just like any other program.

The drawback here is that you need to put the same capabilites to the `gdb` process as the `dp_service_user` binary has. For the most current list of capabilities please see the `hack/set_cap.sh` helper script.


## Debugging the test-suite
Normally, tests are run via the `meson test` command. For easier debugging once the tests fails, direct call to `pytest` in `test/` directory is recommended. Even only running the appropriate `test_*.py` can be better.

Additionally, `pytest` supports the `--attach` argument, which makes it not start its own service process and instead attaches to an already running one (instead of using the provided wrapper script `dp_service.py` to run it). This is a way for the developer to run a service under debugger and then let the tests run on it.

Of course, you need to use the same command-line arguments as the test-suite would use. For that, run the test once with `pytest -s` and then look at the output. The service command-line will be there.

### GDB Signal handler
As the TUN/TAP driver uses signals, it is recommended to use `handle signal SIG35 nostop pass noprint` while debugging the test-suite (as this is just the first of real-time signal values used, you may need to add more).


## Debugging graph nodes
To provide a rudimentary packet analysis while the packet is being processed inside dp-service, there is a command-line tool provided by the repository called `dp_graphtrace`. This allows you to see packet data as it travels through the DPDK graph (as opposed to only seeing ingress/egress packets using `tcpdump`).

Be aware that this will produce large amounts of logs, so only use it for debugging and if possible, on a prepared traffic flow.
