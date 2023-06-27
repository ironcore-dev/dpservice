# Logging in dp-service
The codebase of Dataplane Service uses [structured logging](https://go.googlesource.com/proposal/+/master/design/56345-structured-logging.md). This enables the service to produce JSON-lines output log format with key-value pairs for easier parsing. Although a more standard (syslog-like) output is also supported (via `--log-format` command line switch).
```
{ "ts": "2023-06-27 12:13:17.624", "thread_id": 1, "thread_name": "control", "level": "info", "logger": "service", "msg": "Starting DP Service version 1.0.0", "caller": "../src/dp_service.c:204:run_service()" }
{ "ts": "2023-06-27 12:13:17.960", "thread_id": 2, "thread_name": "grpc", "level": "info", "logger": "grpc", "msg": "Server started and listening", "listen_address": "[::]:1337", "caller": "../src/grpc/dp_grpc_service.cpp:34:run()" }
```

To provide this structured logging approach in C, a custom logging API is provided in `include/dp_log.h`.


## Initialization
`dp_log_init()` is needed to initialize the logging subsystem once. Each thread must then call `dp_log_set_thread_name()` to properly initialize thread-specific information.

## Early errors
Before `dp_log_init()` (that requires at least command-line to be parsed, thus DPDK to initialize) errors cannot be reported via the logging subsystem. Therefore an early-error macro `DP_EARLY_ERR` has been provided. This macro uses printf-style arguments (as the structured logging has not yet been initialized)!


## Logging macros
The proper way of using the logging API is to use provided macros that automatically fill-in many fields. They are named according to a template `<LOGGER>_LOG_<LEVEL>()`, for exaple `DPS_LOG_ERR()`, `DPGRPC_LOG_INFO()`, etc. There is also a special `DPNODE_LOG_<LEVEL>()` that also take a graph-node parameter to provide some info automatically.

### Log levels
There are currently four levels to choose from: `ERR`, `WARNING`, `INFO` and `DEBUG`. Names have been chosen to match DPDK level names, but only a subset is in use by dp-service.

### Calling convention
In the most basic form, logging macros can be called with just one argument, the message. This way, following fields will be present in the resulting log line: `ts`, `thread_id`, `thread_name`, `level`, `logger`, `msg` and `caller`.

To provide any other fields, the logging macro needs additional arguments, that specify the key name, value type and the value itself. To simplify the call, another set of macros has been provided in the form of `DP_LOG_<FIELD>(<value>)`. Thus the real-world example can look like follows:
```
DPGRPC_LOG_WARNING("Failed request", DP_LOG_GRPCRET(ret), DP_LOG_VNI(vni), DP_LOG_IPV4(nat_ipv4));
```

### Best practices
Always use `DP_LOG_RET(ret)` for logging `rte_` and `dp_` function-call results (and errno).

Do not use `_DP_LOG_<TYPE>()` directly, except for situations where the key is unique to a single call/situation. It is better to use pre-defined keys via `DP_LOG_<KEY>()`.

If a general-purpose value is needed, consider using `DP_LOG_VALUE(<int>)`. For limits or counters (like how many items succeeded), consider also using `DP_LOG_MAX()` in conjuction.

For string identifier, consider re-using the appropriate key or adding a new one, if such identifier is global (like loadbalancer id, interface id, etc.). For general cases (like memory allocation tags, debugging, etc.), consider using `DP_LOG_NAME()`.


## Implementation specifics
Due to the nature fo structured logging, variable-length argument list is needed. In C, this will always be inherently unsafe. Especially since the calling convention does not follow printf-style API.

In reality, logging macros call `_dp_log_structured()` function that accepts standard variadic arguments. Instead of the arguments being parsed based on the format string (like printf), the arguments muse follow a key-format-value schema and be terminated by a `NULL` entry. This is why it is critical to only use provided macros for logging and not use printf-style arguments.

There have been some steps taken to prevent accidental use of wrong arguments (like using canary values for the format field and preventing the use of `%` in the message) and there are asserts in debug compilation.
