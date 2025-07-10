# Dataplane Service code style guide


## General principles
Keep in mind that the most valued properties are redability and maintainability. Performance can often be achieved even then (and is only top-priority in critical path).

As a good starting point, please read [Linux kernel coding style](https://www.kernel.org/doc/html/v6.0/process/coding-style.html). Apart from kernel-specific sections and a few details (e.g. line length), it is the style being used by this project.

"clean code" and "Return early" principles are also recommended to read upon.


## Code checking script
Since the Linux kernel style is the starting point, this project is also using the `checkpatch.pl` script (with appropriate arguments) to check any commits. Please run `code_check/check.sh` before pushing into this repository.

As part of GitHub CI, this script will be run on your PR automatically and can lead to a failed check.

If you want to make sure this check is run automatically on your side, think about using [Git hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks).
```bash
echo -e '#!/bin/sh\n./code_check/check.sh' > .git/hooks/pre-push
chmod a+x .git/hooks/pre-push
```


## Consistency
There can be multiple acceptable ways to achieve your goal, but be consistent, otherwise it makes the reader question why are thing done differently. Take examples from existing code and commits and be consistent with those, unless refactoring is in order.


## Naming
Use `snake_case`, avoid unclear shortened names except for well-known conventions like `i`, `ptr`, `ret`, etc.

All exported names should be prefixed by `dp_` and preferrably followed by a namespace/context name, like `dp_conf_parse_args()`, `dp_port_create()`, etc.


## Variable definition
As per kernel style guidelines, define variables first, put code second, separated by an empty line. If readability suggests putting declaration in a block, think about using a nested function (potentially inlined) instead.

Feel free to use initialization in definiton.

Prefer initialization over `memset()` for zeroing.


## Inlines
Prefer inlines instead of macros. In a critical path, use `__rte_always_inline` where necessary instead of `inline` which lets the compiler/optimizer decide on inlining.

Inlines are a preferred way to break long functions up without unnecessary nested calls.


## Constants
If a function requires a true/false argument, unless obvious because of the function name (like `dp_port_set_enabled(port, true)`), prefer using a constant definition, e.g. `dp_port_set_mode(port, ENABLED)`. Using a basic type directly, e.g. `dp_port_set_mode(port, true)` is not obvious.

Enums are preffered over defines as they are visible in a debugger and (more importantly) checked by the compiler when using `switch` statements.


## Return values
If a function is a predicate, e.g. `dp_is_enabled()`, then the return value should be boolean.

If a function is a getter, e.g. `dp_get_value()`, then the return value should be the value itself and an out-of-range value should indicate an error. That means `NULL` for pointers and an appropriate value (preferrably negative) for numbers. For a small set of return values (especially if then used in a `switch`), consider using an enum.

If a function is imperative, e.g. `dp_init()`, then the return value should be zero for success, negative for errors and optionally a positive return value if required (best to add a comment to the header about such values). There are constants `DP_OK` and `DP_ERROR` defined in `dp_error.h`, if you want to be more precise, use `-errno`.


## Error handling
Function calls **must** be checked for errors. If a function can return an error, but *that can never happen* (e.g. it only fails when an argument is wrong and we provide a constant literal there), comment such fact. Only then you can skip error checking.

Check the documentation (or even better, the code) of called functions and choose the right handling based on that.

### Dataplane Service calls
There is a helper macro `DP_FAILED()` defined in `dp_error.h` to clearly indicate the return value convention. Please use the following pattern for all appropriate `dp_` calls:
```c
  if (DP_FAILED(dp_func()))
    return DP_ERROR;
```
If the value should be propagated, try to stick to `ret` for convention:
```c
int caller()
{
  int ret;

  ret = dp_func();
  if (DP_FAILED(ret))
    return ret;

  // some work done here

  return DP_OK;
}
```
> There is also a `DP_SUCCESS(ret)` for the unlikely inverse test, e.g. `if (DP_SUCCESS(rte_hash_lookup(...)))`.

### Boolean-like calls
If a function returns `0` for failure and a non-zero for success, use this pattern:
```c
  if (!func())
    return DP_ERROR;
```
Note that this is the same for pointer-calls as they indicate errors by returning `NULL`.

### DPDK calls
Most of `rte_` calls should use the same convention as [dpservice calls](#dataplane-service-calls). For those that do, stick to `DP_FAILED()`.
```c
  ret = rte_func();
  if (DP_FAILED(ret)) {
    DPS_LOG_ERR("Failed to do what func does", DP_LOG_ERR(ret));
    return ret;
  }
```

### Other calls
In other cases, use your best judgement, but be defensive. If there is a clear "success value", then check for that instead of cheking for error values for example. If the function returns `0` for success and some undefined value for errors, prefer:
```c
  if (func()) {
    DPS_LOG_ERR("Failed to do what func() does");
    return DP_ERROR;
  }
```
This way it does not matter what the actual error value is, the condition will work anyway. If the value will be useful to the caller, then propagate it, but be sure that negative values indicate an error, while positive ones do not.


## Logging
Logging should be done as early as reasonably possible (which, unless in critical path, means pretty much always). This enables the service to log source code information of the call.

Unless helpful, there is no need to log at all points of the callstack, so checked the called function for logging and if done there, do not log errors in the caller.

There are currenlty four log-levels. It is expected, that `ERR` will lead to the function's failure, `WARN` will continue on and logs an abnormal state. `INFO` should cover normal state. `DEBUG` should only be used for debugging and is by default not shown.

Please note that the logging function already adds endline where needed, do not include endlines in logged messages.

For `dp_*`, `rte_*` and system calls that return (or use) errno, there is a `dp_strerror()` function in `dp_error.h` if needed, but for direct logging, `DP_LOG_RET()` handles that already.
```c
  ret = some_call();  // returns 0 for success or 'an error number'
  if (ret) {
    DPS_LOG_ERR("Cannot do something", DP_LOG_RET(ret));
    return DP_ERROR;
  }

  name = get_name();  // return NULL for error and raises errno
  if (!name) {
    DPS_LOG_ERR("Cannot get something", DP_LOG_RET(errno));
    return DP_ERROR;
  }
```
