# Dataplane Service code style guide

## General principles
Keep in mind that the most valued properties are redability and maintainability. Performance can often be achieved even then (and is only top-priority in critical path).

As a good starting point, please read [Linux kernel coding style](https://www.kernel.org/doc/html/v6.0/process/coding-style.html). Apart from kernel-specific sections and a few details (e.g. line length), it is the style being used by this project.

"clean code" and "Return early" principles are also recommended to read upon.

## Code checking script
Since the Linux kernel style is the starting point, this project is also using the `checkpatch.pl` script (with appropriate arguments) to check any commits. Please run `code_check/check.sh` before pushing into this repository.

As part of GitHub CI, this script will be run on your PR automatically and can lead to a failed check.

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

## Return values and errors
If a function is a predicate, e.g. `dp_is_enabled()`, then the return value should be boolean.

If a function is a getter, e.g. `dp_get_value()`, then the return value should be the value itself and an out-of-range value should indicate an error. That means `NULL` for pointers and an appropriate value (preferrably negative) for numbers. For a small set of return values (especially if then used in a `switch`), consider using an enum.

If a function is imperative, e.g. `dp_init()`, then the return value should be zero for success, negative for errors (the actual value is up to the API) and optionally a positive return value if required (the actual value is up to the API).

### Helpers
There are constants `DP_OK` (0) and `DP_ERROR` and a helper function `DP_FAILED()` (-1) to make the code clearer. Please include `dp_error.h` and use the following pattern:
```c
int dp_func()
{
  int ret;

  ret = lib_call();
  if (ret < 0)
      return ret;

  ret = lib_call2();
  if (ret == LIB_ERR_VALUE)
      return DP_ERROR;

  return DP_OK;
}

int caller()
{
  int ret;

  ret = dp_func();
  if (DP_FAILED(ret))
      return ret;

  ret = dp_func2();
  if (DP_FAILED(ret))
      return ret;

  return dp_func3();
}
```
Sticking to `ret` for the return value also helps with readability (as it will be always the same in all uses of the helper).
