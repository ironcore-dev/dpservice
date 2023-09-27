# Config file and command-line arguments
dp-service supports a custom configuration file that reflects its custom command-line arguments, not EAL ones.

In order to make changes to these easier, along with creating a documentation, argument definition for `getopt` and config file parser is delegated to a python script `hack/dp_conf_generate.py`. You only need to provide a command-line options specification via a JSON file, e.g. `hack/dp_conf.json` and then run `hack/dp_conf_generate.py -s hack/dp_conf.json` to update all needed definitions.

This document will try to explain most of it, but it can be easier to just look at the generated files if you already have experience with `getopt_long()`.

## Compiling the parser
After running `hack/dp_conf_generate.py`, you need to include the generated C source file into your own source code. While highly irregular, this removes unnecessary linking problems and hides implementation.

The generated header file is to be included where needed, i.e. either directly in a single source file, or in a guarded custom header file as usual.

## Calling the parser
The only thing needed is to pass `argc` and `argv` to `dp_conf_parse_args()`:
```
switch (dp_conf_parse_args(argc, argv)) {
case DP_CONF_RUNMODE_ERROR:
	return EXIT_FAILURE;
case DP_CONF_RUNMODE_EXIT:
	return EXIT_SUCCESS;
case DP_CONF_RUNMODE_NORMAL:
	break;
}
```
The return value is documented in the generated header file.

## JSON Specification
First, you need to specify the output to generate into:
```json
  "header": "../include/dp_conf_opts.h",
  "source": "../src/dp_conf_opts.c",
  "markdown": "../docs/deployment/help_dpservice-bin.md",
```
And provide a list of options that your program needs to use, e.g. for `--my-option xxx` that takes a string argument and is only used when `#define EXTRA_OPTIONS` is present:
```json
  "options": [
    {
      "shopt": "m",
      "lgopt": "my-option",
      "arg": "MY_ARGUMENT",
      "help": "this is an example option -m, --my-option MY_ARGUMENT",
      "var": "storage_variable",
      "type": "char",
      "array_size": "DEFINED_STRBUF_LEN",
      "ifdef": "EXTRA_OPTIONS"
    },
    ...
  ]
```
You can also use `int` arguments:
```json
  "options": [
    {
      "lgopt": "timeout",
      "arg": "SECONDS",
      "help": "this is an example option --timeout SECONDS",
      "var": "timeout",
      "type": "int",
      "min": 1,
      "max": 120,
      "default": 60
    },
    ...
  ]
```
Or even an `enum`:
```json
  "options": [
    {
      "shopt": "l",
      "arg": "LOGLEVEL",
      "help": "this is an example option -l LOGLEVEL",
      "var": "log_level",
      "type": "enum",
     "choices": [ "err", "warn", "info" ],
      "default": "warn"
    },
    ...
  ]
```
There are also `bool` options, the default value dictates, what the option will do, i.e. using the option will switch the value to the negative of the default value:
```json
  "options": [
    {
      "shopt": "i",
      "lgopt": "inverse",
      "help": "invert something",
      "var": "inverted",
      "type": "bool",
      "default": "false"
    },
    ...
  ]
```
All these options are parsed automatically. If you however need a special combination of settings, `dp_conf_generate.py` will create a static function signature that forces you (via a compilation error) to implement the parser yourself:
```json
  "options": [
    {
      "shopt": "x",
      "arg": "SPECIAL",
      "help": "this does something complicated"
    },
    ...
  ]
```
This will cause a following error:
```
In file included from main.c:19:
opts.c:60:13: error: ‘dp_argparse_opt_x’ used but never defined [-Werror]
   19 | static void dp_argparse_x(const char *arg);
```
Simply implement the function above in the file that included the generated source code.
