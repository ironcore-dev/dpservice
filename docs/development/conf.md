# Config file and command-line arguments
dp-service supports a custom configuration file that reflects its custom command-line arguments, not EAL ones.

In order to make changes to these easier, along with creating a documentation, argument definition for `getopt` and config file parser is delegated to a python script. You only need to edit `hack/dp_conf.json` and then run `hack/dp_conf_generate.py` to update all needed definitions.

The last thing to do is to actually parse the argument itself, i.e. do something with the string given to you in `src/dp_conf.c:parse_opt()`. If employing memory allocation, also edit `src/dp_conf.c:dp_conf_free()`.

Almost every usage case is already covered by `dp_conf.json` so the best way to understand the possibilities is to look at that file first.
