#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import argparse
import json
import re
import os
import sys


re_shopt = re.compile("^[a-zA-Z]$")
re_lgopt = re.compile("^[a-zA-Z][a-zA-Z0-9\-]")

class Option:
	def __init__(self, spec):
		self.shopt = spec.get('shopt')
		self.lgopt = spec.get('lgopt')
		self.arg = spec.get('arg')
		self.help_str = spec.get('help')
		self.ctype = spec.get('type')
		self.varname = spec.get('var')
		self.default = spec.get('default')
		self.array_size = spec.get('array_size')
		self.ifdef = spec.get('ifdef')
		self.choices = spec.get('choices')
		self.min_val = spec.get('min')
		self.max_val = spec.get('max')

		if self.varname and not self.ctype:
			raise KeyError(f"Missing 'type' for {spec}")

		if self.ctype and not self.varname:
			raise KeyError(f"Missing 'var' for {spec}")

		if not self.shopt and not self.lgopt:
			raise KeyError(f"Missing either long or short option for {spec}")

		if self.shopt and not re_shopt.match(self.shopt):
			raise ValueError(f"Invalid short option '{self.shopt}' in {spec}")

		if self.lgopt and not re_lgopt.match(self.lgopt):
			raise ValueError(f"Invalid long option '{self.lgopt}' in {spec}")

		if self.min_val == None:
			self.min_val = "INT_MIN"

		if self.max_val == None:
			self.max_val = "INT_MAX"

		if self.ctype == 'enum':
			if not self.choices:
				raise KeyError(f"Missing choices in enum definition for {spec}")
			if len(self.choices) > len(set(self.choices)):
				raise ValueError(f"Duplicate entries in choices for {spec}")
			if self.default and not self.default in self.choices:
				raise ValueError(f"Invalid choice in default enum value for {spec}")

		opt = self.lgopt if self.lgopt else self.shopt
		self.optid = "OPT_" + opt.replace('-', '_').upper()

		if self.shopt and self.lgopt:
			self.help_opts = f"-{self.shopt}, --{self.lgopt}"
		elif self.shopt:
			self.help_opts = f"-{self.shopt}"
		else:
			self.help_opts = f"    --{self.lgopt}"
		if self.arg:
			self.help_opts += f"={self.arg}"

		if not self.ifdef:
			self.ifdef = []
		elif self.ifdef and isinstance(self.ifdef, str):
			self.ifdef = [ self.ifdef ]

		self.help_choices = ""
		if self.choices:
			for choice in self.choices:
				if choice != self.choices[0]:
					self.help_choices += " or " if choice == self.choices[-1] else ", "
				default = " (default)" if self.default == choice else ""
				self.help_choices += f"'{choice}'{default}"

		# This will force the user to implement custom parsing functions
		self.argparse_signature = f"int dp_argparse_{self.optid.lower()}"
		if not self.arg:
			if self.ctype == "bool":
				self.argparse_signature = None
			else:
				self.argparse_signature += "(void)"
		else:
			if not self.ctype:
				self.argparse_signature += "(const char *arg)"
			elif self.ctype == "enum" or self.ctype == "char" or self.ctype == "int":
				self.argparse_signature = None
			elif self.array_size is not None:
				self.argparse_signature += f"({self.ctype} dst_{self.varname}[{self.array_size}], const char *arg)"
			else:
				self.argparse_signature += f"({self.ctype} *dst_{self.varname}, const char *arg)"

		# This is the actual parsing implementation call
		self.argparse_call = f"dp_argparse_{self.optid.lower()}"
		if not self.arg:
			if self.ctype == "bool":
				self.argparse_call = f"dp_argparse_store_{'false' if self.default == 'true' else 'true'}"
			self.argparse_call += f"(&{self.varname})"
		else:
			if not self.ctype:
				self.argparse_call += "(arg)"
			elif self.ctype == "enum":
				choices = f"{self.varname}_choices"
				self.argparse_call = f"dp_argparse_enum(arg, (int *)&{self.varname}, {choices}, ARRAY_SIZE({choices}))"
			elif self.ctype == "char":
				self.argparse_call = f"dp_argparse_string(arg, {self.varname}, ARRAY_SIZE({self.varname}))"
			elif self.ctype == "int":
				self.argparse_call = f"dp_argparse_int(arg, &{self.varname}, {self.min_val}, {self.max_val})"
			elif self.array_size is not None:
				self.argparse_call += f"(arg, {self.varname}, ARRAY_SIZE({self.varname}))"
			else:
				self.argparse_call += f"(arg, &{self.varname})"

	# Use this to make sure given line is under #ifdef
	def print(self, string):
		for ifdef in self.ifdef:
			print(f"#ifdef {ifdef}")
		print(string)
		for ifdef in self.ifdef:
			print("#endif")


def get_signature(option):
	ptr = "*" if option.array_size is not None else ""
	const = "const " if ptr else ""
	prefix = "dp_conf_is_" if option.ctype == "bool" else "dp_conf_get_"
	ctype = f"enum dp_conf_{option.varname}" if option.ctype == "enum" else option.ctype
	return f"{const}{ctype} {ptr}{prefix}{option.varname}(void)"

def generate_c(options):
	# dp_argparse.h is needed for the default parsing functions
	print('#include "dp_argparse.h"\n')
	print("#ifndef ARRAY_SIZE")
	print("#\tdefine ARRAY_SIZE(ARRAY) (sizeof(ARRAY) / sizeof((ARRAY)[0]))")
	print("#endif\n")
	# Generate IDs
	print("enum {")
	print("\tOPT_HELP = 'h',")
	print("\tOPT_VERSION = 'v',")
	for option in options:
		if not option.shopt:
			continue
		option.print(f"\t{option.optid} = '{option.shopt}',")
	print("_OPT_SHOPT_MAX = 255,")
	for option in options:
		if option.shopt:
			continue
		option.print(f"\t{option.optid},")
	print("};\n")
	# Generate getopt() and getopt_long() optstring
	print('#define OPTSTRING ":hv" \\')
	for option in options:
		if not option.shopt:
			continue
		arg = ':' if option.arg else '';
		option.print(f'\t"{option.shopt}{arg}" \\')
	print("")
	# Generate getopt_long() option array
	print("static const struct option dp_conf_longopts[] = {")
	print('\t{ "help", 0, 0, OPT_HELP },')
	print('\t{ "version", 0, 0, OPT_VERSION },')
	for option in options:
		if not option.lgopt:
			continue
		has_arg = 1 if option.arg else 0
		option.print(f'\t{{ "{option.lgopt}", {has_arg}, 0, {option.optid} }},')
	print("\t{ NULL, 0, 0, 0 }")
	print("};\n")
	# Generate translation tables for choices
	for option in options:
		if not option.choices:
			continue
		option.print(f"static const char *{option.varname}_choices[] = {{")
		for choice in option.choices:
			option.print(f'\t"{choice}",')
		option.print("};\n")
	# Generate storage variables
	for option in options:
		if not option.ctype:
			continue
		array = f"[{option.array_size}]" if option.array_size is not None else "";
		ctype = option.ctype
		default = ""
		if ctype == "enum":
			if option.default is not None:
				default = f" = DP_CONF_{option.varname.upper()}_{option.default.upper()}"
			ctype = f"enum dp_conf_{option.varname}"
		else:
			if option.default is not None:
				default = f" = {option.default}"
		option.print(f"static {ctype} {option.varname}{array}{default};")
	print("")
	# Generate getters
	for option in options:
		if not option.ctype:
			continue
		signature = get_signature(option)
		option.print(f"{signature}\n{{\n\treturn {option.varname};\n}}\n")
	print("")
	# Generate function signatures to be provided by the user
	print("\n/* These functions need to be implemented by the user of this generated code */")
	print("static void dp_argparse_version(void);")
	for option in options:
		if option.argparse_signature:
			option.print(f"static {option.argparse_signature};")
	print("\n")
	# Generate help function
	print("static inline void dp_argparse_help(const char *progname, FILE *outfile)")
	print("{")
	print('\tfprintf(outfile, "Usage: %s [options]\\n"')
	longest_opt = max(len(option.help_opts) for option in options)
	help_opts_help = "-h, --help"
	help_opts_version = "-v, --version"
	longest_opt = max(longest_opt, len(help_opts_help), len(help_opts_version))
	print(f'\t\t" {help_opts_help.ljust(longest_opt)}  display this help and exit\\n"')
	print(f'\t\t" {help_opts_version.ljust(longest_opt)}  display version and exit\\n"')
	for option in options:
		help_opts = option.help_opts.ljust(longest_opt)
		choices = f": {option.help_choices}" if option.choices else ""
		option.print(f'\t\t" {help_opts}  {option.help_str}{choices}\\n"')
	print("\t, progname);")
	print("}\n")
	# Generate the main switch to enforce user-implemented functions
	print("static int dp_conf_parse_arg(int opt, const char *arg)")
	print("{")
	print("\t(void)arg;  // if no option uses an argument, this would be unused")
	print("\tswitch (opt) {")
	for option in options:
		option.print(f"\tcase {option.optid}:\n\t\treturn {option.argparse_call};")
	print("\tdefault:")
	print('\t\tfprintf(stderr, "Unimplemented option %d\\n", opt);')
	print("\t\treturn DP_ERROR;")
	print("\t}")
	print("}\n")
	# Generate the parser entrypoint
	print("enum dp_conf_runmode dp_conf_parse_args(int argc, char **argv, int *positional_index)")
	print("{")
	print("\tconst char *progname = argv[0];")
	print("\tint option_index = -1;")
	print("\tint opt;")
	print("")
	print("\twhile ((opt = getopt_long(argc, argv, OPTSTRING, dp_conf_longopts, &option_index)) != -1) {")
	print("\t\tswitch (opt) {")
	print("\t\tcase OPT_HELP:")
	print("\t\t\tdp_argparse_help(progname, stdout);")
	print("\t\t\treturn DP_CONF_RUNMODE_EXIT;")
	print("\t\tcase OPT_VERSION:")
	print("\t\t\tdp_argparse_version();")
	print("\t\t\treturn DP_CONF_RUNMODE_EXIT;")
	print("\t\tcase ':':")
	print("\t\t\tfprintf(stderr, \"Missing argument for '%s'\\n\", argv[optind-1]);")
	print("\t\t\treturn DP_CONF_RUNMODE_ERROR;")
	print("\t\tcase '?':")
	print("\t\t\tif (optopt > 0)")
	print("\t\t\t\tfprintf(stderr, \"Unknown option '-%c'\\n\", optopt);")
	print("\t\t\telse")
	print("\t\t\t\tfprintf(stderr, \"Unknown option '%s'\\n\", argv[optind-1]);")
	print("\t\t\treturn DP_CONF_RUNMODE_ERROR;")
	print("\t\tdefault:")
	print("\t\t\tif (DP_FAILED(dp_conf_parse_arg(opt, optarg))) {")
	print("\t\t\t\tif (option_index >= 0)")
	print("\t\t\t\t\tfprintf(stderr, \"Invalid argument for '--%s'\\n\", dp_conf_longopts[option_index].name);")
	print("\t\t\t\telse")
	print("\t\t\t\t\tfprintf(stderr, \"Invalid argument for '-%c'\\n\", opt);")
	print("\t\t\t\treturn DP_CONF_RUNMODE_ERROR;")
	print("\t\t\t}")
	print("\t\t}")
	print("\t\toption_index = -1;")
	print("\t}")
	print("")
	print("\tif (positional_index)")
	print("\t\t*positional_index = optind;")
	print("")
	print("\treturn DP_CONF_RUNMODE_NORMAL;")
	print("}\n")

"""
TODO markwówn, mention _args and _arg generated output? TODO public _arg?
In file included from ../tools/dump/main.c:19:
../tools/dump/opts.c:60:13: error: ‘dp_argparse_version’ used but never defined [-Werror]
   60 | static void dp_argparse_version(void);
"""

def generate_h(options):
	# Generate enums
	for option in options:
		if not option.ctype or option.ctype != 'enum':
			continue
		option.print(f"enum dp_conf_{option.varname} {{")
		for choice in option.choices:
			option.print(f"\tDP_CONF_{option.varname.upper()}_{choice.upper()},")
		option.print("};\n")
	# Generate getters
	for option in options:
		if not option.ctype:
			continue
		signature = get_signature(option)
		option.print(f"{signature};")
	# Generate parser entrypoint and result
	print("")
	print("enum dp_conf_runmode {")
	print("\tDP_CONF_RUNMODE_NORMAL, /**< Start normally */")
	print("\tDP_CONF_RUNMODE_EXIT,   /**< End succesfully (e.g. for --help etc.) */")
	print("\tDP_CONF_RUNMODE_ERROR,  /**< Error parsing arguments */")
	print("};")
	print("")
	print("/** Pass program's arguments and optionally a place to store the index to first positional argument. */")
	print("enum dp_conf_runmode dp_conf_parse_args(int argc, char **argv, int *positional_index);")

def generate_md(options):
	print("# Command-line Options")
	print("")
	print("| Option | Argument | Description | Choices |")
	print("|--------|----------|-------------|---------|")
	print("| -h, --help | None | display this help and exit |  |")
	print("| -v, --version | None | display version and exit |  |")
	for option in options:
		opts = option.shopt
		opts = f"-{opts}, --{option.lgopt}" if opts else f"--{option.lgopt}"
		print(f"| {opts} | {option.arg} | {option.help_str} | {option.help_choices} |")
	print("")
	print("> This file has been generated by dp_conf_generate.py. As such it should fully reflect the output of `--help`.")
	print("")


def print_license():
	print("// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors")
	print("// SPDX-License-Identifier: Apache-2.0")
	print("")

def print_warning():
	print("/***********************************************************************/")
	print("/*                        DO NOT EDIT THIS FILE                        */")
	print("/*                                                                     */")
	print("/* This file has been generated by dp_conf_generate.py                 */")
	print("/* Please edit dp_conf.json and re-run the script to update this file. */")
	print("/***********************************************************************/")
	print("")

if __name__ == "__main__":
	script_path = os.path.dirname(os.path.abspath(__file__))
	parser = argparse.ArgumentParser()
	parser.add_argument("-s", "--specs", action="store", default=f"{script_path}/dp_conf.json")
	args = parser.parse_args()

	specs_path = os.path.dirname(args.specs)

	with open(args.specs, "r") as infile:
		specs = json.load(infile)
		header = f"{specs_path}/{specs['header']}"
		source = f"{specs_path}/{specs['source']}"
		markdown = f"{specs_path}/{specs['markdown']}"
		opts = specs['options']
		if not isinstance(opts, list):
			raise ValueError("Specs do not contain a list of options")

		options = [ Option(opt) for opt in opts ]

		# easier use of print()
		stdout = sys.stdout

		with open(source, "w") as outfile:
			sys.stdout = outfile
			print_license()
			print_warning()
			generate_c(options)

		with open(header, "w") as outfile:
			sys.stdout = outfile
			print_license()
			print_warning()
			generate_h(options)

		with open(markdown, "w") as outfile:
			sys.stdout = outfile
			generate_md(options)

		sys.stdout = stdout
