#!/usr/bin/env python3

import argparse
import json
import re
import os
import sys


re_shopt = re.compile("^[a-zA-Z]$")
re_lgopt = re.compile("^[a-zA-Z][a-zA-Z0-9_\-]")  # TODO remove underscore?

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
	# Generate IDs
	print("enum {")
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
	print("#define OPTSTRING \\")
	for option in options:
		if not option.shopt:
			continue
		arg = ':' if option.arg else '';
		option.print(f'\t"{option.shopt}{arg}" \\')
	print("")
	# Generate getopt_long() option array
	print("static const struct option longopts[] = {")
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
	# Generate help function
	longest_opts = max(len(option.help_opts) for option in options)
	print('static void print_help_args(FILE *outfile)\n{\n\tfprintf(outfile, "%s",')
	for option in options:
		help_opts = option.help_opts.ljust(longest_opts)
		choices = f": {option.help_choices}" if option.choices else ""
		option.print(f'\t\t" {help_opts}  {option.help_str}{choices}\\n"')
	print("\t);\n}\n")
	# Generate storage variables
	for option in options:
		if not option.ctype or not option.varname:
			continue
		array = f"[{option.array_size}]" if option.array_size is not None else "";
		ctype = option.ctype
		default = ""
		if ctype == "enum":
			if option.default:
				default = f" = DP_CONF_{option.varname.upper()}_{option.default.upper()}"
			ctype = f"enum dp_conf_{option.varname}"
		else:
			if option.default:
				default = f" = {option.default}"
		option.print(f"static {ctype} {option.varname}{array}{default};")
	print("")
	# Generate getters
	for option in options:
		if not option.ctype or not option.varname:
			continue
		signature = get_signature(option)
		option.print(f"{signature}\n{{\n\treturn {option.varname};\n}}\n")

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
		if not option.ctype or not option.varname:
			continue
		signature = get_signature(option)
		option.print(f"{signature};")

def generate_md(options):
	print("# Dataplane Service Command-line Options")
	print("> This file has been generated by dp_conf_generate.py. As such it should fully reflect the current `dp_service` argument parser.")
	print("")
	print("`dp_service` accepts two sets of options separated by `--`. The first set contains DPDK options, the second `dp_service` options proper. Both sets support `--help`")
	print("")
	print("## EAL Options")
	print("For more information on EAL options, please see [the official docs](https://doc.dpdk.org/guides/linux_gsg/linux_eal_parameters.html)")
	print("")
	print("## Dataplane Service Options")
	print("| Option | Argument | Description | Choices |")
	print("|--------|----------|-------------|---------|")
	for option in options:
		opts = option.shopt
		opts = f"-{opts}, --{option.lgopt}" if opts else f"--{option.lgopt}"
		print(f"| {opts} | {option.arg} | {option.help_str} | {option.help_choices} |")
	print("")
	print("## Configuration file")
	print("Unless an environment variable `DP_CONF` is set to override the path, `dp_service` uses `/tmp/dp_service.conf` to read configuration before processing any arguments.")
	print("This way you can provide any arguments via such file and simplify the commandline use. The helper script `prepare.sh` generates such a file for Mellanox users.")


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
	parser.add_argument("--source", action="store", default=f"{script_path}/../src/dp_conf_opts.c")
	parser.add_argument("--header", action="store", default=f"{script_path}/../include/dp_conf_opts.h")
	parser.add_argument("--markdown", action="store", default=f"{script_path}/../docs/deployment/commandline.md")
	args = parser.parse_args()

	with open(args.specs, "r") as infile:
		specs = json.load(infile)
		if not isinstance(specs, list):
			raise ValueError("Specs do not contain a list of options")

		options = [ Option(spec) for spec in specs ]

		stdout = sys.stdout

		with open(args.source, "w") as outfile:
			sys.stdout = outfile
			print_warning()
			generate_c(options)

		with open(args.header, "w") as outfile:
			sys.stdout = outfile
			print_warning()
			generate_h(options)

		with open(args.markdown, "w") as outfile:
			sys.stdout = outfile
			generate_md(options)

		sys.stdout = stdout
