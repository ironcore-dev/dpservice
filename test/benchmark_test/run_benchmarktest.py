#!/usr/bin/env python3

import argparse
import pytest
import re
import os
import time


def underscore_convert(text):
	return re.sub("_", "-", text)


def execute_benchmark_pytest(args):

	args_template = ['-vv']
	modes = ["non-offload", "offload"] if args.mode == "both" else [args.mode]

	for arg_name, arg_value in vars(args).items():
		if arg_name != "mode" and arg_name != "verbose" and arg_name != "reboot" and arg_name != "func":
			args_template.append("--" + underscore_convert(arg_name))
			args_template.append(arg_value)
		if arg_name == "verbose" and arg_value:
			args_template.append('-s')
		if arg_name == "reboot" and arg_value:
			args_template.append('--reboot')

	pytest_args_collection = []
	for mode in modes:
		pytest_args_collection.append(["--mode", mode] + args_template)

	for pytest_args in pytest_args_collection:
		print(pytest_args)
		pytest.main(args=pytest_args)
		time.sleep(1)


def add_arg_parser():
	script_path = os.path.dirname(os.path.abspath(__file__))
	parser = argparse.ArgumentParser(
		formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=32))
	parser.add_argument("--mode", action="store", choices=['offload', 'non-offload', 'both'],
						help="Benchmarking tests in the non-offloading/offloading mode. Select from 'offload', 'non-offload' and 'both'. ")
	parser.add_argument("--stage", action="store", choices=[
						'dev', 'cicd'], help="Benchmarking tests to assist local development (local development machine will not run docker container).")
	parser.add_argument("--docker-image", action="store", default="",
						help="Container image to be deployed to almost all hypervsiors")
	parser.add_argument("--dpservice-build-path", action="store",
						default=f"{script_path}/../../build", help="Path to dpservice-bin build directory")
	parser.add_argument("--reboot", action="store_true", default=False,
						help="Reboot VMs to obtain new configurations such as IPs")
	parser.add_argument("--env-config-file", action="store", default="./test_configurations.json",
						help="Specify the file containing setup information")
	parser.add_argument("--env-config-name", action="store", default="regular_setup",
						help="Specify the name of environment configuration that fits to hardware and VM setup. ")
	parser.add_argument("-v", "--verbose", action="store_true", default=False,
						help="Allow to output debug information during pytest execution")
	parser.set_defaults(func=execute_benchmark_pytest)

	args = parser.parse_args()
	if hasattr(args, 'func'):
		args.func(args)
	else:
		parser.print_help()


if __name__ == '__main__':
	add_arg_parser()
