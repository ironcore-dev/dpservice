#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import argparse
import os
import random
import sys
import subprocess
import shutil

from exporter import Exporter
from grpc_client import GrpcClient

class TestSuite:

	def __init__(self, label, description, args, files=[]):
		global script_path
		self.label = label
		self.description = description
		self.args = args
		self.files = [f"{script_path}/{testfile}" for testfile in files] if files else [script_path]


def queryDpService(dpservice, arg):
	return subprocess.check_output([dpservice, '--no-pci', '--no-huge', '--', arg],
								   stderr=subprocess.DEVNULL).decode('utf8').strip()

def generateTestSuits(test_args, build_path, dpservice_help):
	suites = []
	if 'pf_proxy' in build_path:
		suites.append(TestSuite("pf-proxy-base", "Basic set of tests with common dpservice setup",
		test_args + ['--pf1-proxy']))
		suites.append(TestSuite("pf-proxy-xtra", "Test the impact of using the pf proxy solution",
			test_args + ['--pf1-proxy'] +  ['--port-redundancy'], ['test_encap.py', 'test_vf_to_pf.py', 'test_virtsvc.py', 'xtratest_pf_proxy.py']))
		return suites
	
	suites.append(TestSuite("base", "Basic set of tests with common dpservice setup",
		test_args))
	suites.append(TestSuite("wcmp", "Port-redundancy tests with WCMP enabled",
		test_args + ['--port-redundancy'], ['test_encap.py', 'test_vf_to_pf.py', 'test_virtsvc.py']))
	
	if '--flow-timeout' in dpservice_help:
		suites.append(TestSuite("flow", "Flow timeout tests with extremely fast flow timeout",
			test_args + ['--fast-flow-timeout'], ['xtratest_flow_timeout.py']))
		
	return suites


def testDpService(build_path, print_header):
	global args

	# Verify dpservice-bin
	dpservice = f"{build_path}/src/dpservice-bin"
	assert os.access(dpservice, os.X_OK), \
		"Provided directory does not contain a runnable dpservice binary"

	# Verify dpservice-cli
	grpc_client = GrpcClient(build_path)

	test_args = [f"--build-path={build_path}"]
	if args.hw:
		test_args.append('--hw')
		if args.offloading:
			test_args.append('--offloading')

	# Read help to know which features are supported
	dpservice_help = queryDpService(dpservice, '--help')
	if '--udp-virtsvc' in dpservice_help:
		test_args.append('--virtsvc')

	# Generate test suites supported by this binary
	suites = generateTestSuits(test_args, build_path, dpservice_help)

	# --list-suites prints and terminates
	if args.list_suites:
		print(f"Available test suites for {build_path}:")
		col_width = 0
		for suite in suites:
			if len(suite.label) > col_width:
				col_width = len(suite.label)
		for suite in suites:
			print(f"  {suite.label.ljust(col_width)} - {suite.description}")
		return

	# Run tests
	bin_ver = queryDpService(dpservice, '--version')
	cli_ver = grpc_client.getClientVersion()
	exporter_ver = Exporter(build_path).getVersion()
	assert bin_ver.startswith('DP Service version '), \
		"Invalid dpservice-bin version string"
	assert cli_ver.startswith('dpservice-cli version '), \
		"Invalid dpservice-cli version string"
	assert bin_ver[19:] == cli_ver[22:], \
		f"Version mismatch between dpservice-bin and dpservice-cli ({bin_ver} != {cli_ver})"
	assert exporter_ver.startswith('dpservice-exporter version '), \
		"Invalid dpservice-exporter version string"
	assert bin_ver[19:] == exporter_ver[27:], \
		f"Version mismatch between dpservice-bin and dpservice-exporter ({bin_ver} != {exporter_ver})"
	print(f"Testing using {bin_ver}")

	# Improve memory allocation randomness
	env = dict(os.environ)
	env['MALLOC_PERTURB_'] = str(random.randint(1, 255))
	print(f"MALLOC_PERTURB_={env['MALLOC_PERTURB_']}")

	pytest_command = 'pytest-3' if shutil.which('pytest-3') else 'pytest'

	to_run = [ suite for suite in suites if not args.suite or args.suite.lower() == suite.label.lower() ]
	for i, suite in enumerate(to_run):
		print(f"\n{print_header} TEST {i+1}/{len(to_run)}: {suite.label} tests")
		command = [pytest_command, '-x', '-v'] + suite.args + suite.files
		print(' '.join(command))
		result = subprocess.run(command, env=env)
		if result.returncode != 0:
			print(f"\nTEST FAILED with returncode {result.returncode}", file=sys.stderr)
			print(' '.join(command), file=sys.stderr)
			sys.exit(result.returncode)


if __name__ == '__main__':
	assert os.geteuid() == 0, \
		"dp-service tests must be run as root"
	script_path = os.path.dirname(os.path.abspath(__file__))
	parser = argparse.ArgumentParser(formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=32))
	parser.add_argument("-l", "--list-suites", action="store_true", help="List all available test suites")
	parser.add_argument("-s", "--suite", action="store", help="Which test suite to run (omit to run all)")
	parser.add_argument("--hw", action="store_true", help="Test using actual hardware NIC instead of TAP devices")
	parser.add_argument("--offloading", action="store_true", help="Test with offloading enabled")
	parser.add_argument("build_dirs", nargs="*", default=[f"{script_path}/../../build"], help="Path(s) to dpservice-bin build directory")
	args = parser.parse_args()
	for i, build_dir in enumerate(args.build_dirs):
		testDpService(build_dir, f"[{i+1}/{len(args.build_dirs)}]")
