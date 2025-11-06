# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import os
import pytest
from scapy.all import conf

from config import *
from dp_grpc_client import DpGrpcClient
from dp_service import DpService
from exporter import Exporter
from grpc_client import GrpcClient
from helpers import request_ip, wait_for_port, is_port_open, run_command


def pytest_addoption(parser):
	script_dir = os.path.dirname(os.path.abspath(__file__))
	parser.addoption(
		"--build-path", action="store", default=f"{script_dir}/../../build", help="Path to the root build directory"
	)
	parser.addoption(
		"--port-redundancy", action="store_true", help="Test with port redundancy"
	)
	parser.addoption(
		"--fast-flow-timeout", action="store_true", help="Test with fast flow timeout"
	)
	parser.addoption(
		"--virtsvc", action="store_true", help="Include virtual services tests"
	)
	parser.addoption(
		"--attach", action="store_true", help="Attach to a currently running service (for debugging)"
	)
	parser.addoption(
		"--hw", action="store_true", help="Test on actual hardware NIC instead of virtual TAPs"
	)
	parser.addoption(
		"--offloading", action="store_true", help="Test with offloading enabled (HW only)"
	)
	parser.addoption(
		"--dpgrpc", action="store_true", help="Use C++ gRPC client"
	)
	parser.addoption(
		"--graphtrace", action="store_true", help="Log graph tracing messages"
	)
	parser.addoption(
		"--ha", action="store_true", help="Run two dpservice instances"
	)

@pytest.fixture(scope="package")
def build_path(request):
	return request.config.getoption("--build-path")

@pytest.fixture(scope="package")
def port_redundancy(request):
	return request.config.getoption("--port-redundancy")

@pytest.fixture(scope="package")
def fast_flow_timeout(request):
	return request.config.getoption("--fast-flow-timeout")

@pytest.fixture(scope="package")
def ha_mode(request):
	return request.config.getoption("--ha")

@pytest.fixture(scope="package")
def grpc_client(request, build_path):
	if request.config.getoption("--dpgrpc"):
		return DpGrpcClient(build_path)
	return GrpcClient(build_path, grpc_port)

@pytest.fixture(scope="package")
def grpc_client_b(build_path):
	return GrpcClient(build_path, grpc_port_b)


# All tests require dp_service to be running
def _dp_service(request, build_path, port_redundancy, fast_flow_timeout, secondary, ha):

	port = grpc_port_b if secondary else grpc_port

	dp_service = DpService(build_path, port_redundancy, fast_flow_timeout,
						   secondary = secondary,
						   ha = ha,
						   test_virtsvc = request.config.getoption("--virtsvc"),
						   hardware = request.config.getoption("--hw"),
						   offloading = request.config.getoption("--offloading"),
						   graphtrace = request.config.getoption("--graphtrace"))

	if request.config.getoption("--attach"):
		print("Attaching to an already running service")
		wait_for_port(port)
		return dp_service

	if is_port_open(port):
		raise AssertionError("Another service already running")

	def tear_down():
		dp_service.stop()
	request.addfinalizer(tear_down)

	print("------ Service init ------")
	print(dp_service.get_cmd())
	dp_service.start()
	wait_for_port(port, 10)

	print("--------------------------")
	return dp_service

@pytest.fixture(scope="package")
def sync_setup(request, ha_mode):
	if not ha_mode:
		return

	def tear_down():
		print("------ Sync cleanup ------")
		for iface in (sync_tap_b, sync_tap_a, sync_bridge):
			#print(run_command(f"ip -s link show {iface}").decode())
			run_command(f"sh -c 'ip link show {iface} && ip link del {iface} || true'")
	request.addfinalizer(tear_down)

	print("------- Sync init --------")
	run_command(f"sh -c 'ip link show {sync_bridge} || ip link add {sync_bridge} type bridge'")
	run_command(f"sh -c 'echo 0 > /sys/class/net/{sync_bridge}/bridge/multicast_snooping'")
	for sync_tap in (sync_tap_a, sync_tap_b):
		run_command(f"sh -c 'ip link show {sync_tap} || ip tuntap add dev {sync_tap} mode tap multi_queue'")
		# the default is fine for this test suite
		#run_command(f"ip link set {sync_tap} txqueuelen 500000")
		run_command(f"ip link set {sync_tap} master {sync_bridge}")
	for iface in (sync_bridge, sync_tap_a, sync_tap_b):
		run_command(f"sysctl net.ipv6.conf.{iface}.disable_ipv6=1")
		run_command(f"ip link set {iface} up")

@pytest.fixture(scope="package")
def dp_service(request, build_path, port_redundancy, fast_flow_timeout, ha_mode, sync_setup):
	return _dp_service(request, build_path, port_redundancy, fast_flow_timeout, secondary=False, ha=ha_mode)

# This one needs to be "activated" during tests, so the scope is set to function
@pytest.fixture(scope="function")
def dp_service_b(request, build_path, port_redundancy, fast_flow_timeout, ha_mode):
	if not ha_mode:
		raise ValueError("Secondary dpservice only available for --ha")
	return _dp_service(request, build_path, port_redundancy, fast_flow_timeout, secondary=True, ha=ha_mode)


# Most tests require interfaces to be up and routing established
@pytest.fixture(scope="package")
def prepare_ifaces(request, dp_service, grpc_client):
	if request.config.getoption("--attach"):
		dp_service.attach(grpc_client)
		return
	print("---- Interfaces init -----")
	dp_service.init_ifaces(grpc_client)
	print("--------------------------")

# This one uses function-scoped dpservice, must also be function-scoped
@pytest.fixture(scope="function")
def prepare_ifaces_b(dp_service_b, grpc_client_b):
	print("--- B Interfaces init ----")
	conf.ifaces.reload()  # Otherwise scapy remembers the old TAPs from previous test
	dp_service_b.init_ifaces(grpc_client_b)
	print("--------------------------")


# Some tests require IPv4 addresses assigned
@pytest.fixture(scope="package")
def prepare_ipv4(prepare_ifaces):
	print("-------- IPs init --------")
	request_ip(VM1)
	request_ip(VM2)
	request_ip(VM3)
	print("--------------------------")
	return prepare_ifaces


# Telemetry tests require a running prometheus exporter
@pytest.fixture(scope="package")
def start_exporter(request, build_path):
	print("-------- Exporter init --------")
	exporter = Exporter(build_path)
	def tear_down():
		exporter.stop()
	request.addfinalizer(tear_down)
	exporter.start()
	wait_for_port(exporter_port)
	print("-------------------------------")
