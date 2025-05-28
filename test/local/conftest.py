# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import pytest
import os

from config import *
from dp_grpc_client import DpGrpcClient
from dp_service import DpService
from exporter import Exporter
from grpc_client import GrpcClient
from helpers import request_ip, wait_for_port, is_port_open


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
def _dp_service(request, build_path, port_redundancy, fast_flow_timeout, secondary):

	port = grpc_port_b if secondary else grpc_port

	dp_service = DpService(build_path, port_redundancy, fast_flow_timeout,
						   secondary = secondary,
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
def dp_service(request, build_path, port_redundancy, fast_flow_timeout):
	return _dp_service(request, build_path, port_redundancy, fast_flow_timeout, secondary=False)

@pytest.fixture(scope="package")
def dp_service_b(request, build_path, port_redundancy, fast_flow_timeout, ha_mode):
	if not ha_mode:
		raise ValueError("Secondary dpservice only available for --ha")
	return _dp_service(request, build_path, port_redundancy, fast_flow_timeout, secondary=True)


# Most tests require interfaces to be up and routing established
@pytest.fixture(scope="package")
def prepare_ifaces(request, dp_service, grpc_client):
	if request.config.getoption("--attach"):
		dp_service.attach(grpc_client)
		return
	print("---- Interfaces init -----")
	dp_service.init_ifaces(grpc_client)
	print("--------------------------")

@pytest.fixture(scope="package")
def prepare_ifaces_b(dp_service_b, grpc_client_b):
	print("--- B Interfaces init ----")
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
