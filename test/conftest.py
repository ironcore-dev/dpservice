import pytest
import os

from config import *
from dp_service import DpService
from grpc_client import GrpcClient
from helpers import request_ip


def pytest_addoption(parser):
	script_dir = os.path.dirname(os.path.abspath(__file__))
	parser.addoption(
		"--build-path", action="store", default=f"{script_dir}/../build", help="Path to the root build directory"
	)
	parser.addoption(
		"--tun-opt", action="store", choices=["ipip", "geneve"], default="ipip", help="Tunnel type"
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

@pytest.fixture(scope="package")
def build_path(request):
	return request.config.getoption("--build-path")

@pytest.fixture(scope="package")
def tun_opt(request):
	return request.config.getoption("--tun-opt")

@pytest.fixture(scope="package")
def port_redundancy(request):
	return request.config.getoption("--port-redundancy")

@pytest.fixture(scope="package")
def fast_flow_timeout(request):
	return request.config.getoption("--fast-flow-timeout")

@pytest.fixture(scope="package")
def grpc_client(build_path):
	return GrpcClient(build_path)


# All tests require dp_service to be running
@pytest.fixture(scope="package")
def dp_service(request, build_path, tun_opt, port_redundancy, fast_flow_timeout):

	test_virtsvc = request.config.getoption("--virtsvc")
	dp_service = DpService(build_path, tun_opt, port_redundancy, fast_flow_timeout, test_virtsvc=test_virtsvc)

	if request.config.getoption("--attach"):
		print("Attaching to an already running service")
		GrpcClient.wait_for_port()
		return dp_service

	if GrpcClient.port_open():
		raise AssertionError("Another service already running")

	print("------ Service init ------")
	print(dp_service.get_cmd())
	dp_service.start()
	GrpcClient.wait_for_port()
	print("--------------------------")

	def tear_down():
		dp_service.stop()
	request.addfinalizer(tear_down)

	return dp_service


# Most tests require interfaces to be up and routing established
@pytest.fixture(scope="package")
def prepare_ifaces(request, dp_service, tun_opt, grpc_client):
	# TODO look into this when doing Geneve, is this the right way?
	global t_vni
	if tun_opt == tun_type_geneve:
		t_vni = vni1

	if request.config.getoption("--attach"):
		dp_service.attach(grpc_client)
		return

	print("---- Interfaces init -----")
	dp_service.init_ifaces(grpc_client)
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
