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
def grpc_client(build_path):
	return GrpcClient(build_path)


# All tests require dp_service to be running
@pytest.fixture(scope="package")
def dp_service(request, build_path, tun_opt, port_redundancy):

	dp_service = DpService(build_path, tun_opt, port_redundancy)

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
def prepare_ifaces(request, dp_service, tun_opt, port_redundancy, grpc_client):
	# TODO look into this when doing Geneve, is this the right way?
	global t_vni
	if tun_opt == tun_type_geneve:
		t_vni = vni

	if request.config.getoption("--attach"):
		return

	print("---- Interfaces init -----")
	dp_service.init_ifaces(grpc_client)
	print("--------------------------")


# Some tests require IPv4 addresses assigned
@pytest.fixture(scope="package")
def prepare_ipv4(prepare_ifaces):
	print("-------- IPs init --------")
	request_ip(vf0_tap, vf0_mac, vf0_ip)
	request_ip(vf1_tap, vf1_mac, vf1_ip)
	print("--------------------------")
