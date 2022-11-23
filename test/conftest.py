import os
import pytest
import shlex
import subprocess
import time

from config import *
from helpers import request_ip
from helpers import interface_up
from grpc_client import GrpcClient


def pytest_addoption(parser):
	parser.addoption(
		"--build-path", action="store", default="../build", help="Path to the root build directory"
	)
	parser.addoption(
		"--tun-opt", action="store", choices=["ipip", "geneve"], default="ipip", help="Tunnel type"
	)
	parser.addoption(
		"--port-redundancy", action="store_true", help="Test with port redundancy"
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
def prepare_env(request, build_path, tun_opt, port_redundancy):

	# TODO this should be done via some option in dp_service, reading a hardcoded path is not the way
	if os.path.exists(config_file_path):
		os.rename(config_file_path, config_file_path + ".backup")

	dp_service_cmd = (f'{build_path}/src/dp_service -l 0,1'
						f' --vdev=net_tap0,iface={pf0_tap},mac="{pf0_mac}"'
						f' --vdev=net_tap1,iface={pf1_tap},mac="{pf1_mac}"'
						f' --vdev=net_tap2,iface={vf0_tap},mac="{vf0_mac}"'
						f' --vdev=net_tap3,iface={vf1_tap},mac="{vf1_mac}"'
						f' --vdev=net_tap4,iface={vf2_tap},mac="{vf2_mac}"'
						' --'
						f' --pf0={pf0_tap} --pf1={pf1_tap} --vf-pattern={vf_patt}'
						f' --ipv6={ul_ipv6} --enable-ipv6-overlay'
						 ' --no-offload --no-stats'
						 ' --op_env=scapytest'
						f' --tun_opt={tun_opt}')
	if port_redundancy:
		dp_service_cmd += ' --wcmp-frac=0.5'

	if GrpcClient.port_open():
		raise AssertionError("Another service already running")

	print("------ Service init ------")
	print(dp_service_cmd)
	process = subprocess.Popen(shlex.split(dp_service_cmd))
	GrpcClient.wait_for_port()
	print("--------------------------")

	def tear_down():
		process.terminate()
		# TODO see above
		if os.path.exists(config_file_path + ".backup") :
			os.rename(config_file_path + ".backup", config_file_path)
	request.addfinalizer(tear_down)

# Most tests require interfaces to be up and routing established
@pytest.fixture(scope="package")
def prepare_ifaces(prepare_env, tun_opt, port_redundancy, grpc_client):
	# TODO look into this when doing Geneve, is this the right way?
	global t_vni
	if tun_opt == tun_type_geneve:
		t_vni = vni

	print("---- Interfaces init -----")
	interface_up(vf0_tap)
	interface_up(vf1_tap)
	interface_up(vf2_tap)
	interface_up(pf0_tap)
	if port_redundancy:
		interface_up(pf1_tap)
	grpc_client.assert_output("--init", "Init called")
	grpc_client.assert_output(f"--addmachine {vm1_name} --vni {vni} --ipv4 {vf0_ip} --ipv6 {vf0_ipv6}", "Allocated VF for you")
	grpc_client.assert_output(f"--addmachine {vm2_name} --vni {vni} --ipv4 {vf1_ip} --ipv6 {vf1_ipv6}", "Allocated VF for you")
	grpc_client.assert_output(f"--addroute --vni {vni} --ipv4 {ov_target_pfx} --length 24 --t_vni {t_vni} --t_ipv6 {ul_actual_dst}", f"Route ip {ov_target_pfx}")
	grpc_client.assert_output(f"--addroute --vni {vni} --ipv6 2002::123 --length 128 --t_vni {t_vni} --t_ipv6 {ul_actual_dst}", "target ipv6 2002::123")
	grpc_client.assert_output(f"--addroute --vni {vni} --ipv4 0.0.0.0 --length 0 --t_vni {vni} --t_ipv6 {ul_actual_dst}", "Route ip 0.0.0.0")
	# TODO(plague): this is required as service obviously is still doing some initialization
	# Discuss a logline to wait for (would need to rework service outptu handling) or waiting with GRPC thread for this to finish
	time.sleep(3)
	print("--------------------------")

	# TODO this needs explanation, or better yet fixing service startup
	# (plague): my guess is that it takes some time to apply the GRPC command in service, the client is asynchronous
	# so maybe do a --list* loop here!
	time.sleep(2)

	# TODO add timeout=2 to all sniff calls missign it (3 cases I think)
	# TODO all the prints are wrong, either print context too or stay quiet?
	# (actually not needed, when run via scapy it is verbose enough and colored)
	# TODO assert is a keyword, not a function
	# TODO sleeps in test, so at least comment them if not doable?
	# TODO multiprocessing or threading?
	# TODO AssertionError instead of assert

# Many tests require IPs already assigned on VFs
# TODO is this called before arp test?
=======
# Some tests require IPv4 addresses assigned
>>>>>>> ac9d2a5 (Reworked pytest fixtures)
@pytest.fixture(scope="package")
def prepare_ipv4(prepare_ifaces):
	print("-------- IPs init --------")
	request_ip(vf0_tap, vf0_mac, vf0_ip)
	request_ip(vf1_tap, vf1_mac, vf1_ip)
	print("--------------------------")
