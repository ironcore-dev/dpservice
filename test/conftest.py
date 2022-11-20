import pytest
import pytest, shlex, subprocess, time
from config import *
from helpers import request_ip
import time
import os

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
def prepare_env(request, build_path, tun_opt, port_redundancy):
	
	wcmp_opt_str = ""
	if port_redundancy:
		wcmp_opt_str = " --wcmp-frac=0.5"

	if os.path.exists(config_file_path) :
		os.rename(config_file_path, config_file_path + ".backup")

	dp_service_cmd = build_path+"/src/dp_service -l 0,1 --vdev=net_tap0,iface="+pf0_tap+",mac=\""+pf0_mac+"\" "\
		"--vdev=net_tap1,iface="+pf1_tap+",mac=\""+pf1_mac+ "\" --vdev=net_tap2,"\
		"iface="+vf0_tap+",mac=\""+vf0_mac + "\" --vdev=net_tap3,iface="+vf1_tap+",mac=\""+vf1_mac+ "\" --vdev=net_tap4,iface="+vf2_tap+",mac=\""+vf2_mac + "\"  -- "\
		"--pf0="+pf0_tap+" --pf1="+pf1_tap+" --vf-pattern="+vf_patt+" --ipv6="+ul_ipv6+" --no-offload --no-stats"+" --op_env=scapytest " + "--tun_opt=" + tun_opt + wcmp_opt_str + \
		" --enable-ipv6-overlay"
	cmd = shlex.split(dp_service_cmd)
	print(dp_service_cmd)
	process = subprocess.Popen(cmd, 
								stdout=subprocess.PIPE,
								universal_newlines=True)

	while True:
		output = process.stdout.readline()
		line = output.strip()
		
		if start_str in line:
			break
		return_code = process.poll()
		if return_code is not None:
			# Process has finished, read rest of the output 
			for output in process.stdout.readlines():
				print(output.strip())
			break
	def tear_down():
		process.terminate()
		time.sleep(1)
		if os.path.exists(config_file_path + ".backup") :
			os.rename(config_file_path + ".backup", config_file_path)
	request.addfinalizer(tear_down)
	return process

# TODO look into how this actually works
@pytest.fixture(autouse=True,scope="package")
def check_dpservice(prepare_env):
	return_code = prepare_env.poll()
	assert return_code is None, "dp_service is not running"

@pytest.fixture(scope="package")
def grpc_client(build_path):
	return GrpcClient(build_path)

@pytest.fixture(scope="package")
def add_machine(tun_opt, grpc_client): # TODO rename to 'add_machines'
	# TODO look into this when doing Geneve, is this the right way?
	global t_vni
	if tun_opt == tun_type_geneve:
		t_vni = vni

	# TODO is this still needed?
	#time.sleep(5)


	print("---------- Init ----------")
	subprocess.check_output(shlex.split(f"ip link set dev {vf0_tap} up"))
	subprocess.check_output(shlex.split(f"ip link set dev {vf1_tap} up"))
	subprocess.check_output(shlex.split(f"ip link set dev {vf2_tap} up"))
	subprocess.check_output(shlex.split(f"ip link set dev {pf0_tap} up"))
	grpc_client.assert_output("--init", "Init called")
	grpc_client.assert_output(f"--addmachine {vm1_name} --vni {vni} --ipv4 {vf0_ip} --ipv6 {vf0_ipv6}", "Allocated VF for you")
	grpc_client.assert_output(f"--addmachine {vm2_name} --vni {vni} --ipv4 {vf1_ip} --ipv6 {vf1_ipv6}", "Allocated VF for you")
	grpc_client.assert_output(f"--addroute --vni {vni} --ipv4 {ov_target_pfx} --length 24 --t_vni {t_vni} --t_ipv6 {ul_actual_dst}", f"Route ip {ov_target_pfx}")
	grpc_client.assert_output(f"--addroute --vni {vni} --ipv6 2002::123 --length 128 --t_vni {t_vni} --t_ipv6 {ul_actual_dst}", "target ipv6 2002::123")
	grpc_client.assert_output(f"--addroute --vni {vni} --ipv4 0.0.0.0 --length 0 --t_vni {vni} --t_ipv6 {ul_actual_dst}", "Route ip 0.0.0.0")
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
@pytest.fixture(scope="package")
def request_ip_vf0(add_machine):
	request_ip(vf0_tap)
@pytest.fixture(scope="package")
def request_ip_vf1(add_machine):
	request_ip(vf1_tap)

# TODO rework includes?

# TODO remove capsys

# TODO create helper to call sniffers
# TODO scapy '/' endline


# TODO grpc client needs work - no return code and some command are missing outputs for testing
# (don't forget to rewrite tests then!)

# TODO move responders back into respective scripts
