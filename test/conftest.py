import pytest
import pytest, shlex, subprocess, time
from config import *
import time
import os


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
			print('RETURN CODE', return_code)
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

@pytest.fixture(autouse=True,scope="package")
def check_dpservice(prepare_env,build_path):
	return_code = prepare_env.poll()
	if return_code is not None:
		print("dp_service is not running")
		assert False
	
	return

@pytest.fixture(scope="package")
def add_machine(build_path, tun_opt):
	global t_vni
	if tun_opt == tun_type_geneve:
		t_vni = vni
	time.sleep(5)
	init_cmd = build_path+"/test/dp_grpc_client --init"
	add_machine_cmd = build_path+"/test/dp_grpc_client --addmachine " + vm1_name + " --vni "+ vni + " --ipv4 " + vf0_ip + " --ipv6 " + vf0_ipv6
	add_machine_cmd2 = build_path+"/test/dp_grpc_client --addmachine " + vm2_name + " --vni "+ vni + " --ipv4 " + vf1_ip + " --ipv6 " + vf1_ipv6
	print(add_machine_cmd2)
	add_ipv4_route_cmd = build_path+"/test/dp_grpc_client --addroute --vni " + vni + " --ipv4 " + ov_target_pfx + " --length 24 --t_vni " + t_vni + " --t_ipv6 " + ul_actual_dst
	add_ipv6_route_cmd = build_path+"/test/dp_grpc_client --addroute --vni " + vni + " --ipv6 2002::123 --length 128 --t_vni " + t_vni + " --t_ipv6 " + ul_actual_dst
	add_default_public_route = build_path+"/test/dp_grpc_client --addroute " + " --vni " + vni + " --ipv4 0.0.0.0 --length 0 --t_vni "+ vni + " --t_ipv6 " + ul_actual_dst
	print(add_default_public_route)
	
	subprocess.run(shlex.split("ip link set dev "+vf0_tap+" up"))
	subprocess.run(shlex.split("ip link set dev "+vf1_tap+" up"))
	subprocess.run(shlex.split("ip link set dev "+vf2_tap+" up"))
	subprocess.run(shlex.split("ip link set dev "+pf0_tap+" up"))
	# subprocess.run(shlex.split("ip link set dev "+pf1_tap+" up"))
	subprocess.run(shlex.split(init_cmd))
	subprocess.run(shlex.split(add_machine_cmd))
	subprocess.run(shlex.split(add_machine_cmd2))
	subprocess.run(shlex.split(add_ipv4_route_cmd))
	subprocess.run(shlex.split(add_ipv6_route_cmd))
	subprocess.run(shlex.split(add_default_public_route))
	time.sleep(1)

