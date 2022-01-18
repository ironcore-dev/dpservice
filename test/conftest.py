import pytest
import pytest, shlex, subprocess, time
from config import *


def pytest_addoption(parser):
	parser.addoption(
		"--build_path", action="store", default="../build", help="Provide absolute path of the build directory"
	)

@pytest.fixture(scope="package")
def build_path(request):
	return request.config.getoption("--build_path")

@pytest.fixture(scope="package")
def prepare_env(request, build_path):
	dp_service_cmd = build_path+"/src/dp_service -l 0,1 --vdev=net_tap0,iface="+pf0_tap+",mac=\""+pf0_mac+"\" "\
		"--vdev=net_tap1,iface="+pf1_tap+",mac=\""+pf1_mac+"\" --vdev=net_tap2,iface="+vf0_tap+",mac=\""+vf0_mac+"\"   -- "\
		"--pf0="+pf0_tap+" --pf1="+pf1_tap+" --vf-pattern="+vf_patt+" --ipv6="+ul_ipv6+" --no-offload --no-stats"
	cmd = shlex.split(dp_service_cmd)
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
	request.addfinalizer(tear_down)
	return process

@pytest.fixture(autouse=True,scope="package")
def check_dpservice(prepare_env,build_path):
	return_code = prepare_env.poll()
	if return_code is not None:
		print("dp_service is not running")
		assert False
	
	return

