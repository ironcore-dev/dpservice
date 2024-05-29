import pytest
import sys
import os
import signal
import json

from benchmark_test_config import prepare_test_environment, tear_down_test_environment, init_lb


def pytest_addoption(parser):
	script_dir = os.path.dirname(os.path.abspath(__file__))

	parser.addoption(
		"--mode", action="store", default="non-offload", choices=['offload', 'non-offload'], help="Benchmarking tests in the non-offloading/offloading mode."
	)
	parser.addoption(
		"--stage", action="store", default="dev", choices=['dev', 'cicd'], help="Benchmarking tests to assist local development (local development machine will not run docker container). "
	)
	parser.addoption(
		"--docker-image", action="store", help="Container image to be deployed to almost all hypervsiors"
	)
	parser.addoption(
		"--reboot", action="store_true", help="Reboot VMs to obtain new configurations such as IPs"
	)
	parser.addoption(
		"--env-config-file", action="store", default="./test_configurations.json", help="Specify the file containing setup information"
	)
	parser.addoption(
		"--env-config-name", action="store", default="regular_setup", help="Specify the name of environment configuration that fits to hardware and VM setup. "
	)
	parser.addoption(
		"--dpservice-build-path", action="store", default=f"{script_dir}/../../build", help="Path to the root build directory"
	)


def signal_handler(sig, frame):
	print("Ctrl-C pressed. Cleaning up...")
	tear_down_test_environment()
	sys.exit(0)


@pytest.fixture(scope="package")
def test_config(request):
	config = request.config
	test_config_file = config.getoption("--env-config-file")
	test_config_name = config.getoption("--env-config-name")

	with open(test_config_file, 'r') as file:
		config = json.load(file)

	env_config = next(
		(env for env in config['environments'] if env['name'] == test_config_name), None)
	if not env_config:
		raise RuntimeError(
			f"Failed to get config info for environment with name {test_config_name}")

	return env_config


@pytest.fixture(scope="package", autouse=True)
def test_mode(request):
	config = request.config
	is_offload = True if config.getoption("--mode") == "offload" else False
	return is_offload


@pytest.fixture(scope="package", autouse=True)
def test_flow_count(test_config):
	return test_config["concurrent_flow_count"]


@pytest.fixture(scope="package")
def test_min_throughput_sw_local(test_config):
	return test_config["expected_throughput"]["sw"]["local_vm2vm"]


@pytest.fixture(scope="package")
def test_min_throughput_sw_remote(test_config):
	return test_config["expected_throughput"]["sw"]["remote_vm2vm"]


@pytest.fixture(scope="package")
def test_min_throughput_hw_local(test_config):
	return test_config["expected_throughput"]["hw"]["local_vm2vm"]


@pytest.fixture(scope="package")
def test_min_throughput_hw_remote(test_config):
	return test_config["expected_throughput"]["hw"]["remote_vm2vm"]


@pytest.fixture(scope="package")
def test_min_throughput_sw_lb(test_config):
	return test_config["expected_throughput"]["sw"]["lb"]


@pytest.fixture(scope="package")
def test_min_throughput_hw_lb(test_config):
	return test_config["expected_throughput"]["hw"]["lb"]


@pytest.fixture(scope="package", autouse=True)
def benchmark_test_setup(request, test_config, test_mode):
	config = request.config

	stage = config.getoption("--stage")
	docker_iamge_url = config.getoption("--docker-image")
	build_path = config.getoption("--dpservice-build-path")
	reboot_vm = config.getoption("--reboot")

	signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame))
	try:
		prepare_test_environment(
			test_mode, stage, docker_iamge_url, reboot_vm, test_config, build_path)
	except Exception as e:
		print(f"Failed to prepare test environment due to: {e}")

	request.addfinalizer(tear_down_test_environment)
