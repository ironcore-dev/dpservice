import sys
import os
import json

from remote_machine_management import hypervisor_machines, vm_machines, RemoteMachine, add_remote_machine, cleanup_remote_machine
from remote_machine_operations import *

script_dir = os.path.dirname(os.path.abspath(__file__))

def init_machines(env_config, ssh_key_file):
	try:
		for hypervisor_info in env_config['hypervisors']:
			hypervisor_machine = RemoteMachine(hypervisor_info, ssh_key_file)
			add_remote_machine(hypervisor_machine, False)
			for vm_info in hypervisor_info['vms']:
				vm_machine = RemoteMachine(vm_info, ssh_key_file, hypervisor_machine)
				add_remote_machine(vm_machine, True)
	except Exception as e:
		print(f"Failed to setup remote control machine due to {e} ")
		raise e

	try:
		for machine in hypervisor_machines + vm_machines:
			machine.start()
	except Exception as e:
		print(f"Failed to start machine due to {e}")
		raise e

def init_dpservice(env_config, is_dev, docker_image, build_path, is_offload = False):
	try:
		for hypervisor_info in env_config['hypervisors']:
			if is_dev and hypervisor_info["role"] == "local":
				binary_path = os.path.abspath(f'{build_path}/src/dpservice-bin')
				remote_machine_op_dpservice_start(hypervisor_info["machine_name"], offload=is_offload, is_docker=False, path_to_bin= binary_path)
			else:
				remote_machine_op_dpservice_start(hypervisor_info["machine_name"], offload=is_offload, is_docker=True, docker_image_url=docker_image)
			machine_name = hypervisor_info["machine_name"]
			print(f"init on machine {machine_name}")
			remote_machine_op_dpservice_init(hypervisor_info["machine_name"])
	except Exception as e:
		print(f"Failed to start dpservice due to {e} ")
		raise e

def init_vms(env_config):
	remote_machine_op_dpservice_add_vms(env_config)
	
	script_path_to_upload = os.path.abspath('../../hack/connectivity_test/flow_test.py')
	script_path_to_land = '/tmp/flow_test.py'
	
	try:
		for hypervisor_info in env_config['hypervisors']:
			for vm_info in hypervisor_info['vms']:
				remote_machine_op_reboot(vm_info['machine_name'])
				remote_machine_op_vm_config_rm_default_route(vm_info['machine_name'])
				remote_machine_op_upload(vm_info['machine_name'], script_path_to_upload, script_path_to_land)
				remote_machine_op_make_runnable(vm_info['machine_name'], script_path_to_land)
	except Exception as e:
		print(f"Failed to init vms due to {e} ")
		raise e

def prepare_test_environment(is_offload, is_dev, docker_image_url, config, build_path):
	key_file = os.path.expanduser(config['key_file'])
	if not key_file:
		raise RuntimeError(f"Failed to get ssh key file with name {config['key_file']}")

	try:
		init_machines(config, key_file)
		init_dpservice(config, is_dev, docker_image_url, build_path, is_offload)
		init_vms(config)
	except Exception as e:
		tear_down_test_environment()
		raise RuntimeError(f"failed to prepare test environment due to: {e}")

def tear_down_test_environment():
	try:
		for machine in hypervisor_machines:
			dpservice_log = machine.fetch_log("dpservice")
			print(dpservice_log)

		for machine in vm_machines + hypervisor_machines:
			machine.stop()
			time.sleep(1)

		cleanup_remote_machine()
	except Exception as e:
		print(f"Failed to stop a connection due to {e} ")
		raise e
