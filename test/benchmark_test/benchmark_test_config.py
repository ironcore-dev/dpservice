import sys
import os
import json

from remote_machine_management import hypervisor_machines, vm_machines, RemoteMachine, LBConfig, add_remote_machine, cleanup_remote_machine
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

def init_lb(env_config):
	if "lb" not in env_config:
		return None
	
	lb_config = env_config["lb"]
	config = LBConfig(lb_config["name"], lb_config["ip"], lb_config["ports"], lb_config["vni"], lb_config["lb_nodes"], lb_config["lb_machines"])
	
	for node in config.get_nodes():
		output = remote_machine_op_dpservice_create_lb(node, config.get_id(), config.get_vni(), config.get_ip(), config.get_ports())
		lb_underly_ip = get_underly_ip(output)
		config.set_lb_underly_ip(node, lb_underly_ip)

	for vm in config.get_vms():
		parent_machine = get_remote_machine(vm).get_parent_machine_name()
		output = remote_machine_op_dpservice_create_lbpfx(parent_machine, f"{config.get_ip()}/32", vm)
		pfx_underly_ip = get_underly_ip(output)
		config.set_vm_lb_pfx(vm, pfx_underly_ip)

	for node in config.get_nodes():
		for vm in config.get_vms():
			lbpfx_ip = config.get_vm_lb_pfx(vm)
			remote_machine_op_dpservice_create_lbtarget(node, lbpfx_ip, config.get_id())

	return config


def tear_down_lb(lb_config):
	for node in lb_config.get_nodes():
		for vm in lb_config.get_vms():
			vm_pfx_underly_ip = lb_config.get_vm_lb_pfx(vm)
			remote_machine_op_dpservice_delete_lbtarget(node, vm_pfx_underly_ip, lb_config.get_id())
	

	for vm in lb_config.get_vms():
		parent_machine = get_remote_machine(vm).get_parent_machine_name()
		remote_machine_op_dpservice_delete_lbpfx(parent_machine, f"{lb_config.get_ip()}/32", vm)

	for node in lb_config.get_nodes():
		remote_machine_op_dpservice_delete_lb(node, lb_config.get_id())


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
