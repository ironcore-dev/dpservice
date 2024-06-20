# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import sys
import os
import subprocess
import json
import psutil

from remote_machine_management import (
	hypervisor_machines,
	vm_machines,
	RemoteMachine,
	LBConfig,
	add_remote_machine,
	cleanup_remote_machine,
)
from remote_machine_operations import *
from helper import MachineLogger

script_dir = os.path.dirname(os.path.abspath(__file__))

test_logger = MachineLogger("Benchmark-test")

def init_machines(env_config, ssh_key_file):
	try:
		for hypervisor_info in env_config["hypervisors"]:
			hypervisor_machine = RemoteMachine(hypervisor_info, ssh_key_file)
			add_remote_machine(hypervisor_machine, False)
			for vm_info in hypervisor_info["vms"]:
				vm_machine = RemoteMachine(
					vm_info, ssh_key_file, hypervisor_machine)
				add_remote_machine(vm_machine, True)
	except Exception as e:
		test_logger.error(f"Failed to setup remote control machine: {e} ")
		raise e

	try:
		for machine in hypervisor_machines + vm_machines:
			machine.start()
	except Exception as e:
		test_logger.error(f"Failed to start machine: {e}")
		raise e


def init_dpservice(
		env_config, stage, docker_image, build_path, is_offload=False, docker_file=""
):
	try:
		for hypervisor_info in env_config["hypervisors"]:
			check_dpservice_cli(hypervisor_info["machine_name"], build_path)

			if stage == "dev":
				upload_and_import_docker_image(
					hypervisor_info["machine_name"],
					docker_image,
					build_path,
					docker_file,
				)

			remote_machine_op_terminate_containers(hypervisor_info["machine_name"])
			remote_machine_op_dpservice_start(
				hypervisor_info["machine_name"],
				offload=is_offload,
				is_docker=True,
				docker_image_url=docker_image,
			)
			machine_name = hypervisor_info["machine_name"]
			test_logger.info(f"Initialising dpservice on {machine_name}...")
			remote_machine_op_dpservice_init(hypervisor_info["machine_name"])
			test_logger.info(f"Initialised dpservice on {machine_name}")
	except Exception as e:
		test_logger.error(f"Failed to start dpservice:{e} ")
		raise e


def init_vms(env_config, reboot_vm):
	remote_machine_op_dpservice_add_vms(env_config)

	script_path_to_upload = os.path.abspath(
		"../../hack/connectivity_test/flow_test.py")
	script_path_to_land = "/tmp/flow_test.py"

	try:
		for hypervisor_info in env_config["hypervisors"]:
			for vm_info in hypervisor_info["vms"]:
				if reboot_vm:
					remote_machine_op_reboot(vm_info["machine_name"])
				remote_machine_op_vm_config_rm_default_route(
					vm_info["machine_name"])
				remote_machine_op_vm_config_tmp_dir(vm_info["machine_name"])
				remote_machine_op_terminate_processes(vm_info["machine_name"])
				remote_machine_op_upload(
					vm_info["machine_name"], script_path_to_upload, script_path_to_land
				)
				remote_machine_op_make_runnable(
					vm_info["machine_name"], script_path_to_land
				)
	except Exception as e:
		test_logger.error(f"Failed to init vms: {e} ")
		raise e


def init_lb(env_config):
	if "lb" not in env_config:
		return None

	lb_config = env_config["lb"]
	config = LBConfig(
		lb_config["name"],
		lb_config["ip"],
		lb_config["ports"],
		lb_config["vni"],
		lb_config["lb_nodes"],
		lb_config["lb_machines"],
	)

	for node in config.get_nodes():
		output = remote_machine_op_dpservice_create_lb(
			node, config.get_id(), config.get_vni(), config.get_ip(), config.get_ports()
		)
		lb_underly_ip = get_underly_ip(output)
		config.set_lb_underly_ip(node, lb_underly_ip)

	for vm in config.get_vms():
		parent_machine = get_remote_machine(vm).get_parent_machine_name()
		output = remote_machine_op_dpservice_create_lbpfx(
			parent_machine, f"{config.get_ip()}/32", vm
		)
		pfx_underly_ip = get_underly_ip(output)
		config.set_vm_lb_pfx(vm, pfx_underly_ip)

	for node in config.get_nodes():
		for vm in config.get_vms():
			lbpfx_ip = config.get_vm_lb_pfx(vm)
			remote_machine_op_dpservice_create_lbtarget(
				node, lbpfx_ip, config.get_id())

	return config


def tear_down_lb(lb_config):
	for node in lb_config.get_nodes():
		for vm in lb_config.get_vms():
			vm_pfx_underly_ip = lb_config.get_vm_lb_pfx(vm)
			remote_machine_op_dpservice_delete_lbtarget(
				node, vm_pfx_underly_ip, lb_config.get_id()
			)

	for vm in lb_config.get_vms():
		parent_machine = get_remote_machine(vm).get_parent_machine_name()
		remote_machine_op_dpservice_delete_lbpfx(
			parent_machine, f"{lb_config.get_ip()}/32", vm
		)

	for node in lb_config.get_nodes():
		remote_machine_op_dpservice_delete_lb(node, lb_config.get_id())


def check_dpservice_cli(machine_name, build_dir):
	downloaded_cli_path = f"{build_dir}/cli/dpservice-cli/dpservice-cli"
	target_cli_path = "/tmp/dpservice-cli"
	try:
		if not remote_machine_op_file_exists(machine_name, target_cli_path):
			test_logger.info(f"Uploading dpservice-cli to {machine_name}")
			remote_machine_op_upload(
				machine_name, downloaded_cli_path, target_cli_path)
			remote_machine_op_make_runnable(machine_name, target_cli_path)
			test_logger.info(f"Uploaded dpservice-cli to {machine_name}")
	except Exception as e:
		test_logger.error(f"Failed to prepare dpservice cli on hypervisors due to {e}")


def prepare_test_environment(
		is_offload, stage, docker_image_url, reboot_vm, config, build_path
):
	key_file = os.path.expanduser(config["key_file"])
	docker_image_name = "dpservice_tester"
	docker_image_file = "dpservice_image.tar"
	if not key_file:
		raise RuntimeError(
			f"Failed to get ssh key file with name {config['key_file']}")

	try:
		init_machines(config, key_file)
		if stage == "dev":
			prepare_local_docker_image(
				docker_image_name, docker_image_file, build_path)
			init_dpservice(
				config,
				stage,
				docker_image_name,
				build_path,
				is_offload,
				docker_image_file,
			)
		else:
			init_dpservice(config, stage, docker_image_url,
						   build_path, is_offload)
		init_vms(config, reboot_vm)
	except Exception as e:
		tear_down_test_environment(forced=True)
		raise RuntimeError(f"failed to prepare test environment due to: {e}")


def prepare_local_docker_image(image_name, output_file, build_dir):
	main_dir = f"{script_dir}/../../"
	os.chdir(main_dir)

	# Build the Docker image
	build_command = ["sudo", "docker", "build", "-t", image_name, "."]
	subprocess.run(build_command, check=True)

	# Export the Docker image to a tar file
	save_command = [
		"sudo",
		"docker",
		"save",
		"-o",
		f"{build_dir}/{output_file}",
		image_name,
	]
	subprocess.run(save_command, check=True)

	mode_change_command = ["sudo", "chmod",
						   "a+r", f"{build_dir}/{output_file}"]
	subprocess.run(mode_change_command, check=True)

	test_logger.info(f"Image {image_name} built and exported to {output_file}")
	os.chdir(script_dir)


def upload_and_import_docker_image(machine_name, image_name, build_dir, output_file):
	generated_image_file = f"{build_dir}/{output_file}"
	target_image_file = f"/tmp/{output_file}"
	try:
		remote_machine_op_docker_rm_image(machine_name, image_name)
		remote_machine_op_upload(
			machine_name, generated_image_file, target_image_file)
		remote_machine_op_docker_load_image(machine_name, target_image_file)
	except Exception as e:
		test_logger.error(f"Failed to prepare dpservice cli on hypervisors {machine_name}: {e}")


def tear_down_test_environment(forced=False):
	try:
		if not forced:
			for machine in hypervisor_machines:
				machine.stop_containers()
				remote_machine_op_fetch_dpservice_container_log(machine.get_machine_name())
				dpservice_log = machine.fetch_log("dpservice")
				test_logger.info(f"Fetched dpservice log from {machine.get_machine_name()}:")
				test_logger.info(dpservice_log)

		for machine in vm_machines + hypervisor_machines:
			machine.stop()
			time.sleep(1)

		cleanup_remote_machine()

		if forced:
			pid = os.getpid()  # Get the current process ID
			process = psutil.Process(pid)
			process.terminate()  # Terminate the process
			sys.exit(0)  # Exit with a status code
	except Exception as e:
		test_logger.error(f"Failed to stop a connection: {e} ")
		raise e
