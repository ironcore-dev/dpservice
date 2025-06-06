# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import time
import re
import sys


from remote_machine_management import get_remote_machine, add_vm_config_info, add_vm_nat_config

def generate_dpservice_cli_base_cmd(machine_name):
	dpservice_container_name = f"dpservice_{machine_name}"
	return f"docker exec {dpservice_container_name} dpservice-cli "

def remote_machine_op_upload(machine_name, local_path, remote_path):
	machine = None
	try:
		machine = get_remote_machine(machine_name)
		machine.upload("sftp", local_path, remote_path)
		if not remote_machine_op_file_exists(machine_name, remote_path):
			machine.upload("scp", local_path, remote_path)
	except Exception as e:
		if machine:
			machine.logger.error(f"Failed to copy {local_path} to {remote_path}: {e}")


def remote_machine_op_make_runnable(machine_name, path):
	machine = None
	try:
		machine = get_remote_machine(machine_name)
		task = [
			{"command": f"chmod +x {path}", "sudo": True}
		]
		machine.exec_task(task)
	except Exception as e:
		if machine:
			machine.logger.error(f"Failed to make this file {path} runnable: {e}")


def remote_machine_op_file_exists(machine_name, path):
	machine = None
	try:
		machine = get_remote_machine(machine_name)
		task = [
			{"command": f'test -e {path} && echo "exists" || echo "not exists"'}
		]
		result = machine.exec_task(task)
		return result == "exists"
	except Exception as e:
		if machine:
			machine.logger.error(f"Failed to test {path}: {e}")


def remote_machine_op_docker_rm_image(machine_name, image_name):
	machine = None
	try:
		machine = get_remote_machine(machine_name)
		task = [
			{"command": "docker",
				"parameters": f"image rm {image_name} --force", "sudo": True}
		]
		machine.exec_task(task)
	except Exception as e:
		if machine:
			machine.logger.error(f"Failed to remove docker image {image_name}: {e}")


def remote_machine_op_docker_load_image(machine_name, image_file):
	machine = None
	try:
		machine = get_remote_machine(machine_name)
		task = [
			{"command": "docker", "parameters": f"load -i {image_file}",  "sudo": True}
		]
		machine.exec_task(task)
	except Exception as e:
		if machine:
			machine.logger.error(f"Failed to load docker image {image_file}: {e}")


def remote_machine_op_dpservice_start(machine_name, offload, docker_image_url='', path_to_bin="/tmp/dpservice-bin"):

	if docker_image_url == '':
		raise ValueError(
			f"docker image url is required if dpservice is running in docker env")
	machine = None
	try:
		machine = get_remote_machine(machine_name)
		docker_container_name = f"dpservice_{machine_name}"
		if machine.parent_machine:
			raise NotImplementedError(
				f"Cannot start dpservice on a vm machine {machine_name}")

		flag = '--  --no-offload ' if not offload else '-- '
		flag += '--enable-ipv6-overlay '
		parameters = f"-l 0,1 {flag}"

		docker_run_command = f"docker run"
		docker_run_parameters = f"-d --privileged --network host --name {docker_container_name} " \
			f"--mount type=bind,source=/dev/hugepages,target=/dev/hugepages " \
			f"--mount type=bind,source=/tmp,target=/tmp {docker_image_url}  {parameters} "
		docker_run_task = [
			{"command": docker_run_command, "parameters": docker_run_parameters,
				"background": False, "sudo": True}
		]
		machine.exec_task(docker_run_task)
		
	except Exception as e:
		if machine:
			machine.logger.error(f"Failed to start dpservice on hypervisor: {e}")

def remote_machine_op_fetch_dpservice_container_log(machine_name):
	machine = None
	try:
		machine = get_remote_machine(machine_name)
		if machine.parent_machine:
			raise NotImplementedError(
				f"Cannot fetch dpservice container log on a vm machine {machine_name}")

		log_file = f"/tmp/dpservice.log"
		docker_container_name = f"dpservice_{machine_name}"
		docker_log_command = f"docker logs"
		docker_log_parameters = f"-f --tail 150 {docker_container_name} > {log_file} 2>&1 "
		docker_run_task = [
			{"command": docker_log_command, "parameters": docker_log_parameters,
				"background": False, "sudo": True}
		]
		machine.exec_task(docker_run_task)
	except Exception as e:
		if machine:
			machine.logger.error(f"Failed to get dpservice container log: {e}")

def remote_machine_op_dpservice_init(machine_name):
	machine = None
	try:
		machine = get_remote_machine(machine_name)
		if machine.parent_machine:
			raise NotImplementedError(
				f"Cannot configure dpservice on a vm machine {machine_name}")
		cli_task = [
			{"command": generate_dpservice_cli_base_cmd(machine_name), "sudo": True, "parameters": "init", "delay": 5},
		]
		machine.exec_task(cli_task)
		time.sleep(1)
	except Exception as e:
		if machine:
			machine.logger.error(f"Failed to init dpservice on hypervisor: {e}")


def remote_machine_op_dpservice_create_interface(machine_name, if_id, vni, ipv4, ipv6, pci_dev):
	machine = None
	try:
		machine = get_remote_machine(machine_name)
		if machine.parent_machine:
			raise NotImplementedError(
				f"Cannot configure dpservice on a vm machine {machine_name}")
		parameters = f"create interface --id={if_id} --vni={vni} --ipv4={ipv4} --ipv6={ipv6} --device={pci_dev}"
		cli_task = [
			{"command": generate_dpservice_cli_base_cmd(machine_name), "sudo": True, "parameters": parameters},
		]
		return machine.exec_task(cli_task)
	except Exception as e:
		if machine:
			machine.logger.error(f"Failed to create interface: {e}")


def remote_machine_op_dpservice_create_nat(machine_name, if_id, ip, ports):
	machine = None
	try:
		machine = get_remote_machine(machine_name)
		if machine.parent_machine:
			raise NotImplementedError(
				f"Cannot configure dpservice and create nat on a vm machine {machine_name}")
		parameters = f"create nat --interface-id={if_id} --nat-ip={ip} --minport={ports[0]} --maxport={ports[1]}"
		cli_task = [
			{"command": generate_dpservice_cli_base_cmd(machine_name), "sudo": True, "parameters": parameters},
		]
		return machine.exec_task(cli_task)
	except Exception as e:
		if machine:
			machine.logger.error(f"Failed to create nat on hypervisor: {e}")


def remote_machine_op_dpservice_delete_nat(machine_name, if_id):
	machine = None
	try:
		machine = get_remote_machine(machine_name)
		if machine.parent_machine:
			raise NotImplementedError(
				f"Cannot configure dpservice and delete nat on a vm machine {machine_name}")
		parameters = f"delete nat --interface-id={if_id} "
		cli_task = [
			{"command": generate_dpservice_cli_base_cmd(machine_name), "sudo": True, "parameters": parameters},
		]
		return machine.exec_task(cli_task)
	except Exception as e:
		if machine:
			machine.logger.error(f"Failed to delete nat: {e}")


def remote_machine_op_dpservice_create_lb(machine_name, lb_name, lb_vni, lb_ip, lb_ports):
	machine = None
	try:
		machine = get_remote_machine(machine_name)
		if machine.parent_machine:
			raise NotImplementedError(
				f"Cannot configure dpservice and create lb on a vm machine {machine_name}")
		parameters = f"create loadbalancer --id={lb_name} --vni={lb_vni} --vip={lb_ip} --lbports={lb_ports}"
		cli_task = [
			{"command": generate_dpservice_cli_base_cmd(machine_name), "sudo": True, "parameters": parameters},
		]
		return machine.exec_task(cli_task)
	except Exception as e:
		if machine:
			machine.logger.error(f"Failed to create lb: {e}")


def remote_machine_op_dpservice_delete_lb(machine_name, lb_name):
	machine = None
	try:
		machine = get_remote_machine(machine_name)
		if machine.parent_machine:
			raise NotImplementedError(
				f"Cannot configure dpservice and delete lb on a vm machine {machine_name}")
		parameters = f"delete loadbalancer --id={lb_name}"
		cli_task = [
			{"command": generate_dpservice_cli_base_cmd(machine_name), "sudo": True, "parameters": parameters},
		]
		return machine.exec_task(cli_task)
	except Exception as e:
		if machine:
			machine.logger.error(f"Failed to delete lb: {e}")


def remote_machine_op_dpservice_create_lbpfx(machine_name, prefix, if_id):
	machine = None
	try:
		machine = get_remote_machine(machine_name)
		if machine.parent_machine:
			raise NotImplementedError(
				f"Cannot configure dpservice and create lbpfx on a vm machine {machine_name}")
		parameters = f"create lbprefix --interface-id={if_id} --prefix={prefix}"
		cli_task = [
			{"command": generate_dpservice_cli_base_cmd(machine_name), "sudo": True, "parameters": parameters},
		]
		return machine.exec_task(cli_task)
	except Exception as e:
		if machine:
			machine.logger.error(f"Failed to create lbpfx: {e}")


def remote_machine_op_dpservice_delete_lbpfx(machine_name, prefix, if_id):
	machine = None
	try:
		machine = get_remote_machine(machine_name)
		if machine.parent_machine:
			raise NotImplementedError(
				f"Cannot configure dpservice and delete lbpfx on a vm machine {machine_name}")
		parameters = f"delete lbprefix --interface-id={if_id} --prefix={prefix}"
		cli_task = [
			{"command": generate_dpservice_cli_base_cmd(machine_name), "sudo": True, "parameters": parameters},
		]
		return machine.exec_task(cli_task)
	except Exception as e:
		if machine:
			machine.logger.error(f"Failed to delete lbpfx: {e}")


def remote_machine_op_dpservice_create_lbtarget(machine_name, target_ip, lb_name):
	machine = None
	try:
		machine = get_remote_machine(machine_name)
		if machine.parent_machine:
			raise NotImplementedError(
				f"Cannot configure dpservice and create lbtarget on a vm machine {machine_name}")
		parameters = f"create lbtarget --target-ip={target_ip} --lb-id={lb_name}"
		cli_task = [
			{"command": generate_dpservice_cli_base_cmd(machine_name), "sudo": True, "parameters": parameters},
		]
		return machine.exec_task(cli_task)
	except Exception as e:
		if machine:
			machine.logger.error(f"Failed to create lbtarget: {e}")


def remote_machine_op_dpservice_delete_lbtarget(machine_name, target_ip, lb_name):
	machine = None
	try:
		machine = get_remote_machine(machine_name)
		if machine.parent_machine:
			raise NotImplementedError(
				f"Cannot configure dpservice and delete lbtarget on a vm machine {machine_name}")
		parameters = f"delete lbtarget --target-ip={target_ip} --lb-id={lb_name}"
		cli_task = [
			{"command": generate_dpservice_cli_base_cmd(machine_name), "sudo": True, "parameters": parameters},
		]
		return machine.exec_task(cli_task)
	except Exception as e:
		if machine:
			machine.logger.error(f"Failed to delete lbtarget: {e}")


def remote_machine_op_dpservice_add_vms(env_config):
	try:
		for hypervisor_info in env_config['hypervisors']:
			for vm_info in hypervisor_info['vms']:
				if_config = vm_info["if_config"]
				output = remote_machine_op_dpservice_create_interface(
					hypervisor_info["machine_name"], vm_info["machine_name"], if_config["vni"], if_config["ipv4"], if_config["ipv6"], if_config["pci_addr"])
				if_config["underly_ip"] = get_underly_ip(output)
				add_vm_config_info(vm_info["machine_name"], if_config["ipv4"], if_config["ipv6"],
								   if_config["pci_addr"], if_config["underly_ip"], if_config["vni"])

				if "nat" in vm_info:
					add_vm_nat_config(
						vm_info["machine_name"], vm_info["nat"]["ip"], vm_info["nat"]["ports"])

	except Exception as e:
		raise e


def remote_machine_op_dpservice_create_route(machine_name, prefix, nxt_hop_vni, nxt_hop_underly_ip, vni):
	machine = None
	try:
		machine = get_remote_machine(machine_name)
		if machine.parent_machine:
			raise NotImplementedError(
				f"Cannot configure dpservice on a vm machine {machine_name}")
		parameters = f"create route --prefix={prefix} --next-hop-vni={nxt_hop_vni} --next-hop-ip={nxt_hop_underly_ip} --vni={vni}"
		cli_task = [
			{"command": generate_dpservice_cli_base_cmd(machine_name), "sudo": True, "parameters": parameters},
		]
		machine.exec_task(cli_task)
	except Exception as e:
		if machine:
			machine.logger.error(f"Failed to create route: {e}")


def remote_machine_op_dpservice_delete_route(machine_name, prefix, vni):
	machine = None
	try:
		machine = get_remote_machine(machine_name)
		if machine.parent_machine:
			raise NotImplementedError(
				f"Cannot configure dpservice on a vm machine {machine_name}")
		parameters = f"delete route --prefix={prefix} --vni={vni}"
		cli_task = [
			{"command": generate_dpservice_cli_base_cmd(machine_name), "sudo": True, "parameters": parameters},
		]
		machine.exec_task(cli_task)
	except Exception as e:
		if machine:
			machine.logger.error(f"Failed to delete route: {e}")


def remote_machine_op_reboot(machine_name):
	machine = None
	try:
		machine = get_remote_machine(machine_name)
		if not machine.parent_machine:
			raise NotImplementedError(
				f"Cannot reboot a non-vm machine {machine_name}")

		reboot_task = [
			{"command": "sleep 3 && sudo reboot", "background": True}
		]
		machine.exec_task(reboot_task)

		ssh_stop_socket_command = [
			{"command": "systemctl", "parameters": "stop ssh.socket", "sudo": True}
		]
		machine.exec_task(ssh_stop_socket_command)
		ssh_stop_command = [
			{"command": "systemctl", "parameters": "stop ssh", "sudo": True}
		]
		machine.exec_task(ssh_stop_command)
		machine.stop()

		machine.logger.info(f"Waiting for {machine_name} to reboot...")
		machine.start()
	except Exception as e:
		if machine:
			machine.logger.error(f"Failed to reboot vm: {e}")


def remote_machine_op_terminate_processes(machine_name):
	machine = None
	try:
		machine = get_remote_machine(machine_name)
		machine.terminate_processes()
		time.sleep(1)
	except Exception as e:
		if machine:
			machine.logger.error(f"Failed to terminate processes: {e}")


def remote_machine_op_terminate_containers(machine_name):
	machine = None
	try:
		machine = get_remote_machine(machine_name)
		machine.terminate_containers()
	except Exception as e:
		if machine:
			machine.logger.error(f"Failed to terminate containers: {e}")

def remote_machine_op_vm_config_rm_default_route(machine_name, default_gw="192.168.122.1"):
	try:
		machine = get_remote_machine(machine_name)
		if not machine.parent_machine:
			raise NotImplementedError(
				f"Cannot rm default route on a non-vm machine {machine_name}")
		vm_task = [
			{"command": f"ip r del default via {default_gw}", "sudo": True}
		]
		machine.exec_task(vm_task)
	except Exception as e:
		if machine:
			machine.logger.error(f"Failed to remove the default route: {e}")

def remote_machine_op_vm_config_nft_default_accept(machine_name):
	try:
		machine = get_remote_machine(machine_name)
		if not machine.parent_machine:
			raise NotImplementedError(
				f"Cannot rm default route on a non-vm machine {machine_name}")

		vm_task = [
			{"command": f"nft add chain inet filter input '{{ policy accept; }}'", "sudo": True}
		]
		machine.exec_task(vm_task)
	except Exception as e:
		if machine:
			machine.logger.error(f"Failed to remove the default route: {e}")


def remote_machine_op_vm_config_tmp_dir(machine_name):
	machine = None
	try:
		machine = get_remote_machine(machine_name)
		if not machine.parent_machine:
			raise NotImplementedError(
				f"Cannot change ownership of tmp dir on a non-vm machine {machine_name}")
		vm_task = [
			{"command": f"chown 777 /tmp", "sudo": True}
		]
		machine.exec_task(vm_task)
	except Exception as e:
		if machine:
			machine.logger.error(f"Failed to change ownership of tmp dir: {e}")

def remote_machine_op_flow_test(machine_name, is_server, server_ip, flow_count, run_time=5, round_count=3, payload_length=1000, output_file_name="test", test_script='/tmp/flow_test.py'):
	machine = None
	try:
		machine = get_remote_machine(machine_name)
		if not machine.parent_machine:
			raise NotImplementedError(
				f"Cannot invoke testing script on a non-vm machine {machine_name}")

		if is_server:
			parameters = f"server --server-ip {server_ip} --flow-count {flow_count}"
		else:
			parameters = f"client --server-ip  {server_ip} --flow-count {flow_count} --run-time {run_time} --round-count {round_count} --payload-length {payload_length} --output-file-prefix {output_file_name}"

		test_task = [
			{"command": f"python3 {test_script}", "parameters": f"{parameters}",
				"background": True if is_server else False, "cmd_output_name": "flow_test" if is_server else ''},
		]
		return machine.exec_task(test_task)
	except Exception as e:
		if machine:
			machine.logger.error(f"Failed to invoke flow test: {e}")


def remote_machine_op_add_ip_addr(machine_name, ip, dev, is_v6):
	machine = None
	try:
		machine = get_remote_machine(machine_name)
		if not machine.parent_machine:
			raise NotImplementedError(
				f"Cannot add hypervisor's ip address {machine_name}")

		if is_v6:
			parameters = f"-6 addr add {ip} dev {dev}"
		else:
			parameters = f"addr add {ip} dev {dev}"

		test_task = [
			{"command": "ip", "parameters": parameters, "sudo": True},
		]
		return machine.exec_task(test_task)
	except Exception as e:
		if machine:
			machine.logger.error(f"Failed to add ip address to vm: {e}")


def remote_machine_op_delete_ip_addr(machine_name, ip, dev, is_v6):
	machine = None
	try:
		machine = get_remote_machine(machine_name)
		if not machine.parent_machine:
			raise NotImplementedError(
				f"Cannot delete hypervisor's ip address {machine_name}")

		if is_v6:
			parameters = f"-6 addr del {ip} dev {dev}"
		else:
			parameters = f"addr del {ip} dev {dev}"

		test_task = [
			{"command": "ip", "parameters": parameters},
		]
		return machine.exec_task(test_task)
	except Exception as e:
		if machine:
			machine.logger.error(f"Failed to delete ip address: {e}")


def get_underly_ip(output_string):
	# dpservice only generate uncompressed ipv6 address. Enhance it when necessary.
	re_ipv6 = re.compile(r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}")
	return re_ipv6.search(output_string).group(0)
