import time
import re
import sys


from remote_machine_management import get_remote_machine, add_vm_config_info, add_vm_nat_config

def remote_machine_op_upload(machine_name, local_path, remote_path):
	try:
		machine = get_remote_machine(machine_name)
		machine.upload(local_path, remote_path)
	except Exception as e:
		print(f"Failed to copy {local_path} to {remote_path} on machine {machine_name}")

def remote_machine_op_make_runnable(machine_name, path):
	try:
		machine = get_remote_machine(machine_name)
		task = [
			{"command": f"chmod +x {path}", "sudo": True}
		]
		machine.exec_task(task)
	except Exception as e:
		print(f"Failed to make this file {path} on machine {machine_name} runnable due to {e}")

def remote_machine_op_file_exists(machine_name, path):
	try:
		machine = get_remote_machine(machine_name)
		task = [
			{"command": f'test -e {path} && echo "exists" || echo "not exists"'}
		]
		result = machine.exec_task(task)
		return result == 'exists'
	except Exception as e:
		print(f"Failed to test {path} on machine {machine_name} due to {e}")

def remote_machine_op_docker_rm_image(machine_name, image_name):
	try:
		machine = get_remote_machine(machine_name)
		task = [
			{"command": "docker", "parameters": f"image rm {image_name} --force", "sudo": True}
		]
		machine.exec_task(task)
	except Exception as e:
		print(f"Failed to remove docker image {image_name} from machine {machine_name} due to {e}")

def remote_machine_op_docker_load_image(machine_name, image_file):
	try:
		machine = get_remote_machine(machine_name)
		task = [
			{"command": "docker", "parameters": f"load -i {image_file}",  "sudo": True}
		]
		machine.exec_task(task)
	except Exception as e:
		print(f"Failed to load docker image {image_file} on machine {machine_name} due to {e}")


def remote_machine_op_dpservice_start(machine_name, offload, is_docker, docker_image_url='', path_to_bin="/tmp/dpservice-bin"):

	if is_docker and docker_image_url == '':
		raise ValueError(f"docker image url is required if dpservice is running in docker env")

	try:
		machine = get_remote_machine(machine_name)
		if machine.parent_machine:
			raise NotImplementedError(f"Cannot start dpservice on a vm machine {machine_name}")
		
		flag = '--  --no-offload ' if not offload else '-- '
		flag += '--enable-ipv6-overlay '
		parameters = f"-l 0,1 {flag}"

		if is_docker:
			docker_container_name = f"dpservice_{machine_name}"
			docker_kill_command = f"docker stop"
			docker_kill_task = [
				{"command": docker_kill_command, "parameters": docker_container_name, "background": False, "sudo": True}
			]
			machine.exec_task(docker_kill_task)
			time.sleep(1)

			log_file = f"/tmp/dpservice.log"
			docker_run_command = f"docker run"
			docker_run_parameters = f"-d --rm --privileged --network host --name {docker_container_name} " \
									f"--mount type=bind,source=/dev/hugepages,target=/dev/hugepages " \
									f"--mount type=bind,source=/tmp,target=/tmp {docker_image_url}  {parameters} " \
									f"> {log_file} 2>&1"
			docker_run_task = [
				{"command": docker_run_command, "parameters": docker_run_parameters, "background": False, "sudo": True}
			]
			machine.exec_task(docker_run_task)
		else:
			# Check if dpservice is already running
			check_command = f"pgrep -f {path_to_bin}"
			running_pid = machine.ssh_manager.run_command(check_command)
			if running_pid:
				# If running, kill the existing process
				kill_command = f"kill {running_pid.strip()}"
				machine.ssh_manager.run_command(kill_command, sudo=True)
				time.sleep(1)
				print(f"Existing dpservice process killed: PID {running_pid.strip()}")

			dpservice_task = [
					{"command": path_to_bin, "parameters": parameters, "background": True, "sudo": True, "cmd_output_name": "dpservice"},
			]
			machine.exec_task(dpservice_task)
	except Exception as e:
		print(f"Failed to start dpservice on hypervisor {machine_name} due to {e}")

def remote_machine_op_dpservice_init(machine_name):
	try:
		machine = get_remote_machine(machine_name)
		if machine.parent_machine:
			raise NotImplementedError(f"Cannot configure dpservice on a vm machine {machine_name}")
		cli_task = [
				{"command": "/tmp/dpservice-cli", "parameters": "init", "delay": 5},
		]
		machine.exec_task(cli_task)
		time.sleep(1)
	except Exception as e:
		print(f"Failed to init dpservice on hypervisor {machine_name} due to {e}")	

def remote_machine_op_dpservice_create_interface(machine_name, if_id, vni, ipv4, ipv6, pci_dev):
	try:
		machine = get_remote_machine(machine_name)
		if machine.parent_machine:
			raise NotImplementedError(f"Cannot configure dpservice on a vm machine {machine_name}")
		parameters = f"create interface --id={if_id} --vni={vni} --ipv4={ipv4} --ipv6={ipv6} --device={pci_dev}"
		cli_task = [
				{"command": "/tmp/dpservice-cli", "parameters": parameters},
		]
		return machine.exec_task(cli_task)
	except Exception as e:
		print(f"Failed to create interface on hypervisor {machine_name} due to {e}")


def remote_machine_op_dpservice_create_nat(machine_name, if_id, ip, ports):
	try:
		machine = get_remote_machine(machine_name)
		if machine.parent_machine:
			raise NotImplementedError(f"Cannot configure dpservice and create nat on a vm machine {machine_name}")
		parameters = f"create nat --interface-id={if_id} --nat-ip={ip} --minport={ports[0]} --maxport={ports[1]}"
		cli_task = [
				{"command": "/tmp/dpservice-cli", "parameters": parameters},
		]
		return machine.exec_task(cli_task)
	except Exception as e:
		print(f"Failed to create nat on hypervisor {machine_name} due to {e}")


def remote_machine_op_dpservice_delete_nat(machine_name, if_id):
	try:
		machine = get_remote_machine(machine_name)
		if machine.parent_machine:
			raise NotImplementedError(f"Cannot configure dpservice and delete nat on a vm machine {machine_name}")
		parameters = f"delete nat --interface-id={if_id} "
		cli_task = [
				{"command": "/tmp/dpservice-cli", "parameters": parameters},
		]
		return machine.exec_task(cli_task)
	except Exception as e:
		print(f"Failed to delete nat on hypervisor {machine_name} due to {e}")


def remote_machine_op_dpservice_create_lb(machine_name, lb_name, lb_vni, lb_ip, lb_ports):
	try:
		machine = get_remote_machine(machine_name)
		if machine.parent_machine:
			raise NotImplementedError(f"Cannot configure dpservice and create lb on a vm machine {machine_name}")
		parameters = f"create loadbalancer --id={lb_name} --vni={lb_vni} --vip={lb_ip} --lbports={lb_ports}"
		cli_task = [
				{"command": "/tmp/dpservice-cli", "parameters": parameters},
		]
		return machine.exec_task(cli_task)
	except Exception as e:
		print(f"Failed to create lb on hypervisor {machine_name} due to {e}")

def remote_machine_op_dpservice_delete_lb(machine_name, lb_name):
	try:
		machine = get_remote_machine(machine_name)
		if machine.parent_machine:
			raise NotImplementedError(f"Cannot configure dpservice and delete lb on a vm machine {machine_name}")
		parameters = f"delete loadbalancer --id={lb_name}"
		cli_task = [
				{"command": "/tmp/dpservice-cli", "parameters": parameters},
		]
		return machine.exec_task(cli_task)
	except Exception as e:
		print(f"Failed to delete lb on hypervisor {machine_name} due to {e}")

def remote_machine_op_dpservice_create_lbpfx(machine_name, prefix, if_id):
	try:
		machine = get_remote_machine(machine_name)
		if machine.parent_machine:
			raise NotImplementedError(f"Cannot configure dpservice and create lbpfx on a vm machine {machine_name}")
		parameters = f"create lbprefix --interface-id={if_id} --prefix={prefix}"
		cli_task = [
				{"command": "/tmp/dpservice-cli", "parameters": parameters},
		]
		return machine.exec_task(cli_task)
	except Exception as e:
		print(f"Failed to create lbpfx on hypervisor {machine_name} due to {e}")

def remote_machine_op_dpservice_delete_lbpfx(machine_name, prefix, if_id):
	try:
		machine = get_remote_machine(machine_name)
		if machine.parent_machine:
			raise NotImplementedError(f"Cannot configure dpservice and delete lbpfx on a vm machine {machine_name}")
		parameters = f"delete lbprefix --interface-id={if_id} --prefix={prefix}"
		cli_task = [
				{"command": "/tmp/dpservice-cli", "parameters": parameters},
		]
		return machine.exec_task(cli_task)
	except Exception as e:
		print(f"Failed to delete lbpfx on hypervisor {machine_name} due to {e}")


def remote_machine_op_dpservice_create_lbtarget(machine_name, target_ip, lb_name):
	try:
		machine = get_remote_machine(machine_name)
		if machine.parent_machine:
			raise NotImplementedError(f"Cannot configure dpservice and create lbtarget on a vm machine {machine_name}")
		parameters = f"create lbtarget --target-ip={target_ip} --lb-id={lb_name}"
		cli_task = [
				{"command": "/tmp/dpservice-cli", "parameters": parameters},
		]
		return machine.exec_task(cli_task)
	except Exception as e:
		print(f"Failed to delete lbpfx on hypervisor {machine_name} due to {e}")


def remote_machine_op_dpservice_delete_lbtarget(machine_name, target_ip, lb_name):
	try:
		machine = get_remote_machine(machine_name)
		if machine.parent_machine:
			raise NotImplementedError(f"Cannot configure dpservice and delete lbtarget on a vm machine {machine_name}")
		parameters = f"delete lbtarget --target-ip={target_ip} --lb-id={lb_name}"
		cli_task = [
				{"command": "/tmp/dpservice-cli", "parameters": parameters},
		]
		return machine.exec_task(cli_task)
	except Exception as e:
		print(f"Failed to delete lbpfx on hypervisor {machine_name} due to {e}")


def remote_machine_op_dpservice_add_vms(env_config):
	try:
		for hypervisor_info in env_config['hypervisors']:
			for vm_info in hypervisor_info['vms']:
				if_config = vm_info["if_config"]
				output = remote_machine_op_dpservice_create_interface(hypervisor_info["machine_name"], vm_info["machine_name"], if_config["vni"], if_config["ipv4"], if_config["ipv6"], if_config["pci_addr"])
				if_config["underly_ip"] = get_underly_ip(output)
				add_vm_config_info(vm_info["machine_name"], if_config["ipv4"], if_config["ipv6"], if_config["pci_addr"], if_config["underly_ip"], if_config["vni"])
				
				if "nat" in vm_info:
					add_vm_nat_config(vm_info["machine_name"], vm_info["nat"]["ip"], vm_info["nat"]["ports"])
				
	except Exception as e:
		print(f"Failed to add vm interfaces via dpservice cli due to {e} ")
		sys.exit(1)


def remote_machine_op_dpservice_create_route(machine_name, prefix, nxt_hop_vni, nxt_hop_underly_ip, vni):
	try:
		machine = get_remote_machine(machine_name)
		if machine.parent_machine:
			raise NotImplementedError(f"Cannot configure dpservice on a vm machine {machine_name}")
		parameters = f"create route --prefix={prefix} --next-hop-vni={nxt_hop_vni} --next-hop-ip={nxt_hop_underly_ip} --vni={vni}"
		cli_task = [
				{"command": "/tmp/dpservice-cli", "parameters": parameters},
		]
		machine.exec_task(cli_task)
	except Exception as e:
		print(f"Failed to create route on hypervisor {machine_name} due to {e}")


def remote_machine_op_dpservice_delete_route(machine_name, prefix, vni):
	try:
		machine = get_remote_machine(machine_name)
		if machine.parent_machine:
			raise NotImplementedError(f"Cannot configure dpservice on a vm machine {machine_name}")
		parameters = f"delete route --prefix={prefix} --vni={vni}"
		cli_task = [
				{"command": "/tmp/dpservice-cli", "parameters": parameters},
		]
		machine.exec_task(cli_task)
	except Exception as e:
		print(f"Failed to delete route on hypervisor {machine_name} due to {e}")


def remote_machine_op_reboot(machine_name):
	try:
		machine = get_remote_machine(machine_name)
		if not machine.parent_machine:
			raise NotImplementedError(f"Cannot reboot a non-vm machine {machine_name}")
		
		reboot_task = [
				{"command": "sleep 3 && reboot", "background": True}
		]
		machine.exec_task(reboot_task)

		ssh_stop_command = [
			{"command": "systemctl", "parameters": "stop ssh"}
		]
		machine.exec_task(ssh_stop_command)
		machine.stop()

		print(f"Waiting for {machine_name} to reboot...")
		machine.start()
	except Exception as e:
		print(f"Failed to reboot vm {machine_name} due to {e}")

def remote_machine_op_terminate_processes(machine_name):
	try:
		machine = get_remote_machine(machine_name)
		machine.terminate_processes()
		time.sleep(1)
	except Exception as e:
		print(f"Failed to terminate processes on {machine_name} due to {e}")

def remote_machine_op_terminate_containers(machine_name):
	try:
		machine = get_remote_machine(machine_name)
		machine.terminate_containers()
	except Exception as e:
		print(f"Failed to terminate containers on hypervisor {machine_name} due to {e}")


def remote_machine_op_vm_config_rm_default_route(machine_name, default_gw = "192.168.122.1"):
	try:
		machine = get_remote_machine(machine_name)
		if not machine.parent_machine:
			raise NotImplementedError(f"Cannot rm default route on a non-vm machine {machine_name}")
		vm_task = [
				{"command": f"ip r del default via {default_gw}"}
		]
		machine.exec_task(vm_task)
	except Exception as e:
		print(f"Failed to remove the default route from vm {machine_name} due to {e}")

def remote_machine_op_flow_test(machine_name, is_server, server_ip, flow_count, run_time = 5, round_count = 3, payload_length = 1000, output_file_name="test", test_script = '/tmp/flow_test.py'):
	try:
		machine = get_remote_machine(machine_name)
		if not machine.parent_machine:
			raise NotImplementedError(f"Cannot invoke testing script on a non-vm machine {machine_name}")
		
		if is_server:
			parameters = f"server --server-ip {server_ip} --flow-count {flow_count}"
		else:
			parameters = f"client --server-ip  {server_ip} --flow-count {flow_count} --run-time {run_time} --round-count {round_count} --payload-length {payload_length} --output-file-prefix {output_file_name}"

		test_task = [
				{"command": f"python3 {test_script}", "parameters": f"{parameters}", "background": True if is_server else False, "cmd_output_name": "flow_test" if is_server else ''},
		]
		return machine.exec_task(test_task)
	except Exception as e:
		print(f"Failed to invoke flow test on vm {machine_name} due to {e}")


def remote_machine_op_add_ip_addr(machine_name, ip, dev, is_v6):
	try:
		machine = get_remote_machine(machine_name)
		if not machine.parent_machine:
			raise NotImplementedError(f"Cannot add hypervisor's ip address {machine_name}")
		
		if is_v6:
			parameters = f"-6 addr add {ip} dev {dev}"
		else:
			parameters = f"addr add {ip} dev {dev}"

		test_task = [
				{"command": "ip", "parameters": parameters},
		]
		return machine.exec_task(test_task)
	except Exception as e:
		print(f"Failed to add ip address to vm {machine_name} due to {e}")


def remote_machine_op_delete_ip_addr(machine_name, ip, dev, is_v6):
	try:
		machine = get_remote_machine(machine_name)
		if not machine.parent_machine:
			raise NotImplementedError(f"Cannot delete hypervisor's ip address {machine_name}")
		
		if is_v6:
			parameters = f"-6 addr del {ip} dev {dev}"
		else:
			parameters = f"addr del {ip} dev {dev}"

		test_task = [
				{"command": "ip", "parameters": parameters},
		]
		return machine.exec_task(test_task)
	except Exception as e:
		print(f"Failed to delete ip address to vm {machine_name} due to {e}")


def get_underly_ip(output_string):
	re_ipv6 = re.compile(r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}") # dpservice only generate uncompressed ipv6 address. Enhance it when necessary.
	return re_ipv6.search(output_string).group(0)
