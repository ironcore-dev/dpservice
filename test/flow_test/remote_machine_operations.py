import time
import re
import sys

from remote_machine_management import get_remote_machine, add_vm_config_info

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
			{"command": f"chmod +x {path}"}
		]
		machine.exec_task(task)
	except Exception as e:
		print(f"Failed to make this file {path} on machine {machine_name} runnable due to {e}")

def remote_machine_op_dpservice_start(machine_name, offload, is_docker, docker_image_url='', path_to_bin="/tmp/dpservice-bin"):

	if is_docker and docker_image_url == '':
		raise ValueError(f"docker image url is required if dpservice is running in docker env")

	try:
		machine = get_remote_machine(machine_name)
		if machine.parent_machine:
			raise NotImplementedError(f"Cannot start dpservice on a vm machine {machine_name}")
		
		flag = '--  --no-offload' if not offload else ''
		parameters = f"-l 0,1 {flag}"

		if is_docker:
			docker_container_name = f"dpservice_{machine_name}"
			docker_kill_command = f"docker stop"
			docker_kill_task = [
				{"command": docker_kill_command, "parameters": docker_container_name, "background": False, "sudo": True}
			]
			machine.exec_task(docker_kill_task)
			time.sleep(3)

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
				time.sleep(3)
				print(f"Existing dpservice process killed: PID {running_pid.strip()}")

			dpservice_task = [
					{"command": path_to_bin, "parameters": parameters, "background": True, "sudo": True, "cmd_output_name": "dpservice"},
			]
			machine.exec_task(dpservice_task)
	except Exception as e:
		print(f"Failed to start dpservice on hypervisor {machine_name} due to {e}")

def remote_machine_op_dpservice_init(machine_name, path_to_bin="/tmp/dpservice-cli"):
	try:
		machine = get_remote_machine(machine_name)
		if machine.parent_machine:
			raise NotImplementedError(f"Cannot configure dpservice on a vm machine {machine_name}")
		cli_task = [
				{"command": path_to_bin, "parameters": "init", "delay": 5},
		]
		machine.exec_task(cli_task)
	except Exception as e:
		print(f"Failed to init dpservice on hypervisor {machine_name} due to {e}")	

def remote_machine_op_dpservice_create_interface(machine_name, if_id, vni, ipv4, ipv6, pci_dev, path_to_bin="/tmp/dpservice-cli"):
	try:
		machine = get_remote_machine(machine_name)
		if machine.parent_machine:
			raise NotImplementedError(f"Cannot configure dpservice on a vm machine {machine_name}")
		parameters = f"create interface --id={if_id} --vni={vni} --ipv4={ipv4} --ipv6={ipv6} --device={pci_dev}"
		cli_task = [
				{"command": path_to_bin, "parameters": parameters},
		]
		return machine.exec_task(cli_task)
	except Exception as e:
		print(f"Failed to create interface on hypervisor {machine_name} due to {e}")

def remote_machine_op_dpservice_add_vms(config, env_name, path_to_cli_bin="/tmp/dpservice-cli"):
	env_config = next((env for env in config['environments'] if env['name'] == env_name), None)
	try:
		for hypervisor_info in env_config['hypervisors']:
			for vm_info in hypervisor_info['vms']:
				if_config = vm_info["if_config"]
				output = remote_machine_op_dpservice_create_interface(hypervisor_info["machine_name"], vm_info["machine_name"], if_config["vni"], if_config["ipv4"], if_config["ipv6"], if_config["pci_addr"], path_to_cli_bin)
				if_config["underly_ip"] = get_underly_ip(output)
				print(env_config['hypervisors'])
				add_vm_config_info(vm_info["machine_name"], if_config["ipv4"], if_config["ipv6"], if_config["pci_addr"], if_config["underly_ip"], if_config["vni"])
	except Exception as e:
		print(f"Failed to add vm interfaces via dpservice cli due to {e} ")
		sys.exit(1)


def remote_machine_op_dpservice_create_route(machine_name, prefix, nxt_hop_vni, nxt_hop_underly_ip, vni, path_to_bin="/tmp/dpservice-cli"):
	try:
		machine = get_remote_machine(machine_name)
		if machine.parent_machine:
			raise NotImplementedError(f"Cannot configure dpservice on a vm machine {machine_name}")
		parameters = f"create route --prefix={prefix} --next-hop-vni={nxt_hop_vni} --next-hop-ip={nxt_hop_underly_ip} --vni={vni}"
		cli_task = [
				{"command": path_to_bin, "parameters": parameters},
		]
		machine.exec_task(cli_task)
	except Exception as e:
		print(f"Failed to create route on hypervisor {machine_name} due to {e}")	

def remote_machine_op_reboot(machine_name):
	try:
		machine = get_remote_machine(machine_name)
		if not machine.parent_machine:
			raise NotImplementedError(f"Cannot reboot a non-vm machine {machine_name}")
		reboot_task = [
				{"command": "reboot"}
		]
		machine.exec_task(reboot_task)
		machine.stop()
		time.sleep(5) # Need to wait a bit otherwise next call will succeed immediately
		machine.start()
	except Exception as e:
		print(f"Failed to reboot vm {machine_name} due to {e}")

def remote_machine_op_terminate_processes(machine_name):
	try:
		machine = get_remote_machine(machine_name)
		machine.terminate_processes()
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



def get_underly_ip(output_string):
	re_ipv6 = re.compile(r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}") # dpservice only generate uncompressed ipv6 address. Enhance it when necessary.
	return re_ipv6.search(output_string).group(0)

# result checking functions
def result_checking_ping_failed(result, query):
	return query in result

def result_checking_throughput_higher_than(result, minimum_throughput):
	# Regex to find the "Average Throughput (Gbits/sec):" followed by a number
	match = re.search(r"Average Throughput \(Gbits/sec\):\s+(\d+\.\d+)", result)
	if match:
		# Convert the found string to a float
		average_throughput = float(match.group(1))
		# Compare it to the minimum threshold
		if average_throughput >= minimum_throughput:
			return True
		else:
			return False
	else:
		# If no matching throughput is found, handle it accordingly
		print("No average throughput found in the result.")
		return False
