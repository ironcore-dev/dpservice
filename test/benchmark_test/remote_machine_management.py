import paramiko
import time
import threading
from helper import remove_last_empty_line, MachineLogger


hypervisor_machines = []
vm_machines = []


class SSHManager:
	def __init__(self, host_name, host_address, port, user_name, key_file, proxy=None, max_retries=10):
		self.host_name = host_name
		self.logger = MachineLogger(self.host_name)
		self.host_address = host_address
		self.port = port
		self.username = user_name
		self.key_file = key_file
		self.proxy = proxy  # Proxy is another SSHManager instance
		self.client = None
		self.max_retries = max_retries
		self.pid_file = "/tmp/pids.txt"  # a file to store all PIDs
		self.stop_event = threading.Event()

	def connect_one_shot(self, timeout=1):
		try:
			if self.proxy:
				proxy_sock = self.proxy.client.get_transport().open_channel(
					'direct-tcpip', (self.host_address, self.port), ('127.0.0.1', 0))
				self.client.connect(self.host_address, port=self.port, username=self.username,
									pkey=self.pkey, sock=proxy_sock, timeout=timeout)
			else:
				self.client.connect(self.host_address, port=self.port, username=self.username,
									pkey=self.pkey, timeout=timeout)
		except Exception:
			raise ConnectionError("")

	def connect(self):
		"""Establish an SSH connection using a key file. Uses a proxy if specified."""
		self.pkey = paramiko.RSAKey.from_private_key_file(self.key_file)
		self.client = paramiko.SSHClient()
		self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		initial_delay = 1  # Initial delay in seconds before the first retry

		for attempt in range(1, self.max_retries + 1):
			try:
				if self.proxy:
					if not self.proxy.client:
						if not self.proxy.connect():
							raise Exception("Unable to connect through proxy")

				self.connect_one_shot()
				self.logger.info(
					f"Connection established successfully on attempt {attempt}.")
				break
			except Exception as e:
				self.logger.error(f"Attempt {attempt} failed: {e}")
				if attempt < self.max_retries:
					time_to_sleep = initial_delay * \
						(2 ** (attempt - 1))  # Exponential backoff
					self.logger.info(f"Retrying in {time_to_sleep} seconds...")
					self.stop_event.wait(time_to_sleep)
				else:
					raise ConnectionError(
						"Failed to establish SSH connection after multiple attempts.")

	def command_exists(self, command):
		"""Check if a command exists on the remote system."""
		check_command = f"command -v {command}"
		output = self.run_command(check_command)
		# Returns True if command exists, False otherwise
		return bool(output.strip())

	def run_command(self, command, parameters='', background=False, sudo=False, delay=0, command_output_name=''):
		"""Run a command over SSH and optionally run it in the background with output redirection."""
		if delay:
			time.sleep(delay)

		if self.client:
			command = f"{command} {parameters}"
			if sudo:
				command = f"sudo {command}"
			if background:
				if command_output_name == '':
					command = f"bash -c '{command}'"
				else:
					command = f"bash -c 'nohup {command} > /tmp/{command_output_name}.log 2>&1 & echo $! >> {self.pid_file}'"
			self.logger.info(f"Execute command: {command}")
			stdin, stdout, stderr = self.client.exec_command(command)
			if not background:
				return stdout.read().decode('utf-8') + stderr.read().decode('utf-8')
			return "Command started in the background."
		else:
			return "Connection not established"

	def get_all_pids(self):
		"""Retrieve all PIDs from the PID file."""
		stdin, stdout, stderr = self.client.exec_command(
			f"cat {self.pid_file}")
		return stdout.read().strip().split()

	def disconnect(self):
		"""Close the SSH connection."""
		self.logger.info("Disconnecting...")
		self.stop_event.set()
		self.client.close()
		self.logger.info("Disconnected.")

	def is_alive(self):
		is_alive = False
		if self.client.get_transport() is not None:
			is_alive = self.client.get_transport().is_alive()
		return is_alive

	def upload(self, proto, local_path, remote_path):
		"""Upload a file to a remote location"""
		try:
			if proto == "sftp":
				upload_chan = self.client.open_sftp()
			if proto == "scp":
				upload_chan = paramiko.SCPClient(self.client.get_transport())
			upload_chan.put(local_path, remote_path)
			upload_chan.close()
		except Exception as e:
			return f"Error uploading a file: {e}"

	def terminate_all_processes(self):
		"""Terminate all processes listed in the PID file."""
		pids = self.get_all_pids()
		for pid in pids:
			pid_v = pid.decode('utf-8')
			self.run_command(f"kill {pid_v}", sudo=True)
		self.run_command(f"echo '' > {self.pid_file}")  # Clear the PID file

	def stop_all_containers(self):
		"""stop all possible running docker containers"""
		# Command to list all running container IDs
		list_running_containers_command = "sudo docker ps -q"
		running_containers = self.run_command(
			list_running_containers_command)

		if running_containers.strip():  # Check if there is any output
			# Command to stop all running Docker containers
			stop_command = "sudo docker stop $(sudo docker ps -q)"
			stop_output = self.run_command(stop_command)
			self.logger.info(
				f"All containers stopped with the status: {stop_output}")
		else:
			self.logger.info("No running containers to stop.")

	def remove_all_containers(self):
		"""remove all possible running docker containers"""
		# Command to list all container IDs
		list_all_containers_command = "sudo docker ps -a -q"
		all_containers = self.run_command(list_all_containers_command)

		if all_containers.strip():  # Check if there is any output
			# Command to remove all stopped containers
			remove_command = "sudo docker rm $(sudo docker ps -a -q)"
			remove_output = self.run_command(remove_command)
			self.logger.info(
				f"All containers removed on with the status: {remove_output}")
		else:
			self.logger.info("No containers to remove.")

	def terminate_all_containers(self):
		"""Terminate all possible running docker containers"""
		self.stop_all_containers()
		self.remove_all_containers()

	def fetch_logs(self, log_file_name):
		"""Fetch the logs of the DPDK application."""
		try:
			sftp = self.client.open_sftp()
			with sftp.open(f'/tmp/{log_file_name}.log', 'r') as log_file:
				logs = log_file.read()
			return logs.decode('utf-8')
		except Exception as e:
			return f"Error retrieving logs: {e}"

	def __enter__(self):
		self.connect()
		return self

	def __exit__(self, exc_type, exc_val, exc_tb):
		self.disconnect()


class VMConfig:
	def __init__(self, ip='', ipv6='', pci='', underly_ip='', vni=0):
		self.vm_ip = ip
		self.vm_ipv6 = ipv6
		self.vm_pci = pci
		self.underly_ip = underly_ip
		self.vni = vni
		self.nat_ip = None
		self.nat_port = None

	def get_ip(self):
		return self.vm_ip

	def get_ipv6(self):
		return self.vm_ipv6

	def get_pci(self):
		return self.vm_pci

	def get_underly_ip(self):
		return self.underly_ip

	def get_vni(self):
		return self.vni

	def set_nat(self, ip, ports):
		self.nat_ip = ip
		self.nat_ports = ports

	def get_nat_ip(self):
		return self.nat_ip

	def get_nat_ports(self):
		return self.nat_ports

	def get_nat(self):
		return self.nat


class LBConfig:

	def __init__(self, name, ip, ports, vni, nodes, vms):
		self.lb_id = name
		self.ip = ip
		self.ports = ports
		self.vni = vni
		self.lb_underly_ip = {}
		self.vm_pfx = {}
		for node in nodes:
			self.lb_underly_ip[node] = ""
		for vm in vms:
			self.vm_pfx[vm] = ""

	def get_id(self):
		return self.lb_id

	def get_ip(self):
		return self.ip

	def get_ports(self):
		return self.ports

	def get_vni(self):
		return self.vni

	def get_nodes(self):
		return self.lb_underly_ip.keys()

	def get_lb_underly_ip(self, node):
		return self.lb_underly_ip[node]

	def set_lb_underly_ip(self, node, underly_ip):
		self.lb_underly_ip[node] = underly_ip

	def get_vms(self):
		return self.vm_pfx.keys()

	def get_vm_lb_pfx(self, vm):
		return self.vm_pfx[vm]

	def set_vm_lb_pfx(self, vm, underly_ip):
		self.vm_pfx[vm] = underly_ip


class RemoteMachine:

	def __init__(self, config, key_file, parent_machine=None):
		self.machine_name = config["machine_name"]
		self.parent_machine = parent_machine
		self.ssh_manager = SSHManager(self.machine_name, config["host_address"], config["port"], config["user_name"],
									  key_file=key_file, proxy=None if not parent_machine else self.parent_machine.get_connection())
		self.logger = self.ssh_manager.logger

	def start(self):
		self.logger.info(f"Connecting via ssh...")
		try:
			self.ssh_manager.connect()

		except Exception as e:
			self.logger.error(f"Failed to connect due to: {e}")

	def probe_connect(self):
		try:
			self.ssh_manager.connect_one_shot(1)
		except ConnectionError:
			raise ConnectionError("")

	def stop(self):
		if self.ssh_manager.is_alive():
			self.ssh_manager.terminate_all_processes()
			if not self.parent_machine:
				self.ssh_manager.terminate_all_containers()
		self.ssh_manager.disconnect()

	def get_machine_name(self):
		return self.machine_name

	def get_parent_machine_name(self):
		if not self.parent_machine:
			return ""
		else:
			return self.parent_machine.get_machine_name()

	def terminate_processes(self):
		self.ssh_manager.terminate_all_processes()

	def terminate_containers(self):
		if not self.parent_machine:
			self.ssh_manager.terminate_all_containers()

	def stop_containers(self):
		self.ssh_manager.stop_all_containers()

	def fetch_log(self, log_name):
		return self.ssh_manager.fetch_logs(log_name)

	def get_connection(self):
		return self.ssh_manager

	def upload(self, proto, local_path, remote_path):
		self.ssh_manager.upload(proto, local_path, remote_path)

	def exec_task(self, tasks):
		task = tasks[0]
		output = self.ssh_manager.run_command(task['command'], parameters=task.get('parameters', ''), background=task.get(
			'background', False), sudo=task.get('sudo', False), delay=task.get('delay', 0), command_output_name=task.get('cmd_output_name', ''))
		output = remove_last_empty_line(output)
		self.logger.info(f"Execution result: {output}")
		return output

	def set_vm_config(self, ipv4, ipv6, pci, underly_ip, vni):
		self.vm_config = VMConfig(ipv4, ipv6, pci, underly_ip, vni)

	def get_vm_config(self):
		return self.vm_config

	def __enter__(self):
		self.start
		return self

	def __exit__(self, exc_type, exc_val, exc_tb):
		self.stop()


def get_remote_machine(machine_name):
	machine = next((machine for machine in (
		vm_machines + hypervisor_machines) if machine.machine_name == machine_name), None)
	if not machine:
		raise ValueError(f"Failed to get machine for {machine_name}")
	return machine


def add_remote_machine(machine, is_vm):
	vm_machines.append(
		machine) if is_vm else hypervisor_machines.append(machine)


def cleanup_remote_machine():
	vm_machines.clear()
	hypervisor_machines.clear()


def add_vm_config_info(machine_name, ipv4, ipv6, pci, underly_ip, vni):
	machine = get_remote_machine(machine_name)
	try:
		machine.set_vm_config(ipv4, ipv6, pci, underly_ip, vni)
	except Exception as e:
		machine.logger.error(f"Failed to store vm config due to: {e} ")


def add_vm_nat_config(machine_name, ip, ports):
	machine = get_remote_machine(machine_name)
	try:
		machine.get_vm_config().set_nat(ip, ports)
	except Exception as e:
		machine.logger.error(
			f"Failed to store vm's nat configuration due to: {e}")


def get_vm_config_detail(machine_name):
	try:
		machine = get_remote_machine(machine_name)
		return machine.get_vm_config()
	except Exception as e:
		machine.logger.error(f"Failed to get stored vm config due to {e} ")
