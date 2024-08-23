#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import argparse, json, shutil
import re
import os, time
import random
from jinja2 import Environment, FileSystemLoader

from remote_machine_management import (
	RemoteMachine,
)

tmpls_output_path = ''
working_test_config_file = ''
provision_tmpls_compressed = ''

current_script_directory = os.getcwd()
local_provision_tmpls_path = current_script_directory + '/provision_tmpls'
target_provision_tmpls_output_path = '/tmp/provision_tmpls'

hypervisor_machines = []

def underscore_convert(text):
	return re.sub("_", "-", text)


def get_test_config(args, init):
	if init:
		os.system(f"cp ./config_templates/test_configurations.json {working_test_config_file}")
	
	with open(working_test_config_file, 'r') as file:
		config = json.load(file)

	return config


def get_working_test_config_file_path():
	return os.path.join(tmpls_output_path, 'test_configurations.json')


def prepare_ignition_file(env_config, template_path, ignition_template_name):
	# Read public RSA key
	pub_rsa_key_path = os.path.expanduser(env_config["public_key_file"])
	with open(pub_rsa_key_path, 'r') as key_file:
		pub_rsa_key = key_file.read().strip()
	
	# Load the Jinja2 template for the ignition file
	env = Environment(loader=FileSystemLoader(os.path.expanduser(template_path)))
	template = env.get_template(ignition_template_name)

	ignition_config = template.render(pub_rsa_key=pub_rsa_key)

	# Save the ignition file
	output_ignition_path = os.path.join(tmpls_output_path, "provision.ign")
	with open(output_ignition_path, 'w') as output_file:
		output_file.write(ignition_config)


def create_path_on_local(path):
	# If the directory does not exist, create it
	if not os.path.exists(path):
		os.makedirs(path)
		print(f"Created directory: {path}")
	else:
		print(f"Directory already exists: {path}")


def remove_path_on_local(path):
	try:
		if os.path.exists(path):
			if os.path.isfile(path) or os.path.islink(path):
				os.remove(path)  # Remove the file or symbolic link
				print(f"File or symlink removed: {path}")
			elif os.path.isdir(path):
				shutil.rmtree(path)  # Remove the directory and its contents
				print(f"Directory removed: {path}")
			else:
				print(f"Unknown file type: {path}")
		else:
			print(f"Path does not exist: {path}")
	except Exception as e:
		print(f"Error removing {path}: {e}")


def create_local_provision_tmpls_path():
	create_path_on_local(local_provision_tmpls_path)
	os.system(f"cp ./config_templates/test_configurations.json {local_provision_tmpls_path}/test_configurations.json")
	os.system(f"cp ./config_templates/provision_tmpl.ign {local_provision_tmpls_path}/provision_tmpl.ign")
	os.system(f"cp ./config_templates/vm_tmpl.xml {local_provision_tmpls_path}/vm_tmpl.xml")


def remove_local_provision_tmpls_path():
	try:
		remove_path_on_local(local_provision_tmpls_path)
	except Exception as e:
		print(f"Failed to remove local provision templates path: {e}")


def create_tmpls_output_path():
	# Append '/output' to the provided path
	output_path = os.path.join(local_provision_tmpls_path, 'output')
	
	# Expand user (~) and create the full path if it doesn't exist
	expanded_output_path = os.path.expanduser(output_path)
	create_path_on_local(expanded_output_path)

	return expanded_output_path

def generate_vm_iface_mac_addr():
	mac_addr = [0x02, 0x00, 0x00]
	
	for _ in range(3):
		mac_addr.append(random.randint(0x00, 0xFF))
	
	mac_addr_str = ":".join(map(lambda x: f"{x:02x}", mac_addr))
	
	return mac_addr_str



def update_vm_mac_addresses(config):
	for hypervisor in config['hypervisors']:
		for vm in hypervisor['vms']:
			# Generate MAC address
			mac_address = generate_vm_iface_mac_addr()
			# Add the MAC address to the VM's if_config
			vm['mac_address'] = mac_address
			print(f"Generated MAC address for {vm['machine_name']}: {mac_address}")
	
	# Write updated configuration back to the JSON file
	with open(working_test_config_file, 'w') as file:
		json.dump(config, file, indent=4)
		print(f"Updated configuration written to {working_test_config_file}")


def convert_pci_address(pci_addr):
	# Extract the domain, bus, slot, function, and vf using regex
	match = re.match(r"(?:(?P<domain>[0-9a-fA-F]{4}):)?(?P<bus>[0-9a-fA-F]{2}):(?P<slot>[0-9a-fA-F]{2})\.(?P<function>[0-9a-fA-F])_representor_vf(?P<vf>\d+)", pci_addr)
	
	if match:
		# If domain is missing, default it to '0000'
		domain = match.group('domain') if match.group('domain') else '0000'
		bus = match.group('bus')
		slot = match.group('slot')
		vf = match.group('vf')
		
		# Compute the function value as the VF value plus 2
		function = hex(int(vf) + 2)[2:]

		return f'domain="0x{domain}" bus="0x{bus}" slot="0x{slot}" function="0x{function}"'
	else:
		raise ValueError("Invalid PCI address format")


def generate_vm_domain_xml(config):
	ignition_file = os.path.join(target_provision_tmpls_output_path, "provision.ign")
	env = Environment(loader=FileSystemLoader(os.path.expanduser('./config_templates')))
	template = env.get_template('vm_tmpl.xml')

	for hypervisor in config['hypervisors']:
		hypervisor_name = hypervisor['machine_name']
		xml_repo_per_hypervisor = tmpls_output_path + '/' + hypervisor_name
		create_path_on_local(xml_repo_per_hypervisor)
		
		for vm in hypervisor['vms']:
			vm_name = vm['machine_name']
			vm_xml_name = xml_repo_per_hypervisor + '/' + f'{vm_name}.xml'
			pci_address = convert_pci_address(vm['if_config']['pci_addr'])
			print(pci_address)
			mac_address = vm['mac_address']

			disk_image = os.path.expanduser(f'{target_provision_tmpls_output_path}/{hypervisor_name}/{vm_name}.raw')

			vm_tmpl = template
			vm_xml = vm_tmpl.render(VM_NAME=vm_name, VF_PCI_ADDRESS=pci_address, BRIDGE_IFACE_MAC=mac_address, DISK_IMAGE=disk_image, IGNITION_FILE=ignition_file)

			# Save the xml file
			with open(vm_xml_name, 'w') as output_file:
				output_file.write(vm_xml)


def add_remote_machine(machine):
	hypervisor_machines.append(machine)

def cleanup_remote_machine():
	hypervisor_machines.clear()

def get_remote_machine_by_name(name):
	machine = next((machine for machine in hypervisor_machines if machine.machine_name == name), None)
	if not machine:
		raise ValueError(f"Failed to get machine for {name}")
	return machine


def compress_provision_tmpls():
	global provision_tmpls_compressed
	provision_tmpls_compressed = os.path.join(local_provision_tmpls_path, "provision_tmpls.tar.gz")
	shutil.make_archive(provision_tmpls_compressed.replace('.tar.gz', ''), 'gztar', tmpls_output_path)
	print(f"Compressed provision templates directory to {provision_tmpls_compressed}")


def upload_and_decompress_provision_tmpls(machine):
	try:
		# Remove existing repo
		task = [
			{"command": "rm -r", "parameters": f"{target_provision_tmpls_output_path}"}
		]
		machine.exec_task(task)

		# Upload the compressed file to the remote machine
		provision_tmpls_dst = '/tmp/provision_tmpls.tar.gz'
		machine.upload("sftp", provision_tmpls_compressed, provision_tmpls_dst)
		task = [
			{"command": f'test -e {provision_tmpls_dst} && echo "exists" || echo "not exists"'}
		]
		result = machine.exec_task(task)
		if result != "exists":
			machine.upload("scp", provision_tmpls_compressed, provision_tmpls_dst)
		print(f"Uploaded {provision_tmpls_compressed} to remote machine at {provision_tmpls_compressed}")

		# Decompress the file on the remote machine
		task = [
			{"command": "mkdir -p", "parameters": f"{target_provision_tmpls_output_path}"}
		]
		machine.exec_task(task)
	
		task = [
			{"command": "tar -xzf", "parameters": f"{provision_tmpls_dst} -C {target_provision_tmpls_output_path}"}
		]
		machine.exec_task(task)
		print(f"Decompressed {provision_tmpls_dst} to {target_provision_tmpls_output_path}")

		# Clean up the compressed file on the remote machine
		task = [
			{"command": "rm", "parameters": f"{provision_tmpls_dst}"}
		]
		machine.exec_task(task)
		print(f"Removed compressed file {provision_tmpls_compressed} from remote machine")
	except Exception as e:
		print(f"Failed to transfer provision templates: {e}")
		raise e


def upload_vm_disk_image(machine, hypervisor_info, src_disk_image_path):
	try:
		for vm in hypervisor_info['vms']:
			vm_name = vm['machine_name']
			print(f"Uploading vm disk image for remote machine {vm_name}")
			dst_disk_image_path = os.path.expanduser(f'{target_provision_tmpls_output_path}/{hypervisor_info['machine_name']}/{vm_name}.raw')
			machine.upload("sftp", src_disk_image_path, dst_disk_image_path)
			task = [
				{"command": f'test -e {dst_disk_image_path} && echo "exists" || echo "not exists"'}
			]
			result = machine.exec_task(task)
			if result != "exists":
				machine.upload("scp", src_disk_image_path, dst_disk_image_path)
			print(f"Uploaded {src_disk_image_path} to remote machine at {dst_disk_image_path}")
	except Exception as e:
		print("Cannot transfer disk image")


def start_vm_on_hypervisor(machine, hypervisor_info):
	try:
		for vm in hypervisor_info['vms']:
			vm_name = vm['machine_name']
			vm_xml_path = os.path.expanduser(f'{target_provision_tmpls_output_path}/{hypervisor_info["machine_name"]}/{vm_name}.xml')
			print(f"Starting VM {vm_name} on hypervisor {hypervisor_info['machine_name']}")
			task = [
				{"command": "virsh define", "parameters": vm_xml_path, "sudo":True},
			]
			machine.exec_task(task)
			task = [
				{"command": "virsh start", "parameters": vm_name, "sudo":True, "delay": 3}
			]
			machine.exec_task(task)
			print(f"VM {vm_name} started successfully on {hypervisor_info['machine_name']}")
	except Exception as e:
		print(f"Failed to start VM {vm_name}: {e}")
		raise e

def stop_and_remove_vm_on_hypervisor(machine, hypervisor_info):
	try:
		for vm in hypervisor_info['vms']:
			vm_name = vm['machine_name']
			print(f"Stopping and removing VM {vm_name} on hypervisor {hypervisor_info['machine_name']}")
			task = [
				{"command": "virsh destroy", "parameters": vm_name, "sudo": True},
			]
			machine.exec_task(task)
			task = [
				{"command": "virsh undefine", "parameters": vm_name, "sudo": True, "delay": 10}
			]
			machine.exec_task(task)
			print(f"VM {vm_name} stopped and removed successfully on {hypervisor_info['machine_name']}")
	except Exception as e:
		print(f"Failed to stop and remove VM {vm_name}: {e}")
		raise e
	

def provision_vms_on_hypervisor(config, args):
	try:
		for hypervisor_info in config["hypervisors"]:
			hypervisor_machine = get_remote_machine_by_name(hypervisor_info["machine_name"])
			upload_and_decompress_provision_tmpls(hypervisor_machine)
			upload_vm_disk_image(hypervisor_machine, hypervisor_info, args['disk_template'])
			start_vm_on_hypervisor(hypervisor_machine, hypervisor_info)
	except Exception as e:
		print("Cannot transfer provision tmpls")


def clean_up_on_hypervisors(config, args):
	try:
		for hypervisor_info in config['hypervisors']:
			hypervisor_machine = get_remote_machine_by_name(hypervisor_info['machine_name'])
			# Stop and remove all VMs on the hypervisor
			stop_and_remove_vm_on_hypervisor(hypervisor_machine, hypervisor_info)

			# Remove the /mnt/provision_tmpls directory on the hypervisor
			task = [
				{"command": "rm -rf", "parameters": f"{target_provision_tmpls_output_path}"}
			]
			hypervisor_machine.exec_task(task)
			print(f"Removed {target_provision_tmpls_output_path} from {hypervisor_info['machine_name']}")

	except Exception as e:
		print(f"Failed to clean up on hypervisors: {e}")


def update_vm_ip_addresses(config, args):
	try:
		for hypervisor_info in config['hypervisors']:
			print(f"Retrieving IP addresses from hypervisor {hypervisor_info['machine_name']}")

			hypervisor_machine = get_remote_machine_by_name(hypervisor_info['machine_name'])
			# Attempt to retrieve IP address up to 10 times, with a 3-second interval
			for attempt in range(10):
				print(f"Attempt {attempt + 1}/10 to retrieve IP addresses...")
				task = [
					{"command": "virsh net-dhcp-leases", "parameters": 'default', "sudo": True}
				]
				result = hypervisor_machine.exec_task(task)
				
				for vm in hypervisor_info['vms']:
					mac_address = vm['mac_address']
					vm_ip = None
					
					# Parse each line in the virsh net-dhcp-leases result
					for line in result.splitlines():
						if mac_address in line:
							match = re.search(r"(\d{1,3}\.){3}\d{1,3}", line)
							if match:
								vm_ip = match.group(0)
								break
					
					if vm_ip:
						print(f"Found IP address {vm_ip} for VM {vm['machine_name']} with MAC {mac_address}")
						vm['host_address'] = vm_ip
					else:
						print(f"No IP address found yet for VM {vm['machine_name']} with MAC {mac_address}")

				# Break out of the loop if all VMs have been assigned an IP address
				all_vms_have_ips = all('host_address' in vm for vm in hypervisor_info['vms'])
				if all_vms_have_ips:
					break
				
				# Wait for 3 seconds before trying again
				time.sleep(3)

					
		# Write the updated configuration with IP addresses back to the JSON file
		with open(working_test_config_file, 'w') as file:
			json.dump(config, file, indent=4)
			print(f"Updated configuration written to {working_test_config_file}")

	except Exception as e:
		print(f"Failed to update VM IP addresses: {e}")
		raise e


def connect_with_hypervisors(config):
	try:
		for hypervisor_info in config["hypervisors"]:
			hypervisor_machine = RemoteMachine(hypervisor_info, os.path.expanduser(config["key_file"]))
			add_remote_machine(hypervisor_machine)
			hypervisor_machine.start()
	except Exception as e:
		print("Cannot connect with hypervisor")

def disconnect_from_hypervisors():
	for machine in hypervisor_machines:
		machine.disconnect()
		print(f"Disconnected from {machine.machine_name}")
	cleanup_remote_machine()

def provision_benchmark_environment(args):
	global tmpls_output_path
	global working_test_config_file
	
	args = vars(args)

	create_local_provision_tmpls_path()
	tmpls_output_path = create_tmpls_output_path()
	working_test_config_file = get_working_test_config_file_path()
	config = get_test_config(args, True)
	connect_with_hypervisors(config)

	if args["clean_up"]:
		clean_up_on_hypervisors(config, args)
		disconnect_from_hypervisors()
		remove_local_provision_tmpls_path()
		return
	if args['disk_template'] == '':
		print("Disk template must be provided")
		exit(1)

	prepare_ignition_file(config, local_provision_tmpls_path, args["ignition_template_name"])
	update_vm_mac_addresses(config)
	config = get_test_config(args, False)
	generate_vm_domain_xml(config)

	compress_provision_tmpls()
	provision_vms_on_hypervisor(config, args)

	update_vm_ip_addresses(config, args)

	disconnect_from_hypervisors()

def add_arg_parser():
	script_path = os.path.dirname(os.path.abspath(__file__))
	parser = argparse.ArgumentParser(
		formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=32))

	parser.add_argument("--disk-template", action="store",
					   default='', help="Disk image template location and name")
	parser.add_argument("--ignition-template-name", action="store", default="provision_tmpl.ign",
						help="Ignition file template's name")
	parser.add_argument("--xml-template-name", action="store", default="vm.xml",
						help="VM xml definition template's name")
	parser.add_argument("--clean-up", action="store_true", default=False, help="Flag to clean up VM and provision files on hypervisors via tunnels.")
	parser.set_defaults(func=provision_benchmark_environment)

	args = parser.parse_args()
	if hasattr(args, 'func'):
		args.func(args)
	else:
		parser.print_help()


if __name__ == '__main__':
	add_arg_parser()
