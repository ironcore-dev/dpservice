import sys
import os

from remote_machine_management import hypervisor_machines, vm_machines, RemoteMachine

def signal_handler(sig, frame):
	print("Ctrl-C pressed. Cleaning up...")
	tear_down_environment()
	sys.exit(0)

def setup_environment(config, env_name):
	key_file = os.path.expanduser(config['key_file'])
	env_config = next((env for env in config['environments'] if env['name'] == env_name), None)
	if not env_config:
		print(f"Failed to get config info for environment with name {env_name}")
		sys.exit(1)

	try:
		for hypervisor_info in env_config['hypervisors']:
			hypervisor_machine = RemoteMachine(hypervisor_info, key_file)
			hypervisor_machines.append(hypervisor_machine)
			vm_machines.extend([RemoteMachine(vm_info, key_file, hypervisor_machine) for vm_info in hypervisor_info['vms']])
	except Exception as e:
		print(f"Failed to setup remote control machine due to {e} ")
		sys.exit(1)

	try:
		for machine in hypervisor_machines + vm_machines:
			machine.start()
	except Exception as e:
		print(f"Failed to start machine due to {e}")

def tear_down_environment():
	try:
		for machine in hypervisor_machines:
			dpservice_log = machine.fetch_log("dpservice")
			print(dpservice_log)

		for machine in vm_machines + hypervisor_machines:
			machine.stop()
	except Exception as e:
		print(f"Failed to stop a connection due to {e} ")
