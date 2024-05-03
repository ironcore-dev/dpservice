import os
import json
import signal

from remote_machine_operations import *
from flow_test_config import *
from remote_machine_management import get_vm_config_detail

script_dir = os.path.dirname(os.path.abspath(__file__))


# get info from config file
with open('access_details.json', 'r') as file:
	config = json.load(file)


def prepare_test_environment():

	setup_environment(config, "regular_setup")
	
	remote_machine_op_dpservice_start("lenovo1", offload=False, is_docker=True, docker_image_url="ghcr.io/ironcore-dev/dpservice:sha-e9b4272")
	remote_machine_op_dpservice_start("dell3", offload=False, is_docker=False)

	remote_machine_op_dpservice_init("lenovo1")
	remote_machine_op_dpservice_init("dell3")

	remote_machine_op_dpservice_add_vms(config, "regular_setup")

	remote_machine_op_reboot("vm1")
	remote_machine_op_reboot("vm2")
	remote_machine_op_reboot("vm3")

	remote_machine_op_vm_config_rm_default_route("vm1")
	remote_machine_op_vm_config_rm_default_route("vm2")
	remote_machine_op_vm_config_rm_default_route("vm3")

	script_path_to_upload = os.path.expanduser('../../hack/connectivity_test/flow_test.py')
	script_path_to_land = '/tmp/flow_test.py'
	remote_machine_op_upload("vm1", script_path_to_upload, script_path_to_land)
	remote_machine_op_upload("vm2", script_path_to_upload, script_path_to_land)
	remote_machine_op_upload("vm3", script_path_to_upload, script_path_to_land)

	remote_machine_op_make_runnable("vm1", script_path_to_land)
	remote_machine_op_make_runnable("vm2", script_path_to_land)
	remote_machine_op_make_runnable("vm3", script_path_to_land)


def test_cross_hypervisor_ipv4_non_offloading():
	# vm1 is the flow test server
	# vm3 is the flow test client

	vm1_config = get_vm_config_detail("vm1")
	vm3_config = get_vm_config_detail("vm3")
	remote_machine_op_dpservice_create_route("lenovo1", f"{vm3_config.get_ip()}/32", 0, vm3_config.get_underly_ip(), vm3_config.get_vni())
	remote_machine_op_dpservice_create_route("dell3",  f"{vm1_config.get_ip()}/32", 0, vm1_config.get_underly_ip(), vm1_config.get_vni())

	remote_machine_op_flow_test("vm1", True, vm1_config.get_ip(), 1)
	client_output = remote_machine_op_flow_test("vm3", False, vm1_config.get_ip(), 1)
	print(client_output)

	if result_checking_ping_failed(client_output, "Server is not reachable"):
		print("Failed due to connectivity issue between two VMs")
	else:
		print("Passed ping test")

	if result_checking_throughput_higher_than(client_output, 7.0):
		print("Passed throughput test")
	else:
		print("Failed throughput test")

	remote_machine_op_terminate_processes("vm1")
	

def test_same_hypervisor_ipv4_non_offloading():
	# vm1 is the flow test server
	# vm2 is the flow test client

	vm1_config = get_vm_config_detail("vm1")

	remote_machine_op_flow_test("vm1", True, vm1_config.get_ip(), 1)
	client_output = remote_machine_op_flow_test("vm2", False, vm1_config.get_ip(), 1)

	print(client_output)

	if result_checking_ping_failed(client_output, "Server is not reachable"):
		print("Failed due to connectivity issue between two VMs")
	else:
		print("Passed ping test")

	if result_checking_throughput_higher_than(client_output, 10.0):
		print("Passed throughput test")
	else:
		print("Failed throughput test")

	remote_machine_op_terminate_processes("vm1")


def main():
	# setup hypervisors
	# need to think how to upload / exec dpservice container
	prepare_test_environment()

	signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame))

	test_cross_hypervisor_ipv4_non_offloading()
	test_same_hypervisor_ipv4_non_offloading()

	#  Wait for some time or until a condition ` to terminate the DPDK application
	signal.pause()


if __name__ == "__main__": 
	main()
