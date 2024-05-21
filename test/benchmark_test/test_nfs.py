from remote_machine_management import get_vm_config_detail
from remote_machine_operations import *
from helper import *

def test_nat_cross_machine(test_mode, test_min_throughput_hw_remote, test_min_throughput_sw_remote):
	# vm1 runs the server
	# vm3 is behind a NAT and connects to vm1

	# it is not for the ideal setup involving actual router facing internet but emulate the usage of NAT using two machines

	vm1_config = get_vm_config_detail("vm1")
	vm3_config = get_vm_config_detail("vm3")

	output = remote_machine_op_dpservice_create_nat("hypervisor-2", "vm3", vm3_config.get_nat_ip(), vm3_config.get_nat_ports())
	nat_underly_ip = get_underly_ip(output)

	remote_machine_op_dpservice_create_route("hypervisor-1", f"{vm3_config.get_nat_ip()}/32", 0, nat_underly_ip, vm3_config.get_vni())
	remote_machine_op_dpservice_create_route("hypervisor-2",  "0.0.0.0/0", 0, vm1_config.get_underly_ip(), vm1_config.get_vni())

	remote_machine_op_flow_test("vm1", True, vm1_config.get_ip(), 1)
	client_output = remote_machine_op_flow_test("vm3", False, vm1_config.get_ip(), 1)
	print(client_output)

	if result_checking_ping_failed(client_output, "Server is not reachable"):
		raise AssertionError("Failed to pass cross hypervisor ipv4 test, ping failed")
	else:
		print("Passed ping test")

	min_throughput = test_min_throughput_hw_remote if test_mode else test_min_throughput_sw_remote
	if not result_checking_throughput_higher_than(client_output, min_throughput):
		raise AssertionError("Failed to pass cross hypervisor ipv4 test, throughput test failed")
	else:
		print("Passed throughput test")

	remote_machine_op_terminate_processes("vm1")
	remote_machine_op_dpservice_delete_route("hypervisor-1", f"{vm3_config.get_nat_ip()}/32", vm3_config.get_vni())
	remote_machine_op_dpservice_delete_nat("hypervisor-2", "vm3")
	remote_machine_op_dpservice_delete_route("hypervisor-2", "0.0.0.0/0", vm1_config.get_vni())

