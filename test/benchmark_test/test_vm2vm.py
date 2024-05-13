from remote_machine_management import get_vm_config_detail
from remote_machine_operations import *
from helper import *


def test_cross_hypervisor_ipv4(test_flow_count, test_mode, test_min_throughput_sw_remote, test_min_throughput_hw_remote):
	# vm1 is the flow test server
	# vm3 is the flow test client

	vm1_config = get_vm_config_detail("vm1")
	vm3_config = get_vm_config_detail("vm3")
	remote_machine_op_dpservice_create_route("hypervisor-1", f"{vm3_config.get_ip()}/32", 0, vm3_config.get_underly_ip(), vm3_config.get_vni())
	remote_machine_op_dpservice_create_route("hypervisor-2",  f"{vm1_config.get_ip()}/32", 0, vm1_config.get_underly_ip(), vm1_config.get_vni())

	remote_machine_op_flow_test("vm1", True, vm1_config.get_ip(), test_flow_count)
	client_output = remote_machine_op_flow_test("vm3", False, vm1_config.get_ip(), test_flow_count)
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
	remote_machine_op_dpservice_delete_route("hypervisor-1", f"{vm3_config.get_ip()}/32", vm3_config.get_vni())
	remote_machine_op_dpservice_delete_route("hypervisor-2", f"{vm1_config.get_ip()}/32", vm1_config.get_vni())
	

def test_same_hypervisor_ipv4(test_flow_count, test_mode, test_min_throughput_sw_local, test_min_throughput_hw_local):
	# vm1 is the flow test server
	# vm2 is the flow test client

	vm1_config = get_vm_config_detail("vm1")

	remote_machine_op_flow_test("vm1", True, vm1_config.get_ip(), test_flow_count)
	client_output = remote_machine_op_flow_test("vm2", False, vm1_config.get_ip(), test_flow_count)

	print(client_output)

	if result_checking_ping_failed(client_output, "Server is not reachable"):
		raise AssertionError("Failed to pass same hypervisor ipv4 test, ping failed")
	else:
		print("Passed ping test")

	min_throughput = test_min_throughput_hw_local if test_mode else test_min_throughput_sw_local
	if not result_checking_throughput_higher_than(client_output, min_throughput):
		raise AssertionError("Failed to pass same hypervisor ipv4 test, throughput test failed")
	else:
		print("Passed throughput test")

	remote_machine_op_terminate_processes("vm1")


def test_cross_hypervisor_ipv6(test_flow_count, test_mode, test_min_throughput_sw_remote, test_min_throughput_hw_remote):
	# vm1 is the flow test server
	# vm3 is the flow test client

	vm1_config = get_vm_config_detail("vm1")
	vm3_config = get_vm_config_detail("vm3")
	remote_machine_op_dpservice_create_route("hypervisor-1", f"{vm3_config.get_ipv6()}/128", 0, vm3_config.get_underly_ip(), vm3_config.get_vni())
	remote_machine_op_dpservice_create_route("hypervisor-2",  f"{vm1_config.get_ipv6()}/128", 0, vm1_config.get_underly_ip(), vm1_config.get_vni())

	remote_machine_op_flow_test("vm1", True, vm1_config.get_ipv6(), test_flow_count)
	client_output = remote_machine_op_flow_test("vm3", False, vm1_config.get_ipv6(), test_flow_count)
	print(client_output)

	if result_checking_ping_failed(client_output, "Server is not reachable"):
		raise AssertionError("Failed to pass cross hypervisor ipv6 test, ping failed")
	else:
		print("Passed ping test")

	min_throughput = test_min_throughput_hw_remote if test_mode else test_min_throughput_sw_remote
	if not result_checking_throughput_higher_than(client_output, min_throughput):
		raise AssertionError("Failed to pass cross hypervisor ipv6 test, throughput test failed")
	else:
		print("Passed throughput test")

	remote_machine_op_terminate_processes("vm1")
	remote_machine_op_dpservice_delete_route("hypervisor-1", f"{vm3_config.get_ipv6()}/128", vm3_config.get_vni())
	remote_machine_op_dpservice_delete_route("hypervisor-2", f"{vm1_config.get_ipv6()}/128", vm1_config.get_vni())


def test_same_hypervisor_ipv6(test_flow_count, test_mode, test_min_throughput_sw_local, test_min_throughput_hw_local):
	# vm1 is the flow test server
	# vm2 is the flow test client

	vm1_config = get_vm_config_detail("vm1")

	remote_machine_op_flow_test("vm1", True, vm1_config.get_ipv6(), test_flow_count)
	client_output = remote_machine_op_flow_test("vm2", False, vm1_config.get_ipv6(), test_flow_count)

	print(client_output)

	if result_checking_ping_failed(client_output, "Server is not reachable"):
		raise AssertionError("Failed to pass same hypervisor ipv6 test, ping failed")
	else:
		print("Passed ping test")

	min_throughput = test_min_throughput_hw_local if test_mode else test_min_throughput_sw_local
	if not result_checking_throughput_higher_than(client_output, min_throughput):
		raise AssertionError("Failed to pass same hypervisor ipv6 test, throughput test failed")
	else:
		print("Passed throughput test")

	remote_machine_op_terminate_processes("vm1")
