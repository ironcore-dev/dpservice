# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

from remote_machine_management import get_vm_config_detail
from remote_machine_operations import *
from benchmark_test_config import init_lb, tear_down_lb, test_logger
from helper import *


def test_nat_cross_machine(test_mode, test_min_throughput_hw_remote, test_min_throughput_sw_remote):
	# vm1 runs the server
	# vm3 is behind a NAT and connects to vm1

	# it is not for the ideal setup involving actual router facing internet but to emulate the usage of NAT using two machines

	vm1_config = get_vm_config_detail("vm1")
	vm3_config = get_vm_config_detail("vm3")

	output = remote_machine_op_dpservice_create_nat(
		"hypervisor-2", "vm3", vm3_config.get_nat_ip(), vm3_config.get_nat_ports())
	nat_underly_ip = get_underly_ip(output)

	remote_machine_op_dpservice_create_route(
		"hypervisor-1", f"{vm3_config.get_nat_ip()}/32", 0, nat_underly_ip, vm3_config.get_vni())
	remote_machine_op_dpservice_create_route(
		"hypervisor-2",  "0.0.0.0/0", 0, vm1_config.get_underly_ip(), vm1_config.get_vni())

	remote_machine_op_flow_test("vm1", True, vm1_config.get_ip(), 1)
	client_output = remote_machine_op_flow_test(
		"vm3", False, vm1_config.get_ip(), 1)

	if result_checking_ping_failed(client_output, "Server is not reachable"):
		raise AssertionError(
			"Failed to pass cross hypervisor ipv4 test, ping failed")

	min_throughput = test_min_throughput_hw_remote if test_mode else test_min_throughput_sw_remote
	if not result_checking_throughput_higher_than(client_output, min_throughput):
		raise AssertionError(
			"Failed to pass cross hypervisor ipv4 test, throughput test failed")
	else:
		test_logger.info("test_nat_cross_machine succeeds")

	remote_machine_op_terminate_processes("vm1")
	remote_machine_op_dpservice_delete_route(
		"hypervisor-1", f"{vm3_config.get_nat_ip()}/32", vm3_config.get_vni())
	remote_machine_op_dpservice_delete_nat("hypervisor-2", "vm3")
	remote_machine_op_dpservice_delete_route(
		"hypervisor-2", "0.0.0.0/0", vm1_config.get_vni())


def test_loadbalancer_cross_machine(test_mode, test_config, test_min_throughput_sw_lb, test_min_throughput_hw_lb):
	# vm3 runs a server and it is behind a loadbalancer created on hypervisor-2
	# vm1, running on hypervisor-1, connects to the loadbalancer and further connects to vm3

	# init lb by creating lb on nodes, pfx for vms, and installing pfx for lb
	lb_config = init_lb(test_config)
	if not lb_config:
		raise AssertionError("No LB is configured in the test config file")

	vm1_config = get_vm_config_detail("vm1")

	# install route to lb on hypervisor-1 where vm1 is running
	underlying_ip_lb = lb_config.get_lb_underly_ip("hypervisor-2")
	remote_machine_op_dpservice_create_route(
		"hypervisor-1", f"{lb_config.get_ip()}/32", 0, underlying_ip_lb, lb_config.get_vni())

	# install route on hypervisor-2 so as reply traffic can reach it
	remote_machine_op_dpservice_create_route(
		"hypervisor-2", f"{vm1_config.get_ip()}/32", 0, vm1_config.get_underly_ip(), vm1_config.get_vni())

	remote_machine_op_add_ip_addr(
		"vm3", f"{lb_config.get_ip()}/32", "lo", False)

	remote_machine_op_flow_test("vm3", True, lb_config.get_ip(), 1)
	client_output = remote_machine_op_flow_test(
		"vm1", False, lb_config.get_ip(), 1)

	if result_checking_ping_failed(client_output, "Server is not reachable"):
		raise AssertionError(
			"Failed to pass cross hypervisor ipv4 test, ping failed")

	min_throughput = test_min_throughput_hw_lb if test_mode else test_min_throughput_sw_lb
	if not result_checking_throughput_higher_than(client_output, min_throughput):
		raise AssertionError(
			"Failed to pass cross hypervisor ipv4 test, throughput test failed")
	else:
		test_logger.info("test_loadbalancer_cross_machine succeeds")

	tear_down_lb(lb_config)
	remote_machine_op_delete_ip_addr(
		"vm3", f"{lb_config.get_ip()}/32", "lo", False)
	remote_machine_op_dpservice_delete_route(
		"hypervisor-1", f"{lb_config.get_ip()}/32", lb_config.get_vni())
	remote_machine_op_dpservice_delete_route(
		"hypervisor-2", f"{vm1_config.get_ip()}/32", vm1_config.get_vni())
