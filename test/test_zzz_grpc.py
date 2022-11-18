from config import *
from helpers import *

def test_grpc_addmachine_error_102(add_machine, build_path):
	# Try to add using an existing vm identifier
	expected_error_str = "error 102"
	add_machine_test = build_path+"/test/dp_grpc_client --addmachine " + vm2_name + " --vni "+ vni + " --ipv4 " + vf1_ip + " --ipv6 " + vf1_ipv6
	eval_cmd_output(add_machine_test, expected_error_str)

def test_grpc_getmachine_single(add_machine, build_path):
	# Try to get a single existing interface(machine)
	expected_str = vf1_ip
	add_machine_test = build_path+"/test/dp_grpc_client --getmachine " + vm2_name
	eval_cmd_output(add_machine_test, expected_str)

def test_grpc_addmachine_error_106(add_machine, build_path):
	# Try to add with new machine identifer but already given IPv4
	expected_error_str = "error 106"
	add_machine_test = build_path+"/test/dp_grpc_client --addmachine " + vm3_name + " --vni "+ vni + " --ipv4 " + vf1_ip + " --ipv6 " + vf1_ipv6
	eval_cmd_output(add_machine_test, expected_error_str)

def test_grpc_delmachine_error_151(capsys, add_machine, build_path):
	# Try to delete with machine identifer which doesnt exist
	expected_str = "error 151"
	del_machine_test = build_path+"/test/dp_grpc_client --delmachine " + vm3_name
	eval_cmd_output(del_machine_test, expected_str)

def test_grpc_add_list_delmachine(capsys, add_machine, build_path):
	# Try to add a new machine, list it, delete it and confirm the deletion with list again
	expected_str = "net_tap4"
	add_machine_test = build_path+"/test/dp_grpc_client --addmachine " + vm3_name+ " --vni "+ vni + " --ipv4 " + vf2_ip + " --ipv6 " + vf2_ipv6
	eval_cmd_output(add_machine_test, expected_str)

	expected_str = vm3_name
	list_machine_test = build_path+"/test/dp_grpc_client --getmachines "
	eval_cmd_output(list_machine_test, expected_str)

	expected_str = "Delmachine"
	del_machine_test = build_path+"/test/dp_grpc_client --delmachine " + vm3_name
	eval_cmd_output(del_machine_test, expected_str)

	expected_str = vm3_name
	list_machine_test = build_path+"/test/dp_grpc_client --getmachines "
	eval_cmd_output(list_machine_test, expected_str, negate=True)

def test_grpc_addroute_error_251(capsys, add_machine, build_path):
	# Try to add a route which is already added
	expected_str = "error 251"
	add_route_test = build_path+"/test/dp_grpc_client --addroute --vni " + vni + " --ipv4 " + ov_target_pfx + " --length 24 --t_vni " + vni + " --t_ipv6 2a10:afc0:e01f:f408::1"
	eval_cmd_output(add_route_test, expected_str)

def test_grpc_list_delroutes(capsys, add_machine, build_path):
	# Try to list routes, delete one of them, list and add again
	expected_str = ov_target_pfx
	list_route_test = build_path+"/test/dp_grpc_client --listroutes --vni " + vni
	eval_cmd_output(list_route_test, expected_str)

	expected_str = "Delroute"
	del_route_test = build_path+"/test/dp_grpc_client --delroute --vni " + vni + " --ipv4 " + ov_target_pfx + " --length 24"
	eval_cmd_output(del_route_test, expected_str)

	expected_str = ov_target_pfx
	list_route_test = build_path+"/test/dp_grpc_client --listroutes --vni " + vni
	eval_cmd_output(list_route_test, expected_str, negate=True)

	expected_str = "error"
	add_route_test = build_path+"/test/dp_grpc_client --addroute --vni " + vni + " --ipv4 " + ov_target_pfx + " --length 24 --t_vni " + vni + " --t_ipv6 2a10:afc0:e01f:f408::1"
	eval_cmd_output(add_route_test, expected_str, negate=True)

def test_grpc_add_list_delVIP(capsys, add_machine, build_path):
	# Try to add VIP, list, test error cases, delete vip and list again
	expected_str = ul_actual_src
	add_vip_test = build_path+"/test/dp_grpc_client --addvip " + vm2_name + " --ipv4 " + virtual_ip
	eval_cmd_output(add_vip_test, expected_str)

	expected_str = virtual_ip
	get_vip_test = build_path+"/test/dp_grpc_client --getvip " + vm2_name
	eval_cmd_output(get_vip_test, expected_str)

	# Try to add the same vip again
	expected_str = "351"
	add_vip_test = build_path+"/test/dp_grpc_client --addvip " + vm2_name + " --ipv4 " + virtual_ip
	eval_cmd_output(add_vip_test, expected_str)

	# Try to add to a machine which doesnt exist
	expected_str = "350"
	add_vip_test = build_path+"/test/dp_grpc_client --addvip " + vm3_name + " --ipv4 " + virtual_ip
	eval_cmd_output(add_vip_test, expected_str)

	expected_str = "Delvip"
	del_vip_test = build_path+"/test/dp_grpc_client --delvip " + vm2_name
	eval_cmd_output(del_vip_test, expected_str)

	expected_str = virtual_ip
	get_vip_test = build_path+"/test/dp_grpc_client --getvip " + vm2_name
	eval_cmd_output(get_vip_test, expected_str, negate=True)

def test_grpc_add_list_delLBVIP(capsys, add_machine, build_path):
	# Try to add LB VIP, list, test error cases, delete vip and list again
	expected_str = ul_actual_src
	add_lbvip_test = build_path+"/test/dp_grpc_client --createlb "+ mylb + " --vni " + vni + " --ipv4 " + virtual_ip + " --port 80 --protocol tcp"
	eval_cmd_output(add_lbvip_test, expected_str)

	expected_str = "LB target added"
	add_lbvip_test = build_path+"/test/dp_grpc_client --addlbvip " + mylb + " --t_ipv6 " + back_ip1
	eval_cmd_output(add_lbvip_test, expected_str)

	expected_str = back_ip1
	list_backips_test = build_path+"/test/dp_grpc_client --listbackips " + mylb
	eval_cmd_output(list_backips_test, expected_str)

	expected_str = "LB target added"
	add_lbvip_test = build_path+"/test/dp_grpc_client --addlbvip " + mylb + " --t_ipv6 " + back_ip2
	eval_cmd_output(add_lbvip_test, expected_str)

	expected_str = back_ip2
	list_backips_test = build_path+"/test/dp_grpc_client --listbackips " + mylb
	eval_cmd_output(list_backips_test, expected_str)

	expected_str = "Dellbvip"
	del_lbvip_test = build_path+"/test/dp_grpc_client --dellbvip " + mylb + " --t_ipv6 " + back_ip1
	eval_cmd_output(del_lbvip_test, expected_str)

	expected_str = back_ip1
	list_backips_test = build_path+"/test/dp_grpc_client --listbackips " + mylb
	eval_cmd_output(list_backips_test, expected_str, negate=True)

	expected_str = "Dellbvip"
	del_lbvip_test = build_path+"/test/dp_grpc_client --dellbvip " + mylb + " --t_ipv6 " + back_ip2
	eval_cmd_output(del_lbvip_test, expected_str)

	expected_str = back_ip2
	list_backips_test = build_path+"/test/dp_grpc_client --listbackips " + mylb
	eval_cmd_output(list_backips_test, expected_str, negate=True)

	expected_str = ul_actual_src
	del_lbvip_test = build_path+"/test/dp_grpc_client --getlb " + mylb
	eval_cmd_output(del_lbvip_test, expected_str)

	expected_str = "Delete LB Success"
	del_lbvip_test = build_path+"/test/dp_grpc_client --dellb " + mylb
	eval_cmd_output(del_lbvip_test, expected_str)

def test_grpc_add_list_delPfx(capsys, add_machine, build_path):
	# Try to add Prefix, list, test error cases, delete prefix and list again
	expected_str = ul_actual_src
	add_pfx_test = build_path+"/test/dp_grpc_client --addpfx " + vm2_name + " --ipv4 " + pfx_ip + " --length 24"
	eval_cmd_output(add_pfx_test, expected_str)

	expected_str = pfx_ip
	list_pfx_test = build_path+"/test/dp_grpc_client --listpfx " + vm2_name
	eval_cmd_output(list_pfx_test, expected_str)

	# Try to add the same pfx again
	expected_str = "652"
	add_pfx_test = build_path+"/test/dp_grpc_client --addpfx " + vm2_name + " --ipv4 " + pfx_ip + " --length 24"
	eval_cmd_output(add_pfx_test, expected_str)

	# Try to add/delete to/from a machine which doesnt exist
	expected_str = "651"
	add_pfx_test = build_path+"/test/dp_grpc_client --addpfx " + vm3_name + " --ipv4 " + pfx_ip + " --length 24"
	eval_cmd_output(add_pfx_test, expected_str)

	expected_str = "701"
	del_pfx_test = build_path+"/test/dp_grpc_client --delpfx " + vm3_name + " --ipv4 " + pfx_ip + " --length 24"
	eval_cmd_output(del_pfx_test, expected_str)

	expected_str = "Delprefix"
	del_pfx_test = build_path+"/test/dp_grpc_client --delpfx " + vm2_name + " --ipv4 " + pfx_ip + " --length 24"
	eval_cmd_output(del_pfx_test, expected_str)

	expected_str = pfx_ip
	list_pfx_test = build_path+"/test/dp_grpc_client --listpfx " + vm2_name
	eval_cmd_output(list_pfx_test, expected_str, negate=True)

def test_grpc_add_list_delLoadBalancerTargets(capsys, add_machine, build_path):
	# Try to add Prefix, list, test error cases, delete prefix and list again
	expected_str = ul_short_src
	add_pfx_test = build_path+"/test/dp_grpc_client --addlbpfx " + vm2_name + " --ipv4 " + pfx_ip + " --length 32"
	eval_cmd_output(add_pfx_test, expected_str)

	expected_str = pfx_ip
	list_pfx_test = build_path+"/test/dp_grpc_client --listlbpfx " + vm2_name
	eval_cmd_output(list_pfx_test, expected_str)

	# Try to add/delete to/from a machine which doesnt exist
	expected_str = "651"
	add_pfx_test = build_path+"/test/dp_grpc_client --addlbpfx " + vm3_name + " --ipv4 " + pfx_ip + " --length 32"
	eval_cmd_output(add_pfx_test, expected_str)

	expected_str = "701"
	del_pfx_test = build_path+"/test/dp_grpc_client --dellbpfx " + vm3_name + " --ipv4 " + pfx_ip + " --length 32"
	eval_cmd_output(del_pfx_test, expected_str)

	expected_str = "DelLBprefix"
	del_pfx_test = build_path+"/test/dp_grpc_client --dellbpfx " + vm2_name + " --ipv4 " + pfx_ip + " --length 32"
	eval_cmd_output(del_pfx_test, expected_str)

	expected_str = pfx_ip
	list_pfx_test = build_path+"/test/dp_grpc_client --listpfx " + vm2_name
	eval_cmd_output(list_pfx_test, expected_str, negate=True)

# def test_grpc_add_list_del_routes_big_reply(capsys, add_machine, build_path):
# 	expected_str = "Listroute called"
# 	pfx_first = "192.168."
# 	pfx_second = 29
# 	max_lines = MAX_LINES_ROUTE_REPLY + 2 + 1
# 	for idx in range(MAX_LINES_ROUTE_REPLY):
# 		pfx_second = pfx_second + 1
# 		ov_target_pfx = pfx_first + str(pfx_second) + ".0"
# 		add_ipv4_route_cmd = build_path+"/test/dp_grpc_client --addroute --vni " + vni + " --ipv4 " + ov_target_pfx + " --length 32 --t_vni " + t_vni + " --t_ipv6 " + ul_actual_dst
# 		subprocess.run(shlex.split(add_ipv4_route_cmd), stdout=subprocess.DEVNULL)
# 	list_route_test = build_path + "/test/dp_grpc_client --listroutes --vni " + vni
# 	#TODO this test case is not complete and needs to handle more than 38 lines
# 	eval_cmd_output(list_route_test, expected_str, maxlines=max_lines)
# 	pfx_first = "192.168."
# 	pfx_second = 29
# 	for idx in range(MAX_LINES_ROUTE_REPLY):
# 		pfx_second = pfx_second + 1
# 		ov_target_pfx = pfx_first + str(pfx_second) + ".0"
# 		del_route_test = build_path+"/test/dp_grpc_client --delroute --vni " + vni + " --ipv4 " + ov_target_pfx + " --length 32"
#		subprocess.run(shlex.split(del_route_test), stdout=subprocess.DEVNULL)
