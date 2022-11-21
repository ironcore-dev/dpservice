from helpers import *


def test_grpc_addmachine_error_102(add_machine, grpc_client):
	# Try to add using an existing vm identifier
	grpc_client.assert_output(f"--addmachine {vm2_name} --vni {vni} --ipv4 {vf1_ip} --ipv6 {vf1_ipv6}",
		"error 102")

def test_grpc_getmachine_single(add_machine, grpc_client):
	# Try to get a single existing interface(machine)
	grpc_client.assert_output(f"--getmachine {vm2_name}",
		vf1_ip)

def test_grpc_addmachine_error_106(add_machine, grpc_client):
	# Try to add with new machine identifer but already given IPv4
	grpc_client.assert_output(f"--addmachine {vm3_name} --vni {vni} --ipv4 {vf1_ip} --ipv6 {vf1_ipv6}",
		"error 106")

def test_grpc_delmachine_error_151(add_machine, grpc_client):
	# Try to delete with machine identifer which doesnt exist
	grpc_client.assert_output(f"--delmachine {vm3_name}",
		"error 151")

def test_grpc_add_list_delmachine(add_machine, grpc_client):
	# Try to add a new machine, list it, delete it and confirm the deletion with list again
	grpc_client.assert_output(f"--addmachine {vm3_name} --vni {vni} --ipv4 {vf2_ip} --ipv6 {vf2_ipv6}",
		"net_tap4")
	grpc_client.assert_output(f"--getmachines",
		vm3_name)
	grpc_client.assert_output(f"--delmachine {vm3_name}",
		"Interface deleted")
	grpc_client.assert_output(f"--getmachines",
		vm3_name, negate=True)

def test_grpc_addroute_error_251(add_machine, grpc_client):
	# Try to add a route which is already added
	grpc_client.assert_output(f"--addroute --vni {vni} --ipv4 {ov_target_pfx} --length 24 --t_vni {vni} --t_ipv6 2a10:afc0:e01f:f408::1",
		"error 251")

def test_grpc_list_delroutes(add_machine, grpc_client):
	# Try to list routes, delete one of them, list and add again
	grpc_client.assert_output(f"--listroutes --vni {vni}",
		ov_target_pfx)
	grpc_client.assert_output(f"--delroute --vni {vni} --ipv4 {ov_target_pfx} --length 24",
		"Route deleted")
	grpc_client.assert_output(f"--listroutes --vni {vni}",
		ov_target_pfx, negate=True)
	grpc_client.assert_output(f"--addroute --vni {vni} --ipv4 {ov_target_pfx} --length 24 --t_vni {vni} --t_ipv6 2a10:afc0:e01f:f408::1",
		ov_target_pfx)

def test_grpc_add_list_delVIP(add_machine, grpc_client):
	# Try to add VIP, list, test error cases, delete vip and list again
	grpc_client.assert_output(f"--addvip {vm2_name} --ipv4 {virtual_ip}",
		ul_actual_src)
	grpc_client.assert_output(f"--getvip {vm2_name}",
		virtual_ip)
	# Try to add the same vip again
	grpc_client.assert_output(f"--addvip {vm2_name} --ipv4 {virtual_ip}",
		"error 351")
	# Try to add to a machine which doesnt exist
	grpc_client.assert_output(f"--addvip {vm3_name} --ipv4 {virtual_ip}",
		"error 350")
	grpc_client.assert_output(f"--delvip {vm2_name}",
		"VIP deleted")
	grpc_client.assert_output(f"--getvip {vm2_name}",
		virtual_ip, negate=True)

def test_grpc_add_list_delLBVIP(add_machine, grpc_client):
	# Try to add LB VIP, list, test error cases, delete vip and list again
	grpc_client.assert_output(f"--createlb {mylb} --vni {vni} --ipv4 {virtual_ip} --port 80 --protocol tcp",
		ul_actual_src)
	grpc_client.assert_output(f"--addlbvip {mylb} --t_ipv6 {back_ip1}",
		"LB VIP added")
	grpc_client.assert_output(f"--listbackips {mylb}",
		back_ip1)
	grpc_client.assert_output(f"--addlbvip {mylb} --t_ipv6 {back_ip2}",
		"LB VIP added")
	grpc_client.assert_output(f"--listbackips {mylb}",
		back_ip2)
	grpc_client.assert_output(f"--dellbvip {mylb} --t_ipv6 {back_ip1}",
		"LB VIP deleted")
	grpc_client.assert_output(f"--listbackips {mylb}",
		back_ip1, negate=True)
	grpc_client.assert_output(f"--dellbvip {mylb} --t_ipv6 {back_ip2}",
		"LB VIP deleted")
	grpc_client.assert_output(f"--listbackips {mylb}",
		back_ip2, negate=True)
	grpc_client.assert_output(f"--getlb {mylb}",
		ul_actual_src)
	grpc_client.assert_output(f"--dellb {mylb}",
		"LB deleted")
	grpc_client.assert_output(f"--getlb {mylb}",
		ul_actual_src, negate=True)

def test_grpc_add_list_delPfx(add_machine, grpc_client):
	# Try to add Prefix, list, test error cases, delete prefix and list again
	grpc_client.assert_output(f"--addpfx {vm2_name} --ipv4 {pfx_ip} --length 24",
		ul_actual_src)
	grpc_client.assert_output(f"--listpfx {vm2_name}",
		pfx_ip)
	# Try to add the same pfx again
	grpc_client.assert_output(f"--addpfx {vm2_name} --ipv4 {pfx_ip} --length 24",
		"error 652")
	# Try to add/delete to/from a machine which doesnt exist
	grpc_client.assert_output(f"--addpfx {vm3_name} --ipv4 {pfx_ip} --length 24",
		"error 651")
	grpc_client.assert_output(f"--delpfx {vm3_name} --ipv4 {pfx_ip} --length 24",
		"error 701")
	grpc_client.assert_output(f"--delpfx {vm2_name} --ipv4 {pfx_ip} --length 24",
		"Prefix deleted")
	grpc_client.assert_output(f"--listpfx {vm2_name}",
		pfx_ip, negate=True)

def test_grpc_add_list_delLoadBalancerTargets(add_machine, grpc_client):
	# Try to add Prefix, list, test error cases, delete prefix and list again
	grpc_client.assert_output(f"--addlbpfx {vm2_name} --ipv4 {pfx_ip} --length 32",
		ul_short_src)
	grpc_client.assert_output(f"--listlbpfx {vm2_name}",
		pfx_ip)
	# Try to add/delete to/from a machine which doesnt exist
	grpc_client.assert_output(f"--addlbpfx {vm3_name} --ipv4 {pfx_ip} --length 32",
		"error 651")
	grpc_client.assert_output(f"--dellbpfx {vm3_name} --ipv4 {pfx_ip} --length 32",
		"error 701")
	grpc_client.assert_output(f"--dellbpfx {vm2_name} --ipv4 {pfx_ip} --length 32",
		"LB prefix deleted")
	grpc_client.assert_output(f"--listpfx {vm2_name}",
		pfx_ip, negate=True)


def test_grpc_add_list_del_routes_big_reply(add_machine, grpc_client):
	for subnet in range(30, 30+MAX_LINES_ROUTE_REPLY):
		ov_target_pfx = f"192.168.{subnet}.0"
		grpc_client.assert_output(f"--addroute --vni {vni} --ipv4 {ov_target_pfx} --length 32 --t_vni {t_vni} --t_ipv6 {ul_actual_dst}",
			ov_target_pfx)

	listing = grpc_client.assert_output(f"--listroutes --vni {vni}",
		"Listroute called")
	assert listing.count("Route prefix") == MAX_LINES_ROUTE_REPLY + 1  # +1 for the one already there

	for subnet in range(30, 30+MAX_LINES_ROUTE_REPLY):
		ov_target_pfx = f"192.168.{subnet}.0"
		grpc_client.assert_output(f"--delroute --vni {vni} --ipv4 {ov_target_pfx} --length 32",
			"Route deleted")
