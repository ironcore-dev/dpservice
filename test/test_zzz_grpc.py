from helpers import *


def test_grpc_addmachine_error_109(prepare_ifaces, grpc_client):
	# Try to add using an existing vm identifier
	grpc_client.assert_output(f"--addmachine {vm2_name} --vm_pci net_tap3 --vni {vni} --ipv4 {vf1_ip} --ipv6 {vf1_ipv6}",
		"error 109")

def test_grpc_addmachine_error_110(prepare_ifaces, grpc_client):
	# Try to add without specifying PCI address
	grpc_client.assert_output(f"--addmachine {vm3_name} --vni {vni} --ipv4 {vf1_ip} --ipv6 {vf1_ipv6}",
		"error 110")

def test_grpc_getmachine_single(prepare_ifaces, grpc_client):
	# Try to get a single existing interface(machine)
	grpc_client.assert_output(f"--getmachine {vm2_name}",
		vf1_ip)

def test_grpc_addmachine_error_106(prepare_ifaces, grpc_client):
	# Try to add with new machine identifer but already given IPv4
	grpc_client.assert_output(f"--addmachine {vm3_name} --vm_pci net_tap4 --vni {vni} --ipv4 {vf1_ip} --ipv6 {vf1_ipv6}",
		"error 106")

def test_grpc_delmachine_error_151(prepare_ifaces, grpc_client):
	# Try to delete with machine identifer which doesnt exist
	grpc_client.assert_output(f"--delmachine {vm3_name}",
		"error 151")

def test_grpc_add_list_delmachine(prepare_ifaces, grpc_client):
	# Try to add a new machine, list it, delete it and confirm the deletion with list again
	grpc_client.addmachine(vm3_name, "net_tap4", vni, vf2_ip, vf2_ipv6)
	grpc_client.assert_output(f"--getmachines",
		vm3_name)
	grpc_client.delmachine(vm3_name)
	grpc_client.assert_output(f"--getmachines",
		vm3_name, negate=True)

def test_grpc_addroute_error_251(prepare_ifaces, grpc_client):
	# Try to add a route which is already added
	grpc_client.assert_output(f"--addroute --vni {vni} --ipv4 {ov_target_pfx} --length 24 --t_vni {vni} --t_ipv6 2a10:afc0:e01f:f408::1",
		"error 251")

def test_grpc_list_delroutes(prepare_ifaces, grpc_client):
	# Try to list routes, delete one of them, list and add again
	grpc_client.assert_output(f"--listroutes --vni {vni}",
		ov_target_pfx)
	grpc_client.delroute_ipv4(vni, ov_target_pfx,  24)
	grpc_client.assert_output(f"--listroutes --vni {vni}",
		ov_target_pfx, negate=True)
	# NOTE this has to be the same as the one in DpService::init_ifaces()
	grpc_client.addroute_ipv4(vni, ov_target_pfx, 24, t_vni, ul_actual_dst)

def test_grpc_add_list_delVIP(prepare_ifaces, grpc_client):
	# Try to add VIP, list, test error cases, delete vip and list again
	ul_ipv6 = grpc_client.addvip(vm2_name, virtual_ip)
	grpc_client.assert_output(f"--getvip {vm2_name}",
		f"Received VIP {virtual_ip} underlayroute {ul_ipv6}")
	# Try to add the same vip again
	grpc_client.assert_output(f"--addvip {vm2_name} --ipv4 {virtual_ip}",
		"error 351")
	# Try to add to a machine which doesnt exist
	grpc_client.assert_output(f"--addvip {vm3_name} --ipv4 {virtual_ip}",
		"error 350")
	grpc_client.delvip(vm2_name)
	grpc_client.assert_output(f"--getvip {vm2_name}",
		virtual_ip, negate=True)

def test_grpc_add_list_delLBVIP(prepare_ifaces, grpc_client):
	# Try to add LB VIP, list, test error cases, delete vip and list again
	ul_ipv6 = grpc_client.createlb(mylb, vni, virtual_ip, 80, "tcp")
	grpc_client.addlbvip(mylb, back_ip1)
	grpc_client.assert_output(f"--listbackips {mylb}",
		back_ip1)
	grpc_client.addlbvip(mylb, back_ip2)
	grpc_client.assert_output(f"--listbackips {mylb}",
		back_ip2)
	grpc_client.dellbvip(mylb, back_ip1)
	grpc_client.assert_output(f"--listbackips {mylb}",
		back_ip1, negate=True)
	grpc_client.dellbvip(mylb, back_ip2)
	grpc_client.assert_output(f"--listbackips {mylb}",
		back_ip2, negate=True)
	grpc_client.assert_output(f"--getlb {mylb}",
		ul_ipv6)
	grpc_client.dellb(mylb)
	grpc_client.assert_output(f"--getlb {mylb}",
		ul_ipv6, negate=True)

def test_grpc_add_list_delPfx(prepare_ifaces, grpc_client):
	# Try to add Prefix, list, test error cases, delete prefix and list again
	ul_ipv6 = grpc_client.addpfx(vm2_name, pfx_ip, 24)
	grpc_client.assert_output(f"--listpfx {vm2_name}",
		f"Route prefix {pfx_ip} len 24 underlayroute {ul_ipv6}")
	# Try to add the same pfx again
	grpc_client.assert_output(f"--addpfx {vm2_name} --ipv4 {pfx_ip} --length 24",
		"error 652")
	# Try to add/delete to/from a machine which doesnt exist
	grpc_client.assert_output(f"--addpfx {vm3_name} --ipv4 {pfx_ip} --length 24",
		"error 651")
	grpc_client.assert_output(f"--delpfx {vm3_name} --ipv4 {pfx_ip} --length 24",
		"error 701")
	grpc_client.delpfx(vm2_name, pfx_ip, 24)
	grpc_client.assert_output(f"--listpfx {vm2_name}",
		pfx_ip, negate=True)

def test_grpc_add_list_delLoadBalancerTargets(prepare_ifaces, grpc_client):
	# Try to add Prefix, list, test error cases, delete prefix and list again
	ul_ipv6 = grpc_client.addlbpfx(vm2_name, pfx_ip)
	grpc_client.assert_output(f"--listlbpfx {vm2_name}",
		f"LB Route prefix {pfx_ip} len 32 underlayroute {ul_ipv6}")
	# Try to add/delete to/from a machine which doesnt exist
	grpc_client.assert_output(f"--addlbpfx {vm3_name} --ipv4 {pfx_ip} --length 32",
		"error 651")
	grpc_client.assert_output(f"--dellbpfx {vm3_name} --ipv4 {pfx_ip} --length 32",
		"error 701")
	grpc_client.dellbpfx(vm2_name, pfx_ip)
	grpc_client.assert_output(f"--listpfx {vm2_name}",
		pfx_ip, negate=True)

def test_grpc_add_list_del_routes_big_reply(prepare_ifaces, grpc_client):
	for subnet in range(30, 30+MAX_LINES_ROUTE_REPLY):
		ov_target_pfx = f"192.168.{subnet}.0"
		grpc_client.addroute_ipv4(vni, ov_target_pfx, 32, t_vni, ul_actual_dst)

	listing = grpc_client.assert_output(f"--listroutes --vni {vni}",
		"Listroute called")
	route_count = listing.count("Route prefix")
	# +1 for the one already there (from env setup)
	assert route_count == MAX_LINES_ROUTE_REPLY + 1, \
		f"Not all routes have been added ({route_count}/{MAX_LINES_ROUTE_REPLY+1})"

	for subnet in range(30, 30+MAX_LINES_ROUTE_REPLY):
		ov_target_pfx = f"192.168.{subnet}.0"
		grpc_client.delroute_ipv4(vni, ov_target_pfx, 32)
