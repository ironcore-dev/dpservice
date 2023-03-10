from helpers import *


def test_grpc_addmachine_error_109(prepare_ifaces, grpc_client):
	# Try to add using an existing vm identifier
	grpc_client.assert_output(f"--addmachine {VM2.name} --vm_pci {VM2.pci} --vni {VM2.vni} --ipv4 {VM2.ip} --ipv6 {VM2.ipv6}",
		"error 109")

def test_grpc_addmachine_error_110(prepare_ifaces, grpc_client):
	# Try to add without specifying PCI address or using a bad one
	grpc_client.assert_output(f"--addmachine new_vm --vni {VM2.vni} --ipv4 {VM2.ip} --ipv6 {VM2.ipv6}",
		"error 110")
	grpc_client.assert_output(f"--addmachine new_vm --vm_pci invalid --vni {VM2.vni} --ipv4 {VM2.ip} --ipv6 {VM2.ipv6}",
		"error 110")

def test_grpc_getmachine_single(prepare_ifaces, grpc_client):
	# Try to get a single existing interface(machine)
	grpc_client.assert_output(f"--getmachine {VM2.name}",
		VM2.ip)

def test_grpc_addmachine_error_106(prepare_ifaces, grpc_client):
	# Try to add with new machine identifer but already given IPv4
	grpc_client.assert_output(f"--addmachine {VM4.name} --vm_pci {VM4.pci} --vni {VM4.vni} --ipv4 {VM1.ip} --ipv6 {VM1.ipv6}",
		"error 106")

def test_grpc_delmachine_error_151(prepare_ifaces, grpc_client):
	# Try to delete with machine identifer which doesnt exist
	grpc_client.assert_output(f"--delmachine invalid_name",
		"error 151")

def test_grpc_add_list_delmachine(prepare_ifaces, grpc_client):
	# Try to add a new machine, list it, delete it and confirm the deletion with list again
	grpc_client.addmachine(VM4.name, VM4.pci, VM4.vni, VM4.ip, VM4.ipv6)
	grpc_client.assert_output(f"--getmachines",
		VM4.name)
	grpc_client.delmachine(VM4.name)
	grpc_client.assert_output(f"--getmachines",
		VM4.name, negate=True)

def test_grpc_addroute_error_251(prepare_ifaces, grpc_client):
	# Try to add a route which is already added
	# NOTE this has to be based on the one in DpService::init_ifaces()
	grpc_client.assert_output(f"--addroute --vni {vni1} --ipv4 {neigh_vni1_ov_ip_range} --length {neigh_vni1_ov_ip_range_len} --t_vni {vni1} --t_ipv6 {neigh_vni1_ul_ipv6}",
		"error 251")

def test_grpc_list_delroutes(prepare_ifaces, grpc_client):
	# Try to list routes, delete one of them, list and add again
	grpc_client.assert_output(f"--listroutes --vni {vni1}",
		neigh_vni1_ov_ip_range)
	# NOTE this has to be the one in DpService::init_ifaces()
	grpc_client.delroute_ipv4(vni1, neigh_vni1_ov_ip_range, neigh_vni1_ov_ip_range_len)
	grpc_client.assert_output(f"--listroutes --vni {vni1}",
		neigh_vni1_ov_ip_range, negate=True)
	# NOTE this has to be the same as the one in DpService::init_ifaces()
	grpc_client.addroute_ipv4(vni1, neigh_vni1_ov_ip_range, neigh_vni1_ov_ip_range_len, t_vni, neigh_vni1_ul_ipv6)

def test_grpc_add_list_delVIP(prepare_ifaces, grpc_client):
	# Try to add VIP, list, test error cases, delete vip and list again
	ul_ipv6 = grpc_client.addvip(VM2.name, vip_vip)
	grpc_client.assert_output(f"--getvip {VM2.name}",
		f"Received VIP {vip_vip} underlayroute {ul_ipv6}")
	# Try to add the same vip again
	grpc_client.assert_output(f"--addvip {VM2.name} --ipv4 {vip_vip}",
		"error 351")
	# Try to add to a machine which doesnt exist
	grpc_client.assert_output(f"--addvip invalid_name --ipv4 {vip_vip}",
		"error 350")
	grpc_client.delvip(VM2.name)
	grpc_client.assert_output(f"--getvip {VM2.name}",
		vip_vip, negate=True)

def test_grpc_add_list_delLBVIP(prepare_ifaces, grpc_client):
	# Try to add LB VIP, list, test error cases, delete vip and list again
	back_ip1 = "2a10:abc0:d015:4027:0:c8::"
	back_ip2 = "2a10:abc0:d015:4027:0:7b::"
	ul_ipv6 = grpc_client.createlb(lb_name, vni1, lb_ip, 80, "tcp")
	grpc_client.addlbvip(lb_name, back_ip1)
	grpc_client.assert_output(f"--listbackips {lb_name}",
		back_ip1)
	grpc_client.addlbvip(lb_name, back_ip2)
	grpc_client.assert_output(f"--listbackips {lb_name}",
		back_ip2)
	grpc_client.dellbvip(lb_name, back_ip1)
	grpc_client.assert_output(f"--listbackips {lb_name}",
		back_ip1, negate=True)
	grpc_client.dellbvip(lb_name, back_ip2)
	grpc_client.assert_output(f"--listbackips {lb_name}",
		back_ip2, negate=True)
	grpc_client.assert_output(f"--getlb {lb_name}",
		ul_ipv6)
	grpc_client.dellb(lb_name)
	grpc_client.assert_output(f"--getlb {lb_name}",
		ul_ipv6, negate=True)

def test_grpc_add_list_delPfx(prepare_ifaces, grpc_client):
	# Try to add Prefix, list, test error cases, delete prefix and list again
	ul_ipv6 = grpc_client.addpfx(VM2.name, pfx_ip, 24)
	grpc_client.assert_output(f"--listpfx {VM2.name}",
		f"Route prefix {pfx_ip} len 24 underlayroute {ul_ipv6}")
	# Try to add the same pfx again
	grpc_client.assert_output(f"--addpfx {VM2.name} --ipv4 {pfx_ip} --length 24",
		"error 652")
	# Try to add/delete to/from a machine which doesnt exist
	grpc_client.assert_output(f"--addpfx invalid_name --ipv4 {pfx_ip} --length 24",
		"error 651")
	grpc_client.assert_output(f"--delpfx invalid_name --ipv4 {pfx_ip} --length 24",
		"error 701")
	grpc_client.delpfx(VM2.name, pfx_ip, 24)
	grpc_client.assert_output(f"--listpfx {VM2.name}",
		pfx_ip, negate=True)

def test_grpc_add_list_delLoadBalancerTargets(prepare_ifaces, grpc_client):
	# Try to add Prefix, list, test error cases, delete prefix and list again
	ul_ipv6 = grpc_client.addlbpfx(VM2.name, pfx_ip)
	grpc_client.assert_output(f"--listlbpfx {VM2.name}",
		f"LB Route prefix {pfx_ip} len 32 underlayroute {ul_ipv6}")
	# Try to add/delete to/from a machine which doesnt exist
	grpc_client.assert_output(f"--addlbpfx invalid_name --ipv4 {pfx_ip} --length 32",
		"error 651")
	grpc_client.assert_output(f"--dellbpfx invalid_name --ipv4 {pfx_ip} --length 32",
		"error 701")
	grpc_client.dellbpfx(VM2.name, pfx_ip)
	grpc_client.assert_output(f"--listpfx {VM2.name}",
		pfx_ip, negate=True)

def test_grpc_add_list_del_routes_big_reply(prepare_ifaces, grpc_client):
	MAX_LINES_ROUTE_REPLY = 36
	for subnet in range(30, 30+MAX_LINES_ROUTE_REPLY):
		ov_target_pfx = f"192.168.{subnet}.0"
		grpc_client.addroute_ipv4(vni1, ov_target_pfx, 32, t_vni, neigh_vni1_ul_ipv6)

	listing = grpc_client.assert_output(f"--listroutes --vni {vni1}",
		"Listroute called")
	route_count = listing.count("Route prefix")
	# +1 for the one already there (from env setup)
	assert route_count == MAX_LINES_ROUTE_REPLY + 1, \
		f"Not all routes have been added ({route_count}/{MAX_LINES_ROUTE_REPLY+1})"

	for subnet in range(30, 30+MAX_LINES_ROUTE_REPLY):
		ov_target_pfx = f"192.168.{subnet}.0"
		grpc_client.delroute_ipv4(vni1, ov_target_pfx, 32)
