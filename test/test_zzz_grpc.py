# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

from helpers import *
import pytest

def test_grpc_addinterface_already_exists(prepare_ifaces, grpc_client):
	# Try to add using an existing vm identifier
	grpc_client.expect_error(202).addinterface(VM2.name, VM2.pci, VM2.vni, VM2.ip, VM2.ipv6)

def test_grpc_addinterface_bad_interface(prepare_ifaces, grpc_client):
	# Try to add without specifying PCI address or using a bad one
	grpc_client.expect_error(201).addinterface("new_vm", "invalid", VM2.vni, VM2.ip, VM2.ipv6)
	# Try to add with zero IPs (actually an input error, not a request error)
	grpc_client.expect_failure().addinterface(VM4.name, VM4.pci, VM4.vni, "0.0.0.0", "::")

def test_grpc_getmachine_single(prepare_ifaces, grpc_client):
	# Try to get a single existing interface(machine)
	myspec = { "vni": VM2.vni, "device": VM2.pci, "primary_ipv4": VM2.ip, "primary_ipv6": VM2.ipv6, "underlay_route": VM2.ul_ipv6, "metering": {} }
	spec = grpc_client.getinterface(VM2.name)
	assert spec == myspec, \
		f"Invalid getmachine output for {VM2.name}"

def test_grpc_addinterface_route_exists(prepare_ifaces, grpc_client):
	# Try to add with new machine identifer but already given IPv4
	grpc_client.expect_error(301).addinterface(VM4.name, VM4.pci, VM4.vni, VM1.ip, VM1.ipv6)

def test_grpc_delinterface_not_found(prepare_ifaces, grpc_client):
	# Try to delete with machine identifer which doesnt exist
	grpc_client.expect_error(201).delinterface("invalid_name")

def test_grpc_add_list_delinterface(prepare_ifaces, grpc_client):
	# Try to add a new machine, list it, delete it and confirm the deletion with list again
	vm4_ul_ipv6 = grpc_client.addinterface(VM4.name, VM4.pci, VM4.vni, VM4.ip, VM4.ipv6)
	myspec = { "vni": VM4.vni, "device": VM4.pci, "primary_ipv4": VM4.ip, "primary_ipv6": VM4.ipv6, "underlay_route": vm4_ul_ipv6, "metering": {} }
	specs = grpc_client.listinterfaces()
	assert myspec in specs, \
		f"Interface {VM4.name} not properly added"
	grpc_client.delinterface(VM4.name)
	specs = grpc_client.listinterfaces()
	assert myspec not in specs, \
		f"Interface {VM4.name} not properly deleted"

def test_grpc_addroute_route_exists(prepare_ifaces, grpc_client):
	# Try to add a route which is already added
	# NOTE this has to be based on the one in DpService::init_ifaces()
	grpc_client.expect_error(301).addroute(vni1, neigh_vni1_ov_ip_route, vni1, neigh_vni1_ul_ipv6)

def test_grpc_list_delroutes(prepare_ifaces, grpc_client):
	# Try to list routes, delete one of them, list and add again
	# NOTE this route has to be the one in DpService::init_ifaces()
	routespec = { "prefix": neigh_vni1_ov_ip_route, "next_hop": { "address": neigh_vni1_ul_ipv6, "vni": 0 } }
	routes = grpc_client.listroutes(vni1)
	assert routespec in routes, \
		"List of routes does not contain an initial route"
	grpc_client.delroute(vni1, neigh_vni1_ov_ip_route)
	routes = grpc_client.listroutes(vni1)
	assert routespec not in routes, \
		"List of routes does not contain an initial route"
	grpc_client.addroute(vni1, neigh_vni1_ov_ip_route, 0, neigh_vni1_ul_ipv6)

def test_grpc_add_NAT_and_VIP_same_IP(prepare_ifaces, grpc_client):
	# Try to add NAT, delete and add VIP with same IP
	nat_ul_ipv6 = grpc_client.addnat(VM2.name, vip_vip, nat_local_min_port, nat_local_max_port)
	natspec = { "nat_ip": vip_vip, "min_port": nat_local_min_port, "max_port": nat_local_max_port, "underlay_route": nat_ul_ipv6, "vni": 0 }
	spec = grpc_client.getnat(VM2.name)
	assert spec == natspec, \
		"NAT not added properly"
	grpc_client.delnat(VM2.name)

	vip_ul_ipv6 = grpc_client.addvip(VM2.name, vip_vip)
	vipspec = { "vip_ip": vip_vip, "underlay_route": vip_ul_ipv6}
	spec = grpc_client.getvip(VM2.name)
	assert spec == vipspec, \
		"VIP not set properly"
	grpc_client.delvip(VM2.name)
	grpc_client.expect_error(341).getvip(VM2.name)
	grpc_client.expect_error(341).getnat(VM2.name)

def test_grpc_add_list_delVIP(prepare_ifaces, grpc_client):
	# Try to add VIP, list, test error cases, delete vip and list again
	ul_ipv6 = grpc_client.addvip(VM2.name, vip_vip)
	vipspec = { "vip_ip": vip_vip, "underlay_route": ul_ipv6}
	spec = grpc_client.getvip(VM2.name)
	assert spec == vipspec, \
		"VIP not set properly"
	# Try to add the same vip again
	grpc_client.expect_error(343).addvip(VM2.name, vip_vip)
	# Try to add to a machine which doesnt exist
	grpc_client.expect_error(205).addvip("invalid_name", vip_vip)
	grpc_client.delvip(VM2.name)
	grpc_client.expect_error(341).getvip(VM2.name)

def test_grpc_add_list_delLBVIP(prepare_ifaces, grpc_client):
	back_ip1 = "2a10:abc0:d015:4027:0:c8::"
	back_ip2 = "2a10:abc0:d015:4027:0:7b::"
	# Try to add LB VIP, list, test error cases, delete vip and list again
	ul_ipv6 = grpc_client.createlb(lb_name, vni1, lb_ip, "tcp/80")
	lbspec = { "vni": vni1, "loadbalanced_ip": lb_ip, "loadbalanced_ports": [ { "protocol": 6, "port": 80 } ], "underlay_route": ul_ipv6 }
	spec = grpc_client.getlb(lb_name)
	assert spec == lbspec, \
		"Loadbalancer not created properly"

	spec1 = { "target_ip": back_ip1 }
	spec2 = { "target_ip": back_ip2 }
	grpc_client.addlbtarget(lb_name, back_ip1)
	specs = grpc_client.listlbtargets(lb_name)
	assert spec1 in specs, \
		f"Target {back_ip1} not added properly"
	grpc_client.addlbtarget(lb_name, back_ip2)
	specs = grpc_client.listlbtargets(lb_name)
	assert spec2 in specs, \
		f"Target {back_ip2} not added properly"
	grpc_client.dellbtarget(lb_name, back_ip1)
	specs = grpc_client.listlbtargets(lb_name)
	assert spec1 not in specs and spec2 in specs, \
		f"Target {back_ip1} not removed properly"
	grpc_client.dellbtarget(lb_name, back_ip2)
	specs = grpc_client.listlbtargets(lb_name)
	assert spec2 not in specs, \
		f"Target {back_ip2} not removed properly"

	grpc_client.dellb(lb_name)
	grpc_client.expect_error(201).getlb(lb_name)

def test_grpc_add_list_delPfx(prepare_ifaces, grpc_client):
	# Try to add Prefix, list, test error cases, delete prefix and list again
	prefix = f"{pfx_ip}/24"
	ul_ipv6 = grpc_client.addprefix(VM2.name, prefix)
	myspec = { "prefix": prefix, "underlay_route": ul_ipv6 }
	specs = grpc_client.listprefixes(VM2.name)
	assert myspec in specs, \
		f"Prefix {prefix} not added properly"
	# Try to add the same pfx again
	grpc_client.expect_error(301).addprefix(VM2.name, prefix)
	# Try to add/delete to/from a machine which doesnt exist
	grpc_client.expect_error(205).addprefix("invalid_name", prefix)
	grpc_client.expect_error(205).delprefix("invalid_name", prefix)
	grpc_client.delprefix(VM2.name, prefix)
	specs = grpc_client.listprefixes(VM2.name)
	assert myspec not in specs, \
		f"Prefix {prefix} not deleted properly"

def test_grpc_add_list_delPfx_ipv6(prepare_ifaces, grpc_client):
	# Try to add Prefix, list, test error cases, delete prefix and list again
	prefix = f"{pfx_ip6}/124"
	ul_ipv6 = grpc_client.addprefix(VM2.name, prefix)
	myspec = { "prefix": prefix, "underlay_route": ul_ipv6 }
	specs = grpc_client.listprefixes(VM2.name)
	assert myspec in specs, \
		f"Prefix {prefix} not added properly"
	# Try to add the same pfx again
	grpc_client.expect_error(301).addprefix(VM2.name, prefix)
	# Try to add/delete to/from a machine which doesnt exist
	grpc_client.expect_error(205).addprefix("invalid_name", prefix)
	grpc_client.expect_error(205).delprefix("invalid_name", prefix)
	grpc_client.delprefix(VM2.name, prefix)
	specs = grpc_client.listprefixes(VM2.name)
	assert myspec not in specs, \
		f"Prefix {prefix} not deleted properly"

def test_grpc_add_list_delLoadBalancerTargets(prepare_ifaces, grpc_client):
	# Try to add Prefix, list, test error cases, delete prefix and list again
	ul_ipv6 = grpc_client.addlbprefix(VM2.name, lb_pfx)
	myspec = { "prefix": lb_pfx, "underlay_route": ul_ipv6 }
	specs = grpc_client.listlbprefixes(VM2.name)
	assert myspec in specs, \
		f"Loadbalancer prefix {lb_pfx} not added properly"
	# Try to add/delete to/from a machine which doesnt exist
	grpc_client.expect_error(205).addlbprefix("invalid_name", lb_pfx)
	grpc_client.expect_error(205).dellbprefix("invalid_name", lb_pfx)
	grpc_client.dellbprefix(VM2.name, lb_pfx)
	specs = grpc_client.listlbprefixes(VM2.name)
	assert myspec not in specs, \
		f"Loadbalancer prefix {lb_pfx} not deleted properly"

def test_grpc_add_list_delLoadBalancerTargets_ipv6(prepare_ifaces, grpc_client):
	# Try to add Prefix, list, test error cases, delete prefix and list again
	ul_ipv6 = grpc_client.addlbprefix(VM2.name, lb_ip6_pfx)
	myspec = { "prefix": lb_ip6_pfx, "underlay_route": ul_ipv6 }
	specs = grpc_client.listlbprefixes(VM2.name)
	assert myspec in specs, \
		f"Loadbalancer prefix {lb_ip6_pfx} not added properly"
	# Try to add/delete to/from a machine which doesnt exist
	grpc_client.expect_error(205).addlbprefix("invalid_name", lb_ip6_pfx)
	grpc_client.expect_error(205).dellbprefix("invalid_name", lb_ip6_pfx)
	grpc_client.dellbprefix(VM2.name, lb_ip6_pfx)
	specs = grpc_client.listlbprefixes(VM2.name)
	assert myspec not in specs, \
		f"Loadbalancer prefix {lb_ip6_pfx} not deleted properly"

def test_grpc_add_list_delFirewallRules(prepare_ifaces, grpc_client):
	# Try to add FirewallRule, get, list, delete and test error cases

	# We do not support "drop" rules (yet)
	grpc_client.expect_error(441).addfwallrule(VM3.name, "fw0-vm3", src_prefix="1.2.3.4/16", proto="tcp", action="drop")
	grpc_client.addfwallrule(VM3.name, "fw0-vm3", src_prefix="1.2.3.4/16", proto="tcp")
	# Used rule-id
	grpc_client.expect_error(202).addfwallrule(VM3.name, "fw0-vm3", src_prefix="1.2.3.4/16", proto="tcp", action="drop")

	rulespec = { "id": "fw0-vm3",
				 "direction": "Ingress", "action": "Accept", "priority": 1000,
				 "source_prefix": "1.2.3.4/16", "destination_prefix": "0.0.0.0/0",
				 "protocol_filter": { "Filter": { "Tcp": {
					 "src_port_lower": -1, "src_port_upper": -1, "dst_port_lower": -1, "dst_port_upper": -1
				 } } } }
	spec = grpc_client.getfwallrule(VM3.name, "fw0-vm3")
	assert spec == rulespec, \
		"Firewall rule corruption"

	grpc_client.addfwallrule(VM3.name, "fw1-vm3", src_prefix="8.8.8.8/16", proto="udp", direction="egress")
	spec = grpc_client.getfwallrule(VM3.name, "fw1-vm3")
	assert spec['direction'] == "Egress", \
		"Failed to add egress rule"

	specs = grpc_client.listfwallrules(VM3.name)
	assert rulespec in specs, \
		"Firewall rule list corruption"
	grpc_client.delfwallrule(VM3.name, "fw0-vm3")
	grpc_client.expect_error(201).getfwallrule(VM3.name, "fw0-vm3")
	specs = grpc_client.listfwallrules(VM3.name)
	assert rulespec not in specs, \
		"Firewall rule deletion failed corruption"
	# The other must still remain
	assert len(specs) == 1 and specs[0]['source_prefix'] == '8.8.8.8/16', \
		"Firewall rule list corruption"

	grpc_client.delfwallrule(VM3.name, "fw1-vm3")
	grpc_client.expect_error(201).getfwallrule(VM3.name, "fw1-vm3")
	specs = grpc_client.listfwallrules(VM3.name)
	assert len(specs) == 0, \
		"Firewall rules not properly deleted"


def test_grpc_add_list_del_routes_big_reply(prepare_ifaces, grpc_client):
	MAX_LINES_ROUTE_REPLY = 36
	for subnet in range(30, 30+MAX_LINES_ROUTE_REPLY):
		ov_target_pfx = f"192.168.{subnet}.0/32"
		grpc_client.addroute(vni1, ov_target_pfx, 0, neigh_vni1_ul_ipv6)

	specs = grpc_client.listroutes(vni1)
	# +2 for the ones already there (from env setup)
	assert len(specs) == MAX_LINES_ROUTE_REPLY + 2, \
		f"Not all routes have been added ({len(specs)}/{MAX_LINES_ROUTE_REPLY+2})"

	for subnet in range(30, 30+MAX_LINES_ROUTE_REPLY):
		ov_target_pfx = f"192.168.{subnet}.0/32"
		grpc_client.delroute(vni1, ov_target_pfx)
