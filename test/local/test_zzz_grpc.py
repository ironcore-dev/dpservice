# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

from helpers import *
import pytest


def test_grpc_init(prepare_ifaces, grpc_client):
	# Already initialized
	grpc_client.expect_failure().init()

def test_grpc_getinit(prepare_ifaces, grpc_client, request):
	if request.config.getoption("--attach"):
		pytest.skip("gRPC GetInit not available when attaching to an already running service")
	spec = grpc_client.getinit()
	assert spec['uuid'] == grpc_client.uuid, \
		f"UUID mismatch: {spec['uuid']} (get init) vs. {grpc_client.uuid} (init)"

def test_grpc_getver(prepare_ifaces, grpc_client):
	spec = grpc_client.getversion()
	# Nothing good to test against atm.
	assert spec['service_protocol'] == spec['service_version'], \
		f"Service version mismatch"

#
# Following tests try to use the same pattern:
# 1. Create the object
# 2. Test listing/getting it back
# 3. Try creating it again (should fail)
# 4. Delete the object
# 5. Test listing/getting it back (should fail)
# 6. Delete it again (should fail)
# 7. Re-create and delete for a second time (to test residual conflicts)
#
# *_list tests try additional testing for list consistency:
# 1. Add two objects
# 2. Remove one of them
# 3. Verify the other is still present
# 4. Remove the other one
#

def test_grpc_interface(prepare_ifaces, grpc_client):
	vm4_ul_ipv6 = grpc_client.addinterface(VM4.name, VM4.pci, VM4.vni, VM4.ip, VM4.ipv6)
	vmspec = { "vni": VM4.vni, "device": VM4.pci, "primary_ipv4": VM4.ip, "primary_ipv6": VM4.ipv6, "underlay_route": vm4_ul_ipv6, "metering": {} }
	spec = grpc_client.getinterface(VM4.name)
	assert spec == vmspec, \
		"Interface not properly added"
	grpc_client.expect_error(202).addinterface(VM4.name, VM4.pci, VM4.vni, VM4.ip, VM4.ipv6)
	grpc_client.delinterface(VM4.name)
	grpc_client.expect_error(201).getinterface(VM4.name)
	grpc_client.expect_error(201).delinterface(VM4.name)
	grpc_client.addinterface(VM4.name, VM4.pci, VM4.vni, VM4.ip, VM4.ipv6)
	grpc_client.delinterface(VM4.name)

def test_grpc_interface_list(prepare_ifaces, grpc_client):
	old_list = grpc_client.listinterfaces()
	grpc_client.addinterface(VM4.name, VM4.pci, VM4.vni, VM4.ip, VM4.ipv6)
	spec = grpc_client.getinterface(VM4.name)
	new_list = grpc_client.listinterfaces()
	assert new_list == [ *old_list, spec ], \
		"Interface not properly added to a list"
	grpc_client.delinterface(VM4.name)
	new_list = grpc_client.listinterfaces()
	assert new_list == old_list, \
		"Interface nor properly removed from a list"

def test_grpc_interface_errors(prepare_ifaces, grpc_client):
	# Try to add with invalid PCI address
	grpc_client.expect_error(201).addinterface(VM4.name, "invalid", VM4.vni, VM4.ip, VM4.ipv6)
	# Try to add with zero IPs (actually an input error, not a request error)
	grpc_client.expect_failure().addinterface(VM4.name, VM4.pci, VM4.vni, "0.0.0.0", "::")
	# Try to add with new machine identifer but already given IP
	grpc_client.expect_error(301).addinterface(VM4.name, VM4.pci, VM4.vni, "1.2.3.4", VM1.ipv6)
	grpc_client.expect_error(301).addinterface(VM4.name, VM4.pci, VM4.vni, VM1.ip, "1234::")
	# Also test proper rollback of the above
	grpc_client.addinterface(VM4.name, VM4.pci, VM4.vni, "1.2.3.4", "1234::")
	grpc_client.delinterface(VM4.name)
	# Use the same address as VM1 but a different VNI
	grpc_client.addinterface(VM4.name, VM4.pci, VM1.vni+1, VM1.ip, VM1.ipv6)
	grpc_client.delinterface(VM4.name)


def test_grpc_route(prepare_ifaces, grpc_client):
	grpc_client.addinterface(VM4.name, VM4.pci, 999, VM4.ip, VM4.ipv6)
	grpc_client.addroute(999, "1.2.3.4/24", vni1, neigh_vni1_ul_ipv6)
	grpc_client.expect_error(301).addroute(999, "1.2.3.4/24", vni1, neigh_vni1_ul_ipv6)
	grpc_client.delroute(999, "1.2.3.4/24")
	grpc_client.expect_error(302).delroute(999, "1.2.3.4/24")
	grpc_client.addroute(999, "1.2.3.4/24", vni1, neigh_vni1_ul_ipv6)
	grpc_client.delroute(999, "1.2.3.4/24")
	grpc_client.delinterface(VM4.name)

def test_grpc_route_list(prepare_ifaces, grpc_client):
	# Use already pre-configured routes on VM1's VNI
	old_routes = grpc_client.listroutes(vni1)
	assert old_routes, \
		f"No routes in VNI {vni1}"
	routespec = old_routes[0]
	grpc_client.delroute(vni1, routespec['prefix'])
	routes = grpc_client.listroutes(vni1)
	assert [ routespec, *routes] == old_routes, \
		"Route not properly deleted"
	grpc_client.addroute(vni1, routespec['prefix'], routespec['next_hop']['vni'], routespec['next_hop']['address'])
	routes = grpc_client.listroutes(vni1)
	assert routes == old_routes, \
		"Route not properly added"

def test_grpc_route_errors(prepare_ifaces, grpc_client):
	# Try to address an invalid VNI
	grpc_client.expect_error(206).addroute(vni3, "0.0.0.0/0", 0, "1234::")
	grpc_client.expect_error(206).listroutes(vni3)
	grpc_client.expect_error(206).delroute(vni3, "0.0.0.0/0")
	# Use IPv4 underlay
	grpc_client.expect_error(204).addroute(vni1, "4.5.6.7/32", 0, "1.2.3.4")


def grpc_test_prefix(grpc_client, prefix):
	grpc_client.addprefix(VM1.name, prefix)
	grpc_client.expect_error(301).addprefix(VM1.name, prefix)
	grpc_client.delprefix(VM1.name, prefix)
	grpc_client.expect_error(302).delprefix(VM1.name, prefix)
	grpc_client.addprefix(VM1.name, prefix)
	grpc_client.delprefix(VM1.name, prefix)

def grpc_test_prefix_list(grpc_client, prefix1, prefix2):
	pfx1_ul = grpc_client.addprefix(VM1.name, prefix1)
	pfx2_ul = grpc_client.addprefix(VM1.name, prefix2)
	spec1 = { "prefix": prefix1, "underlay_route": pfx1_ul }
	spec2 = { "prefix": prefix2, "underlay_route": pfx2_ul }
	specs = grpc_client.listprefixes(VM1.name)
	assert specs == [ spec1, spec2 ], \
		"Prefixes not properly added to a list"
	grpc_client.delprefix(VM1.name, prefix1)
	specs = grpc_client.listprefixes(VM1.name)
	assert specs == [ spec2 ], \
		"Prefix not properly removed from a list"
	grpc_client.delprefix(VM1.name, prefix2)
	specs = grpc_client.listprefixes(VM1.name)
	assert specs == [], \
		"Prefixex not properly removed from a list"

def test_grpc_prefix(prepare_ifaces, grpc_client):
	grpc_test_prefix(grpc_client, f"1.2.3.0/24")
	grpc_test_prefix_list(grpc_client, f"1.2.3.0/24", f"1.2.4.0/24")

def test_grpc_prefix_ipv6(prepare_ifaces, grpc_client):
	grpc_test_prefix(grpc_client, f"1234::/64")
	grpc_test_prefix_list(grpc_client, f"1234:1::/64", f"1234:2::/64")

def test_grpc_prefix_errors(prepare_ifaces, grpc_client):
	# Try to address a machine which doesn't exist
	grpc_client.expect_error(205).addprefix("invalid_name", "1.2.3.4/24")
	grpc_client.expect_error(205).listprefixes("invalid_name")
	grpc_client.expect_error(205).delprefix("invalid_name", "1.2.3.4/24")


def test_grpc_vip(prepare_ifaces, grpc_client):
	ul_ipv6 = grpc_client.addvip(VM1.name, vip_vip)
	vipspec = { "vip_ip": vip_vip, "underlay_route": ul_ipv6}
	spec = grpc_client.getvip(VM1.name)
	assert spec == vipspec, \
		"VIP not set properly"
	grpc_client.expect_error(343).addvip(VM1.name, vip_vip)
	grpc_client.delvip(VM1.name)
	grpc_client.expect_error(341).getvip(VM1.name)
	grpc_client.expect_error(341).delvip(VM1.name)
	grpc_client.addvip(VM1.name, vip_vip)
	grpc_client.delvip(VM1.name)

def test_grpc_vip_errors(prepare_ifaces, grpc_client):
	# Try to add to address a machine which doesn't exist
	grpc_client.expect_error(205).addvip("invalid_name", vip_vip)
	grpc_client.expect_error(205).getvip("invalid_name")
	grpc_client.expect_error(205).delvip("invalid_name")
	# Use IPv6 VIP address
	grpc_client.expect_error(204).addvip(VM1.name, "1234::1")


def test_grpc_nat(prepare_ifaces, grpc_client):
	ul_ipv6 = grpc_client.addnat(VM1.name, nat_vip, nat_local_min_port, nat_local_max_port)
	natspec = { "nat_ip": nat_vip, "min_port": nat_local_min_port, "max_port": nat_local_max_port, "underlay_route": ul_ipv6, "vni": 0 }
	spec = grpc_client.getnat(VM1.name)
	assert spec == natspec, \
		"NAT not properly added"
	natspec = { "nat_ip": VM1.ip, "min_port": nat_local_min_port, "max_port": nat_local_max_port, "vni": VM1.vni }
	grpc_client.expect_error(343).addnat(VM1.name, nat_vip, nat_local_min_port, nat_local_max_port)
	grpc_client.delnat(VM1.name)
	grpc_client.expect_error(341).getnat(VM1.name)
	grpc_client.expect_error(341).delnat(VM1.name)
	grpc_client.addnat(VM1.name, nat_vip, nat_local_min_port, nat_local_max_port)
	grpc_client.delnat(VM1.name)

def test_grpc_nat_list(prepare_ifaces, grpc_client):
	grpc_client.addnat(VM1.name, nat_vip, nat_local_min_port, nat_local_max_port)
	grpc_client.addnat(VM2.name, nat_vip, nat_local_max_port, nat_local_max_port+1)
	# Local NAT list is not a list of NAT objects, need to create it manually
	nat1spec = { "nat_ip": VM1.ip, "min_port": nat_local_min_port, "max_port": nat_local_max_port, "vni": VM1.vni }
	nat2spec = { "nat_ip": VM2.ip, "min_port": nat_local_max_port, "max_port": nat_local_max_port+1, "vni": VM1.vni }
	specs = grpc_client.listlocalnats(nat_vip)
	# List order is apparently not the same as the order of operations
	assert specs == [ nat2spec, nat1spec ], \
		"Nats not properly added to a list"
	grpc_client.delnat(VM2.name)
	specs = grpc_client.listlocalnats(nat_vip)
	assert specs == [ nat1spec ], \
		"NAT not properly removed from a list"
	grpc_client.delnat(VM1.name)
	specs = grpc_client.listlocalnats(nat_vip)
	assert specs == [], \
		"NATs not properly removed from a list"

def test_grpc_nat_share(prepare_ifaces, grpc_client):
	# Test NAT with two machines, same IP
	grpc_client.addnat(VM1.name, nat_vip, nat_local_min_port, nat_local_max_port)
	# Overlapping port ranges are forbiden
	grpc_client.expect_error(343).addnat(VM1.name, nat_vip, nat_local_max_port, nat_local_max_port+1)
	grpc_client.addnat(VM2.name, nat_vip, nat_local_max_port, nat_local_max_port+1)
	grpc_client.delnat(VM2.name)
	grpc_client.delnat(VM1.name)

def test_grpc_nat_errors(prepare_ifaces, grpc_client):
	assert grpc_client.listlocalnats(nat_vip) == [], \
		"Listing of nonexistent NAT should be empty"
	# Try to add to address a machine which doesn't exist
	grpc_client.expect_error(205).addnat("invalid_name", nat_vip, nat_local_min_port, nat_local_max_port)
	grpc_client.expect_error(205).getnat("invalid_name")
	grpc_client.expect_error(205).delnat("invalid_name")
	# Use IPv6 NAT address
	grpc_client.expect_error(204).addnat(VM1.name, "1234::1", 1024, 2048)
	grpc_client.expect_error(204).listlocalnats("1234::1")

def test_grpc_nat_vip_same_ip(prepare_ifaces, grpc_client):
	# There was a problem with NAT and VIP sharing some data, thus not freeing up properly
	grpc_client.addnat(VM1.name, nat_vip, nat_local_min_port, nat_local_max_port)
	grpc_client.delnat(VM1.name)
	grpc_client.addvip(VM1.name, nat_vip)
	grpc_client.delvip(VM1.name)
	grpc_client.expect_error(341).getvip(VM1.name)
	grpc_client.expect_error(341).getnat(VM1.name)


def test_grpc_neighnat(prepare_ifaces, grpc_client):
	grpc_client.addneighnat(nat_vip, vni1, nat_neigh_min_port, nat_neigh_max_port, neigh_vni1_ul_ipv6)
	grpc_client.expect_error(202).addneighnat(nat_vip, vni1, nat_neigh_min_port, nat_neigh_max_port, neigh_vni1_ul_ipv6)
	grpc_client.delneighnat(nat_vip, vni1, nat_neigh_min_port, nat_neigh_max_port)
	grpc_client.expect_error(201).delneighnat(nat_vip, vni1, nat_neigh_min_port, nat_neigh_max_port)
	grpc_client.addneighnat(nat_vip, vni1, nat_neigh_min_port, nat_neigh_max_port, neigh_vni1_ul_ipv6)
	grpc_client.delneighnat(nat_vip, vni1, nat_neigh_min_port, nat_neigh_max_port)

def test_grpc_neighnat_list(prepare_ifaces, grpc_client):
	grpc_client.addneighnat(nat_vip, vni1, nat_neigh_min_port, nat_neigh_max_port, neigh_vni1_ul_ipv6)
	grpc_client.addneighnat(nat_vip, vni1, nat_neigh_max_port, nat_neigh_max_port+1, neigh_vni1_ul_ipv6)
	# Neighbor NAT list is not a list of NAT objects, need to create it manually
	neigh1spec = { "min_port": nat_neigh_min_port, "max_port": nat_neigh_max_port, "underlay_route": neigh_vni1_ul_ipv6, "vni": vni1 }
	neigh2spec = { "min_port": nat_neigh_max_port, "max_port": nat_neigh_max_port+1, "underlay_route": neigh_vni1_ul_ipv6, "vni": vni1 }
	specs = grpc_client.listneighnats(nat_vip)
	assert specs == [ neigh1spec, neigh2spec ], \
		"Neighboring NATs not properly added to a list"
	grpc_client.delneighnat(nat_vip, vni1, nat_neigh_min_port, nat_neigh_max_port)
	specs = grpc_client.listneighnats(nat_vip)
	assert specs == [ neigh2spec ], \
		"Neighboring NAT not properly removed from a list"
	grpc_client.delneighnat(nat_vip, vni1, nat_neigh_max_port, nat_neigh_max_port+1)
	specs = grpc_client.listneighnats(nat_vip)
	assert specs == [], \
		"Neighboring NATs not properly removed from a list"

def test_grpc_neighnat_errors(prepare_ifaces, grpc_client):
	assert len(grpc_client.listneighnats(nat_vip)) == 0, \
		"Neighbor listing of nonexistent NAT should be empty"
	grpc_client.addneighnat(nat_vip, vni1, nat_neigh_min_port, nat_neigh_max_port, neigh_vni1_ul_ipv6)
	# Try to add the same neighnat in different VNI
	grpc_client.expect_error(202).addneighnat(nat_vip, vni2, nat_neigh_min_port, nat_neigh_max_port, neigh_vni1_ul_ipv6)
	# Try to add an overlapping port range for the same IP
	grpc_client.expect_error(202).addneighnat(nat_vip, vni2, nat_neigh_min_port+1, nat_neigh_max_port+1, neigh_vni1_ul_ipv6)
	grpc_client.delneighnat(nat_vip, vni1, nat_neigh_min_port, nat_neigh_max_port)
	# Use IPv6 NAT address
	grpc_client.expect_error(204).addneighnat("1234::1", vni1, nat_neigh_min_port, nat_neigh_max_port, neigh_vni1_ul_ipv6)
	grpc_client.expect_error(204).delneighnat("1234::1", vni1, nat_neigh_min_port, nat_neigh_max_port)
	grpc_client.expect_error(204).listneighnats("1234::1")


def test_grpc_lb(prepare_ifaces, grpc_client):
	ul_ipv6 = grpc_client.createlb(lb_name, vni1, lb_ip, "tcp/80")
	lbspec = { "vni": vni1, "loadbalanced_ip": lb_ip, "loadbalanced_ports": [ { "protocol": 6, "port": 80 } ], "underlay_route": ul_ipv6 }
	spec = grpc_client.getlb(lb_name)
	assert spec == lbspec, \
		"Loadbalancer not created properly"
	grpc_client.expect_error(202).createlb(lb_name, vni1, lb_ip, "tcp/80")
	grpc_client.dellb(lb_name)
	grpc_client.expect_error(201).getlb(lb_name)
	grpc_client.expect_error(201).dellb(lb_name)
	grpc_client.createlb(lb_name, vni1, lb_ip, "tcp/80")
	grpc_client.dellb(lb_name)

def test_grpc_lb_list(prepare_ifaces, grpc_client):
	lb1_ul = grpc_client.createlb("lb1", vni1, "1.2.3.4", "tcp/80,udp/80")
	lb2_ul = grpc_client.createlb("lb2", vni1, "1234::1", "tcp/80")
	lb1spec = grpc_client.getlb("lb1")
	lb2spec = grpc_client.getlb("lb2")
	specs = grpc_client.listlbs()
	assert specs == [ lb1spec, lb2spec ], \
		"Loadbalancers not properly added to a list"
	grpc_client.dellb("lb1")
	specs = grpc_client.listlbs()
	assert specs == [ lb2spec ], \
		"Loadbalancer not properly removed from a list"
	grpc_client.dellb("lb2")
	specs = grpc_client.listlbs()
	assert specs == [], \
		"Loadbalancers not properly removed from a list"

def test_grpc_lb_errors(prepare_ifaces, grpc_client):
	# Try to use an invalid port specification
	grpc_client.expect_failure().createlb(lb_name, vni1, lb_ip, "invalid")
	grpc_client.expect_failure().createlb(lb_name, vni1, lb_ip, "icmp/22")
	grpc_client.expect_failure().createlb(lb_name, vni1, lb_ip, "udp/65536")
	# Try to use duplicate port specification
	grpc_client.expect_failure().createlb(lb_name, vni1, lb_ip, "tcp/80,tcp/80")
	# Try same port with different protocol both at once
	grpc_client.createlb(lb_name, vni1, lb_ip, "tcp/80,udp/80")
	grpc_client.dellb(lb_name)

def test_grpc_lbtarget(prepare_ifaces, grpc_client):
	target_ul = "1234::1"
	grpc_client.createlb(lb_name, vni1, lb_ip, "tcp/80")
	grpc_client.addlbtarget(lb_name, target_ul)
	grpc_client.expect_error(202).addlbtarget(lb_name, target_ul)
	grpc_client.dellbtarget(lb_name, target_ul)
	grpc_client.expect_error(201).dellbtarget(lb_name, target_ul)
	grpc_client.addlbtarget(lb_name, target_ul)
	grpc_client.dellbtarget(lb_name, target_ul)
	grpc_client.dellb(lb_name)

def test_grpc_lbtarget_list(prepare_ifaces, grpc_client):
	target1spec = { "target_ip": "1234::1" }
	target2spec = { "target_ip": "1234::2" }
	grpc_client.createlb(lb_name, vni1, lb_ip, "tcp/80")
	grpc_client.addlbtarget(lb_name, target1spec['target_ip'])
	grpc_client.addlbtarget(lb_name, target2spec['target_ip'])

	specs = grpc_client.listlbtargets(lb_name)
	assert specs == [ target1spec, target2spec ], \
		"Loadbalancer targets not properly added to a list"
	grpc_client.dellbtarget(lb_name, target1spec['target_ip'])
	specs = grpc_client.listlbtargets(lb_name)
	assert specs == [ target2spec ], \
		"Loadbalancer target not properly removed from a list"
	grpc_client.dellbtarget(lb_name, target2spec['target_ip'])
	specs = grpc_client.listlbtargets(lb_name)
	assert specs == [], \
		"Loadbalancer targets not properly removed from a list"
	grpc_client.dellb(lb_name)

def test_grpc_lbtarget_errors(prepare_ifaces, grpc_client):
	# Try to specify invalid LB
	grpc_client.expect_error(422).addlbtarget("nonexisting", "::")
	grpc_client.expect_error(422).dellbtarget("nonexisting", "::")
	grpc_client.expect_error(422).listlbtargets("nonexisting")
	# Use IPv4 underlay
	grpc_client.createlb(lb_name, vni1, lb_ip, "tcp/80")
	grpc_client.expect_error(204).addlbtarget(lb_name, "1.2.3.4")
	grpc_client.expect_error(204).dellbtarget(lb_name, "1.2.3.4")
	grpc_client.dellb(lb_name)


def grpc_test_lbprefix(grpc_client, prefix):
	grpc_client.addlbprefix(VM1.name, prefix)
	grpc_client.expect_error(202).addlbprefix(VM1.name, prefix)
	grpc_client.dellbprefix(VM1.name, prefix)
	grpc_client.expect_error(201).dellbprefix(VM1.name, prefix)
	grpc_client.addlbprefix(VM1.name, prefix)
	grpc_client.dellbprefix(VM1.name, prefix)

def grpc_test_lbprefix_list(grpc_client, prefix1, prefix2):
	pfx1_ul = grpc_client.addlbprefix(VM1.name, prefix1)
	pfx2_ul = grpc_client.addlbprefix(VM1.name, prefix2)
	spec1 = { "prefix": prefix1, "underlay_route": pfx1_ul }
	spec2 = { "prefix": prefix2, "underlay_route": pfx2_ul }
	specs = grpc_client.listlbprefixes(VM1.name)
	assert specs == [ spec1, spec2 ], \
		"Loadbalancer prefixes not properly added to a list"
	grpc_client.dellbprefix(VM1.name, prefix1)
	specs = grpc_client.listlbprefixes(VM1.name)
	assert specs == [ spec2 ], \
		"Loadbalancer prefix not properly removed from a list"
	grpc_client.dellbprefix(VM1.name, prefix2)
	specs = grpc_client.listlbprefixes(VM1.name)
	assert specs == [], \
		"Loadbalancer prefixex not properly removed from a list"

def test_grpc_lbprefix(prepare_ifaces, grpc_client):
	grpc_test_lbprefix(grpc_client, f"1.2.3.0/24")
	grpc_test_lbprefix_list(grpc_client, f"1.2.3.0/24", f"1.2.4.0/24")

def test_grpc_lbprefix_ipv6(prepare_ifaces, grpc_client):
	grpc_test_lbprefix(grpc_client, f"1234::/64")
	grpc_test_lbprefix_list(grpc_client, f"1234:1::/64", f"1234:2::/64")

def test_grpc_lbprefix_errors(prepare_ifaces, grpc_client):
	# Try to address a machine which doesn't exist
	grpc_client.expect_error(205).addlbprefix("invalid_name", "1.2.3.4/24")
	grpc_client.expect_error(205).listlbprefixes("invalid_name")
	grpc_client.expect_error(205).dellbprefix("invalid_name", "1.2.3.4/24")


def test_grpc_fwallrule(prepare_ifaces, grpc_client):
	grpc_client.addfwallrule(VM1.name, "fw0-vm1", src_prefix="1.2.3.4/16", proto="tcp")
	rulespec = { "id": "fw0-vm1",
				 "direction": "Ingress", "action": "Accept", "priority": 1000,
				 "source_prefix": "1.2.3.4/16", "destination_prefix": "0.0.0.0/0",
				 "protocol_filter": { "Filter": { "Tcp": {
					 "src_port_lower": -1, "src_port_upper": -1, "dst_port_lower": -1, "dst_port_upper": -1
				 } } } }
	spec = grpc_client.getfwallrule(VM1.name, "fw0-vm1")
	assert spec == rulespec, \
		"Firewall rule not added properly"
	grpc_client.expect_error(202).addfwallrule(VM1.name, "fw0-vm1", src_prefix="1.2.3.4/16", proto="tcp")
	grpc_client.delfwallrule(VM1.name, "fw0-vm1")
	grpc_client.expect_error(201).getfwallrule(VM1.name, "fw0-vm1")
	specs = grpc_client.listfwallrules(VM1.name)
	assert rulespec not in specs, \
		"Firewall rule not removed properly"
	grpc_client.expect_error(201).delfwallrule(VM1.name, "fw0-vm1")
	grpc_client.addfwallrule(VM1.name, "fw0-vm1", src_prefix="1.2.3.4/16", proto="tcp")
	grpc_client.delfwallrule(VM1.name, "fw0-vm1")

def test_grpc_fwallrule_list(prepare_ifaces, grpc_client):
	grpc_client.addfwallrule(VM1.name, "fw0-vm1", src_prefix="1.2.3.4/16", proto="tcp")
	grpc_client.addfwallrule(VM1.name, "fw1-vm1", src_prefix="4.5.6.7/16", proto="udp", direction="egress")
	rule1spec = grpc_client.getfwallrule(VM1.name, "fw0-vm1")
	rule2spec = grpc_client.getfwallrule(VM1.name, "fw1-vm1")
	specs = grpc_client.listfwallrules(VM1.name)
	assert specs == [ rule1spec, rule2spec ], \
		"Firewall rules not properly added to a list"
	grpc_client.delfwallrule(VM1.name, "fw0-vm1")
	specs = grpc_client.listfwallrules(VM1.name)
	assert specs == [ rule2spec ], \
		"Firewall rule not properly removed from a list"
	grpc_client.delfwallrule(VM1.name, "fw1-vm1")
	specs = grpc_client.listfwallrules(VM1.name)
	assert specs == [], \
		"Firewall rules not properly removed from a list"

def test_grpc_fwallrule_errors(prepare_ifaces, grpc_client):
	# Try to specify an invalid VM
	grpc_client.expect_error(205).addfwallrule("invalid", "fw0-vm1", src_prefix="1.2.3.4/16", proto="tcp")
	grpc_client.expect_error(205).getfwallrule("invalid", "fw0-vm1")
	grpc_client.expect_error(205).listfwallrules("invalid")
	# Try to add an unsupported "drop" rule
	grpc_client.expect_error(441).addfwallrule(VM1.name, "fw0-vm1", src_prefix="1.2.3.4/16", proto="tcp", action="drop")


def test_grpc_vni(prepare_ifaces, grpc_client):
	spec = grpc_client.getvni(VM1.vni)
	assert spec['in_use'] is True, \
		f"VM1 VNI {VM1.vni} not in use"
	spec = grpc_client.getvni(999)
	assert spec['in_use'] is False, \
		f"Invalid VNI 99 in use"

def test_grpc_vni_reset(prepare_ifaces, grpc_client):
	# Copy routes of VM1 to make this easier
	vm1_routes = grpc_client.listroutes(VM1.vni)
	grpc_client.addinterface(VM4.name, VM4.pci, 999, VM4.ip, VM4.ipv6)
	for route in vm1_routes:
		grpc_client.addroute(999, route['prefix'], route['next_hop']['vni'], route['next_hop']['address'])
	routes = grpc_client.listroutes(999)
	assert len(routes) == len(vm1_routes), \
		"Unable to copy VM1 routes"
	grpc_client.resetvni(999)
	routes = grpc_client.listroutes(999)
	assert len(routes) == 0, \
		"Resetting VNI 999 did not work"
	grpc_client.delinterface(VM4.name)


#
# Testing offloaded packet capturing is not doable using TUN/TAP devices
# Thus a unit-test for CaptureStart, CaptureStop and CaptureStatus
# will not be provided here
#


# Test of internal workings of gRPC
# Listings can be sent in multiple bursts when long
# This test tries to enforce such event using routes (assuming other objects would work the same)
def test_grpc_multireply(prepare_ifaces, grpc_client):
	ENTRIES = 64
	for subnet in range(30, 30+ENTRIES):
		ov_target_pfx = f"192.168.{subnet}.0/32"
		grpc_client.addroute(vni1, ov_target_pfx, 0, neigh_vni1_ul_ipv6)

	specs = grpc_client.listroutes(vni1)
	# +2 for the ones already there (from env setup)
	assert len(specs) == ENTRIES + 2, \
		f"Not all routes have been added and listed ({len(specs)}/{ENTRIES+2})"

	for subnet in range(30, 30+ENTRIES):
		ov_target_pfx = f"192.168.{subnet}.0/32"
		grpc_client.delroute(vni1, ov_target_pfx)
