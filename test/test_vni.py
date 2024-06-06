# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

from helpers import *

def test_vni_existence(prepare_ipv4, grpc_client):
	lb_ul_ipv6 = grpc_client.createlb(lb_name, vni3, lb_ip, "tcp/80")
	assert grpc_client.getvni(vni3)['in_use'], \
		f"VNI {vni3} should be in use"

	grpc_client.addinterface(VM4.name, VM4.pci, vni3, VM4.ip, VM4.ipv6)
	assert grpc_client.getvni(vni3)['in_use'], \
		f"VNI {vni3} should be in use"

	grpc_client.delinterface(VM4.name)
	assert grpc_client.getvni(vni3)['in_use'], \
		f"VNI {vni3} should be in use"

	grpc_client.dellb(lb_name)
	assert not grpc_client.getvni(vni3)['in_use'], \
		f"VNI {vni3} should not be in use anymore"


def test_vni_reset(prepare_ipv4, grpc_client):
	grpc_client.addinterface(VM4.name, VM4.pci, vni3, VM4.ip, VM4.ipv6)
	grpc_client.addroute(vni3, neigh_vni1_ov_ip_route, 0, neigh_vni1_ul_ipv6)

	# Also test invalid vni reset and its impact (does not fail though)
	grpc_client.resetvni(999)

	# This is intentionally the same as in VNI1 (see the last test)
	routespec = { "prefix": neigh_vni1_ov_ip_route, "next_hop": { "vni": 0, "address": neigh_vni1_ul_ipv6 } }
	routes = grpc_client.listroutes(vni3)
	assert routespec in routes, \
		"List of routes does not contain the added route"

	grpc_client.resetvni(vni3)

	routes = grpc_client.listroutes(vni3)
	assert routespec not in routes, \
		"List of routes contains the route although vni is reset"

	routes = grpc_client.listroutes(vni1)
	assert routespec in routes, \
		"Resetting a vni tainted another vni"

	grpc_client.delinterface(VM4.name)


def test_vni_neighnats(prepare_ipv4, grpc_client):
	lb_ul_ipv6 = grpc_client.createlb(lb_name, vni1, lb_ip, "tcp/80")
	nat1_ipv6 = grpc_client.addnat(VM1.name, nat_vip, 1000, 2000)
	nat2_ipv6 = grpc_client.addnat(VM2.name, nat_vip, 2000, 3000)

	grpc_client.addneighnat(nat_vip, vni1, 3000, 4000, neigh_vni1_ul_ipv6)
	grpc_client.addneighnat(nat_vip, vni1, 4000, 5000, neigh_vni1_ul_ipv6)
	neighnats = grpc_client.listneighnats(nat_vip)
	assert len(neighnats) == 2, \
		"List of neighbor NATs is not complete"

	grpc_client.delnat(VM2.name)
	grpc_client.delnat(VM1.name)
	grpc_client.delinterface(VM2.name)
	grpc_client.delinterface(VM1.name)
	neighnats = grpc_client.listneighnats(nat_vip)
	assert len(neighnats) == 2, \
		"Neighbor NATs removed prematurely"

	grpc_client.delneighnat(nat_vip, vni1, 3000, 4000)
	grpc_client.delneighnat(nat_vip, vni1, 4000, 5000)

	# Need to add the VMs back before removing the LB otherwise the VNI will get cleaned up
	VM1.ul_ipv6 = grpc_client.addinterface(VM1.name, VM1.pci, VM1.vni, VM1.ip, VM1.ipv6)
	VM2.ul_ipv6 = grpc_client.addinterface(VM2.name, VM2.pci, VM2.vni, VM2.ip, VM2.ipv6)

	grpc_client.dellb(lb_name)


def test_vni_dnat_reset(prepare_ifaces, grpc_client):
	# Need a VM on a separate VNI with a NAT and neighboring entry
	vni = 999
	grpc_client.addinterface(VM4.name, VM4.pci, vni, VM4.ip, VM4.ipv6)
	grpc_client.addnat(VM4.name, nat_vip, 100, 200)
	grpc_client.addneighnat(nat_vip, vni, 200, 300, neigh_vni1_ul_ipv6)

	# The VM gets removed along with the connected NAT entry
	# However neighboring NAT entries are removed asynchronously, i.e. arrive later
	grpc_client.delnat(VM4.name)
	grpc_client.delinterface(VM4.name)
	# This resets VM4's VNI, thus purges neighbor NAT entries

	# If asynchronous deletion arrives now, there is no NAT entry (purged)
	grpc_client.expect_error(201).delneighnat(nat_vip, vni, 200, 300)

	# A VM is re-created with a VIP
	grpc_client.addinterface(VM4.name, VM4.pci, vni, VM4.ip, VM4.ipv6)
	# BUG The VNI reset forgot to clean-up DNAT entries
	grpc_client.addvip(VM4.name, nat_vip)
	grpc_client.delvip(VM4.name)

	grpc_client.delinterface(VM4.name)
