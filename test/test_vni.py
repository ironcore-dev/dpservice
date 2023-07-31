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
