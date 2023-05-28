from helpers import *


def test_vni_existence(prepare_ipv4, grpc_client):
	lb_ul_ipv6 = grpc_client.createlb(lb_name, vni3, lb_ip, "tcp/80")
	assert grpc_client.vniinuse(vni3), \
		f"VNI {vni3} should be in use"

	grpc_client.addinterface(VM4.name, VM4.pci, vni3, VM4.ip, VM4.ipv6)
	assert grpc_client.vniinuse(vni3), \
		f"VNI {vni3} should be in use"

	grpc_client.delinterface(VM4.name)
	assert grpc_client.vniinuse(vni3), \
		f"VNI {vni3} should be in use"

	grpc_client.dellb(lb_name)
	assert not grpc_client.vniinuse(vni3), \
		f"VNI {vni3} should not be in use anymore"
