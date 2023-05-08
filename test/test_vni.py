from helpers import *


def test_vni_existence(prepare_ipv4, grpc_client):
	lb_ul_ipv6 = grpc_client.createlb(lb_name, vni3, lb_ip, 80, "tcp")
	grpc_client.assert_output(f"--vni_in_use  --vni {vni3}",
		f"not in use", negate=True)

	grpc_client.addmachine(VM4.name, VM4.pci, vni3, VM4.ip, VM4.ipv6)
	grpc_client.assert_output(f"--vni_in_use  --vni {vni3}",
		f"not in use", negate=True)

	grpc_client.delmachine(VM4.name)
	grpc_client.assert_output(f"--vni_in_use  --vni {vni3}",
		f"not in use", negate=True)

	grpc_client.dellb(lb_name)
	grpc_client.assert_output(f"--vni_in_use  --vni {vni3}",
		f"not in use")