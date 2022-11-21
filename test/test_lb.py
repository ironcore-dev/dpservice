from helpers import *


def test_network_lb_external_icmp_echo(add_machine, request_ip_vf0, grpc_client):

	grpc_client.assert_output(f"--createlb {mylb} --vni {vni} --ipv4 {virtual_ip} --port 80 --protocol tcp", ul_actual_src)

	icmp_pkt = (Ether(dst=mc_mac, src=pf0_mac, type=0x86DD) /
				IPv6(dst=ul_actual_dst, src=ul_actual_src, nh=4) /
				IP(dst=virtual_ip, src=public_ip) /
				ICMP(type=8, id=0x0040))
	answer = srp1(icmp_pkt, iface=pf0_tap, timeout=2)
	assert answer and is_icmp_pkt(answer), \
		"No ECHO reply"

	grpc_client.assert_output(f"--dellb {mylb}",
		"LB deleted")
