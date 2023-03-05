from helpers import *


def test_network_lb_external_icmp_echo(prepare_ipv4, grpc_client):

	ipv6_lb = grpc_client.createlb(mylb, vni, virtual_ip, 80, "tcp")

	icmp_pkt = (Ether(dst=mc_mac, src=pf0_mac, type=0x86DD) /
				IPv6(dst=ipv6_lb, src=ul_actual_src, nh=4) /
				IP(dst=virtual_ip, src=public_ip) /
				ICMP(type=8, id=0x0040))
	answer = srp1(icmp_pkt, iface=pf0_tap, timeout=sniff_timeout)
	validate_checksums(answer)
	assert answer and is_icmp_pkt(answer), \
		"No ECHO reply"

	grpc_client.dellb(mylb)
