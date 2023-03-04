import threading

from helpers import *


def send_lb_pkt_to_pf(lb_ipv6):
	lb_pkt = (Ether(dst=mc_mac, src=pf0_mac, type=0x86DD) /
			  IPv6(dst=lb_ipv6, src=ul_actual_src, nh=4) /
			  IP(dst=virtual_ip, src=public_ip) /
			  TCP(sport=1234, dport=80))
	delayed_sendp(lb_pkt, pf0_tap)

def test_pf_to_vf_lb_tcp(prepare_ifaces, grpc_client):

	lb_ipv6 = grpc_client.createlb(mylb, vni, virtual_ip, 80, "tcp")
	lbpfx_ipv6 = grpc_client.addlbpfx(vm1_name, virtual_ip)
	grpc_client.addlbvip(mylb, lbpfx_ipv6)

	threading.Thread(target=send_lb_pkt_to_pf, args=(lb_ipv6,)).start()

	pkt = sniff_packet(vf0_tap, is_tcp_pkt)
	dst_ip = pkt[IP].dst
	dport = pkt[TCP].dport
	assert dst_ip == virtual_ip and dport == 80, \
		f"Wrong packet received (ip: {dst_ip}, dport: {dport})"

	grpc_client.dellbvip(vm1_name, lbpfx_ipv6)
	grpc_client.dellbpfx(vm1_name, virtual_ip)
	grpc_client.dellb(mylb)
